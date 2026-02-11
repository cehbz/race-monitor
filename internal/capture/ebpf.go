// Package capture loads eBPF probes into libtorrent functions and streams events.
package capture

import (
	"bytes"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/cehbz/race-monitor/internal/bpf"
)

// symbolPrefixes maps eBPF program names to their C++ mangled symbol prefixes.
// We search the binary's ELF symbol table for a match (ignoring .cold variants).
var symbolPrefixes = map[string]string{
	"we_have":      "_ZN10libtorrent7torrent7we_haveE",
	"incoming_have": "_ZN10libtorrent15peer_connection13incoming_haveE",
}

// findSymbol searches an ELF binary's symbol table for a symbol with the given prefix,
// skipping compiler-generated .cold split functions.
func findSymbol(binPath, prefix string) (string, error) {
	f, err := elf.Open(binPath)
	if err != nil {
		return "", fmt.Errorf("opening ELF %s: %w", binPath, err)
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		return "", fmt.Errorf("reading symbols from %s: %w", binPath, err)
	}

	for _, sym := range syms {
		if strings.HasPrefix(sym.Name, prefix) && !strings.HasSuffix(sym.Name, ".cold") {
			return sym.Name, nil
		}
	}
	return "", fmt.Errorf("no symbol with prefix %q in %s", prefix, binPath)
}

// Capture attaches eBPF uprobes to the qBittorrent binary and returns
// channels for raw eBPF events and calibration events. The caller is
// responsible for enriching events with torrent metadata from the qBittorrent
// API. Calibration events contain 512-byte memory dumps from peer_connection
// structs for auto-discovering the sockaddr_in offset.
//
// If pid > 0, probes fire only for that process. If pid == 0, probes fire
// for all processes executing the binary.
func Capture(ctx context.Context, logger *slog.Logger, binPath string, pid int) (<-chan bpf.Event, <-chan bpf.CalibrationEvent, error) {
	// Log diagnostic info for permission debugging
	if paranoid, err := os.ReadFile("/proc/sys/kernel/perf_event_paranoid"); err == nil {
		logger.Debug("kernel security", "perf_event_paranoid", strings.TrimSpace(string(paranoid)), "uid", os.Getuid())
	}

	// setcap binaries are marked non-dumpable by the kernel, which blocks
	// /proc/self access that cilium/ebpf needs for kernel version detection
	// and rlimit changes. Re-enable dumpability to restore /proc/self access.
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0); err != nil {
		logger.Warn("prctl PR_SET_DUMPABLE failed", "error", err)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, fmt.Errorf("removing memlock rlimit (needs CAP_SYS_RESOURCE): %w", err)
	}

	// Resolve mangled C++ symbols
	weHaveSym, err := findSymbol(binPath, symbolPrefixes["we_have"])
	if err != nil {
		return nil, nil, fmt.Errorf("resolving we_have symbol: %w", err)
	}
	incomingHaveSym, err := findSymbol(binPath, symbolPrefixes["incoming_have"])
	if err != nil {
		return nil, nil, fmt.Errorf("resolving incoming_have symbol: %w", err)
	}

	logger.Info("resolved probe symbols",
		"we_have", weHaveSym,
		"incoming_have", incomingHaveSym)

	// Load eBPF programs
	objs := bpf.ProbeObjects{}
	if err := bpf.LoadProbeObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading eBPF objects (if 'permission denied': check kernel.perf_event_paranoid <= 2 and CAP_BPF capability): %w", err)
	}

	// Open the target binary for uprobe attachment
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("opening executable %s: %w", binPath, err)
	}

	// Attach uprobes (optionally filtered to a single PID)
	var uprobeOpts *link.UprobeOptions
	if pid > 0 {
		uprobeOpts = &link.UprobeOptions{PID: pid}
	}

	upWeHave, err := ex.Uprobe(weHaveSym, objs.TraceWeHave, uprobeOpts)
	if err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("attaching uprobe to %s: %w", weHaveSym, err)
	}

	upIncomingHave, err := ex.Uprobe(incomingHaveSym, objs.TraceIncomingHave, uprobeOpts)
	if err != nil {
		upWeHave.Close()
		objs.Close()
		return nil, nil, fmt.Errorf("attaching uprobe to %s: %w", incomingHaveSym, err)
	}

	if pid > 0 {
		logger.Info("eBPF probes attached", "binary", binPath, "pid", pid)
	} else {
		logger.Info("eBPF probes attached", "binary", binPath, "pid", "all")
	}

	// Create perf event reader (256 KB per-CPU buffer — sized for ~3K events/sec
	// incoming_have bursts plus calibration events sharing the same perf buffer.
	// Calibration events are 536 bytes but infrequent (~50/race).)
	rd, err := perf.NewReader(objs.Events, 256*1024)
	if err != nil {
		upIncomingHave.Close()
		upWeHave.Close()
		objs.Close()
		return nil, nil, fmt.Errorf("creating perf reader: %w", err)
	}

	eventChan := make(chan bpf.Event, 10000)
	calChan := make(chan bpf.CalibrationEvent, 100)

	go func() {
		defer close(eventChan)
		defer close(calChan)
		defer rd.Close()
		defer upIncomingHave.Close()
		defer upWeHave.Close()
		defer objs.Close()

		logger.Info("perf reader started, waiting for events")

		var totalLost uint64
		for {
			rec, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					logger.Debug("perf reader closed", "total_lost_samples", totalLost)
					return
				}
				logger.Warn("perf read error", "error", err)
				continue
			}

			if rec.LostSamples > 0 {
				totalLost += rec.LostSamples
				logger.Warn("lost perf samples", "batch", rec.LostSamples, "total_lost", totalLost)
				continue
			}

			// Polymorphic decode: peek at first 4 bytes for event type
			if len(rec.RawSample) < 4 {
				logger.Warn("perf record too short", "len", len(rec.RawSample))
				continue
			}

			eventType := binary.LittleEndian.Uint32(rec.RawSample[:4])

			switch eventType {
			case bpf.EventCalibration:
				var cal bpf.CalibrationEvent
				if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &cal); err != nil {
					logger.Warn("failed to decode calibration event", "error", err)
					continue
				}
				select {
				case calChan <- cal:
				case <-ctx.Done():
					return
				}

			default:
				var event bpf.Event
				if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &event); err != nil {
					logger.Warn("failed to decode event", "error", err)
					continue
				}
				select {
				case eventChan <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	// Close the perf reader when context is cancelled (unblocks rd.Read)
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	return eventChan, calChan, nil
}

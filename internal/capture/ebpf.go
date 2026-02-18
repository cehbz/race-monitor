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
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/cehbz/race-monitor/internal/bpf"
)

// setCalibrationFlags writes the calibration gate flags into BPF array maps.
// When a flag is 0, the BPF probe skips emitting calibration dumps.
func setCalibrationFlags(objs *bpf.ProbeObjects, flags *CalibrationFlags, logger *slog.Logger) error {
	// Defaults: all calibration enabled (flag=1).
	var peerFlag, torrentFlag uint32 = 1, 1
	if flags != nil {
		if !flags.PeerCalibrationNeeded {
			peerFlag = 0
		}
		if !flags.TorrentCalibrationNeeded {
			torrentFlag = 0
		}
	}

	key := uint32(0)
	if err := objs.PeerCalNeeded.Put(key, peerFlag); err != nil {
		return fmt.Errorf("setting peer_cal_needed: %w", err)
	}
	if err := objs.TorrentCalNeeded.Put(key, torrentFlag); err != nil {
		return fmt.Errorf("setting torrent_cal_needed: %w", err)
	}

	logger.Info("BPF calibration flags set",
		"peer_cal_needed", peerFlag,
		"torrent_cal_needed", torrentFlag)
	return nil
}

// symbolPrefixes maps eBPF program names to their C++ mangled symbol prefixes.
// We search the binary's ELF symbol table for a match (ignoring .cold variants).
var symbolPrefixes = map[string]string{
	"we_have":          "_ZN10libtorrent7torrent7we_haveE",
	"incoming_have":    "_ZN10libtorrent15peer_connection13incoming_haveE",
	"torrent_start":    "_ZN10libtorrent7torrent5startE",
	"torrent_finished": "_ZN10libtorrent7torrent8finishedE",
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

// readResult carries a perf record and error from the read goroutine.
type readResult struct {
	rec perf.Record
	err error
}

// CalibrationFlags controls which calibration dumps the BPF probes emit.
// When a flag is false, the corresponding calibration events are suppressed
// in the kernel, reducing overhead when offsets are cached.
type CalibrationFlags struct {
	PeerCalibrationNeeded    bool // emit peer_connection struct dumps
	TorrentCalibrationNeeded bool // emit torrent struct dumps
}

// Capture attaches eBPF uprobes to the qBittorrent binary and returns
// channels for raw eBPF events and calibration events. The caller is
// responsible for enriching events with torrent metadata from the qBittorrent
// API. Calibration events contain memory dumps from peer_connection and torrent
// structs for auto-discovering field offsets.
//
// calFlags controls which calibration dumps are emitted. Pass nil for
// defaults (all calibration enabled).
//
// If pid > 0, probes fire only for that process. If pid == 0, probes fire
// for all processes executing the binary.
func Capture(ctx context.Context, logger *slog.Logger, binPath string, pid int, calFlags *CalibrationFlags) (<-chan bpf.Event, <-chan bpf.CalibrationEvent, error) {
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

	// Resolve mangled C++ symbols (required)
	weHaveSym, err := findSymbol(binPath, symbolPrefixes["we_have"])
	if err != nil {
		return nil, nil, fmt.Errorf("resolving we_have symbol: %w", err)
	}
	incomingHaveSym, err := findSymbol(binPath, symbolPrefixes["incoming_have"])
	if err != nil {
		return nil, nil, fmt.Errorf("resolving incoming_have symbol: %w", err)
	}

	// Resolve lifecycle symbols (optional — degrade gracefully if absent)
	torrentStartSym, err := findSymbol(binPath, symbolPrefixes["torrent_start"])
	if err != nil {
		logger.Warn("lifecycle probe: torrent::start() not found, race creation falls back to we_have heuristic", "error", err)
		torrentStartSym = ""
	}
	torrentFinishedSym, err := findSymbol(binPath, symbolPrefixes["torrent_finished"])
	if err != nil {
		logger.Warn("lifecycle probe: torrent::finished() not found, completion detection falls back to idle timeout", "error", err)
		torrentFinishedSym = ""
	}

	logger.Info("resolved probe symbols",
		"we_have", weHaveSym,
		"incoming_have", incomingHaveSym,
		"torrent_start", torrentStartSym,
		"torrent_finished", torrentFinishedSym)

	// Load eBPF programs
	objs := bpf.ProbeObjects{}
	if err := bpf.LoadProbeObjects(&objs, nil); err != nil {
		return nil, nil, fmt.Errorf("loading eBPF objects (if 'permission denied': check kernel.perf_event_paranoid <= 2 and CAP_BPF capability): %w", err)
	}

	// Set calibration gate flags in BPF maps. Default is calibration needed
	// (flag=1); suppress when offsets are cached (flag=0).
	if err := setCalibrationFlags(&objs, calFlags, logger); err != nil {
		objs.Close()
		return nil, nil, fmt.Errorf("setting calibration flags: %w", err)
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

	// closers accumulates cleanup functions for attached probes
	var closers []func()
	closeAll := func() {
		for i := len(closers) - 1; i >= 0; i-- {
			closers[i]()
		}
		objs.Close()
	}

	upWeHave, err := ex.Uprobe(weHaveSym, objs.TraceWeHave, uprobeOpts)
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("attaching uprobe to %s: %w", weHaveSym, err)
	}
	closers = append(closers, func() { upWeHave.Close() })

	upIncomingHave, err := ex.Uprobe(incomingHaveSym, objs.TraceIncomingHave, uprobeOpts)
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("attaching uprobe to %s: %w", incomingHaveSym, err)
	}
	closers = append(closers, func() { upIncomingHave.Close() })

	// Attach optional lifecycle probes
	if torrentStartSym != "" {
		upTorrentStart, err := ex.Uprobe(torrentStartSym, objs.TraceTorrentStart, uprobeOpts)
		if err != nil {
			logger.Warn("failed to attach torrent_start uprobe (non-fatal)", "error", err)
		} else {
			closers = append(closers, func() { upTorrentStart.Close() })
		}
	}
	if torrentFinishedSym != "" {
		upTorrentFinished, err := ex.Uprobe(torrentFinishedSym, objs.TraceTorrentFinished, uprobeOpts)
		if err != nil {
			logger.Warn("failed to attach torrent_finished uprobe (non-fatal)", "error", err)
		} else {
			closers = append(closers, func() { upTorrentFinished.Close() })
		}
	}

	if pid > 0 {
		logger.Info("eBPF probes attached", "binary", binPath, "pid", pid)
	} else {
		logger.Info("eBPF probes attached", "binary", binPath, "pid", "all")
	}

	// Create perf event reader (256 KB per-CPU buffer — sized for ~3K events/sec
	// incoming_have bursts plus calibration events sharing the same perf buffer.
	// Calibration events are ~4KB but infrequent (~50/race).)
	rd, err := perf.NewReader(objs.Events, 256*1024)
	if err != nil {
		closeAll()
		return nil, nil, fmt.Errorf("creating perf reader: %w", err)
	}

	eventChan := make(chan bpf.Event, 10000)
	calChan := make(chan bpf.CalibrationEvent, 100)

	go func() {
		defer close(eventChan)
		defer close(calChan)
		defer rd.Close()
		defer closeAll()

		logger.Info("perf reader started, waiting for events")

		var totalLost uint64
		var eventCount, calCount uint64
		var firstEventLogged bool
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()

		recCh := make(chan readResult, 1)
		go func() {
			for {
				rec, err := rd.Read()
				recCh <- readResult{rec: rec, err: err}
				if err != nil {
					close(recCh)
					return
				}
			}
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				logger.Log(ctx, LevelTrace, "perf: event count", "events", eventCount, "cals", calCount, "lost", totalLost)
			case r, ok := <-recCh:
				if !ok {
					logger.Debug("perf reader closed", "total_lost_samples", totalLost)
					return
				}
				if r.err != nil {
					if errors.Is(r.err, perf.ErrClosed) {
						logger.Debug("perf reader closed", "total_lost_samples", totalLost)
						return
					}
					logger.Warn("perf read error", "error", r.err)
					continue
				}
				rec := r.rec

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

				// Trace: first event received (confirms events reach Go)
				if !firstEventLogged {
					firstEventLogged = true
					logger.Log(ctx, LevelTrace, "perf: first event received", "event_type", eventType)
				}

				switch eventType {
				case bpf.EventCalibration, bpf.EventTorrentCalibration, bpf.EventTorrentStarted:
					calCount++
					// Large calibration events routed to calibration channel.
					// TorrentStarted carries a full torrent struct dump like
					// TorrentCalibration but also triggers race creation.
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
					eventCount++
					// Slim events (24 bytes): we_have, incoming_have, torrent_finished
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
		}
	}()

	// Close the perf reader when context is cancelled (unblocks rd.Read)
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	return eventChan, calChan, nil
}

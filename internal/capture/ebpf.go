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
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/cehbz/race-monitor/internal/bpf"
)

// symbolPrefixes maps eBPF program names to their C++ mangled symbol prefixes.
// We search the binary's ELF symbol table for a match (ignoring .cold variants).
var symbolPrefixes = map[string]string{
	"we_have":           "_ZN10libtorrent7torrent7we_haveE",
	"incoming_have":     "_ZN10libtorrent15peer_connection13incoming_haveE",
	"incoming_bitfield": "_ZN10libtorrent15peer_connection17incoming_bitfieldE",
	"torrent_start":     "_ZN10libtorrent7torrent5startE",
	"torrent_finished":  "_ZN10libtorrent7torrent8finishedE",
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

// HasTorrentStartSymbol checks whether the qBittorrent binary contains the
// torrent::start() symbol needed for race lifecycle management.
func HasTorrentStartSymbol(binPath string) bool {
	_, err := findSymbol(binPath, symbolPrefixes["torrent_start"])
	return err == nil
}

// ProbeConfig holds calibrated offsets to pass to BPF programs for
// identity-based peer deduplication. When nil, BPF falls back to
// pointer-based dedup (calibration mode).
type ProbeConfig struct {
	TorrentPtrOffset uint32 // offset of torrent* within peer_connection struct
	SockaddrOffset   uint32 // offset of sockaddr_in within peer_connection struct
}

// CaptureHandle wraps the event channels and BPF map handles returned by Capture.
type CaptureHandle struct {
	Events       <-chan bpf.Event
	Dumps        <-chan bpf.DumpEvent
	seenPeers    *ebpf.Map
	seenTorrents *ebpf.Map
}

// ForgetPeer deletes a peer identity from the BPF seen_peers dedup map,
// allowing the peer to be rediscovered if it appears in a future race.
func (h *CaptureHandle) ForgetPeer(torrentPtr uint64, endpoint netip.AddrPort) error {
	if h.seenPeers == nil {
		return nil
	}
	// Build key matching BPF struct peer_key layout (16 bytes):
	//   u64 torrent_ptr (native LE)
	//   u32 ip          (raw sin_addr bytes, network byte order)
	//   u16 port        (raw sin_port bytes, network byte order)
	//   u16 _pad        (zero)
	var key [16]byte
	binary.LittleEndian.PutUint64(key[0:], torrentPtr)
	ip4 := endpoint.Addr().As4()
	copy(key[8:12], ip4[:])
	binary.BigEndian.PutUint16(key[12:14], endpoint.Port())
	// key[14:16] already zero (padding)
	return h.seenPeers.Delete(key[:])
}

// ForgetTorrent deletes a torrent pointer from the BPF seen_torrents dedup map,
// allowing the torrent to emit a new struct dump if it restarts.
func (h *CaptureHandle) ForgetTorrent(ptr uint64) error {
	if h.seenTorrents == nil {
		return nil
	}
	return h.seenTorrents.Delete(ptr)
}

// Capture attaches eBPF uprobes to the qBittorrent binary and returns a
// CaptureHandle with channels for slim events and struct dump events.
// Struct dumps carry 4KB memory snapshots from peer_connection and torrent
// objects, used for extracting peer identity (IP, port, peer_id) and torrent
// identity (info_hash).
//
// If pid > 0, probes fire only for that process. If pid == 0, probes fire
// for all processes executing the binary.
//
// If cfg is non-nil, calibrated offsets are written to the BPF config map,
// enabling identity-based peer deduplication. If nil, BPF uses pointer-based
// dedup (calibration mode).
func Capture(ctx context.Context, logger *slog.Logger, binPath string, pid int, cfg *ProbeConfig) (*CaptureHandle, error) {
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
		return nil, fmt.Errorf("removing memlock rlimit (needs CAP_SYS_RESOURCE): %w", err)
	}

	// Resolve mangled C++ symbols (required)
	weHaveSym, err := findSymbol(binPath, symbolPrefixes["we_have"])
	if err != nil {
		return nil, fmt.Errorf("resolving we_have symbol: %w", err)
	}
	incomingHaveSym, err := findSymbol(binPath, symbolPrefixes["incoming_have"])
	if err != nil {
		return nil, fmt.Errorf("resolving incoming_have symbol: %w", err)
	}

	// Resolve peer discovery symbols (optional — improve peer discovery)
	incomingBitfieldSym, err := findSymbol(binPath, symbolPrefixes["incoming_bitfield"])
	if err != nil {
		logger.Warn("peer discovery probe: incoming_bitfield() not found, seeders using BITFIELD may not be discovered", "error", err)
		incomingBitfieldSym = ""
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
		"incoming_bitfield", incomingBitfieldSym,
		"torrent_start", torrentStartSym,
		"torrent_finished", torrentFinishedSym)

	// Load eBPF programs
	objs := bpf.ProbeObjects{}
	if err := bpf.LoadProbeObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading eBPF objects (if 'permission denied': check kernel.perf_event_paranoid <= 2 and CAP_BPF capability): %w", err)
	}

	// Write calibrated offsets to the BPF config map (monitor mode).
	// Default zero values mean calibration mode (pointer-based dedup).
	if cfg != nil {
		// probeConfigValue matches BPF struct probe_config: two u32 fields.
		type probeConfigValue struct {
			TorrentPtrOffset uint32
			SockaddrOffset   uint32
		}
		cfgVal := probeConfigValue{
			TorrentPtrOffset: cfg.TorrentPtrOffset,
			SockaddrOffset:   cfg.SockaddrOffset,
		}
		cfgKey := uint32(0)
		if err := objs.ProbeConfig.Update(cfgKey, cfgVal, ebpf.UpdateAny); err != nil {
			objs.Close()
			return nil, fmt.Errorf("writing probe_config map: %w", err)
		}
		logger.Info("BPF probe_config written",
			"torrent_ptr_offset", cfg.TorrentPtrOffset,
			"sockaddr_offset", cfg.SockaddrOffset)
	}

	// Open the target binary for uprobe attachment
	ex, err := link.OpenExecutable(binPath)
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("opening executable %s: %w", binPath, err)
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
		return nil, fmt.Errorf("attaching uprobe to %s: %w", weHaveSym, err)
	}
	closers = append(closers, func() { upWeHave.Close() })

	upIncomingHave, err := ex.Uprobe(incomingHaveSym, objs.TraceIncomingHave, uprobeOpts)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("attaching uprobe to %s: %w", incomingHaveSym, err)
	}
	closers = append(closers, func() { upIncomingHave.Close() })

	// Attach optional peer discovery probe
	if incomingBitfieldSym != "" {
		upIncomingBitfield, err := ex.Uprobe(incomingBitfieldSym, objs.TraceIncomingBitfield, uprobeOpts)
		if err != nil {
			logger.Warn("failed to attach incoming_bitfield uprobe (non-fatal)", "error", err)
		} else {
			closers = append(closers, func() { upIncomingBitfield.Close() })
		}
	}

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
	// incoming_have bursts plus struct dump events sharing the same perf buffer.
	// Dump events are ~4KB but infrequent (~50/race).)
	rd, err := perf.NewReader(objs.Events, 256*1024)
	if err != nil {
		closeAll()
		return nil, fmt.Errorf("creating perf reader: %w", err)
	}

	eventChan := make(chan bpf.Event, 10000)
	dumpChan := make(chan bpf.DumpEvent, 100)

	go func() {
		defer close(eventChan)
		defer close(dumpChan)
		defer rd.Close()
		defer closeAll()

		logger.Info("perf reader started, waiting for events")

		var totalLost uint64
		var eventCount, dumpCount uint64
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
				logger.Log(ctx, LevelTrace, "perf: event count", "events", eventCount, "dumps", dumpCount, "lost", totalLost)
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
				case bpf.EventPeerDump, bpf.EventTorrentDump, bpf.EventTorrentStarted:
					dumpCount++
					// Large struct dump events routed to dump channel.
					// TorrentStarted carries a full torrent struct dump like
					// TorrentDump but also triggers race creation.
					var dump bpf.DumpEvent
					if err := binary.Read(bytes.NewBuffer(rec.RawSample), binary.LittleEndian, &dump); err != nil {
						logger.Warn("failed to decode struct dump event", "error", err)
						continue
					}
					select {
					case dumpChan <- dump:
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

	return &CaptureHandle{
		Events:       eventChan,
		Dumps:        dumpChan,
		seenPeers:    objs.SeenPeers,
		seenTorrents: objs.SeenTorrents,
	}, nil
}

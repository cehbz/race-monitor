// Package capture loads eBPF probes into libtorrent functions and streams events.
package capture

import (
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

// decodeProbeEvent decodes a raw perf sample into a typed ProbeEvent.
// Zero-copy for slim events: reads fields directly from the slice via
// binary.LittleEndian without intermediate structs or reflection.
// For dump events, allocates a typed struct and copies Data once.
// Returns nil for malformed or unknown events.
func decodeProbeEvent(raw []byte) bpf.ProbeEvent {
	if len(raw) < 24 { // minimum: event_t is 24 bytes
		return nil
	}

	eventType := binary.LittleEndian.Uint32(raw[0:4])

	switch eventType {
	case bpf.EventPeerDump, bpf.EventTorrentDump, bpf.EventTorrentStarted:
		// struct_dump_t layout: EventType(4) | Pad(4) | Timestamp(8) | ObjPtr(8) | Data(4096)
		if len(raw) < 24+4096 {
			return nil
		}
		timestamp := binary.LittleEndian.Uint64(raw[8:16])
		objPtr := binary.LittleEndian.Uint64(raw[16:24])
		switch eventType {
		case bpf.EventPeerDump:
			ev := &bpf.PeerDetailsEvent{ConnPtr: objPtr, Timestamp: timestamp}
			copy(ev.Data[:], raw[24:24+4096])
			return ev
		case bpf.EventTorrentDump:
			ev := &bpf.TorrentDetailsEvent{TorrentPtr: objPtr, Timestamp: timestamp}
			copy(ev.Data[:], raw[24:24+4096])
			return ev
		case bpf.EventTorrentStarted:
			ev := &bpf.TorrentStartedEvent{TorrentPtr: objPtr, Timestamp: timestamp}
			copy(ev.Data[:], raw[24:24+4096])
			return ev
		}

	case bpf.EventWeHave:
		// event_t layout: EventType(4) | PieceIndex(4) | Timestamp(8) | ObjPtr(8)
		return &bpf.WeHaveEvent{
			TorrentPtr: binary.LittleEndian.Uint64(raw[16:24]),
			PieceIndex: binary.LittleEndian.Uint32(raw[4:8]),
			Timestamp:  binary.LittleEndian.Uint64(raw[8:16]),
		}

	case bpf.EventIncomingHave:
		return &bpf.IncomingHaveEvent{
			ConnPtr:    binary.LittleEndian.Uint64(raw[16:24]),
			PieceIndex: binary.LittleEndian.Uint32(raw[4:8]),
			Timestamp:  binary.LittleEndian.Uint64(raw[8:16]),
		}

	case bpf.EventTorrentFinished:
		return &bpf.TorrentFinishedEvent{
			TorrentPtr: binary.LittleEndian.Uint64(raw[16:24]),
			Timestamp:  binary.LittleEndian.Uint64(raw[8:16]),
		}
	}

	return nil
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

// CaptureHandle wraps the event channel and BPF map handles returned by Capture.
type CaptureHandle struct {
	Events       <-chan bpf.ProbeEvent
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
// CaptureHandle with a single typed event channel carrying concrete
// ProbeEvent values decoded from the perf buffer.
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

	eventChan := make(chan bpf.ProbeEvent, 10000)

	// Reader goroutine: uses ReadInto to reuse the Record and its RawSample
	// backing array across reads (zero allocation after warmup). Decodes
	// inline before the next ReadInto overwrites the buffer.
	go func() {
		defer close(eventChan)
		defer rd.Close()
		defer closeAll()

		logger.Info("perf reader started, waiting for events")

		var (
			rec              perf.Record
			totalLost        uint64
			eventCount       uint64
			firstEventLogged bool
			lastLogTime      = time.Now()
		)

		for {
			if err := rd.ReadInto(&rec); err != nil {
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

			if !firstEventLogged && len(rec.RawSample) >= 4 {
				firstEventLogged = true
				logger.Log(ctx, LevelTrace, "perf: first event received",
					"event_type", binary.LittleEndian.Uint32(rec.RawSample[:4]))
			}

			// Decode directly from RawSample — no intermediate structs,
			// no bytes.Buffer, no reflection. Must complete before next
			// ReadInto reuses the backing array.
			typed := decodeProbeEvent(rec.RawSample)
			if typed == nil {
				if len(rec.RawSample) >= 4 {
					logger.Warn("failed to decode event",
						"type", binary.LittleEndian.Uint32(rec.RawSample[:4]),
						"len", len(rec.RawSample))
				}
				continue
			}

			eventCount++

			if since := time.Since(lastLogTime); since >= 5*time.Second {
				logger.Log(ctx, LevelTrace, "perf: event count", "events", eventCount, "lost", totalLost)
				lastLogTime = time.Now()
			}

			select {
			case eventChan <- typed:
			case <-ctx.Done():
				return
			}
		}
	}()

	// Close the perf reader when context is cancelled (unblocks ReadInto)
	go func() {
		<-ctx.Done()
		rd.Close()
	}()

	return &CaptureHandle{
		Events:       eventChan,
		seenPeers:    objs.SeenPeers,
		seenTorrents: objs.SeenTorrents,
	}, nil
}

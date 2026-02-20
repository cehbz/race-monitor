// race-calibrate discovers libtorrent struct byte offsets for race-monitor.
//
// Run this tool once after each qBittorrent upgrade. It attaches eBPF probes,
// waits for a torrent download to occur, discovers the 4 struct offsets, and
// writes a calibration.json file that race-monitor loads at startup.
//
// Requires the qBittorrent web API (webui_url) to provide ground-truth
// info_hashes and peer data for offset discovery.
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/cehbz/qbittorrent"
	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/capture"
	"github.com/cehbz/race-monitor/internal/race"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	pid := flag.Int("pid", 0, "qBittorrent PID (0 = any)")
	binary := flag.String("binary", "", "path to qBittorrent binary")
	webuiURL := flag.String("webui-url", "", "qBittorrent web UI URL (required)")
	webuiUser := flag.String("webui-user", "", "web UI username")
	webuiPass := flag.String("webui-pass", "", "web UI password")
	configPath := flag.String("config", "", "calibration output path (default: ~/.config/race-monitor/calibration.json)")
	verify := flag.Bool("verify", false, "wait for second torrent to verify offsets")
	logLevel := flag.String("log-level", "info", "log level (trace, debug, info, warn, error)")
	flag.Parse()

	// Also accept PID as positional argument
	if *pid == 0 && flag.NArg() > 0 {
		if p, err := strconv.Atoi(flag.Arg(0)); err == nil {
			*pid = p
		}
	}

	// Try to load missing flags from config file
	if *binary == "" || *webuiURL == "" {
		cfgBinary, _, _, cfgWebuiURL, cfgWebuiUser, cfgWebuiPass := loadConfig()
		if *binary == "" {
			*binary = cfgBinary
		}
		if *webuiURL == "" {
			*webuiURL = cfgWebuiURL
		}
		if *webuiUser == "" {
			*webuiUser = cfgWebuiUser
		}
		if *webuiPass == "" {
			*webuiPass = cfgWebuiPass
		}
	}

	if *binary == "" {
		return fmt.Errorf("--binary is required (path to qBittorrent binary)")
	}
	if *webuiURL == "" {
		return fmt.Errorf("--webui-url is required for calibration (qBittorrent web API provides ground-truth data)")
	}

	if *configPath == "" {
		home, _ := os.UserHomeDir()
		*configPath = filepath.Join(home, ".config", "race-monitor", "calibration.json")
	}

	// Setup logging
	var level slog.Level
	switch *logLevel {
	case "trace":
		level = slog.LevelDebug - 4
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	// Validate binary
	if _, err := os.Stat(*binary); err != nil {
		return fmt.Errorf("binary not found: %s", *binary)
	}
	if !capture.HasTorrentStartSymbol(*binary) {
		return fmt.Errorf("torrent::start() symbol not found in %s", *binary)
	}

	// Compute binary hash
	binaryHash, err := race.ComputeBinaryHash(*binary)
	if err != nil {
		return fmt.Errorf("computing binary hash: %w", err)
	}
	logger.Info("binary identified", "path", *binary, "hash", binaryHash)

	// Connect to qBittorrent API
	client, err := qbittorrent.NewClient(*webuiUser, *webuiPass, *webuiURL)
	if err != nil {
		return fmt.Errorf("connecting to qBittorrent API: %w", err)
	}

	// Fetch known info_hashes
	mainData, err := client.SyncMainData(0)
	if err != nil {
		return fmt.Errorf("fetching maindata: %w", err)
	}
	knownHashes := make(map[string]bool, len(mainData.Torrents))
	for h := range mainData.Torrents {
		knownHashes[h] = true
	}
	logger.Info("loaded known torrents from API", "count", len(knownHashes))

	// Setup context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("received shutdown signal")
		cancel()
	}()

	// Start eBPF capture (nil config = calibration mode with pointer-based dedup)
	handle, err := capture.Capture(ctx, logger, *binary, *pid, nil)
	if err != nil {
		return fmt.Errorf("starting eBPF capture: %w", err)
	}

	events := handle.Events
	dumps := handle.Dumps

	// Drain events channel (we don't process piece events during calibration)
	go func() {
		for range events {
		}
	}()

	// Calibration state
	result := calibResult{
		infoHashOffset:   -1,
		torrentPtrOffset: -1,
		sockaddrOffset:   -1,
		peerIDOffset:     -1,
	}

	// Known torrent pointers (from torrent::start events)
	torrentPtrs := make(map[uint64]string)      // ptr → info_hash
	knownTorrentPtrSet := make(map[uint64]bool) // set of known ptrs

	// refreshHashes re-fetches the torrent list from the API.
	refreshHashes := func() {
		md, err := client.SyncMainData(0)
		if err != nil {
			logger.Warn("failed to refresh torrent list from API", "error", err)
			return
		}
		for h := range md.Torrents {
			knownHashes[h] = true
		}
		logger.Debug("refreshed known hashes from API", "count", len(knownHashes))
	}

	fmt.Println("Waiting for torrent events... (start a download in qBittorrent)")

	verified := false
	var torrentStartCount, peerDumpCount int

	for cal := range dumps {
		if ctx.Err() != nil {
			break
		}

		switch cal.EventType {
		case bpf.EventTorrentStarted, bpf.EventTorrentDump:
			// Both carry torrent struct dumps. EventTorrentStarted comes from
			// torrent::start(), EventTorrentDump from first we_have()
			// per torrent. Either can be used for info_hash discovery and to
			// register torrent pointers.
			isTorrentStart := cal.EventType == bpf.EventTorrentStarted
			if isTorrentStart {
				torrentStartCount++
			}

			if result.infoHashOffset >= 0 {
				// Already calibrated — extract and register
				hashBytes, ok := race.ExtractInfoHash(cal.Data, result.infoHashOffset)
				if ok {
					hash := hex.EncodeToString(hashBytes)
					if _, already := torrentPtrs[cal.ObjPtr]; !already {
						torrentPtrs[cal.ObjPtr] = hash
						knownTorrentPtrSet[cal.ObjPtr] = true
						logger.Debug("registered torrent ptr",
							"ptr", fmt.Sprintf("0x%x", cal.ObjPtr),
							"hash", hash,
							"source", cal.EventType,
							"total_ptrs", len(knownTorrentPtrSet))
					}

					if isTorrentStart && *verify && !verified {
						refreshHashes()
						if knownHashes[hash] {
							fmt.Printf("  VERIFIED torrent::start() hash matches API: %s\n", hash)
							verified = true
						} else {
							return fmt.Errorf("VERIFICATION FAILED: extracted hash %s not found in API", hash)
						}
					}
				}
				continue
			}

			// Try to discover info_hash offset by scanning for known API hashes.
			// If no match, refresh the hash list from the API and retry — the
			// torrent may have been added after our initial fetch.
			offset, hash, ok := findInfoHashOffset(cal.Data, knownHashes)
			if !ok {
				logger.Debug("torrent dump: no match with cached hashes, refreshing from API",
					"ptr", fmt.Sprintf("0x%x", cal.ObjPtr),
					"source", cal.EventType)
				refreshHashes()
				offset, hash, ok = findInfoHashOffset(cal.Data, knownHashes)
			}
			if !ok {
				logger.Debug("torrent dump: no known hash found even after API refresh",
					"ptr", fmt.Sprintf("0x%x", cal.ObjPtr))
				continue
			}

			result.infoHashOffset = offset
			torrentPtrs[cal.ObjPtr] = hash
			knownTorrentPtrSet[cal.ObjPtr] = true
			fmt.Printf("  info_hash offset: %d (matched hash: %s)\n", offset, hash)
			fmt.Println("  Waiting for peer_connection events (need active peer traffic)...")

		case bpf.EventPeerDump:
			peerDumpCount++

			if peerDumpCount == 1 {
				logger.Debug("first peer_connection dump received")
			}

			// torrent_ptr offset
			if result.torrentPtrOffset < 0 && len(knownTorrentPtrSet) > 0 {
				offset, ok := findTorrentPtrOffset(cal.Data, knownTorrentPtrSet)
				if ok {
					result.torrentPtrOffset = offset
					fmt.Printf("  torrent_ptr offset: %d\n", offset)
				} else {
					logger.Debug("peer dump: no known torrent_ptr found",
						"known_ptrs", len(knownTorrentPtrSet), "peer_dumps", peerDumpCount)
				}
			}

			// If we know the torrent_ptr offset, extract it and look up the hash
			// to find peers for sockaddr/peer_id calibration
			if result.torrentPtrOffset >= 0 && (result.sockaddrOffset < 0 || result.peerIDOffset < 0) {
				torrentPtr, ok := race.ExtractTorrentPtr(cal.Data, result.torrentPtrOffset)
				if ok {
					if hash, known := torrentPtrs[torrentPtr]; known {
						// Invalidate peer cache so we get fresh data on each attempt
						clearPeerCache(hash)

						// sockaddr_in offset
						if result.sockaddrOffset < 0 {
							offset, ok := findSockaddrOffset(cal.Data, client, hash, logger)
							if ok {
								result.sockaddrOffset = offset
								fmt.Printf("  sockaddr_in offset: %d\n", offset)
							}
						}

						// peer_id offset
						if result.peerIDOffset < 0 && result.sockaddrOffset >= 0 {
							offset, ok := findPeerIDOffset(cal.Data, client, hash, logger)
							if ok {
								result.peerIDOffset = offset
								fmt.Printf("  peer_id offset: %d\n", offset)
							}
						}
					} else {
						logger.Debug("peer dump: torrent_ptr not in known set",
							"torrent_ptr", fmt.Sprintf("0x%x", torrentPtr))
					}
				}
			}
		}

		// Check if all offsets are discovered
		if result.infoHashOffset >= 0 && result.torrentPtrOffset >= 0 &&
			result.sockaddrOffset >= 0 && result.peerIDOffset >= 0 {
			if !*verify || verified {
				break
			}
			// Keep going until verification completes
		}
	}

	if ctx.Err() != nil {
		// Provide actionable guidance based on what's missing
		var missing []string
		if result.infoHashOffset < 0 {
			missing = append(missing, "info_hash (need torrent::start event — add a new torrent)")
		}
		if result.torrentPtrOffset < 0 {
			missing = append(missing, "torrent_ptr (need peer_connection dumps — need active peer traffic)")
		}
		if result.sockaddrOffset < 0 {
			missing = append(missing, "sockaddr (need peer dump matching API peer list)")
		}
		if result.peerIDOffset < 0 {
			missing = append(missing, "peer_id (need sockaddr offset first, then matching peer_id)")
		}
		return fmt.Errorf("interrupted: discovered %d/4 offsets (torrent_start events: %d, peer_connection dumps: %d)\n  still need: %s",
			countDiscovered(result), torrentStartCount, peerDumpCount, strings.Join(missing, ", "))
	}

	if result.infoHashOffset < 0 || result.torrentPtrOffset < 0 ||
		result.sockaddrOffset < 0 || result.peerIDOffset < 0 {
		return fmt.Errorf("calibration incomplete: info_hash=%d torrent_ptr=%d sockaddr=%d peer_id=%d",
			result.infoHashOffset, result.torrentPtrOffset, result.sockaddrOffset, result.peerIDOffset)
	}

	// Save calibration
	if err := os.MkdirAll(filepath.Dir(*configPath), 0755); err != nil {
		return fmt.Errorf("creating config directory: %w", err)
	}
	if err := race.SaveCalibrationCache(
		*configPath, binaryHash,
		result.sockaddrOffset, result.peerIDOffset,
		result.infoHashOffset, result.torrentPtrOffset,
	); err != nil {
		return fmt.Errorf("saving calibration: %w", err)
	}

	fmt.Printf("\nCalibration complete!\n")
	fmt.Printf("  info_hash offset:   %d\n", result.infoHashOffset)
	fmt.Printf("  torrent_ptr offset: %d\n", result.torrentPtrOffset)
	fmt.Printf("  sockaddr_in offset: %d\n", result.sockaddrOffset)
	fmt.Printf("  peer_id offset:     %d\n", result.peerIDOffset)
	fmt.Printf("  binary hash:        %s\n", binaryHash)
	fmt.Printf("  saved to:           %s\n", *configPath)

	return nil
}

type calibResult struct {
	infoHashOffset   int
	torrentPtrOffset int
	sockaddrOffset   int
	peerIDOffset     int
}

func countDiscovered(r calibResult) int {
	n := 0
	if r.infoHashOffset >= 0 {
		n++
	}
	if r.torrentPtrOffset >= 0 {
		n++
	}
	if r.sockaddrOffset >= 0 {
		n++
	}
	if r.peerIDOffset >= 0 {
		n++
	}
	return n
}

// findInfoHashOffset scans a torrent struct dump for any 20-byte sequence that
// matches a known API hash. Returns the offset and matched hash.
func findInfoHashOffset(data [4096]byte, knownHashes map[string]bool) (int, string, bool) {
	for offset := 0; offset <= 4096-20; offset++ {
		candidate := hex.EncodeToString(data[offset : offset+20])
		if knownHashes[candidate] {
			return offset, candidate, true
		}
	}
	return -1, "", false
}

// findTorrentPtrOffset scans a peer_connection dump for an 8-byte aligned
// pointer that matches a known torrent* address.
func findTorrentPtrOffset(data [4096]byte, knownPtrs map[uint64]bool) (int, bool) {
	for offset := 0; offset <= 4096-8; offset += 8 {
		ptr := binary.LittleEndian.Uint64(data[offset : offset+8])
		if ptr != 0 && knownPtrs[ptr] {
			return offset, true
		}
	}
	return -1, false
}

// peerCache caches SyncTorrentPeers results to avoid repeated API calls.
var (
	peerCacheMu    sync.Mutex
	peerCacheAddrs map[string]map[netip.AddrPort]bool   // hash → set of addrs
	peerCacheIDs   map[string]map[netip.AddrPort]string // hash → addr → peer_id
)

func init() {
	peerCacheAddrs = make(map[string]map[netip.AddrPort]bool)
	peerCacheIDs = make(map[string]map[netip.AddrPort]string)
}

func clearPeerCache(hash string) {
	peerCacheMu.Lock()
	defer peerCacheMu.Unlock()
	delete(peerCacheAddrs, hash)
	delete(peerCacheIDs, hash)
}

func getPeers(client *qbittorrent.Client, hash string, logger *slog.Logger) (map[netip.AddrPort]bool, map[netip.AddrPort]string) {
	peerCacheMu.Lock()
	defer peerCacheMu.Unlock()

	if addrs, ok := peerCacheAddrs[hash]; ok {
		return addrs, peerCacheIDs[hash]
	}

	peers, err := client.SyncTorrentPeers(hash, 0)
	if err != nil {
		logger.Debug("failed to fetch peers", "hash", hash, "error", err)
		return nil, nil
	}

	addrs := make(map[netip.AddrPort]bool)
	ids := make(map[netip.AddrPort]string)
	for key, peer := range peers.Peers {
		ap, err := parsePeerKey(key, peer)
		if err != nil {
			continue
		}
		addrs[ap] = true
		if peer.PeerIDClient != "" {
			ids[ap] = peer.PeerIDClient
		}
	}

	peerCacheAddrs[hash] = addrs
	peerCacheIDs[hash] = ids
	logger.Debug("fetched peers for calibration", "hash", hash, "count", len(addrs))
	return addrs, ids
}

// findSockaddrOffset scans a peer_connection dump for a sockaddr_in that
// matches a known peer address from the API.
func findSockaddrOffset(data [4096]byte, client *qbittorrent.Client, hash string, logger *slog.Logger) (int, bool) {
	knownAddrs, _ := getPeers(client, hash, logger)
	if len(knownAddrs) == 0 {
		return -1, false
	}

	for offset := 0; offset <= 4096-8; offset++ {
		addr, ok := race.ExtractEndpoint(data, offset)
		if ok && knownAddrs[addr] {
			return offset, true
		}
	}
	return -1, false
}

// findPeerIDOffset scans a peer_connection dump for a 20-byte peer_id that
// matches a known peer ID from the API.
func findPeerIDOffset(data [4096]byte, client *qbittorrent.Client, hash string, logger *slog.Logger) (int, bool) {
	_, knownIDs := getPeers(client, hash, logger)
	if len(knownIDs) == 0 {
		return -1, false
	}

	// Build a set of known peer_id prefixes (at least 8 bytes)
	knownPrefixes := make(map[string]bool)
	for _, pid := range knownIDs {
		if len(pid) >= 8 {
			knownPrefixes[pid[:8]] = true
		}
	}
	if len(knownPrefixes) == 0 {
		return -1, false
	}

	for offset := 0; offset <= 4096-20; offset++ {
		candidate := string(data[offset : offset+8])
		if knownPrefixes[candidate] {
			return offset, true
		}
	}
	return -1, false
}

// parsePeerKey parses the peer map key (typically "IP:port") into a netip.AddrPort.
func parsePeerKey(key string, peer qbittorrent.TorrentPeer) (netip.AddrPort, error) {
	if ap, err := netip.ParseAddrPort(key); err == nil {
		return ap, nil
	}

	if peer.IP != "" && peer.Port > 0 {
		ipStr := strings.Trim(peer.IP, "[]")
		addr, err := netip.ParseAddr(ipStr)
		if err != nil {
			return netip.AddrPort{}, fmt.Errorf("invalid peer IP %q: %w", peer.IP, err)
		}
		return netip.AddrPortFrom(addr, uint16(peer.Port)), nil
	}

	lastColon := strings.LastIndex(key, ":")
	if lastColon < 0 {
		return netip.AddrPort{}, fmt.Errorf("unparseable peer key %q", key)
	}
	ipStr := strings.Trim(key[:lastColon], "[]")
	portStr := key[lastColon+1:]
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid IP in peer key %q: %w", key, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("invalid port in peer key %q: %w", key, err)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// loadConfig reads the shared config.toml for binary and webui settings.
func loadConfig() (binary, dbPath, dashboardURL, webuiURL, webuiUser, webuiPass string) {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "race-monitor", "config.toml")

	type Config struct {
		Binary    string `toml:"binary"`
		RaceDB    string `toml:"race_db"`
		Dashboard string `toml:"dashboard_url"`
		WebUIURL  string `toml:"webui_url"`
		WebUIUser string `toml:"webui_user"`
		WebUIPass string `toml:"webui_pass"`
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return
	}

	// Simple TOML parsing (avoid extra dependency in calibrate tool)
	var cfg Config
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, "\"")
		switch key {
		case "binary":
			cfg.Binary = val
		case "race_db":
			cfg.RaceDB = val
		case "dashboard_url":
			cfg.Dashboard = val
		case "webui_url":
			cfg.WebUIURL = val
		case "webui_user":
			cfg.WebUIUser = val
		case "webui_pass":
			cfg.WebUIPass = val
		}
	}

	return cfg.Binary, cfg.RaceDB, cfg.Dashboard, cfg.WebUIURL, cfg.WebUIUser, cfg.WebUIPass
}

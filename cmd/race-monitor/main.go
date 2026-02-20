// race-monitor records and analyzes torrent racing performance using eBPF uprobes.
//
// Requires a calibration file produced by race-calibrate. The PID of the
// qBittorrent process is the first positional argument (use 0 for any process).
//
// Usage:
//
//	race-monitor <pid> [--detach] [--log-file path] [--log-level level]
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/BurntSushi/toml"

	"github.com/cehbz/race-monitor/internal/capture"
	"github.com/cehbz/race-monitor/internal/race"
	"github.com/cehbz/race-monitor/internal/storage"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// Config holds the configuration for race-monitor.
type Config struct {
	Binary       string `toml:"binary"`
	RaceDB       string `toml:"race_db"`
	DashboardURL string `toml:"dashboard_url"`
	WebUIURL     string `toml:"webui_url"`
	WebUIUser    string `toml:"webui_user"`
	WebUIPass    string `toml:"webui_pass"`
}

// getConfig reads configuration from $HOME/.config/race-monitor/config.toml.
func getConfig() (binary, dbPath, dashboardURL, webuiURL, webuiUser, webuiPass string) {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "race-monitor", "config.toml")
	var cfg Config

	cfg.RaceDB = filepath.Join(home, ".local", "share", "race-monitor", "races.db")

	if _, err := os.Stat(configPath); err == nil {
		if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse config file %s: %v (using defaults)\n", configPath, err)
		}
	}

	return cfg.Binary, cfg.RaceDB, cfg.DashboardURL, cfg.WebUIURL, cfg.WebUIUser, cfg.WebUIPass
}

func ensureDBDir(dbPath string) error {
	dir := filepath.Dir(dbPath)
	return os.MkdirAll(dir, 0755)
}

// daemonize forks the process to run in the background.
func daemonize(args []string) error {
	var newArgs []string
	for _, arg := range args {
		if arg == "--detach" || arg == "-detach" ||
			arg == "--detach=true" || arg == "-detach=true" ||
			arg == "--detach=false" || arg == "-detach=false" {
			continue
		}
		newArgs = append(newArgs, arg)
	}

	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("getting executable path: %w", err)
	}

	devNull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("opening /dev/null: %w", err)
	}
	defer devNull.Close()

	procAttr := &os.ProcAttr{
		Files: []*os.File{devNull, devNull, devNull},
		Sys: &syscall.SysProcAttr{
			Setsid: true,
		},
	}

	process, err := os.StartProcess(executable, append([]string{executable}, newArgs...), procAttr)
	if err != nil {
		return fmt.Errorf("starting detached process: %w", err)
	}

	fmt.Printf("race-monitor daemon started with PID %d\n", process.Pid)

	if err := process.Release(); err != nil {
		return fmt.Errorf("releasing process: %w", err)
	}

	return nil
}

// loadCalibratedOffsets loads the calibration cache and validates that all 4
// offsets are present and the binary hash matches. Returns the offsets or an
// error explaining what's wrong.
func loadCalibratedOffsets(calibCachePath, binaryHash string) (race.CalibratedOffsets, error) {
	cache := race.LoadCalibrationCache(calibCachePath)
	if cache == nil {
		return race.CalibratedOffsets{}, fmt.Errorf(
			"calibration file not found at %s\n"+
				"Run race-calibrate first to discover struct offsets for this binary.",
			calibCachePath)
	}

	if cache.BinaryHash != binaryHash {
		return race.CalibratedOffsets{}, fmt.Errorf(
			"calibration file binary hash mismatch (cached: %s, current: %s)\n"+
				"The qBittorrent binary has changed. Run race-calibrate again.",
			cache.BinaryHash, binaryHash)
	}

	if cache.InfoHashOffset == nil {
		return race.CalibratedOffsets{}, fmt.Errorf(
			"calibration file missing info_hash offset\n" +
				"Run race-calibrate again to discover all offsets.")
	}
	if cache.TorrentPtrOffset == nil {
		return race.CalibratedOffsets{}, fmt.Errorf(
			"calibration file missing torrent_ptr offset\n" +
				"Run race-calibrate again to discover all offsets.")
	}
	if cache.SockaddrOffset <= 0 {
		return race.CalibratedOffsets{}, fmt.Errorf(
			"calibration file missing sockaddr_in offset\n" +
				"Run race-calibrate again to discover all offsets.")
	}

	return race.CalibratedOffsets{
		SockaddrOffset:   cache.SockaddrOffset,
		PeerIDOffset:     cache.PeerIDOffset,
		InfoHashOffset:   *cache.InfoHashOffset,
		TorrentPtrOffset: *cache.TorrentPtrOffset,
	}, nil
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintf(os.Stderr, `race-monitor — eBPF-based BitTorrent race monitor

Usage: race-monitor <pid> [flags]

  pid    qBittorrent PID (use 0 for any process)

Flags:
  --binary string      path to qBittorrent binary (default: from config)
  --detach             run in background
  --log-file string    log file path (default: stderr)
  --log-level string   trace, debug, info, warn, error (default: info)

Requires a calibration file produced by race-calibrate.
Config: ~/.config/race-monitor/config.toml
`)
		if len(args) == 0 {
			return fmt.Errorf("missing required PID argument")
		}
		return nil
	}

	// First arg must be the PID
	if args[0][0] == '-' {
		return fmt.Errorf("first argument must be the qBittorrent PID, got %q\nUsage: race-monitor <pid> [flags]", args[0])
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil || pid < 0 {
		return fmt.Errorf("invalid PID: %q (use 0 for any process, positive integer for specific PID)", args[0])
	}

	flagArgs := args[1:]

	configBinary, dbPath, dashboardURL, webuiURL, webuiUser, webuiPass := getConfig()

	fs := flag.NewFlagSet("race-monitor", flag.ExitOnError)
	logLevel := fs.String("log-level", "info", "log level (trace, debug, info, warn, error)")
	logFile := fs.String("log-file", "", "log file path (default: stderr)")
	binary := fs.String("binary", configBinary, "path to qBittorrent binary")
	detach := fs.Bool("detach", false, "run in background")
	_ = fs.Parse(flagArgs)

	if *detach {
		return daemonize(args)
	}

	// Setup logging
	var logOutput *os.File
	if *logFile != "" {
		f, err := os.OpenFile(*logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("opening log file: %w", err)
		}
		defer f.Close()
		logOutput = f
	} else {
		logOutput = os.Stderr
	}

	var level slog.Level
	switch *logLevel {
	case "trace":
		level = capture.LevelTrace
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	logger := slog.New(slog.NewTextHandler(logOutput, &slog.HandlerOptions{Level: level}))

	// Validate binary
	if *binary == "" {
		return fmt.Errorf("binary must be set in config file or via --binary flag (path to qBittorrent binary)")
	}
	if _, err := os.Stat(*binary); err != nil {
		return fmt.Errorf("binary not found: %s", *binary)
	}

	// Require torrent::start() probe symbol
	if !capture.HasTorrentStartSymbol(*binary) {
		return fmt.Errorf("torrent::start() symbol not found in %s\n"+
			"This binary does not have the required symbol table.\n"+
			"Ensure qBittorrent is compiled with debug symbols or is not fully stripped.", *binary)
	}

	// Compute binary hash
	binaryHash, err := race.ComputeBinaryHash(*binary)
	if err != nil {
		return fmt.Errorf("computing binary hash: %w", err)
	}

	// Load calibration
	home, _ := os.UserHomeDir()
	calibCachePath := filepath.Join(home, ".config", "race-monitor", "calibration.json")
	offsets, err := loadCalibratedOffsets(calibCachePath, binaryHash)
	if err != nil {
		return err
	}

	logger.Info("starting race monitor daemon",
		"binary", *binary,
		"pid", pid,
		"sockaddr_offset", offsets.SockaddrOffset,
		"peer_id_offset", offsets.PeerIDOffset,
		"info_hash_offset", offsets.InfoHashOffset,
		"torrent_ptr_offset", offsets.TorrentPtrOffset)

	// Ensure DB directory exists
	if err := ensureDBDir(dbPath); err != nil {
		return fmt.Errorf("creating db directory: %w", err)
	}

	store, err := storage.New(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	// Handle signals for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Info("received shutdown signal")
		cancel()
	}()

	// Watch for target process death
	pidDeathCh := race.WatchPID(pid)

	// Create enrichment API client (optional)
	var enrichAPI race.EnrichmentAPI
	if webuiURL != "" {
		api, err := newQBSyncClient(webuiURL, webuiUser, webuiPass, logger)
		if err != nil {
			logger.Warn("webui_url set but failed to create qBittorrent client (enrichment disabled)",
				"error", err)
		} else if api != nil {
			enrichAPI = api
			logger.Info("API enrichment enabled", "webui_url", webuiURL)
		}
	}

	// Start eBPF capture with calibrated offsets for identity-based peer dedup
	probeCfg := &capture.ProbeConfig{
		TorrentPtrOffset: uint32(offsets.TorrentPtrOffset),
		SockaddrOffset:   uint32(offsets.SockaddrOffset),
	}
	handle, err := capture.Capture(ctx, logger, *binary, pid, probeCfg)
	if err != nil {
		return fmt.Errorf("starting eBPF capture: %w", err)
	}

	coordinator := race.NewCoordinator(store, logger, dashboardURL, offsets, enrichAPI, handle)
	return coordinator.Run(ctx, handle.Events, handle.Dumps, pidDeathCh)
}

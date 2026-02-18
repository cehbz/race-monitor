// race-monitor records and analyzes torrent racing performance using eBPF uprobes.
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
	"text/tabwriter"

	"github.com/BurntSushi/toml"

	"github.com/cehbz/race-monitor/internal/capture"
	"github.com/cehbz/race-monitor/internal/race"
	"github.com/cehbz/race-monitor/internal/storage"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "daemon":
		if err := runDaemon(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := runList(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`race-monitor - eBPF-based BitTorrent race monitor

Commands:
  daemon <pid> [options]    Monitor torrent races via eBPF uprobes
                            Requires the PID of the qBittorrent process to monitor
                            --detach: Run in background
                            --log-file: Write logs to file (recommended with --detach)
  list                      List recent races

Example:
  race-monitor daemon $(pgrep -f 'qbittorrent-nox$') --detach --log-file ~/race-monitor.log

Configuration:
  Config file: ~/.config/race-monitor/config.toml

  Example config.toml:
    binary = "/usr/bin/qbittorrent-nox"       # Required: path to qBittorrent binary
    dashboard_url = "http://localhost:8888"    # Optional
    race_db = "/path/to/races.db"             # Optional

  Required:
    binary: Path to the qBittorrent binary (must have symbol table)

  Defaults:
    race_db:   ~/.local/share/race-monitor/races.db

eBPF Probes:
  Requires root or file capabilities for eBPF uprobe attachment.
  Attaches uprobes to libtorrent functions inside the qBittorrent binary:
    - torrent::start()                 — fires when a torrent begins (race creation)
    - torrent::finished()              — fires when download completes (race completion)
    - torrent::we_have()               — fires when we complete a piece
    - peer_connection::incoming_have()  — fires when a peer announces a piece

  The start() and finished() probes replace the previous qBittorrent hook system,
  providing fully passive lifecycle detection without external scripts.

  Grant capabilities (Debian/Ubuntu with kernel < 6.7):
    sudo setcap cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_admin+ep ./race-monitor

  Also requires: kernel.perf_event_paranoid <= 1
    sudo sysctl -w kernel.perf_event_paranoid=1

  Note: CAP_SYS_ADMIN is needed because the uprobe PMU's perf_event_open path
  on Debian 6.1 checks CAP_SYS_ADMIN rather than CAP_PERFMON. Newer kernels
  (>= 6.7) may only need cap_bpf,cap_perfmon,cap_sys_resource.`)
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

	// Defaults
	cfg.Binary = ""
	cfg.RaceDB = filepath.Join(home, ".local", "share", "race-monitor", "races.db")
	cfg.DashboardURL = ""
	cfg.WebUIURL = ""
	cfg.WebUIUser = ""
	cfg.WebUIPass = ""

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
	newArgs = append(newArgs, "daemon")
	for _, arg := range args {
		if arg == "--detach" || arg == "-detach" {
			continue
		}
		if arg == "--detach=true" || arg == "-detach=true" {
			continue
		}
		if arg == "--detach=false" || arg == "-detach=false" {
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

func runDaemon(args []string) error {
	// PID is the first positional argument, flags follow
	if len(args) == 0 {
		return fmt.Errorf("missing required PID argument\nUsage: race-monitor daemon <pid> [flags]\n  pid: 0 = any process, or qBittorrent PID\nExample: race-monitor daemon $(pgrep -f 'qbittorrent-nox$')")
	}

	// Check if first arg looks like a flag (user forgot PID)
	if args[0] == "" || args[0][0] == '-' {
		return fmt.Errorf("first argument must be the qBittorrent PID, got %q\nUsage: race-monitor daemon <pid> [flags]", args[0])
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil || pid < 0 {
		return fmt.Errorf("invalid PID: %q (use 0 for any process, positive integer for specific PID)", args[0])
	}

	// Remaining args are flags
	flagArgs := args[1:]

	configBinary, dbPath, dashboardURL, webuiURL, webuiUser, webuiPass := getConfig()

	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	logLevel := fs.String("log-level", "info", "log level (trace, debug, info, warn, error)")
	logFile := fs.String("log-file", "", "log file path (default: stderr)")
	binary := fs.String("binary", configBinary, "path to qBittorrent binary")
	detach := fs.Bool("detach", false, "run in background")
	_ = fs.Parse(flagArgs)

	if *detach {
		return daemonize(args)
	}

	// Setup logging output
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

	// Validate required configuration
	if *binary == "" {
		return fmt.Errorf("binary must be set in config file or via --binary flag (path to qBittorrent binary)")
	}

	if _, err := os.Stat(*binary); err != nil {
		return fmt.Errorf("binary not found: %s", *binary)
	}

	logger.Info("starting race monitor daemon",
		"binary", *binary,
		"pid", pid)

	// Ensure DB directory exists
	if err := ensureDBDir(dbPath); err != nil {
		return fmt.Errorf("creating db directory: %w", err)
	}

	// Open database
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

	// Watch for target process death via pidfd_open
	pidDeathCh := race.WatchPID(pid)

	// Compute binary hash for calibration cache
	binaryHash, err := race.ComputeBinaryHash(*binary)
	if err != nil {
		logger.Warn("failed to compute binary hash (calibration cache disabled)", "error", err)
	}

	// Calibration cache lives alongside the config file
	home, _ := os.UserHomeDir()
	calibCachePath := filepath.Join(home, ".config", "race-monitor", "calibration.json")

	// Create qBittorrent sync client for API-based calibration when webui_url is set
	var torrentCalibAPI race.TorrentCalibrationAPI
	if webuiURL != "" {
		api, err := newQBSyncClient(webuiURL, webuiUser, webuiPass, logger)
		if err != nil {
			logger.Warn("webui_url set but failed to create qBittorrent client (API calibration disabled)",
				"error", err)
		} else if api != nil {
			torrentCalibAPI = api
			logger.Info("API-based torrent calibration enabled", "webui_url", webuiURL)
		}
	}

	// Determine calibration flags from cache to suppress unnecessary BPF dumps
	calFlags := &capture.CalibrationFlags{
		PeerCalibrationNeeded:    true,
		TorrentCalibrationNeeded: true,
	}
	if binaryHash != "" {
		if cache := race.LoadCalibrationCache(calibCachePath); cache != nil && cache.BinaryHash == binaryHash {
			if cache.SockaddrOffset >= 0 && cache.PeerIDOffset >= 0 {
				calFlags.PeerCalibrationNeeded = false
			}
			if cache.InfoHashOffset != nil && cache.TorrentPtrOffset != nil {
				calFlags.TorrentCalibrationNeeded = false
			}
		}
	}

	// Start eBPF capture — attaches uprobes to libtorrent functions
	events, calibrations, err := capture.Capture(ctx, logger, *binary, pid, calFlags)
	if err != nil {
		return fmt.Errorf("starting eBPF capture: %w", err)
	}

	// Create coordinator and run (routes eBPF events to per-race trackers,
	// calibration events enable auto-discovery of struct offsets,
	// lifecycle events from torrent::start()/finished() drive race creation/completion)
	coordinator := race.NewCoordinator(store, logger, dashboardURL, binaryHash, calibCachePath, torrentCalibAPI)
	return coordinator.Run(ctx, events, calibrations, pidDeathCh)
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	days := fs.Int("days", 7, "show races from last N days")
	_ = fs.Parse(args)

	_, dbPath, _, _, _, _ := getConfig()

	store, err := storage.New(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	races, err := store.ListRecentRaces(context.Background(), *days)
	if err != nil {
		return err
	}

	if len(races) == 0 {
		fmt.Println("No races found.")
		return nil
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tSTARTED\tNAME\tSIZE")
	for _, r := range races {
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\n",
			r.ID,
			r.StartedAt.Local().Format("2006-01-02 15:04"),
			truncate(r.Name, 50),
			formatBytes(r.Size))
	}
	w.Flush()

	return nil
}

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

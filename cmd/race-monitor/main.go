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
	"syscall"
	"text/tabwriter"

	"github.com/BurntSushi/toml"
	qbt "github.com/cehbz/qbittorrent"

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
  daemon [options]          Monitor torrent races via eBPF uprobes
                            Runs forever, tracking races as they appear
                            --detach: Run in background
                            --log-file: Write logs to file (recommended with --detach)
  list                      List recent races

Example:
  race-monitor daemon --detach --log-file ~/race-monitor.log

Configuration:
  Config file: ~/.config/race-monitor/config.toml

  Example config.toml:
    binary = "/usr/bin/qbittorrent-nox"       # Required: path to qBittorrent binary
    pid = 0                                   # Optional: 0 = all processes
    webui_url = "http://localhost:8080"        # Optional
    dashboard_url = "http://localhost:8888"    # Optional
    race_db = "/path/to/races.db"             # Optional

  Required:
    binary: Path to the qBittorrent binary (must have symbol table)

  Defaults:
    pid:       0 (monitor all processes using the binary)
    webui_url: http://localhost:8080
    race_db:   ~/.local/share/race-monitor/races.db

eBPF Probes:
  Requires root or file capabilities for eBPF uprobe attachment.
  Attaches uprobes to libtorrent functions inside the qBittorrent binary:
    - torrent::we_have()               — fires when we complete a piece
    - peer_connection::incoming_have()  — fires when a peer announces a piece

  Grant capabilities (Debian/Ubuntu with kernel < 6.7):
    sudo setcap cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_admin+ep ./race-monitor

  Also requires: kernel.perf_event_paranoid <= 1
    sudo sysctl -w kernel.perf_event_paranoid=1

  Note: CAP_SYS_ADMIN is needed because the uprobe PMU's perf_event_open path
  on Debian 6.1 checks CAP_SYS_ADMIN rather than CAP_PERFMON. Newer kernels
  (>= 6.7) may only need cap_bpf,cap_perfmon,cap_sys_resource.

qBittorrent setup:
  Start the daemon before or after launching qBittorrent:
    race-monitor daemon --detach`)
}

// Config holds the configuration for race-monitor.
type Config struct {
	Binary       string `toml:"binary"`
	PID          int    `toml:"pid"`
	WebUIURL     string `toml:"webui_url"`
	RaceDB       string `toml:"race_db"`
	DashboardURL string `toml:"dashboard_url"`
}

// getConfig reads configuration from $HOME/.config/race-monitor/config.toml.
func getConfig() (binary, webUIURL, dbPath, dashboardURL string, pid int) {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "race-monitor", "config.toml")
	var cfg Config

	// Defaults
	cfg.Binary = ""
	cfg.PID = 0
	cfg.WebUIURL = "http://localhost:8080"
	cfg.RaceDB = filepath.Join(home, ".local", "share", "race-monitor", "races.db")
	cfg.DashboardURL = ""

	if _, err := os.Stat(configPath); err == nil {
		if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse config file %s: %v (using defaults)\n", configPath, err)
		}
	}

	return cfg.Binary, cfg.WebUIURL, cfg.RaceDB, cfg.DashboardURL, cfg.PID
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
	configBinary, configWebUIURL, dbPath, dashboardURL, configPID := getConfig()

	fs := flag.NewFlagSet("daemon", flag.ExitOnError)
	logLevel := fs.String("log-level", "info", "log level (trace, debug, info, warn, error)")
	logFile := fs.String("log-file", "", "log file path (default: stderr)")
	binary := fs.String("binary", configBinary, "path to qBittorrent binary")
	pid := fs.Int("pid", configPID, "qBittorrent PID to monitor (0 = all processes)")
	webUIURL := fs.String("webui-url", configWebUIURL, "qBittorrent Web UI URL")
	detach := fs.Bool("detach", false, "run in background")
	_ = fs.Parse(args)

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
		"pid", *pid,
		"webui_url", *webUIURL)

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

	// Create qBittorrent client (no auth for localhost)
	qbtClient, err := qbt.NewClient("", "", *webUIURL, nil)
	if err != nil {
		return fmt.Errorf("creating qBittorrent client: %w", err)
	}

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

	// Compute binary hash for calibration cache
	binaryHash, err := race.ComputeBinaryHash(*binary)
	if err != nil {
		logger.Warn("failed to compute binary hash (calibration cache disabled)", "error", err)
	}

	// Calibration cache lives alongside the config file
	home, _ := os.UserHomeDir()
	calibCachePath := filepath.Join(home, ".config", "race-monitor", "calibration.json")

	// Start eBPF capture — attaches uprobes to libtorrent functions
	events, calibrations, err := capture.Capture(ctx, logger, *binary, *pid)
	if err != nil {
		return fmt.Errorf("starting eBPF capture: %w", err)
	}

	// Create coordinator and run (routes eBPF events to per-race trackers,
	// calibration events enable auto-discovery of peer_connection struct offsets)
	coordinator := race.NewCoordinator(store, qbtClient, logger, dashboardURL, binaryHash, calibCachePath)
	return coordinator.Run(ctx, events, calibrations)
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	days := fs.Int("days", 7, "show races from last N days")
	_ = fs.Parse(args)

	_, _, dbPath, _, _ := getConfig()

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

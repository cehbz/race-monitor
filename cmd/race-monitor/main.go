// race-monitor records and analyzes torrent racing performance.
package main

import (
	"context"
	"encoding/csv"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/cehbz/qbittorrent"
	"github.com/cehbz/race-monitor/internal/recorder"
	"github.com/cehbz/race-monitor/internal/storage"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "record":
		if err := runRecord(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "stats":
		if err := runStats(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "list":
		if err := runList(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "export":
		if err := runExport(os.Args[2:]); err != nil {
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
	fmt.Println(`race-monitor - torrent racing analytics

Commands:
  record <hash>    Start recording a race (called by qBittorrent hook)
  list             List recent races
  stats <race_id>  Show detailed statistics for a race
  export <race_id> Export race data to CSV

Environment variables:
  QBT_URL          qBittorrent WebUI URL (default: http://127.0.0.1:8080)
  QBT_USER         qBittorrent username
  QBT_PASS         qBittorrent password
  RACE_DB          Database path (default: ~/.local/share/race-monitor/races.db)

qBittorrent setup:
  Add to Options > Downloads > "Run external program on torrent added":
    race-monitor record %I`)
}

// Config holds the configuration for race-monitor.
type Config struct {
	QbtURL  string `toml:"qbt_url"`
	QbtUser string `toml:"qbt_user"`
	QbtPass string `toml:"qbt_pass"`
	RaceDB  string `toml:"race_db"`
}

// getConfig reads configuration from $HOME/.config/race-monitor/config.toml.
// It falls back to sensible defaults if fields are missing.
func getConfig() (url, user, pass, dbPath string) {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "race-monitor", "config.toml")
	var cfg Config

	// Set defaults
	cfg.QbtURL = "http://127.0.0.1:8080"
	cfg.RaceDB = filepath.Join(home, ".local", "share", "race-monitor", "races.db")

	// Parse the config file if it exists
	if _, err := os.Stat(configPath); err == nil {
		_, _ = toml.DecodeFile(configPath, &cfg)
	}

	url = cfg.QbtURL
	user = cfg.QbtUser
	pass = cfg.QbtPass
	dbPath = cfg.RaceDB
	return
}

func ensureDBDir(dbPath string) error {
	dir := filepath.Dir(dbPath)
	return os.MkdirAll(dir, 0755)
}

func runRecord(args []string) error {
	fs := flag.NewFlagSet("record", flag.ExitOnError)
	pollInterval := fs.Duration("poll", 500*time.Millisecond, "poll interval")
	maxDuration := fs.Duration("max", 30*time.Minute, "max recording duration")
	postComplete := fs.Duration("post-complete", 15*time.Minute, "recording time after 100%")
	logLevel := fs.String("log-level", "info", "log level (debug, info, warn, error)")
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		return errors.New("missing torrent hash")
	}
	hash := fs.Arg(0)

	// Setup logging
	var level slog.Level
	switch *logLevel {
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

	url, user, pass, dbPath := getConfig()

	// Ensure DB directory exists
	if err := ensureDBDir(dbPath); err != nil {
		return fmt.Errorf("creating db directory: %w", err)
	}

	// Create HTTP client with reasonable timeout
	httpClient := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Connect to qBittorrent
	client, err := qbittorrent.NewClient(user, pass, url, httpClient)
	if err != nil {
		return fmt.Errorf("connecting to qBittorrent: %w", err)
	}

	// Open database
	store, err := storage.New(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	// Configure recorder
	config := recorder.DefaultConfig()
	config.PollInterval = *pollInterval
	config.MaxDuration = *maxDuration
	config.PostCompletionDuration = *postComplete

	rec := recorder.New(client, store, config, logger)

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

	return rec.Record(ctx, hash)
}

func runList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	days := fs.Int("days", 7, "show races from last N days")
	_ = fs.Parse(args)

	_, _, _, dbPath := getConfig()

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
	fmt.Fprintln(w, "ID\tSTARTED\tNAME\tSIZE\tRANK")
	for _, r := range races {
		rank := "-"
		if r.FinalRank.Valid {
			rank = fmt.Sprintf("#%d", r.FinalRank.Int64)
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\n",
			r.ID,
			r.StartedAt.Local().Format("2006-01-02 15:04"),
			truncate(r.Name, 50),
			formatBytes(r.Size),
			rank)
	}
	w.Flush()

	return nil
}

func runStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	_ = fs.Parse(args)

	if fs.NArg() < 1 {
		return errors.New("missing race ID")
	}

	raceID, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid race ID: %w", err)
	}

	_, _, _, dbPath := getConfig()

	store, err := storage.New(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	stats, err := store.GetRaceStats(context.Background(), raceID)
	if err != nil {
		return err
	}

	fmt.Printf("Race #%d: %s\n\n", stats.RaceID, stats.Name)
	fmt.Printf("  Time to complete:    %v\n", stats.TimeToComplete.Round(time.Second))
	fmt.Printf("  Recording duration:  %v\n", stats.Duration.Round(time.Second))
	fmt.Println()
	fmt.Printf("  Total uploaded:      %s\n", formatBytes(stats.TotalUploaded))
	fmt.Printf("  Uploaded (5 min):    %s\n", formatBytes(stats.UploadedFirst5m))
	fmt.Printf("  Uploaded (15 min):   %s\n", formatBytes(stats.UploadedFirst15m))
	fmt.Println()
	fmt.Printf("  Peak upload rate:    %s\n", formatRate(stats.PeakUploadRate))
	fmt.Printf("  Avg upload rate:     %s\n", formatRate(stats.AvgUploadRate))
	fmt.Println()
	fmt.Printf("  Best rank:           #%d\n", stats.BestRank)
	fmt.Printf("  Average rank:        %.1f\n", stats.AvgRank)
	fmt.Printf("  Final rank:          #%d\n", stats.FinalRank)

	return nil
}

func runExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	output := fs.String("o", "", "output file (default: stdout)")
	includePeers := fs.Bool("peers", false, "include peer samples")
	if err := fs.Parse(args); err != nil {
		return err
	}

	if fs.NArg() < 1 {
		return errors.New("missing race ID")
	}

	raceID, err := strconv.ParseInt(fs.Arg(0), 10, 64)
	if err != nil {
		return fmt.Errorf("invalid race ID: %w", err)
	}

	_, _, _, dbPath := getConfig()

	store, err := storage.New(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	samples, err := store.GetRaceSamples(context.Background(), raceID)
	if err != nil {
		return err
	}

	var out *os.File
	if *output != "" {
		out, err = os.Create(*output)
		if err != nil {
			return fmt.Errorf("creating output file: %w", err)
		}
		defer out.Close()
	} else {
		out = os.Stdout
	}

	w := csv.NewWriter(out)

	// Header
	_ = w.Write([]string{
		"timestamp", "elapsed_ms", "upload_rate", "download_rate",
		"progress", "uploaded", "downloaded", "peer_count", "seed_count", "rank",
	})

	if len(samples) == 0 {
		w.Flush()
		return nil
	}

	start := samples[0].Timestamp
	for _, s := range samples {
		elapsed := s.Timestamp.Sub(start).Milliseconds()
		_ = w.Write([]string{
			s.Timestamp.Format(time.RFC3339Nano),
			strconv.FormatInt(elapsed, 10),
			strconv.FormatInt(s.UploadRate, 10),
			strconv.FormatInt(s.DownloadRate, 10),
			strconv.FormatFloat(s.Progress, 'f', 4, 64),
			strconv.FormatInt(s.Uploaded, 10),
			strconv.FormatInt(s.Downloaded, 10),
			strconv.Itoa(s.PeerCount),
			strconv.Itoa(s.SeedCount),
			strconv.Itoa(s.MyRank),
		})
	}

	w.Flush()

	if *includePeers {
		fmt.Fprintln(out)
		fmt.Fprintln(out, "# Peer samples")
		// TODO: Add GetPeerSamples to storage
	}

	return w.Error()
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

func formatRate(bytesPerSec int64) string {
	return formatBytes(bytesPerSec) + "/s"
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

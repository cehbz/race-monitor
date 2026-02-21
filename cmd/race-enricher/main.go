// race-enricher enriches peer IPs with network metadata (ISP, datacenter, seedbox provider).
//
// Consumes from the enrichment_queue table (populated by race-monitor) and writes
// to ip_dns and network_enrichment tables. Two processing stages: per-IP free DNS
// lookups, then per-BGP-prefix rate-limited ipapi.is lookups.
//
// Usage:
//
//	race-enricher [--backfill] [--once] [--log-level level]
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
	"time"
	"unsafe"

	"github.com/BurntSushi/toml"
	"golang.org/x/sys/unix"

	"github.com/cehbz/race-monitor/internal/enrichment"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

type config struct {
	RaceDB string `toml:"race_db"`
}

func getConfig() string {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "race-monitor", "config.toml")
	var cfg config
	cfg.RaceDB = filepath.Join(home, ".local", "share", "race-monitor", "races.db")

	if _, err := os.Stat(configPath); err == nil {
		if _, err := toml.DecodeFile(configPath, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to parse config %s: %v\n", configPath, err)
		}
	}
	return cfg.RaceDB
}

func run() error {
	backfill := flag.Bool("backfill", false, "Backfill: enqueue all known IPs from connections table")
	once := flag.Bool("once", false, "Process queue and exit (no inotify wait)")
	logLevel := flag.String("log-level", "info", "Log level: debug, info, warn, error")
	dailyLimit := flag.Int("daily-limit", 900, "Daily ipapi.is API call limit")
	flag.Parse()

	// Logger
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

	dbPath := getConfig()
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return fmt.Errorf("database not found: %s", dbPath)
	}

	store, err := enrichment.NewSQLiteStore(dbPath)
	if err != nil {
		return fmt.Errorf("opening database: %w", err)
	}
	defer store.Close()

	// Backfill: enqueue all IPs from connections that aren't already in ip_dns
	if *backfill {
		n, err := store.Backfill(context.Background())
		if err != nil {
			return fmt.Errorf("backfill: %w", err)
		}
		logger.Info("backfill complete", "enqueued", n)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	resolver := enrichment.NewDNSResolver()
	apiClient := enrichment.NewIPAPIClient(nil)
	limiter := enrichment.NewRateLimiter(*dailyLimit)

	ipEnricher := enrichment.NewIPEnricher(store, resolver, logger)
	prefixEnricher := enrichment.NewPrefixEnricher(store, apiClient, limiter, logger)

	logger.Info("race-enricher started",
		"db", dbPath,
		"daily_limit", *dailyLimit,
		"once", *once,
		"backfill", *backfill,
	)

	// Set up inotify on sentinel file (unless --once)
	sentinelPath := filepath.Join(filepath.Dir(dbPath), "enrichment.notify")
	var inotifyFd int
	if !*once {
		// Ensure sentinel file exists
		if f, err := os.Create(sentinelPath); err == nil {
			f.Close()
		}
		inotifyFd, err = unix.InotifyInit1(unix.IN_NONBLOCK)
		if err != nil {
			return fmt.Errorf("inotify_init: %w", err)
		}
		defer unix.Close(inotifyFd)

		_, err = unix.InotifyAddWatch(inotifyFd, sentinelPath, unix.IN_MODIFY|unix.IN_ATTRIB)
		if err != nil {
			return fmt.Errorf("inotify_add_watch: %w", err)
		}
	}

	for {
		// Process IP queue
		for {
			processed, newPrefixes, err := ipEnricher.ProcessBatch(ctx, 50)
			if err != nil {
				logger.Warn("IP batch error", "error", err)
				break
			}
			if processed == 0 {
				break
			}
			logger.Debug("IP batch", "processed", processed, "new_prefixes", newPrefixes)
		}

		// Process prefix queue
		for {
			processed, rateLimited, err := prefixEnricher.ProcessBatch(ctx, 10)
			if err != nil {
				logger.Warn("prefix batch error", "error", err)
				break
			}
			if rateLimited {
				logger.Info("API daily limit reached, prefix queue paused",
					"remaining", limiter.Remaining())
				break
			}
			if processed == 0 {
				break
			}
			logger.Debug("prefix batch", "processed", processed)
		}

		if *once {
			logger.Info("--once: exiting after queue drain")
			return nil
		}

		if ctx.Err() != nil {
			return nil
		}

		// Wait for sentinel file change via inotify
		logger.Debug("waiting for enrichment notifications")
		if err := waitInotify(ctx, inotifyFd); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			logger.Warn("inotify wait error, falling back to sleep", "error", err)
			select {
			case <-time.After(30 * time.Second):
			case <-ctx.Done():
				return nil
			}
		}
	}
}

// waitInotify blocks until the inotify fd has an event or ctx is cancelled.
// Uses ppoll to avoid busy-waiting.
func waitInotify(ctx context.Context, fd int) error {
	for {
		// Drain any pending events
		buf := make([]byte, 4096)
		unix.Read(fd, buf)

		// Wait with ppoll (1 second timeout so we can check ctx)
		pollFds := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
		timeout := &unix.Timespec{Sec: 1}
		n, err := ppoll(pollFds, timeout)
		if err != nil && err != unix.EINTR {
			return err
		}
		if n > 0 {
			// Drain the inotify events
			unix.Read(fd, buf)
			return nil
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// ppoll wraps the ppoll syscall since golang.org/x/sys/unix doesn't expose it directly.
func ppoll(fds []unix.PollFd, timeout *unix.Timespec) (int, error) {
	n, _, errno := unix.Syscall6(
		unix.SYS_PPOLL,
		uintptr(unsafe.Pointer(&fds[0])),
		uintptr(len(fds)),
		uintptr(unsafe.Pointer(timeout)),
		0, 0, 0,
	)
	if errno != 0 {
		return int(n), errno
	}
	return int(n), nil
}

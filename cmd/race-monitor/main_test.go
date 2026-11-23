package main

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadConfig(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	configDir := filepath.Join(tmpDir, ".config", "race-monitor")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("failed to create config dir: %v", err)
	}

	tests := []struct {
		name          string
		configContent string
		wantBinary    string
		wantRaceDB    string
		wantDashboard string
	}{
		{
			name: "custom values from config",
			configContent: `binary = "/usr/bin/qbittorrent-nox"
race_db = "/tmp/races.db"
dashboard_url = "http://localhost:9999"`,
			wantBinary:    "/usr/bin/qbittorrent-nox",
			wantRaceDB:    "/tmp/races.db",
			wantDashboard: "http://localhost:9999",
		},
		{
			name:          "defaults used when config missing",
			configContent: "",
			wantBinary:    "",
			wantRaceDB:    filepath.Join(tmpDir, ".local", "share", "race-monitor", "races.db"),
			wantDashboard: "",
		},
		{
			name:          "partial config with defaults",
			configContent: `binary = "/opt/qbt"`,
			wantBinary:    "/opt/qbt",
			wantRaceDB:    filepath.Join(tmpDir, ".local", "share", "race-monitor", "races.db"),
			wantDashboard: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := filepath.Join(configDir, "config.toml")

			if tt.configContent != "" {
				if err := os.WriteFile(configPath, []byte(tt.configContent), 0644); err != nil {
					t.Fatalf("failed to write config: %v", err)
				}
				defer os.Remove(configPath)
			} else {
				os.Remove(configPath)
			}

			cfg := readConfig()
			gotBinary, gotRaceDB, gotDashboard := cfg.Binary, cfg.RaceDB, cfg.DashboardURL

			if gotBinary != tt.wantBinary {
				t.Errorf("binary = %q, want %q", gotBinary, tt.wantBinary)
			}
			if gotRaceDB != tt.wantRaceDB {
				t.Errorf("race_db = %q, want %q", gotRaceDB, tt.wantRaceDB)
			}
			if gotDashboard != tt.wantDashboard {
				t.Errorf("dashboard_url = %q, want %q", gotDashboard, tt.wantDashboard)
			}
		})
	}
}

func TestReadConfigNoFile(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	cfg := readConfig()
	gotBinary, gotRaceDB, gotDashboard := cfg.Binary, cfg.RaceDB, cfg.DashboardURL

	if gotBinary != "" {
		t.Errorf("binary = %q, want empty", gotBinary)
	}
	if gotRaceDB != filepath.Join(tmpDir, ".local", "share", "race-monitor", "races.db") {
		t.Errorf("race_db = %q, want default path", gotRaceDB)
	}
	if gotDashboard != "" {
		t.Errorf("dashboard_url = %q, want empty", gotDashboard)
	}
}

func TestRequestedStopExitsCleanlyAndQBittorrentDyingExitsWithAnError(t *testing.T) {
	if err := stopResult(stopRequested{sig: syscall.SIGTERM}); err != nil {
		t.Errorf("requested stop: run returns %v, want nil", err)
	}
	died := fmt.Errorf("target qBittorrent process (PID %d) exited", 1338)
	if err := stopResult(died); err == nil {
		t.Error("qBittorrent dying: run returns nil, want an error")
	}
}

func TestSessionLoadWindowDefaultsToTenSecondsAndIsReadFromTheConfig(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("HOME", tmpDir)

	if got := readConfig().SessionLoadWindow; got != 10*time.Second {
		t.Errorf("session load window without a config = %v, want 10s", got)
	}

	configDir := filepath.Join(tmpDir, ".config", "race-monitor")
	if err := os.MkdirAll(configDir, 0755); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(`session_load_window = "30s"`), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if got := readConfig().SessionLoadWindow; got != 30*time.Second {
		t.Errorf("session load window from the config = %v, want 30s", got)
	}
}

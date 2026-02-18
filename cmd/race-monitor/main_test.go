package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetConfig(t *testing.T) {
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

			gotBinary, gotRaceDB, gotDashboard, _, _, _ := getConfig()

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

func TestGetConfigNoFile(t *testing.T) {
	tmpDir := t.TempDir()
	origHome := os.Getenv("HOME")
	os.Setenv("HOME", tmpDir)
	defer os.Setenv("HOME", origHome)

	gotBinary, gotRaceDB, gotDashboard, _, _, _ := getConfig()

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

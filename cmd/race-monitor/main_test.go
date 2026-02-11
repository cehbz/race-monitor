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
		wantPID       int
		wantWebUIURL  string
		wantRaceDB    string
		wantDashboard string
	}{
		{
			name: "custom values from config",
			configContent: `binary = "/usr/bin/qbittorrent-nox"
webui_url = "http://127.0.0.1:9090"
race_db = "/tmp/races.db"`,
			wantBinary:    "/usr/bin/qbittorrent-nox",
			wantPID:       0,
			wantWebUIURL:  "http://127.0.0.1:9090",
			wantRaceDB:    "/tmp/races.db",
			wantDashboard: "",
		},
		{
			name:          "defaults used when config missing",
			configContent: "",
			wantBinary:    "",
			wantPID:       0,
			wantWebUIURL:  "http://localhost:8080",
			wantRaceDB:    filepath.Join(tmpDir, ".local", "share", "race-monitor", "races.db"),
			wantDashboard: "",
		},
		{
			name: "all fields specified",
			configContent: `binary = "/opt/qbt/qbittorrent-nox"
pid = 12345
webui_url = "http://192.168.1.100:8080"
race_db = "/custom/races.db"
dashboard_url = "http://localhost:9999"`,
			wantBinary:    "/opt/qbt/qbittorrent-nox",
			wantPID:       12345,
			wantWebUIURL:  "http://192.168.1.100:8080",
			wantRaceDB:    "/custom/races.db",
			wantDashboard: "http://localhost:9999",
		},
		{
			name:          "partial config with defaults",
			configContent: `webui_url = "http://example.com:8080"`,
			wantBinary:    "",
			wantPID:       0,
			wantWebUIURL:  "http://example.com:8080",
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

			gotBinary, gotWebUIURL, gotRaceDB, gotDashboard, gotPID := getConfig()

			if gotBinary != tt.wantBinary {
				t.Errorf("binary = %q, want %q", gotBinary, tt.wantBinary)
			}
			if gotPID != tt.wantPID {
				t.Errorf("pid = %d, want %d", gotPID, tt.wantPID)
			}
			if gotWebUIURL != tt.wantWebUIURL {
				t.Errorf("webui_url = %q, want %q", gotWebUIURL, tt.wantWebUIURL)
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

	gotBinary, gotWebUIURL, gotRaceDB, gotDashboard, gotPID := getConfig()

	if gotBinary != "" {
		t.Errorf("binary = %q, want empty", gotBinary)
	}
	if gotPID != 0 {
		t.Errorf("pid = %d, want 0", gotPID)
	}
	if gotWebUIURL != "http://localhost:8080" {
		t.Errorf("webui_url = %q, want %q", gotWebUIURL, "http://localhost:8080")
	}
	if gotRaceDB != filepath.Join(tmpDir, ".local", "share", "race-monitor", "races.db") {
		t.Errorf("race_db = %q, want default path", gotRaceDB)
	}
	if gotDashboard != "" {
		t.Errorf("dashboard_url = %q, want empty", gotDashboard)
	}
}

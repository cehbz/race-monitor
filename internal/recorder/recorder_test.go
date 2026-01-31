package recorder_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cehbz/qbittorrent"
	"github.com/cehbz/race-monitor/internal/recorder"
	"github.com/cehbz/race-monitor/internal/storage"
)

// mockClient implements recorder.QBitClient for testing.
type mockClient struct {
	mu           sync.Mutex
	torrents     map[string]qbittorrent.TorrentInfo
	peers        map[string]qbittorrent.TorrentPeer
	rid          int
	callCount    atomic.Int64
	torrentErr   error
	peersErr     error
	updateFunc   func(hash string) // Called each time to update state
}

func newMockClient() *mockClient {
	return &mockClient{
		torrents: make(map[string]qbittorrent.TorrentInfo),
		peers:    make(map[string]qbittorrent.TorrentPeer),
	}
}

func (m *mockClient) TorrentsInfo(params ...*qbittorrent.TorrentsInfoParams) ([]qbittorrent.TorrentInfo, error) {
	m.callCount.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.torrentErr != nil {
		return nil, m.torrentErr
	}

	// No params or nil first param - return all
	if len(params) == 0 || params[0] == nil || len(params[0].Hashes) == 0 {
		var result []qbittorrent.TorrentInfo
		for _, t := range m.torrents {
			result = append(result, t)
		}
		return result, nil
	}

	var result []qbittorrent.TorrentInfo
	for _, hash := range params[0].Hashes {
		if t, ok := m.torrents[hash]; ok {
			result = append(result, t)
		}
	}
	return result, nil
}

func (m *mockClient) SyncTorrentPeers(hash string, rid int) (*qbittorrent.TorrentPeers, error) {
	m.callCount.Add(1)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.peersErr != nil {
		return nil, m.peersErr
	}

	if m.updateFunc != nil {
		m.updateFunc(hash)
	}

	m.rid++
	return &qbittorrent.TorrentPeers{
		FullUpdate: rid == 0,
		Rid:        m.rid,
		Peers:      m.peers,
	}, nil
}

func (m *mockClient) setTorrent(t qbittorrent.TorrentInfo) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.torrents[string(t.Hash)] = t
}

func (m *mockClient) setPeers(peers map[string]qbittorrent.TorrentPeer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = peers
}

func newTestStore(t *testing.T) (*storage.Store, func()) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")

	store, err := storage.New(dbPath)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	cleanup := func() {
		store.Close()
		os.RemoveAll(dir)
	}

	return store, cleanup
}

func nullLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestDefaultConfig(t *testing.T) {
	config := recorder.DefaultConfig()

	if config.PollInterval != 500*time.Millisecond {
		t.Errorf("expected poll interval 500ms, got %v", config.PollInterval)
	}
	if config.MaxDuration != 30*time.Minute {
		t.Errorf("expected max duration 30m, got %v", config.MaxDuration)
	}
	if config.PostCompletionDuration != 15*time.Minute {
		t.Errorf("expected post completion 15m, got %v", config.PostCompletionDuration)
	}
	if config.MinUploadRate != 1024*1024 {
		t.Errorf("expected min upload rate 1MB/s, got %d", config.MinUploadRate)
	}
}

func TestCalculateRank(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	rec := recorder.New(newMockClient(), store, recorder.DefaultConfig(), nullLogger())

	tests := []struct {
		name         string
		mySpeed      int64
		peers        map[string]qbittorrent.TorrentPeer
		expectedRank int
	}{
		{
			name:         "no peers",
			mySpeed:      1000000,
			peers:        map[string]qbittorrent.TorrentPeer{},
			expectedRank: 1,
		},
		{
			name:    "fastest among seeders",
			mySpeed: 10000000,
			peers: map[string]qbittorrent.TorrentPeer{
				"peer1": {Progress: 1.0, UPSpeed: 5000000},
				"peer2": {Progress: 1.0, UPSpeed: 8000000},
				"peer3": {Progress: 1.0, UPSpeed: 3000000},
			},
			expectedRank: 1,
		},
		{
			name:    "second fastest",
			mySpeed: 7000000,
			peers: map[string]qbittorrent.TorrentPeer{
				"peer1": {Progress: 1.0, UPSpeed: 5000000},
				"peer2": {Progress: 1.0, UPSpeed: 10000000},
				"peer3": {Progress: 1.0, UPSpeed: 3000000},
			},
			expectedRank: 2,
		},
		{
			name:    "slowest",
			mySpeed: 1000000,
			peers: map[string]qbittorrent.TorrentPeer{
				"peer1": {Progress: 1.0, UPSpeed: 5000000},
				"peer2": {Progress: 1.0, UPSpeed: 10000000},
				"peer3": {Progress: 1.0, UPSpeed: 3000000},
			},
			expectedRank: 4,
		},
		{
			name:    "ignores non-seeders",
			mySpeed: 5000000,
			peers: map[string]qbittorrent.TorrentPeer{
				"peer1": {Progress: 0.5, UPSpeed: 10000000}, // Not a seeder
				"peer2": {Progress: 1.0, UPSpeed: 3000000},  // Seeder
				"peer3": {Progress: 0.9, UPSpeed: 8000000},  // Not a seeder
			},
			expectedRank: 1,
		},
		{
			name:    "ignores seeders with zero upload",
			mySpeed: 5000000,
			peers: map[string]qbittorrent.TorrentPeer{
				"peer1": {Progress: 1.0, UPSpeed: 0},       // Seeder but not uploading
				"peer2": {Progress: 1.0, UPSpeed: 3000000}, // Active seeder
				"peer3": {Progress: 1.0, UPSpeed: 0},       // Seeder but not uploading
			},
			expectedRank: 1,
		},
		{
			name:    "tied speed",
			mySpeed: 5000000,
			peers: map[string]qbittorrent.TorrentPeer{
				"peer1": {Progress: 1.0, UPSpeed: 5000000}, // Same speed
				"peer2": {Progress: 1.0, UPSpeed: 5000000}, // Same speed
			},
			expectedRank: 1, // Ties don't push us down
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rank := rec.CalculateRank(tt.mySpeed, tt.peers)
			if rank != tt.expectedRank {
				t.Errorf("expected rank %d, got %d", tt.expectedRank, rank)
			}
		})
	}
}

func TestRecord_TorrentNotFound(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	client := newMockClient()
	// Don't add any torrents

	rec := recorder.New(client, store, recorder.DefaultConfig(), nullLogger())

	ctx := context.Background()
	err := rec.Record(ctx, "nonexistent-hash")

	if !errors.Is(err, recorder.ErrTorrentNotFound) {
		t.Errorf("expected ErrTorrentNotFound, got %v", err)
	}
}

func TestRecord_ContextCancellation(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	client := newMockClient()
	client.setTorrent(qbittorrent.TorrentInfo{
		Hash:     "testhash",
		Name:     "Test Torrent",
		Size:     1024 * 1024 * 100,
		Progress: 0.5,
		UpSpeed:  1000000,
		DLSpeed:  5000000,
	})

	config := recorder.DefaultConfig()
	config.PollInterval = 10 * time.Millisecond

	rec := recorder.New(client, store, config, nullLogger())

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short time
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	err := rec.Record(ctx, "testhash")

	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

func TestRecord_MaxDuration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	client := newMockClient()
	client.setTorrent(qbittorrent.TorrentInfo{
		Hash:     "testhash",
		Name:     "Test Torrent",
		Size:     1024 * 1024 * 100,
		Progress: 0.5,
		UpSpeed:  10000000, // High enough to not trigger low activity
		DLSpeed:  5000000,
	})

	config := recorder.DefaultConfig()
	config.PollInterval = 10 * time.Millisecond
	config.MaxDuration = 50 * time.Millisecond

	rec := recorder.New(client, store, config, nullLogger())

	ctx := context.Background()
	err := rec.Record(ctx, "testhash")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify race was recorded
	races, _ := store.ListRecentRaces(ctx, 1)
	if len(races) != 1 {
		t.Fatalf("expected 1 race, got %d", len(races))
	}

	if races[0].Name != "Test Torrent" {
		t.Errorf("expected name 'Test Torrent', got %q", races[0].Name)
	}
}

func TestRecord_PostCompletionDuration(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	client := newMockClient()
	client.setTorrent(qbittorrent.TorrentInfo{
		Hash:     "testhash",
		Name:     "Test Torrent",
		Size:     1024 * 1024 * 100,
		Progress: 1.0, // Already complete
		UpSpeed:  10000000,
		DLSpeed:  0,
	})

	config := recorder.DefaultConfig()
	config.PollInterval = 10 * time.Millisecond
	config.PostCompletionDuration = 30 * time.Millisecond
	config.MaxDuration = 5 * time.Second // Make sure we don't hit this first

	rec := recorder.New(client, store, config, nullLogger())

	start := time.Now()
	err := rec.Record(context.Background(), "testhash")
	duration := time.Since(start)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should stop after ~30ms (post completion), not 5s (max duration)
	if duration > 500*time.Millisecond {
		t.Errorf("took too long: %v (expected ~30ms)", duration)
	}
}

func TestRecord_LowActivity(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	client := newMockClient()
	client.setTorrent(qbittorrent.TorrentInfo{
		Hash:     "testhash",
		Name:     "Test Torrent",
		Size:     1024 * 1024 * 100,
		Progress: 0.5,
		UpSpeed:  100, // Very low upload - below threshold
		DLSpeed:  0,
	})

	config := recorder.DefaultConfig()
	config.PollInterval = 10 * time.Millisecond
	config.MinUploadRate = 1000
	config.StopAfterLowActivity = 30 * time.Millisecond
	config.MaxDuration = 5 * time.Second

	rec := recorder.New(client, store, config, nullLogger())

	start := time.Now()
	err := rec.Record(context.Background(), "testhash")
	duration := time.Since(start)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Should stop after ~30ms (low activity), not 5s (max duration)
	if duration > 500*time.Millisecond {
		t.Errorf("took too long: %v (expected ~30ms)", duration)
	}
}

func TestRecord_SamplesRecorded(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	callCount := 0
	client := newMockClient()
	client.setTorrent(qbittorrent.TorrentInfo{
		Hash:       "testhash",
		Name:       "Test Torrent",
		Size:       1024 * 1024 * 100,
		Progress:   0.0,
		UpSpeed:    5000000,
		DLSpeed:    10000000,
		Uploaded:   0,
		Downloaded: 0,
		NumLeechs:  10,
		NumSeeds:   5,
	})

	// Simulate progress over time
	// Note: updateFunc is called from SyncTorrentPeers which already holds mu
	client.updateFunc = func(hash string) {
		callCount++
		// Don't lock here - caller (SyncTorrentPeers) already holds mu
		t := client.torrents[hash]
		t.Progress = float64(callCount) * 0.1
		if t.Progress > 1.0 {
			t.Progress = 1.0
		}
		t.Uploaded = int64(callCount) * 1000000
		t.Downloaded = int64(callCount) * 2000000
		client.torrents[hash] = t
	}

	client.setPeers(map[string]qbittorrent.TorrentPeer{
		"peer1": {IP: "1.2.3.4", Client: "qBittorrent", Progress: 1.0, UPSpeed: 3000000},
		"peer2": {IP: "5.6.7.8", Client: "Transmission", Progress: 1.0, UPSpeed: 8000000},
	})

	config := recorder.DefaultConfig()
	config.PollInterval = 10 * time.Millisecond
	config.MaxDuration = 100 * time.Millisecond
	config.PostCompletionDuration = 5 * time.Second // Don't trigger this

	rec := recorder.New(client, store, config, nullLogger())

	err := rec.Record(context.Background(), "testhash")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Verify samples were recorded
	ctx := context.Background()
	races, _ := store.ListRecentRaces(ctx, 1)
	if len(races) == 0 {
		t.Fatal("no races recorded")
	}

	samples, _ := store.GetRaceSamples(ctx, races[0].ID)
	if len(samples) == 0 {
		t.Error("no samples recorded")
	}

	// Should have at least a few samples for 100ms at 10ms intervals
	if len(samples) < 5 {
		t.Errorf("expected at least 5 samples, got %d", len(samples))
	}

	t.Logf("Recorded %d samples", len(samples))
}

func BenchmarkCalculateRank(b *testing.B) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	rec := recorder.New(newMockClient(), store, recorder.DefaultConfig(), nullLogger())

	// Create a large peer map
	peers := make(map[string]qbittorrent.TorrentPeer)
	for i := 0; i < 1000; i++ {
		peers[string(rune(i))] = qbittorrent.TorrentPeer{
			Progress: 1.0,
			UPSpeed:  int64(i * 1000),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rec.CalculateRank(500000, peers)
	}
}

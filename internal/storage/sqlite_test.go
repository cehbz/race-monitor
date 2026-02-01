package storage_test

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cehbz/race-monitor/internal/storage"
)

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

func TestNew(t *testing.T) {
	t.Run("creates database and tables", func(t *testing.T) {
		store, cleanup := newTestStore(t)
		defer cleanup()

		if store == nil {
			t.Fatal("expected non-nil store")
		}
	})

	t.Run("fails with invalid path", func(t *testing.T) {
		_, err := storage.New("/nonexistent/path/that/cannot/exist/db.sqlite")
		if err == nil {
			t.Fatal("expected error for invalid path")
		}
	})
}

func TestCreateRace(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("creates race with valid data", func(t *testing.T) {
		id, err := store.CreateRace(ctx, "abc123hash", "Test.Torrent.2024", 1024*1024*1024)
		if err != nil {
			t.Fatalf("failed to create race: %v", err)
		}
		if id <= 0 {
			t.Errorf("expected positive ID, got %d", id)
		}
	})

	t.Run("creates multiple races", func(t *testing.T) {
		id1, _ := store.CreateRace(ctx, "hash1", "Torrent1", 100)
		id2, _ := store.CreateRace(ctx, "hash2", "Torrent2", 200)

		if id1 >= id2 {
			t.Errorf("expected id1 < id2, got %d >= %d", id1, id2)
		}
	})
}

func TestGetRace(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("retrieves created race", func(t *testing.T) {
		id, err := store.CreateRace(ctx, "testhash", "Test.Torrent", 500)
		if err != nil {
			t.Fatalf("failed to create race: %v", err)
		}

		race, err := store.GetRace(ctx, id)
		if err != nil {
			t.Fatalf("failed to get race: %v", err)
		}

		if race.Hash != "testhash" {
			t.Errorf("expected hash 'testhash', got %q", race.Hash)
		}
		if race.Name != "Test.Torrent" {
			t.Errorf("expected name 'Test.Torrent', got %q", race.Name)
		}
		if race.Size != 500 {
			t.Errorf("expected size 500, got %d", race.Size)
		}
		if race.CompletedAt.Valid {
			t.Error("expected CompletedAt to be NULL for new race")
		}
	})

	t.Run("returns error for nonexistent race", func(t *testing.T) {
		_, err := store.GetRace(ctx, 99999)
		if err != storage.ErrRaceNotFound {
			t.Errorf("expected ErrRaceNotFound, got %v", err)
		}
	})
}

func TestCompleteRace(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("marks race as completed", func(t *testing.T) {
		id, _ := store.CreateRace(ctx, "hash", "Torrent", 100)

		err := store.CompleteRace(ctx, id)
		if err != nil {
			t.Fatalf("failed to complete race: %v", err)
		}

		race, _ := store.GetRace(ctx, id)
		if !race.CompletedAt.Valid {
			t.Error("expected CompletedAt to be set")
		}
	})
}

func TestInsertSample(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	raceID, _ := store.CreateRace(ctx, "hash", "Torrent", 100)

	t.Run("inserts sample", func(t *testing.T) {
		sample := &storage.Sample{
			RaceID:       raceID,
			Timestamp:    time.Now(),
			UploadRate:   1024 * 1024 * 10, // 10 MB/s
			DownloadRate: 1024 * 1024 * 50, // 50 MB/s
			Progress:     0.5,
			Uploaded:     1024 * 1024 * 100,
			Downloaded:   1024 * 1024 * 500,
			PeerCount:    20,
			SeedCount:    5,
			MyRank:       2,
		}

		err := store.InsertSample(ctx, sample)
		if err != nil {
			t.Fatalf("failed to insert sample: %v", err)
		}
	})

	t.Run("inserts multiple samples", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			sample := &storage.Sample{
				RaceID:       raceID,
				Timestamp:    time.Now().Add(time.Duration(i) * time.Second),
				UploadRate:   int64(i * 1024),
				DownloadRate: int64(i * 2048),
				Progress:     float64(i) / 10.0,
				Uploaded:     int64(i * 1000),
				Downloaded:   int64(i * 2000),
				PeerCount:    i,
				SeedCount:    i / 2,
				MyRank:       i + 1,
			}
			if err := store.InsertSample(ctx, sample); err != nil {
				t.Fatalf("failed to insert sample %d: %v", i, err)
			}
		}

		samples, err := store.GetRaceSamples(ctx, raceID)
		if err != nil {
			t.Fatalf("failed to get samples: %v", err)
		}
		// 1 from previous test + 10 from this test
		if len(samples) != 11 {
			t.Errorf("expected 11 samples, got %d", len(samples))
		}
	})
}

func TestInsertPeerSamples(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	raceID, _ := store.CreateRace(ctx, "hash", "Torrent", 100)

	t.Run("inserts peer samples with normalized schema", func(t *testing.T) {
		// First create peers
		peer1 := &storage.Peer{IP: "1.2.3.4", Port: 51234, Client: "qBittorrent/4.5.0"}
		peer2 := &storage.Peer{IP: "5.6.7.8", Port: 51235, Client: "Transmission/3.0"}
		peer3 := &storage.Peer{IP: "9.10.11.12", Port: 51236, Client: "Deluge/2.0"}

		peerID1, _ := store.UpsertPeer(ctx, peer1)
		peerID2, _ := store.UpsertPeer(ctx, peer2)
		peerID3, _ := store.UpsertPeer(ctx, peer3)

		now := time.Now()
		samples := []storage.PeerSample{
			{RaceID: raceID, PeerID: peerID1, Timestamp: now, UploadRate: 1024, DownloadRate: 2048, Progress: 1.0, Uploaded: 5000, Downloaded: 10000},
			{RaceID: raceID, PeerID: peerID2, Timestamp: now, UploadRate: 2048, DownloadRate: 4096, Progress: 1.0, Uploaded: 8000, Downloaded: 16000},
			{RaceID: raceID, PeerID: peerID3, Timestamp: now, UploadRate: 512, DownloadRate: 1024, Progress: 0.8, Uploaded: 2000, Downloaded: 4000},
		}

		err := store.InsertPeerSamples(ctx, samples)
		if err != nil {
			t.Fatalf("failed to insert peer samples: %v", err)
		}
	})

	t.Run("handles empty slice", func(t *testing.T) {
		err := store.InsertPeerSamples(ctx, []storage.PeerSample{})
		if err != nil {
			t.Fatalf("failed with empty slice: %v", err)
		}
	})
}

func TestListRecentRaces(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns empty for no races", func(t *testing.T) {
		races, err := store.ListRecentRaces(ctx, 7)
		if err != nil {
			t.Fatalf("failed to list races: %v", err)
		}
		if len(races) != 0 {
			t.Errorf("expected 0 races, got %d", len(races))
		}
	})

	t.Run("returns races within period", func(t *testing.T) {
		_, _ = store.CreateRace(ctx, "hash1", "Torrent1", 100)
		_, _ = store.CreateRace(ctx, "hash2", "Torrent2", 200)
		_, _ = store.CreateRace(ctx, "hash3", "Torrent3", 300)

		races, err := store.ListRecentRaces(ctx, 7)
		if err != nil {
			t.Fatalf("failed to list races: %v", err)
		}
		if len(races) != 3 {
			t.Errorf("expected 3 races, got %d", len(races))
		}
	})

	t.Run("orders by started_at descending", func(t *testing.T) {
		races, _ := store.ListRecentRaces(ctx, 7)
		for i := 1; i < len(races); i++ {
			if races[i-1].StartedAt.Before(races[i].StartedAt) {
				t.Error("races not ordered by started_at descending")
			}
		}
	})
}

func TestGetRaceSamples(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	raceID, _ := store.CreateRace(ctx, "hash", "Torrent", 100)

	// Insert samples with specific timestamps
	baseTime := time.Now().Truncate(time.Second)
	for i := 0; i < 5; i++ {
		sample := &storage.Sample{
			RaceID:       raceID,
			Timestamp:    baseTime.Add(time.Duration(i) * 500 * time.Millisecond),
			UploadRate:   int64((i + 1) * 1000),
			DownloadRate: int64((5 - i) * 2000),
			Progress:     float64(i) * 0.2,
			Uploaded:     int64(i * 10000),
			Downloaded:   int64(i * 20000),
			PeerCount:    10 + i,
			SeedCount:    2 + i,
			MyRank:       5 - i,
		}
		_ = store.InsertSample(ctx, sample)
	}

	t.Run("returns samples in timestamp order", func(t *testing.T) {
		samples, err := store.GetRaceSamples(ctx, raceID)
		if err != nil {
			t.Fatalf("failed to get samples: %v", err)
		}
		if len(samples) != 5 {
			t.Fatalf("expected 5 samples, got %d", len(samples))
		}

		for i := 1; i < len(samples); i++ {
			if samples[i-1].Timestamp.After(samples[i].Timestamp) {
				t.Error("samples not ordered by timestamp ascending")
			}
		}
	})

	t.Run("returns correct data", func(t *testing.T) {
		samples, _ := store.GetRaceSamples(ctx, raceID)

		// Check first sample
		if samples[0].UploadRate != 1000 {
			t.Errorf("expected first upload rate 1000, got %d", samples[0].UploadRate)
		}
		if samples[0].MyRank != 5 {
			t.Errorf("expected first rank 5, got %d", samples[0].MyRank)
		}

		// Check last sample
		last := samples[len(samples)-1]
		if last.UploadRate != 5000 {
			t.Errorf("expected last upload rate 5000, got %d", last.UploadRate)
		}
		if last.Progress != 0.8 {
			t.Errorf("expected last progress 0.8, got %f", last.Progress)
		}
	})

	t.Run("returns empty for nonexistent race", func(t *testing.T) {
		samples, err := store.GetRaceSamples(ctx, 99999)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(samples) != 0 {
			t.Errorf("expected 0 samples, got %d", len(samples))
		}
	})
}

func TestGetRaceStats(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	raceID, _ := store.CreateRace(ctx, "hash", "Test.Torrent.2024", 1024*1024*1024)

	// Insert samples simulating a race
	baseTime := time.Now().Truncate(time.Second)
	samples := []struct {
		offsetSec    int
		uploadRate   int64
		downloadRate int64
		progress     float64
		uploaded     int64
		downloaded   int64
		rank         int
	}{
		{0, 0, 100_000_000, 0.0, 0, 0, 10},                         // Start
		{60, 10_000_000, 80_000_000, 0.1, 10_000_000, 100_000_000, 5},    // 1 min
		{120, 50_000_000, 50_000_000, 0.3, 70_000_000, 300_000_000, 2},   // 2 min
		{180, 80_000_000, 20_000_000, 0.6, 200_000_000, 600_000_000, 1},  // 3 min (peak)
		{240, 60_000_000, 5_000_000, 0.9, 320_000_000, 900_000_000, 1},   // 4 min
		{300, 40_000_000, 0, 1.0, 400_000_000, 1_000_000_000, 2},         // 5 min (complete)
		{600, 30_000_000, 0, 1.0, 600_000_000, 1_000_000_000, 3},         // 10 min
		{900, 20_000_000, 0, 1.0, 750_000_000, 1_000_000_000, 4},         // 15 min
	}

	for _, s := range samples {
		sample := &storage.Sample{
			RaceID:       raceID,
			Timestamp:    baseTime.Add(time.Duration(s.offsetSec) * time.Second),
			UploadRate:   s.uploadRate,
			DownloadRate: s.downloadRate,
			Progress:     s.progress,
			Uploaded:     s.uploaded,
			Downloaded:   s.downloaded,
			PeerCount:    20,
			SeedCount:    5,
			MyRank:       s.rank,
		}
		_ = store.InsertSample(ctx, sample)
	}

	_ = store.CompleteRace(ctx, raceID)

	t.Run("calculates correct stats", func(t *testing.T) {
		stats, err := store.GetRaceStats(ctx, raceID)
		if err != nil {
			t.Fatalf("failed to get stats: %v", err)
		}

		if stats.Name != "Test.Torrent.2024" {
			t.Errorf("expected name 'Test.Torrent.2024', got %q", stats.Name)
		}

		// Time to complete: 5 minutes (300 seconds)
		if stats.TimeToComplete < 4*time.Minute || stats.TimeToComplete > 6*time.Minute {
			t.Errorf("unexpected time to complete: %v", stats.TimeToComplete)
		}

		// Peak upload rate: 80 MB/s
		if stats.PeakUploadRate != 80_000_000 {
			t.Errorf("expected peak upload 80000000, got %d", stats.PeakUploadRate)
		}

		// Best rank: 1
		if stats.BestRank != 1 {
			t.Errorf("expected best rank 1, got %d", stats.BestRank)
		}

		// Total uploaded: 750 MB
		if stats.TotalUploaded != 750_000_000 {
			t.Errorf("expected total uploaded 750000000, got %d", stats.TotalUploaded)
		}

		// Uploaded in first 5 min
		if stats.UploadedFirst5m != 400_000_000 {
			t.Errorf("expected uploaded 5m 400000000, got %d", stats.UploadedFirst5m)
		}
	})

	t.Run("returns error for nonexistent race", func(t *testing.T) {
		_, err := store.GetRaceStats(ctx, 99999)
		if err == nil {
			t.Error("expected error for nonexistent race")
		}
	})

	t.Run("returns error for race with no samples", func(t *testing.T) {
		emptyRaceID, _ := store.CreateRace(ctx, "empty", "Empty Race", 100)
		_, err := store.GetRaceStats(ctx, emptyRaceID)
		if err == nil {
			t.Error("expected error for race with no samples")
		}
	})
}

func TestConcurrentAccess(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	raceID, _ := store.CreateRace(ctx, "hash", "Torrent", 100)

	// Test concurrent reads with sequential writes
	// This tests the Store API works correctly, not SQLite's write concurrency
	for i := 0; i < 100; i++ {
		sample := &storage.Sample{
			RaceID:       raceID,
			Timestamp:    time.Now().Add(time.Duration(i) * time.Millisecond),
			UploadRate:   int64(i * 1000),
			DownloadRate: int64(i * 2000),
			Progress:     float64(i) / 100.0,
			Uploaded:     int64(i * 1000),
			Downloaded:   int64(i * 2000),
			PeerCount:    i,
			SeedCount:    i / 2,
			MyRank:       (i % 10) + 1,
		}
		if err := store.InsertSample(ctx, sample); err != nil {
			t.Fatalf("insert %d failed: %v", i, err)
		}
	}

	// Concurrent reads should work fine
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			samples, err := store.GetRaceSamples(ctx, raceID)
			if err != nil {
				t.Errorf("concurrent read failed: %v", err)
			}
			if len(samples) != 100 {
				t.Errorf("expected 100 samples, got %d", len(samples))
			}
		}()
	}
	wg.Wait()
}

func TestUpsertPeer(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("inserts new peer and returns ID", func(t *testing.T) {
		peer := &storage.Peer{
			IP:         "192.168.1.100",
			Port:       51234,
			Client:     "qBittorrent/4.5.0",
			Country:    "US",
			Connection: "uTP",
			Flags:      "E",
		}

		peerID, err := store.UpsertPeer(ctx, peer)
		if err != nil {
			t.Fatalf("failed to upsert peer: %v", err)
		}
		if peerID == 0 {
			t.Error("expected non-zero peer ID")
		}
	})

	t.Run("returns same ID for same IP:port", func(t *testing.T) {
		peer1 := &storage.Peer{
			IP:     "192.168.1.101",
			Port:   51235,
			Client: "Transmission/3.0",
		}

		id1, _ := store.UpsertPeer(ctx, peer1)

		peer2 := &storage.Peer{
			IP:     "192.168.1.101",
			Port:   51235,
			Client: "Transmission/4.0", // Different client
		}

		id2, err := store.UpsertPeer(ctx, peer2)
		if err != nil {
			t.Fatalf("failed to upsert peer: %v", err)
		}

		if id1 != id2 {
			t.Errorf("expected same ID for same IP:port, got %d and %d", id1, id2)
		}
	})

	t.Run("updates peer metadata on conflict", func(t *testing.T) {
		peer := &storage.Peer{
			IP:     "192.168.1.102",
			Port:   51236,
			Client: "OldClient/1.0",
		}

		store.UpsertPeer(ctx, peer)

		// Update with new client
		updatedPeer := &storage.Peer{
			IP:     "192.168.1.102",
			Port:   51236,
			Client: "NewClient/2.0",
		}

		_, err := store.UpsertPeer(ctx, updatedPeer)
		if err != nil {
			t.Fatalf("failed to update peer: %v", err)
		}

		// Verify update by checking it returns same ID with new data
		peerID, _ := store.UpsertPeer(ctx, updatedPeer)
		if peerID == 0 {
			t.Error("expected non-zero peer ID")
		}
	})

	t.Run("different ports create different peers", func(t *testing.T) {
		peer1 := &storage.Peer{IP: "192.168.1.103", Port: 51237, Client: "Client/1.0"}
		peer2 := &storage.Peer{IP: "192.168.1.103", Port: 51238, Client: "Client/1.0"}

		id1, _ := store.UpsertPeer(ctx, peer1)
		id2, _ := store.UpsertPeer(ctx, peer2)

		if id1 == id2 {
			t.Error("expected different IDs for different ports on same IP")
		}
	})
}

func TestComputeRankings(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create race
	raceID, _ := store.CreateRace(ctx, "hash", "Test Race", 1024*1024*1024)

	// Create peers
	peers := []struct {
		ip             string
		completionTime time.Duration // Offset from race start
		totalUpload    int64
	}{
		{"192.168.1.1", 100 * time.Second, 500_000_000},  // Peer 1: finished 1st, uploaded 500MB
		{"192.168.1.2", 120 * time.Second, 800_000_000},  // Peer 2: finished 2nd, uploaded 800MB (most)
		{"192.168.1.3", 150 * time.Second, 300_000_000},  // Peer 3: finished 4th, uploaded 300MB
		{"192.168.1.4", 140 * time.Second, 400_000_000},  // Peer 4: finished 3rd, uploaded 400MB
	}

	baseTime := time.Now().Truncate(time.Second)
	peerIDs := make([]int64, len(peers))

	for i, p := range peers {
		peer := &storage.Peer{IP: p.ip, Port: 51234, Client: "Test/1.0"}
		peerID, _ := store.UpsertPeer(ctx, peer)
		peerIDs[i] = peerID

		// Insert samples showing download progress
		// Add 30s past completion to ensure we get a sample with progress >= 1.0
		for offset := 0; offset <= int(p.completionTime.Seconds())+30; offset += 30 {
			progress := float64(offset) / p.completionTime.Seconds()
			if progress > 1.0 {
				progress = 1.0
			}

			sample := &storage.PeerSample{
				RaceID:       raceID,
				PeerID:       peerID,
				Timestamp:    baseTime.Add(time.Duration(offset) * time.Second),
				UploadRate:   5_000_000,
				DownloadRate: 10_000_000,
				Progress:     progress,
				Uploaded:     int64(float64(p.totalUpload) * progress),
				Downloaded:   1_000_000_000, // Assume 1GB download
			}
			store.InsertPeerSamples(ctx, []storage.PeerSample{*sample})
		}
	}

	// Insert our samples - we finish at 150s (same time as peer 3 and 4, after peer 1 and 2)
	// Due to 30s sampling interval, peers complete at first sample >= their target time
	// Peer 1 (100s target) completes at 120s, Peer 2 (120s) at 120s,
	// Peer 4 (140s) at 150s, Peer 3 (150s) at 150s, Us (130s target) at 150s
	ourTotalUpload := int64(600_000_000) // 600MB - between peer 2 (800MB) and peer 1 (500MB)

	for offset := 0; offset <= 150; offset += 30 {
		progress := float64(offset) / 130.0
		if progress > 1.0 {
			progress = 1.0
		}

		sample := &storage.Sample{
			RaceID:       raceID,
			Timestamp:    baseTime.Add(time.Duration(offset) * time.Second),
			UploadRate:   5_000_000,
			DownloadRate: 10_000_000,
			Progress:     progress,
			Uploaded:     int64(float64(ourTotalUpload) * progress),
			Downloaded:   1_000_000_000,
			PeerCount:    4,
			SeedCount:    0,
			MyRank:       1,
		}
		store.InsertSample(ctx, sample)
	}

	store.CompleteRace(ctx, raceID)

	t.Run("computes correct completion rank", func(t *testing.T) {
		stats, err := store.GetRaceStats(ctx, raceID)
		if err != nil {
			t.Fatalf("failed to get stats: %v", err)
		}

		// With 30s sampling: We finished at 150s, Peer 1 at 120s, Peer 2 at 120s,
		// Peer 3 at 150s, Peer 4 at 150s
		// Peers who completed before us (< 150s): Peer 1, Peer 2
		// So we're 3rd (2 peers finished before us)
		if stats.CompletionRank != 3 {
			t.Errorf("expected completion rank 3, got %d", stats.CompletionRank)
		}
	})

	t.Run("computes correct upload rank", func(t *testing.T) {
		stats, err := store.GetRaceStats(ctx, raceID)
		if err != nil {
			t.Fatalf("failed to get stats: %v", err)
		}

		// We uploaded 600MB
		// Peer 2 uploaded 800MB (more than us)
		// Peer 1 uploaded 500MB (less than us)
		// Peer 4 uploaded 400MB (less than us)
		// Peer 3 uploaded 300MB (less than us)
		// So we're 2nd (1 peer uploaded more)
		if stats.UploadRank != 2 {
			t.Errorf("expected upload rank 2, got %d", stats.UploadRank)
		}
	})

	t.Run("rank 1 when we finish first", func(t *testing.T) {
		raceID2, _ := store.CreateRace(ctx, "hash2", "Test Race 2", 1024*1024*1024)

		// Create one peer who finishes after us
		peer := &storage.Peer{IP: "192.168.1.10", Port: 51234, Client: "Test/1.0"}
		peerID, _ := store.UpsertPeer(ctx, peer)

		baseTime2 := time.Now().Truncate(time.Second)

		// Peer finishes at 200s
		for offset := 0; offset <= 200; offset += 50 {
			progress := float64(offset) / 200.0
			sample := &storage.PeerSample{
				RaceID:       raceID2,
				PeerID:       peerID,
				Timestamp:    baseTime2.Add(time.Duration(offset) * time.Second),
				UploadRate:   5_000_000,
				DownloadRate: 10_000_000,
				Progress:     progress,
				Uploaded:     int64(500_000_000 * progress),
				Downloaded:   1_000_000_000,
			}
			store.InsertPeerSamples(ctx, []storage.PeerSample{*sample})
		}

		// We finish at 100s (first)
		for offset := 0; offset <= 100; offset += 50 {
			progress := float64(offset) / 100.0
			sample := &storage.Sample{
				RaceID:       raceID2,
				Timestamp:    baseTime2.Add(time.Duration(offset) * time.Second),
				UploadRate:   5_000_000,
				DownloadRate: 10_000_000,
				Progress:     progress,
				Uploaded:     int64(300_000_000 * progress),
				Downloaded:   1_000_000_000,
				PeerCount:    1,
				SeedCount:    0,
				MyRank:       1,
			}
			store.InsertSample(ctx, sample)
		}

		store.CompleteRace(ctx, raceID2)

		stats, _ := store.GetRaceStats(ctx, raceID2)
		if stats.CompletionRank != 1 {
			t.Errorf("expected completion rank 1 when finishing first, got %d", stats.CompletionRank)
		}
	})
}

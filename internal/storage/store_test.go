package storage_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
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

// createTestTorrent is a helper that creates a torrent and returns its ID.
func createTestTorrent(t *testing.T, store *storage.Store, hash, name string, size int64, pieces int) int64 {
	t.Helper()
	id, err := store.CreateTorrent(context.Background(), hash, name, size, pieces)
	if err != nil {
		t.Fatalf("failed to create torrent: %v", err)
	}
	return id
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

func TestCreateTorrent(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("inserts and returns ID", func(t *testing.T) {
		id, err := store.CreateTorrent(ctx, "abc123", "Test.Torrent", 1024*1024, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id <= 0 {
			t.Errorf("expected positive ID, got %d", id)
		}
	})

	t.Run("returns existing ID for duplicate hash", func(t *testing.T) {
		id1, _ := store.CreateTorrent(ctx, "dup_hash", "Name1", 100, 10)
		id2, _ := store.CreateTorrent(ctx, "dup_hash", "Name2", 200, 20)

		if id1 != id2 {
			t.Errorf("expected same ID for duplicate hash, got %d != %d", id1, id2)
		}
	})
}

func TestCreateRace(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("creates race with valid torrent", func(t *testing.T) {
		torID := createTestTorrent(t, store, "abc123hash", "Test.Torrent.2024", 1024*1024*1024, 1024)

		id, err := store.CreateRace(ctx, torID, 0)
		if err != nil {
			t.Fatalf("failed to create race: %v", err)
		}
		if id <= 0 {
			t.Errorf("expected positive ID, got %d", id)
		}
	})

	t.Run("creates multiple races for same torrent", func(t *testing.T) {
		torID := createTestTorrent(t, store, "multi", "Multi", 100, 10)

		id1, _ := store.CreateRace(ctx, torID, 0)
		time.Sleep(2 * time.Millisecond) // ensure different started_at for UNIQUE constraint
		id2, _ := store.CreateRace(ctx, torID, 0)

		if id1 >= id2 {
			t.Errorf("expected id1 < id2, got %d >= %d", id1, id2)
		}
	})
}

func TestGetRace(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("retrieves race with denormalized torrent data", func(t *testing.T) {
		torID := createTestTorrent(t, store, "testhash", "Test.Torrent", 500, 50)
		raceID, _ := store.CreateRace(ctx, torID, 0)

		race, err := store.GetRace(ctx, raceID)
		if err != nil {
			t.Fatalf("failed to get race: %v", err)
		}

		if race.InfoHash != "testhash" {
			t.Errorf("expected hash testhash, got %q", race.InfoHash)
		}
		if race.Name != "Test.Torrent" {
			t.Errorf("expected name Test.Torrent, got %q", race.Name)
		}
		if race.Size != 500 {
			t.Errorf("expected size 500, got %d", race.Size)
		}
		if race.PieceCount != 50 {
			t.Errorf("expected piece_count 50, got %d", race.PieceCount)
		}
		if race.TorrentID != torID {
			t.Errorf("expected torrent_id %d, got %d", torID, race.TorrentID)
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
	torID := createTestTorrent(t, store, "hash", "Torrent", 100, 10)
	raceID, _ := store.CreateRace(ctx, torID, 0)

	if err := store.CompleteRace(ctx, raceID); err != nil {
		t.Fatalf("failed to complete race: %v", err)
	}

	race, _ := store.GetRace(ctx, raceID)
	if !race.CompletedAt.Valid {
		t.Error("expected CompletedAt to be set")
	}
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
		for i, h := range []string{"h1", "h2", "h3"} {
			torID := createTestTorrent(t, store, h, "Torrent"+h, int64((i+1)*100), (i+1)*10)
			store.CreateRace(ctx, torID, 0)
		}

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

func TestInsertConnection(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	torID := createTestTorrent(t, store, "hash", "Torrent", 100, 10)
	raceID, _ := store.CreateRace(ctx, torID, 0)
	now := time.Now()

	t.Run("inserts and returns ID", func(t *testing.T) {
		id, err := store.InsertConnection(ctx, raceID, "deadbeef", now)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id == 0 {
			t.Error("expected non-zero ID")
		}
	})

	t.Run("returns same ID for duplicate conn_ptr", func(t *testing.T) {
		id1, _ := store.InsertConnection(ctx, raceID, "same_ptr", now)
		id2, _ := store.InsertConnection(ctx, raceID, "same_ptr", now.Add(time.Second))

		if id1 != id2 {
			t.Errorf("expected same ID for duplicate conn_ptr, got %d != %d", id1, id2)
		}
	})

	t.Run("different ptrs get different IDs", func(t *testing.T) {
		id1, _ := store.InsertConnection(ctx, raceID, "ptr_a", now)
		id2, _ := store.InsertConnection(ctx, raceID, "ptr_b", now)

		if id1 == id2 {
			t.Error("expected different IDs for different conn_ptrs")
		}
	})
}

func TestInsertPacketEvents(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	torID := createTestTorrent(t, store, "hash", "Torrent", 100, 10)
	raceID, _ := store.CreateRace(ctx, torID, 0)
	connID, _ := store.InsertConnection(ctx, raceID, "self", time.Now())

	t.Run("inserts multiple events", func(t *testing.T) {
		now := time.Now().UnixNano()
		events := []storage.Event{
			{
				RaceID:       raceID,
				ConnectionID: connID,
				Timestamp:    now,
				EventType:    storage.EventTypePieceReceived,
				PieceIndex:   0,
			},
			{
				RaceID:       raceID,
				ConnectionID: connID,
				Timestamp:    now + int64(time.Second),
				EventType:    storage.EventTypeHave,
				PieceIndex:   5,
			},
		}

		if err := store.InsertPacketEvents(ctx, events); err != nil {
			t.Fatalf("failed to insert events: %v", err)
		}
	})

	t.Run("handles empty slice", func(t *testing.T) {
		if err := store.InsertPacketEvents(ctx, []storage.Event{}); err != nil {
			t.Fatalf("unexpected error for empty slice: %v", err)
		}
	})
}

// seedRace creates a race for torrentID with one connection, one packet event
// and one race error.
func seedRace(t *testing.T, store *storage.Store, torrentID int64) int64 {
	t.Helper()
	ctx := context.Background()
	raceID, err := store.CreateRace(ctx, torrentID, 1)
	if err != nil {
		t.Fatalf("create race: %v", err)
	}
	connID, err := store.InsertConnection(ctx, raceID, "self", time.Now())
	if err != nil {
		t.Fatalf("insert connection: %v", err)
	}
	if err := store.InsertPacketEvents(ctx, []storage.Event{{
		RaceID: raceID, ConnectionID: connID, Timestamp: 1,
		EventType: storage.EventTypeHave, PieceIndex: 1,
	}}); err != nil {
		t.Fatalf("insert event: %v", err)
	}
	store.InsertRaceError(ctx, raceID, "test", "test")
	return raceID
}

func countRaceRows(t *testing.T, store *storage.Store, table string, raceID int64) int {
	t.Helper()
	var n int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE race_id = ?`, raceID).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

func TestDeleteRace_RemovesOwnedRowsAndTorrent(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()

	torrentID := createTestTorrent(t, store, "hash_a", "A", 1, 1)
	raceID := seedRace(t, store, torrentID)

	if err := store.DeleteRace(ctx, raceID); err != nil {
		t.Fatalf("DeleteRace: %v", err)
	}

	for _, table := range []string{"packet_events", "connections", "race_errors"} {
		if n := countRaceRows(t, store, table, raceID); n != 0 {
			t.Errorf("%s has %d rows for the race, want 0", table, n)
		}
	}
	if _, err := store.GetRace(ctx, raceID); !errors.Is(err, storage.ErrRaceNotFound) {
		t.Errorf("GetRace err = %v, want ErrRaceNotFound", err)
	}
	var torrents int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM torrents WHERE id = ?`, torrentID).Scan(&torrents); err != nil {
		t.Fatalf("count torrents: %v", err)
	}
	if torrents != 0 {
		t.Errorf("torrents row survived: %d", torrents)
	}
}

func TestDeleteRace_KeepsTorrentOfOtherRaces(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	ctx := context.Background()

	torrentID := createTestTorrent(t, store, "hash_a", "A", 1, 1)
	earlier := seedRace(t, store, torrentID)
	time.Sleep(2 * time.Millisecond) // races are unique on (torrent_id, started_at ms)
	raceID := seedRace(t, store, torrentID)

	if err := store.DeleteRace(ctx, raceID); err != nil {
		t.Fatalf("DeleteRace: %v", err)
	}

	if _, err := store.GetRace(ctx, raceID); !errors.Is(err, storage.ErrRaceNotFound) {
		t.Errorf("GetRace err = %v, want ErrRaceNotFound", err)
	}
	r, err := store.GetRace(ctx, earlier)
	if err != nil {
		t.Fatalf("earlier race: %v", err)
	}
	if r.Name != "A" {
		t.Errorf("earlier race torrent name = %q, want A", r.Name)
	}
	for _, table := range []string{"packet_events", "connections", "race_errors"} {
		if n := countRaceRows(t, store, table, earlier); n != 1 {
			t.Errorf("%s has %d rows for the earlier race, want 1", table, n)
		}
	}
}

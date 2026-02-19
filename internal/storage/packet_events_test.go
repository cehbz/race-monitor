package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/cehbz/race-monitor/internal/storage"
)

func TestPacketEvents(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	torID := createTestTorrent(t, store, "testhash", "test torrent", 1000000, 100)
	raceID, err := store.CreateRace(ctx, torID, 0)
	if err != nil {
		t.Fatalf("failed to create race: %v", err)
	}

	now := time.Now()
	peerConnID, err := store.InsertConnection(ctx, raceID, "deadbeef", now)
	if err != nil {
		t.Fatalf("failed to insert connection: %v", err)
	}

	selfConnID, err := store.InsertConnection(ctx, raceID, "self", now)
	if err != nil {
		t.Fatalf("failed to insert self connection: %v", err)
	}

	nowNano := now.UnixNano()
	events := []storage.Event{
		{
			RaceID:       raceID,
			ConnectionID: peerConnID,
			Timestamp:    nowNano,
			EventType:    storage.EventTypeHave,
			PieceIndex:   15,
		},
		{
			RaceID:       raceID,
			ConnectionID: selfConnID,
			Timestamp:    nowNano + int64(time.Second),
			EventType:    storage.EventTypePieceReceived,
			PieceIndex:   5,
		},
	}

	if err := store.InsertPacketEvents(ctx, events); err != nil {
		t.Fatalf("failed to insert packet events: %v", err)
	}
}

func TestPieceReceivedAndHaveEvents(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	now := time.Now()

	torID := createTestTorrent(t, store, "testhash2", "test torrent 2", 500000, 50)
	raceID, _ := store.CreateRace(ctx, torID, 0)
	selfConnID, _ := store.InsertConnection(ctx, raceID, "self", now)
	remoteConnID, _ := store.InsertConnection(ctx, raceID, "cafebabe", now)

	nowNano := now.UnixNano()
	events := []storage.Event{
		{RaceID: raceID, ConnectionID: selfConnID, Timestamp: nowNano, EventType: storage.EventTypePieceReceived, PieceIndex: 0},
		{RaceID: raceID, ConnectionID: remoteConnID, Timestamp: nowNano + int64(time.Second), EventType: storage.EventTypeHave, PieceIndex: 1},
		{RaceID: raceID, ConnectionID: selfConnID, Timestamp: nowNano + 2*int64(time.Second), EventType: storage.EventTypePieceReceived, PieceIndex: 2},
	}

	if err := store.InsertPacketEvents(ctx, events); err != nil {
		t.Fatalf("have/piece_received events should succeed: %v", err)
	}
}

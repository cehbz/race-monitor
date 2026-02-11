package race

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	qbt "github.com/cehbz/qbittorrent"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// trackerTestLogger creates a logger that discards output to keep tests quiet.
func trackerTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// setupTrackerTest creates a store, torrent, and race for tracker testing.
// Returns the store, raceID, cleanup func, and a pre-computed bootTime-relative
// nanosecond offset for synthesizing realistic eBPF timestamps.
func setupTrackerTest(t *testing.T, hash string, pieceCount int) (*storage.Store, int64, func()) {
	t.Helper()

	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	torID, err := store.CreateTorrent(ctx, hash, "Test.Torrent", 1000000, pieceCount)
	if err != nil {
		store.Close()
		t.Fatalf("failed to create torrent: %v", err)
	}

	raceID, err := store.CreateRace(ctx, torID)
	if err != nil {
		store.Close()
		t.Fatalf("failed to create race: %v", err)
	}

	cleanup := func() { store.Close() }
	return store, raceID, cleanup
}

// ebpfTimestamp returns a nanosecond timestamp suitable for bpf.Event.Timestamp.
// eBPF uses CLOCK_BOOTTIME (nanoseconds since boot); processEvents converts via
// bootTime.Add(Duration(event.Timestamp)). To get a wall-clock-close result we
// compute ns-since-boot for "now + offset".
func ebpfTimestamp(offset time.Duration) uint64 {
	boot := estimateBootTime()
	return uint64(time.Since(boot) + offset)
}

func TestProcessEvents_WeHaveCreatesEvents(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "wehave_test", 10)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.Event, 100)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, nil, logger, "wehave_test", raceID, 10, events, nil, nil)
	}()

	// Send 3 we_have events for different pieces
	for i := 0; i < 3; i++ {
		events <- bpf.Event{
			EventType:  bpf.EventWeHave,
			PieceIndex: uint32(i),
			Timestamp:  ebpfTimestamp(time.Duration(i) * time.Millisecond),
			ObjPtr:     0,
		}
	}

	// Close channel to trigger finalize
	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}

	// Verify race was completed
	race, err := store.GetRace(ctx, raceID)
	if err != nil {
		t.Fatalf("failed to get race: %v", err)
	}
	if !race.CompletedAt.Valid {
		t.Error("expected race to be completed after channel close")
	}
}

func TestProcessEvents_IncomingHaveCreatesConnection(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "incoming_test", 100)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.Event, 100)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, nil, logger, "incoming_test", raceID, 100, events, nil, nil)
	}()

	// Send incoming_have events from two different peer connections
	ts := ebpfTimestamp(0)
	events <- bpf.Event{
		EventType:  bpf.EventIncomingHave,
		PieceIndex: 5,
		Timestamp:  ts,
		ObjPtr:     0xdeadbeef,
	}
	events <- bpf.Event{
		EventType:  bpf.EventIncomingHave,
		PieceIndex: 10,
		Timestamp:  ts + 1000,
		ObjPtr:     0xcafebabe,
	}
	// Second event from same connection should reuse connMap entry
	events <- bpf.Event{
		EventType:  bpf.EventIncomingHave,
		PieceIndex: 15,
		Timestamp:  ts + 2000,
		ObjPtr:     0xdeadbeef,
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}

	// Verify race was finalized
	race, err := store.GetRace(ctx, raceID)
	if err != nil {
		t.Fatalf("failed to get race: %v", err)
	}
	if !race.CompletedAt.Valid {
		t.Error("expected race to be completed")
	}
}

func TestProcessEvents_CompletionDetection(t *testing.T) {
	const pieceCount = 5
	store, raceID, cleanup := setupTrackerTest(t, "complete_test", pieceCount)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.Event, 100)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, nil, logger, "complete_test", raceID, pieceCount, events, nil, nil)
	}()

	// Send we_have for all pieces
	for i := 0; i < pieceCount; i++ {
		events <- bpf.Event{
			EventType:  bpf.EventWeHave,
			PieceIndex: uint32(i),
			Timestamp:  ebpfTimestamp(time.Duration(i) * time.Millisecond),
		}
	}

	// After completing all pieces, incoming_have from new connections should be
	// ignored (loggedComplete = true blocks new InsertConnection calls).
	// Send one more incoming_have with a new ObjPtr.
	events <- bpf.Event{
		EventType:  bpf.EventIncomingHave,
		PieceIndex: 0,
		Timestamp:  ebpfTimestamp(10 * time.Millisecond),
		ObjPtr:     0xfaceface,
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}
}

func TestProcessEvents_BatchFlush(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "batch_test", 200)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.Event, 200)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, nil, logger, "batch_test", raceID, 200, events, nil, nil)
	}()

	// Send 150 events — first 100 should trigger a batch flush, remainder
	// flushed on channel close.
	for i := 0; i < 150; i++ {
		events <- bpf.Event{
			EventType:  bpf.EventWeHave,
			PieceIndex: uint32(i),
			Timestamp:  ebpfTimestamp(time.Duration(i) * time.Millisecond),
		}
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}
}

func TestProcessEvents_ContextCancellation(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "cancel_test", 100)
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())

	events := make(chan bpf.Event, 100)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, nil, logger, "cancel_test", raceID, 100, events, nil, nil)
	}()

	// Send one event so processEvents is active
	events <- bpf.Event{
		EventType:  bpf.EventWeHave,
		PieceIndex: 0,
		Timestamp:  ebpfTimestamp(0),
	}

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-errCh:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("processEvents did not exit on context cancellation")
	}
}

func TestProcessEvents_PeerPolling(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "peerpoll_test", 100)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewMockQBittorrentClient()
	client.mu.Lock()
	client.torrentPeersMap["peerpoll_test"] = &qbt.TorrentPeers{
		Peers: map[string]qbt.TorrentPeer{
			"peer1": {
				IP:           "192.168.1.10",
				Port:         6881,
				Client:       "qBittorrent/4.5.3",
				PeerIDClient: "-qB4530-abc",
				Country:      "US",
				Progress:     0.75,
				DLSpeed:      1024000,
				UPSpeed:      512000,
			},
			"peer2": {
				IP:       "10.0.0.5",
				Port:     51413,
				Client:   "Deluge/2.1.1",
				Country:  "DE",
				Progress: 1.0,
			},
		},
	}
	client.mu.Unlock()

	events := make(chan bpf.Event, 100)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, client, logger, "peerpoll_test", raceID, 100, events, nil, nil)
	}()

	// Allow time for initial peer poll
	time.Sleep(200 * time.Millisecond)

	close(events)
	<-errCh

	// Verify peers were stored
	peers, err := store.GetRacePeers(ctx, raceID)
	if err != nil {
		t.Fatalf("failed to get race peers: %v", err)
	}
	if len(peers) != 2 {
		t.Errorf("expected 2 race peers from poll, got %d", len(peers))
	}

	// Verify peer data was stored correctly
	for _, p := range peers {
		switch p.IP {
		case "192.168.1.10":
			if p.Port != 6881 {
				t.Errorf("expected port 6881, got %d", p.Port)
			}
			if p.Client != "qBittorrent/4.5.3" {
				t.Errorf("expected client qBittorrent/4.5.3, got %q", p.Client)
			}
			if p.Country != "US" {
				t.Errorf("expected country US, got %q", p.Country)
			}
		case "10.0.0.5":
			if p.Port != 51413 {
				t.Errorf("expected port 51413, got %d", p.Port)
			}
			if p.Client != "Deluge/2.1.1" {
				t.Errorf("expected client Deluge/2.1.1, got %q", p.Client)
			}
		default:
			t.Errorf("unexpected peer IP: %s", p.IP)
		}
	}

	// Verify SyncTorrentPeersCtx was called
	client.mu.Lock()
	calls := len(client.syncTorrentPeersCtxCalls)
	client.mu.Unlock()
	if calls == 0 {
		t.Error("expected SyncTorrentPeersCtx to be called at least once")
	}
}

func TestProcessEvents_PeerPollRIDDeltaMode(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "rid_test", 100)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewMockQBittorrentClient()
	client.mu.Lock()
	client.torrentPeersMap["rid_test"] = &qbt.TorrentPeers{
		Peers: map[string]qbt.TorrentPeer{
			"peer1": {
				IP:   "10.0.0.1",
				Port: 6881,
			},
		},
	}
	client.mu.Unlock()

	events := make(chan bpf.Event, 100)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, client, logger, "rid_test", raceID, 100, events, nil, nil)
	}()

	// Wait for the initial async poll to complete (rid=0 → full snapshot)
	time.Sleep(200 * time.Millisecond)

	// Verify the first poll used rid=0
	client.mu.Lock()
	rids := make([]int, len(client.syncTorrentPeersRids))
	copy(rids, client.syncTorrentPeersRids)
	client.mu.Unlock()

	if len(rids) == 0 {
		t.Fatal("expected at least one SyncTorrentPeersCtx call")
	}
	if rids[0] != 0 {
		t.Errorf("expected first poll to use rid=0 (full snapshot), got rid=%d", rids[0])
	}

	close(events)
	<-errCh
}

func TestProcessEvents_AsyncPollDoesNotBlockEvents(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "async_test", 100)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use a nil client so startPeerPoll is a no-op — we just verify the
	// event loop structure handles the peerResultCh select case without
	// blocking on missing poll results.
	events := make(chan bpf.Event, 100)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, nil, logger, "async_test", raceID, 100, events, nil, nil)
	}()

	// Rapidly send events — if polling were synchronous with a slow client
	// this would block. With async polling (or nil client), events flow freely.
	for i := 0; i < 50; i++ {
		events <- bpf.Event{
			EventType:  bpf.EventWeHave,
			PieceIndex: uint32(i),
			Timestamp:  ebpfTimestamp(time.Duration(i) * time.Millisecond),
		}
	}

	close(events)

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("processEvents returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("processEvents did not exit in time — possible event processing blockage")
	}
}

func TestProcessEvents_PeerPollNilClient(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "nilclient_test", 10)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.Event, 10)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		// nil qbtClient — pollPeers should be a no-op
		errCh <- processEvents(ctx, store, nil, logger, "nilclient_test", raceID, 10, events, nil, nil)
	}()

	events <- bpf.Event{
		EventType:  bpf.EventWeHave,
		PieceIndex: 0,
		Timestamp:  ebpfTimestamp(0),
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents with nil client returned error: %v", err)
	}
}

func TestProcessEvents_PeerPollError(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "pollerr_test", 10)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewMockQBittorrentClient()
	client.mu.Lock()
	client.torrentPeersErr = context.DeadlineExceeded
	client.mu.Unlock()

	events := make(chan bpf.Event, 10)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, client, logger, "pollerr_test", raceID, 10, events, nil, nil)
	}()

	// Peer poll will fail but processEvents should continue
	events <- bpf.Event{
		EventType:  bpf.EventWeHave,
		PieceIndex: 0,
		Timestamp:  ebpfTimestamp(0),
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents should not fail on peer poll error: %v", err)
	}
}

func TestProcessEvents_UnknownEventTypeIgnored(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "unknown_type", 10)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.Event, 10)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, nil, logger, "unknown_type", raceID, 10, events, nil, nil)
	}()

	// Send an event with unknown type — should be silently skipped
	events <- bpf.Event{
		EventType:  999,
		PieceIndex: 0,
		Timestamp:  ebpfTimestamp(0),
	}

	// Send a valid event to confirm processing continues
	events <- bpf.Event{
		EventType:  bpf.EventWeHave,
		PieceIndex: 0,
		Timestamp:  ebpfTimestamp(time.Millisecond),
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}
}

func TestFinalize(t *testing.T) {
	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}
	defer store.Close()

	ctx := context.Background()
	torID, _ := store.CreateTorrent(ctx, "finalize_test", "Finalize.Test", 500, 50)
	raceID, _ := store.CreateRace(ctx, torID)

	logger := trackerTestLogger()

	if err := finalize(ctx, store, logger, raceID, 50); err != nil {
		t.Fatalf("finalize returned error: %v", err)
	}

	race, err := store.GetRace(ctx, raceID)
	if err != nil {
		t.Fatalf("failed to get race after finalize: %v", err)
	}
	if !race.CompletedAt.Valid {
		t.Error("expected race to have CompletedAt set")
	}
}

func TestEstimateBootTime(t *testing.T) {
	boot := estimateBootTime()

	// Boot time should be before now
	if boot.After(time.Now()) {
		t.Error("boot time should be in the past")
	}

	// Boot time should be within reasonable bounds (system booted within last year)
	oneYearAgo := time.Now().Add(-365 * 24 * time.Hour)
	if boot.Before(oneYearAgo) {
		t.Errorf("boot time %v is unreasonably old", boot)
	}
}

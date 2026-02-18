package race

import (
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// countPieceReceivedEvents returns the number of piece_received (we_have) events
// stored for the given race. Used by tests to verify routing without relying on ChanLen.
func countPieceReceivedEvents(store *storage.Store, ctx context.Context, raceID int64) int {
	return countEventsByType(store, ctx, raceID, storage.EventTypePieceReceived)
}

// countHaveEvents returns the number of have (incoming_have) events for the given race.
func countHaveEvents(store *storage.Store, ctx context.Context, raceID int64) int {
	return countEventsByType(store, ctx, raceID, storage.EventTypeHave)
}

func countEventsByType(store *storage.Store, ctx context.Context, raceID int64, eventType storage.EventType) int {
	var n int
	err := store.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM packet_events WHERE race_id = ? AND event_type_id = ?`,
		raceID, eventType).Scan(&n)
	if err != nil {
		return 0
	}
	return n
}

// testLogger creates a simple test logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// waitForState polls QueryState until predicate is satisfied or timeout.
func waitForState(t *testing.T, c *Coordinator, predicate func(StateSnapshot) bool, timeout time.Duration) StateSnapshot {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		snap := c.QueryState()
		if predicate(snap) {
			return snap
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for state condition")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// makeTorrentStartEvent creates a CalibrationEvent for EVT_TORRENT_STARTED with
// the info_hash embedded at the given offset in the Data array.
func makeTorrentStartEvent(ptr uint64, infoHashBytes []byte, infoHashOffset int) bpf.CalibrationEvent {
	if len(infoHashBytes) != 20 {
		panic("infoHashBytes must be exactly 20 bytes")
	}
	if infoHashOffset+20 > calibrationDataSize {
		panic("infoHashOffset too large for calibration data")
	}

	event := bpf.CalibrationEvent{
		EventType: bpf.EventTorrentStarted,
		ObjPtr:    ptr,
		Timestamp: uint64(time.Now().UnixNano()),
	}

	copy(event.Data[infoHashOffset:infoHashOffset+20], infoHashBytes)
	return event
}

// --- Unit tests (direct method calls, no Run) ---

// TestNewCoordinator tests basic initialization
func TestNewCoordinator(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()

	c := NewCoordinator(store, logger, "http://localhost:3000", "", "", nil)

	if c == nil {
		t.Fatal("expected non-nil coordinator")
	}
	if c.store != store {
		t.Error("store not set correctly")
	}
	if c.logger != logger {
		t.Error("logger not set correctly")
	}
	if c.dashboardURL != "http://localhost:3000" {
		t.Error("dashboardURL not set correctly")
	}
	if len(c.infoHashToRaceState) != 0 {
		t.Error("infoHashToRaceState should be empty initially")
	}
	if len(c.torrentPtrs) != 0 {
		t.Error("torrentPtrs should be empty initially")
	}
	if len(c.connToRace) != 0 {
		t.Error("connToRace should be empty initially")
	}
}

// TestTorrentStartCreatesRace tests that EVT_TORRENT_STARTED creates a race
func TestTorrentStartCreatesRace(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create a test info_hash
	infoHashBytes := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14}
	infoHashHex := hex.EncodeToString(infoHashBytes)

	// Send EVT_TORRENT_STARTED
	calibrationsChan <- makeTorrentStartEvent(0x1000, infoHashBytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return exists
	}, 2*time.Second)

	if _, exists := snap.ActiveRaces[infoHashHex]; !exists {
		t.Error("expected race to be created from EVT_TORRENT_STARTED")
	}

	close(eventsChan)
	<-errChan
}

// TestTorrentFinishedSignalsCompletion tests that EVT_TORRENT_FINISHED completes a race
func TestTorrentFinishedSignalsCompletion(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create test info_hash
	infoHashBytes := []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34}
	infoHashHex := hex.EncodeToString(infoHashBytes)
	torrentPtr := uint64(0x2000)

	// Send EVT_TORRENT_STARTED
	calibrationsChan <- makeTorrentStartEvent(torrentPtr, infoHashBytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return exists
	}, 2*time.Second)

	if _, exists := snap.ActiveRaces[infoHashHex]; !exists {
		t.Fatal("expected race to be created")
	}

	// Send EVT_TORRENT_FINISHED
	eventsChan <- bpf.Event{
		EventType: bpf.EventTorrentFinished,
		ObjPtr:    torrentPtr,
	}

	// Wait for race to be removed after completion
	waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return !exists
	}, 2*time.Second)

	close(eventsChan)
	<-errChan
}

// TestWeHaveRoutesKnownTorrentPtr tests that we_have events with the known
// torrent_ptr (registered by startRace) are routed correctly, and events
// with unknown pointers are dropped.
func TestWeHaveRoutesAndDrops(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create a single race via EVT_TORRENT_STARTED with torrent_ptr=0x3000
	infoHashBytes := []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
		0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50, 0x51, 0x52, 0x53, 0x54}
	infoHashHex := hex.EncodeToString(infoHashBytes)

	calibrationsChan <- makeTorrentStartEvent(0x3000, infoHashBytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return exists
	}, 2*time.Second)
	raceID := snap.ActiveRaces[infoHashHex].RaceID

	// Send we_have with the KNOWN torrent_ptr — should route to the race
	eventsChan <- bpf.Event{
		EventType:  bpf.EventWeHave,
		ObjPtr:     0x3000,
		PieceIndex: 5,
	}
	eventsChan <- bpf.Event{
		EventType:  bpf.EventWeHave,
		ObjPtr:     0x3000,
		PieceIndex: 10,
	}

	// Send we_have with an UNKNOWN torrent_ptr — should be dropped
	eventsChan <- bpf.Event{
		EventType:  bpf.EventWeHave,
		ObjPtr:     0xaaaa,
		PieceIndex: 99,
	}

	close(eventsChan)
	<-errChan

	// Only the 2 events with the known ptr should be routed
	count := countPieceReceivedEvents(store, ctx, raceID)
	if count != 2 {
		t.Errorf("expected 2 events routed for known torrent_ptr, got %d", count)
	}
}

// TestWeHaveRoutesKnownPtr tests known ptr routes directly
func TestWeHaveRoutesKnownPtr(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create two races via EVT_TORRENT_STARTED
	hash1Bytes := []byte{0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
		0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74}
	hash1Hex := hex.EncodeToString(hash1Bytes)

	hash2Bytes := []byte{0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88,
		0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94}
	hash2Hex := hex.EncodeToString(hash2Bytes)

	calibrationsChan <- makeTorrentStartEvent(0x4000, hash1Bytes, infoHashOffset)
	calibrationsChan <- makeTorrentStartEvent(0x4001, hash2Bytes, infoHashOffset)

	preCloseSnap := waitForState(t, c, func(s StateSnapshot) bool {
		return len(s.ActiveRaces) == 2
	}, 2*time.Second)
	race1ID := preCloseSnap.ActiveRaces[hash1Hex].RaceID
	race2ID := preCloseSnap.ActiveRaces[hash2Hex].RaceID
	if race1ID <= 0 || race2ID <= 0 {
		t.Fatal("expected both races to have RaceID")
	}

	// Manually map a ptr to hash1 (simulating previous discovery)
	c.mapTorrentPtr(0xbbbb, hash1Hex)

	// Send we_have with the known ptr
	eventsChan <- bpf.Event{
		EventType:  bpf.EventWeHave,
		ObjPtr:     0xbbbb,
		PieceIndex: 10,
	}

	// Close only eventsChan so coordinator processes the event before exiting.
	// Closing calibrationsChan would make it always-ready and compete with events in select.
	close(eventsChan)
	<-errChan

	if countPieceReceivedEvents(store, ctx, race1ID) == 0 {
		t.Error("expected event routed to hash1")
	}
	if countPieceReceivedEvents(store, ctx, race2ID) > 0 {
		t.Error("expected we_have to route only to hash1, not hash2")
	}
}

// TestWeHaveDropsMultipleRaces tests drops when multiple races and unknown ptr
func TestWeHaveDropsMultipleRaces(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create two races
	hash1Bytes := []byte{0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
		0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4}

	hash2Bytes := []byte{0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8,
		0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4}

	calibrationsChan <- makeTorrentStartEvent(0x5000, hash1Bytes, infoHashOffset)
	calibrationsChan <- makeTorrentStartEvent(0x5001, hash2Bytes, infoHashOffset)

	preCloseSnap := waitForState(t, c, func(s StateSnapshot) bool {
		return len(s.ActiveRaces) == 2
	}, 2*time.Second)

	// Send we_have with unknown ptr to multiple races
	// This should be dropped (ambiguous)
	eventsChan <- bpf.Event{
		EventType:  bpf.EventWeHave,
		ObjPtr:     0xcccc,
		PieceIndex: 5,
	}

	close(eventsChan)
	<-errChan

	// Neither race should have events (both have unknown ptr -> ambiguous)
	for _, race := range preCloseSnap.ActiveRaces {
		if countPieceReceivedEvents(store, ctx, race.RaceID) > 0 {
			t.Error("expected we_have to be dropped due to ambiguity")
		}
	}
}

// TestIncomingHaveExactRouting tests connToRace-based routing
func TestIncomingHaveExactRouting(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create two races
	hash1Bytes := []byte{0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8,
		0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4}
	hash1Hex := hex.EncodeToString(hash1Bytes)

	hash2Bytes := []byte{0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
		0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25}
	hash2Hex := hex.EncodeToString(hash2Bytes)

	calibrationsChan <- makeTorrentStartEvent(0x6000, hash1Bytes, infoHashOffset)
	calibrationsChan <- makeTorrentStartEvent(0x6001, hash2Bytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		return len(s.ActiveRaces) == 2
	}, 2*time.Second)
	race1ID := snap.ActiveRaces[hash1Hex].RaceID
	race2ID := snap.ActiveRaces[hash2Hex].RaceID

	// Manually set connToRace mapping (simulating calibration)
	c.connToRace[0x5555] = hash1Hex

	// Send incoming_have with exact routing
	eventsChan <- bpf.Event{
		EventType:  bpf.EventIncomingHave,
		ObjPtr:     0x5555,
		PieceIndex: 10,
	}

	close(eventsChan)
	<-errChan

	if countHaveEvents(store, ctx, race1ID) == 0 {
		t.Error("expected event routed to hash1 via exact routing")
	}
	if countHaveEvents(store, ctx, race2ID) > 0 {
		t.Error("expected hash2 to not receive event")
	}
}

// TestIncomingHaveDropsUnmapped tests that incoming_have events for unmapped
// peer_connection pointers are dropped, regardless of how many races are active.
func TestIncomingHaveDropsUnmapped(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create a single race
	hashBytes := []byte{0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
		0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45}
	hashHex := hex.EncodeToString(hashBytes)

	calibrationsChan <- makeTorrentStartEvent(0x7000, hashBytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		return len(s.ActiveRaces) == 1
	}, 2*time.Second)
	raceID := snap.ActiveRaces[hashHex].RaceID

	// Send incoming_have with an unmapped peer_connection ptr — should be dropped
	// even though only one race is active.
	eventsChan <- bpf.Event{
		EventType:  bpf.EventIncomingHave,
		ObjPtr:     0x7777,
		PieceIndex: 25,
	}

	close(eventsChan)
	<-errChan

	total := countHaveEvents(store, ctx, raceID)
	if total != 0 {
		t.Errorf("expected 0 events for unmapped peer_conn, got %d", total)
	}
}

// TestRaceCompleteCleansUp tests cleanup after race completion
func TestRaceCompleteCleansUp(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create a race
	infoHashBytes := []byte{0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79,
		0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85}
	infoHashHex := hex.EncodeToString(infoHashBytes)
	torrentPtr := uint64(0x8000)

	calibrationsChan <- makeTorrentStartEvent(torrentPtr, infoHashBytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return exists
	}, 2*time.Second)

	if _, exists := snap.ActiveRaces[infoHashHex]; !exists {
		t.Fatal("expected race to be created")
	}

	// Complete the race via EVT_TORRENT_FINISHED
	eventsChan <- bpf.Event{
		EventType: bpf.EventTorrentFinished,
		ObjPtr:    torrentPtr,
	}

	// Wait for race to be removed
	waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return !exists
	}, 2*time.Second)

	close(eventsChan)
	<-errChan
}

// TestPidDeathExitsRun tests pidDeathCh causes Run to return
func TestPidDeathExitsRun(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Send a pidDeath error
	testErr := errors.New("process exited")
	pidDeathCh <- testErr

	select {
	case err := <-errChan:
		if err != testErr {
			t.Errorf("expected %v, got %v", testErr, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run to exit")
	}
}

// TestContextCancelExitsRun tests ctx cancel causes Run to return
func TestContextCancelExitsRun(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	ctx, cancel := context.WithCancel(context.Background())

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Give Run a moment to start
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	select {
	case err := <-errChan:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run to exit")
	}
}

// TestRouteEventChannelFull tests handling when event channel is full
func TestRouteEventChannelFull(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	state := &raceState{
		eventChan:  make(chan bpf.Event, 1),
		hash:       "testhash",
		pieceCount: 100,
	}

	// Fill the channel
	select {
	case state.eventChan <- bpf.Event{PieceIndex: 1}:
	default:
		t.Fatal("failed to fill channel")
	}

	// Try to route another event (should be dropped)
	c.routeEvent(state, bpf.Event{PieceIndex: 2})

	if len(state.eventChan) != 1 {
		t.Errorf("expected 1 event in channel (full), got %d", len(state.eventChan))
	}
}

// TestMapTorrentPtr tests mapping a torrent_ptr to an info hash
func TestMapTorrentPtr(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	c.mapTorrentPtr(0x1234, "testhash")

	if hash, ok := c.torrentPtrs[0x1234]; !ok || hash != "testhash" {
		t.Error("expected torrent_ptr mapping to be recorded")
	}
}

// --- Integration tests (Run in goroutine, calibration events) ---

// TestLifecycleStartAndComplete tests complete lifecycle with EVT_TORRENT_STARTED and EVT_TORRENT_FINISHED
func TestLifecycleStartAndComplete(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Start a race
	infoHashBytes := []byte{0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98,
		0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4}
	infoHashHex := hex.EncodeToString(infoHashBytes)
	torrentPtr := uint64(0x9000)

	calibrationsChan <- makeTorrentStartEvent(torrentPtr, infoHashBytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return exists
	}, 2*time.Second)

	if _, exists := snap.ActiveRaces[infoHashHex]; !exists {
		t.Fatal("expected race to be created")
	}

	// Complete the race
	eventsChan <- bpf.Event{
		EventType: bpf.EventTorrentFinished,
		ObjPtr:    torrentPtr,
	}

	waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return !exists
	}, 2*time.Second)

	close(eventsChan)
	<-errChan
}

// TestMultipleRacesWithLifecycle tests managing multiple races with lifecycle events
func TestMultipleRacesWithLifecycle(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Start multiple races
	hashes := make([]string, 3)
	ptrs := []uint64{0xa000, 0xa001, 0xa002}
	for i := 0; i < 3; i++ {
		// Create unique info_hash for each
		infoHashBytes := []byte{
			byte(0xb0 + i), byte(0xb1 + i), byte(0xb2 + i), byte(0xb3 + i), byte(0xb4 + i),
			byte(0xb5 + i), byte(0xb6 + i), byte(0xb7 + i), byte(0xb8 + i), byte(0xb9 + i),
			byte(0xba + i), byte(0xbb + i), byte(0xbc + i), byte(0xbd + i), byte(0xbe + i),
			byte(0xbf + i), byte(0xc0 + i), byte(0xc1 + i), byte(0xc2 + i), byte(0xc3 + i),
		}
		hashes[i] = hex.EncodeToString(infoHashBytes)
		calibrationsChan <- makeTorrentStartEvent(ptrs[i], infoHashBytes, infoHashOffset)
	}

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		return len(s.ActiveRaces) == 3
	}, 2*time.Second)

	if len(snap.ActiveRaces) != 3 {
		t.Fatalf("expected 3 races, got %d", len(snap.ActiveRaces))
	}

	// Complete one race
	eventsChan <- bpf.Event{
		EventType: bpf.EventTorrentFinished,
		ObjPtr:    ptrs[0],
	}

	snap = waitForState(t, c, func(s StateSnapshot) bool {
		return len(s.ActiveRaces) == 2
	}, 2*time.Second)

	if len(snap.ActiveRaces) != 2 {
		t.Errorf("expected 2 races after completion, got %d", len(snap.ActiveRaces))
	}

	// Verify hash0 is gone and hash1, hash2 remain
	if _, exists := snap.ActiveRaces[hashes[0]]; exists {
		t.Error("expected hashes[0] to be removed")
	}
	if _, exists := snap.ActiveRaces[hashes[1]]; !exists {
		t.Error("expected hashes[1] to remain")
	}
	if _, exists := snap.ActiveRaces[hashes[2]]; !exists {
		t.Error("expected hashes[2] to remain")
	}

	close(eventsChan)
	<-errChan
}

// TestContextCancelCleansUpAllRaces tests that all races are cleaned up on cancel
func TestContextCancelCleansUpAllRaces(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithCancel(context.Background())

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create multiple races
	for i := 0; i < 3; i++ {
		infoHashBytes := []byte{
			byte(0xd0 + i), byte(0xd1 + i), byte(0xd2 + i), byte(0xd3 + i), byte(0xd4 + i),
			byte(0xd5 + i), byte(0xd6 + i), byte(0xd7 + i), byte(0xd8 + i), byte(0xd9 + i),
			byte(0xda + i), byte(0xdb + i), byte(0xdc + i), byte(0xdd + i), byte(0xde + i),
			byte(0xdf + i), byte(0xe0 + i), byte(0xe1 + i), byte(0xe2 + i), byte(0xe3 + i),
		}
		calibrationsChan <- makeTorrentStartEvent(uint64(0xb000+i), infoHashBytes, infoHashOffset)
	}

	waitForState(t, c, func(s StateSnapshot) bool {
		return len(s.ActiveRaces) == 3
	}, 2*time.Second)

	// Cancel context
	cancel()

	select {
	case err := <-errChan:
		if err != context.Canceled {
			t.Errorf("expected context.Canceled, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run to exit")
	}

	// After Run exits, QueryState would block (no receiver). Check internal state directly.
	if len(c.infoHashToRaceState) != 0 {
		t.Error("expected all races to be cleaned up on shutdown")
	}
}

// TestEventChannelCloseCleansUp tests that channel close triggers cleanup
func TestEventChannelCloseCleansUp(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create a race
	infoHashBytes := []byte{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
		0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x01, 0x02, 0x03}
	infoHashHex := hex.EncodeToString(infoHashBytes)

	calibrationsChan <- makeTorrentStartEvent(0xc000, infoHashBytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return exists
	}, 2*time.Second)
	raceID := snap.ActiveRaces[infoHashHex].RaceID

	close(eventsChan)

	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("expected nil error after channel close, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for Run to exit")
	}

	// Verify race was finalized (Run waits for processEvents to flush before returning)
	race, err := store.GetRace(ctx, raceID)
	if err != nil {
		t.Fatalf("get race: %v", err)
	}
	if !race.CompletedAt.Valid {
		t.Error("expected race to be completed after channel close")
	}
}

// TestQueryStateSnapshotConsistency tests that QueryState returns consistent snapshots
func TestQueryStateSnapshotConsistency(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Pre-calibrate the info_hash offset
	const infoHashOffset = 64
	c.torrentCalib.infoHashOffset = infoHashOffset

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Create a race
	infoHashBytes := []byte{0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
		0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	infoHashHex := hex.EncodeToString(infoHashBytes)

	calibrationsChan <- makeTorrentStartEvent(0xd000, infoHashBytes, infoHashOffset)

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, exists := s.ActiveRaces[infoHashHex]
		return exists
	}, 2*time.Second)

	// Verify snapshot fields are initialized
	if snap.ActiveRaces == nil {
		t.Error("expected ActiveRaces to be non-nil")
	}

	close(eventsChan)
	<-errChan
}

// TestInfoHashCorrelationCalibration tests calibration via multi-dump correlation
func TestInfoHashCorrelationCalibration(t *testing.T) {
	store, _ := storage.New(":memory:")
	defer store.Close()

	logger := testLogger()
	c := NewCoordinator(store, logger, "", "", "", nil)

	// Do NOT pre-calibrate; test the calibration mechanism
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	eventsChan := make(chan bpf.Event, 10)
	calibrationsChan := make(chan bpf.CalibrationEvent, 10)
	pidDeathCh := make(chan error, 1)

	errChan := make(chan error, 1)
	go func() {
		errChan <- c.Run(ctx, eventsChan, calibrationsChan, pidDeathCh)
	}()

	// Use offset 488 with hash1/hash2 sharing first 12 bytes so correlation
	// finds exactly 1 candidate (overlapping windows at 480 rejected).
	const infoHashOffset = 488

	hash1Bytes := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18}
	hash1Hex := hex.EncodeToString(hash1Bytes)

	hash2Bytes := []byte{0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28}
	hash2Hex := hex.EncodeToString(hash2Bytes)

	// Send first event
	calibrationsChan <- makeTorrentStartEvent(0xe000, hash1Bytes, infoHashOffset)

	// Give it time to buffer (calibration not complete yet)
	time.Sleep(100 * time.Millisecond)

	// Send second event from different ptr - should trigger calibration
	calibrationsChan <- makeTorrentStartEvent(0xe001, hash2Bytes, infoHashOffset)

	// Wait for both races to be created (calibration should lock in after 2nd event)
	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, h1 := s.ActiveRaces[hash1Hex]
		_, h2 := s.ActiveRaces[hash2Hex]
		return h1 && h2 && s.InfoHashCalibOff == infoHashOffset
	}, 2*time.Second)

	if _, exists := snap.ActiveRaces[hash1Hex]; !exists {
		t.Error("expected race from hash1 to be created after calibration")
	}
	if _, exists := snap.ActiveRaces[hash2Hex]; !exists {
		t.Error("expected race from hash2 to be created after calibration")
	}
	if snap.InfoHashCalibOff != infoHashOffset {
		t.Errorf("expected info_hash offset to be calibrated to %d, got %d", infoHashOffset, snap.InfoHashCalibOff)
	}

	close(eventsChan)
	<-errChan
}

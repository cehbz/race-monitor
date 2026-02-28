package race

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// trackerTestLogger creates a logger that discards output to keep tests quiet.
func trackerTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// testTimestamp returns a nanosecond timestamp for event Timestamp fields.
// The tracker stores timestamps as-is; any monotonic sequence is sufficient for tests.
func testTimestamp(offset time.Duration) uint64 {
	return uint64(offset.Nanoseconds())
}

// setupTrackerTest creates a store, torrent, and race for tracker testing.
// Returns the store, raceID, and cleanup func.
func setupTrackerTest(t *testing.T, hash string) (*storage.Store, int64, func()) {
	t.Helper()

	store, err := storage.New(":memory:")
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	ctx := context.Background()
	torID, err := store.CreateTorrent(ctx, hash, "Test.Torrent", 1000000, 100)
	if err != nil {
		store.Close()
		t.Fatalf("failed to create torrent: %v", err)
	}

	raceID, err := store.CreateRace(ctx, torID, 0)
	if err != nil {
		store.Close()
		t.Fatalf("failed to create race: %v", err)
	}

	cleanup := func() { store.Close() }
	return store, raceID, cleanup
}

func TestGraceDuration(t *testing.T) {
	tests := []struct {
		name     string
		elapsed  time.Duration
		expected time.Duration
	}{
		{"floor: 0s download", 0, 5 * time.Second},
		{"floor: 2s download", 2 * time.Second, 5 * time.Second},
		{"floor: 9s download", 9 * time.Second, 5 * time.Second},
		{"exact floor: 10s download", 10 * time.Second, 5 * time.Second},
		{"proportional: 20s download", 20 * time.Second, 10 * time.Second},
		{"proportional: 60s download", 60 * time.Second, 30 * time.Second},
		{"exact ceiling: 120s download", 120 * time.Second, 60 * time.Second},
		{"ceiling: 5min download", 5 * time.Minute, 60 * time.Second},
		{"ceiling: 30min download", 30 * time.Minute, 60 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := graceDuration(tt.elapsed)
			if got != tt.expected {
				t.Errorf("graceDuration(%v) = %v, want %v", tt.elapsed, got, tt.expected)
			}
		})
	}
}

func TestProcessEvents_WeHaveCreatesEvents(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "wehave_test")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 100)
	downloadCompleteCh := make(chan struct{}, 1)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "wehave_test", raceID, nil, events, downloadCompleteCh)
	}()

	// Send 3 we_have events for different pieces
	for i := 0; i < 3; i++ {
		events <- &bpf.WeHaveEvent{
			PieceIndex: uint32(i),
			Timestamp:  testTimestamp(time.Duration(i) * time.Millisecond),
			TorrentPtr: 0,
		}
	}

	// Close channel to trigger finalize
	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}

	// Verify all 3 we_have events were persisted as piece_received (event_type_id=2)
	var eventCount int
	if err := store.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM packet_events WHERE race_id = ? AND event_type_id = 2",
		raceID).Scan(&eventCount); err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if eventCount != 3 {
		t.Errorf("expected 3 piece_received events, got %d", eventCount)
	}
}

func TestProcessEvents_IncomingHaveCreatesConnection(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "incoming_test")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 100)
	downloadCompleteCh := make(chan struct{}, 1)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "incoming_test", raceID, nil, events, downloadCompleteCh)
	}()

	// Send incoming_have events from two different peer connections
	ts := testTimestamp(0)
	events <- &bpf.IncomingHaveEvent{
		PieceIndex: 5,
		Timestamp:  ts,
		ConnPtr:    0xdeadbeef,
	}
	events <- &bpf.IncomingHaveEvent{
		PieceIndex: 10,
		Timestamp:  ts + 1000,
		ConnPtr:    0xcafebabe,
	}
	// Second event from same connection should reuse connMap entry
	events <- &bpf.IncomingHaveEvent{
		PieceIndex: 15,
		Timestamp:  ts + 2000,
		ConnPtr:    0xdeadbeef,
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}

	// Verify 2 peer connections created (0xdeadbeef + 0xcafebabe), plus "self"
	var connCount int
	if err := store.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM connections WHERE race_id = ? AND conn_ptr != 'self'",
		raceID).Scan(&connCount); err != nil {
		t.Fatalf("failed to count connections: %v", err)
	}
	if connCount != 2 {
		t.Errorf("expected 2 peer connections, got %d", connCount)
	}

	// Verify all 3 incoming_have events persisted as have (event_type_id=1)
	var eventCount int
	if err := store.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM packet_events WHERE race_id = ? AND event_type_id = 1",
		raceID).Scan(&eventCount); err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if eventCount != 3 {
		t.Errorf("expected 3 have events, got %d", eventCount)
	}
}

func TestProcessEvents_BatchFlush(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "batch_test")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 200)
	downloadCompleteCh := make(chan struct{}, 1)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "batch_test", raceID, nil, events, downloadCompleteCh)
	}()

	// Send 150 events — first 100 should trigger a batch flush, remainder
	// flushed on channel close.
	for i := 0; i < 150; i++ {
		events <- &bpf.WeHaveEvent{
			PieceIndex: uint32(i),
			Timestamp:  testTimestamp(time.Duration(i) * time.Millisecond),
		}
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}

	// Verify all 150 events were persisted (batch flush at 100 + final flush of 50)
	var eventCount int
	if err := store.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM packet_events WHERE race_id = ?",
		raceID).Scan(&eventCount); err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if eventCount != 150 {
		t.Errorf("expected 150 events (100 batch + 50 final flush), got %d", eventCount)
	}
}

func TestProcessEvents_ContextCancellation(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "cancel_test")
	defer cleanup()

	ctx, cancel := context.WithCancel(context.Background())

	events := make(chan bpf.ProbeEvent, 100)
	downloadCompleteCh := make(chan struct{}, 1)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "cancel_test", raceID, nil, events, downloadCompleteCh)
	}()

	// Send one event so processEvents is active
	events <- &bpf.WeHaveEvent{
		PieceIndex: 0,
		Timestamp:  testTimestamp(0),
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

func TestProcessEvents_DownloadCompleteSignal(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "downloadcomplete_test")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 100)
	downloadCompleteCh := make(chan struct{}, 1)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "downloadcomplete_test", raceID, nil, events, downloadCompleteCh)
	}()

	// Send some events
	events <- &bpf.WeHaveEvent{
		PieceIndex: 0,
		Timestamp:  testTimestamp(0),
	}

	// Signal download completion
	downloadCompleteCh <- struct{}{}

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
		t.Error("expected race to be completed after download signal")
	}
}

func TestProcessEvents_UnknownEventTypeIgnored(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "unknown_type")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 10)
	downloadCompleteCh := make(chan struct{}, 1)
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "unknown_type", raceID, nil, events, downloadCompleteCh)
	}()

	// Send a TorrentFinishedEvent — the tracker only handles WeHave and
	// IncomingHave; other types hit the default branch and are skipped.
	events <- &bpf.TorrentFinishedEvent{
		TorrentPtr: 0x1234,
		Timestamp:  testTimestamp(0),
	}

	// Send a valid event to confirm processing continues
	events <- &bpf.WeHaveEvent{
		PieceIndex: 0,
		Timestamp:  testTimestamp(time.Millisecond),
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}
}

func TestProcessEvents_ContaminationDetected(t *testing.T) {
	const pieceCount = 100
	store, raceID, cleanup := setupTrackerTest(t, "contamination_test")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 200)
	downloadCompleteCh := make(chan struct{}, 1)

	// Use a logger that captures output so we can verify ERROR was logged
	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	// Pre-load pieceCount into a buffered channel so it's available immediately
	metaChan := make(chan int, 1)
	metaChan <- pieceCount
	close(metaChan)

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "contamination_test", raceID, metaChan, events, downloadCompleteCh)
	}()

	// Send valid events
	events <- &bpf.WeHaveEvent{PieceIndex: 0, Timestamp: testTimestamp(0)}
	events <- &bpf.IncomingHaveEvent{PieceIndex: 5, Timestamp: testTimestamp(time.Millisecond), ConnPtr: 0xaaa}

	// Send 10 contaminated we_have events from the same source to hit the
	// threshold (contaminationThreshold = 10). Below threshold is expected
	// cross-CPU jitter; at threshold it escalates to ERROR + race_errors.
	for i := 0; i < 10; i++ {
		events <- &bpf.WeHaveEvent{
			PieceIndex: uint32(200 + i),
			Timestamp:  testTimestamp(time.Duration(2+i) * time.Millisecond),
			TorrentPtr: 0xbbb,
		}
	}

	// Send 10 contaminated incoming_have events from the same source
	for i := 0; i < 10; i++ {
		events <- &bpf.IncomingHaveEvent{
			PieceIndex: uint32(1360 + i),
			Timestamp:  testTimestamp(time.Duration(12+i) * time.Millisecond),
			ConnPtr:    0xccc,
		}
	}

	// Send another valid event to confirm processing continues
	events <- &bpf.WeHaveEvent{PieceIndex: 1, Timestamp: testTimestamp(22 * time.Millisecond)}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}

	// Verify ERROR was logged for both contamination sources at threshold
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "CONTAMINATION") {
		t.Error("expected CONTAMINATION error in logs")
	}
	if !strings.Contains(logOutput, "we_have") {
		t.Error("expected we_have contamination logged")
	}
	if !strings.Contains(logOutput, "incoming_have") {
		t.Error("expected incoming_have contamination logged")
	}

	// Verify contaminated events were NOT persisted — only 3 valid events
	var eventCount int
	err := store.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM packet_events WHERE race_id = ?", raceID).Scan(&eventCount)
	if err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if eventCount != 3 {
		t.Errorf("expected 3 persisted events (contaminated skipped), got %d", eventCount)
	}

	// Verify race_errors were written to the DB
	rows, err := store.DB().QueryContext(ctx,
		"SELECT error_type, message FROM race_errors WHERE race_id = ?", raceID)
	if err != nil {
		t.Fatalf("failed to query race_errors: %v", err)
	}
	defer rows.Close()

	var errorCount int
	for rows.Next() {
		var errorType, message string
		if err := rows.Scan(&errorType, &message); err != nil {
			t.Fatalf("failed to scan race_error: %v", err)
		}
		if errorType != "piece_index_out_of_range" {
			t.Errorf("unexpected error_type: %s", errorType)
		}
		errorCount++
	}
	if errorCount != 2 {
		t.Errorf("expected 2 race_errors (one per source), got %d", errorCount)
	}
}

func TestProcessEvents_MetadataArrivesMidRace(t *testing.T) {
	const pieceCount = 50
	store, raceID, cleanup := setupTrackerTest(t, "meta_midrace")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 200)
	downloadCompleteCh := make(chan struct{}, 1)

	var logBuf strings.Builder
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// Metadata channel — we'll send pieceCount mid-race
	metaChan := make(chan int, 1)

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "meta_midrace", raceID, metaChan, events, downloadCompleteCh)
	}()

	// Send out-of-range events BEFORE metadata arrives — should be accepted
	// (pieceCount == 0, validation inactive)
	for i := 0; i < 5; i++ {
		events <- &bpf.WeHaveEvent{
			PieceIndex: uint32(100 + i),
			Timestamp:  testTimestamp(time.Duration(i) * time.Millisecond),
		}
	}

	// Allow events to be processed
	time.Sleep(50 * time.Millisecond)

	// Now deliver metadata
	metaChan <- pieceCount
	close(metaChan)

	// Allow metadata to be processed
	time.Sleep(50 * time.Millisecond)

	// Send out-of-range events AFTER metadata — should be dropped
	for i := 0; i < 5; i++ {
		events <- &bpf.WeHaveEvent{
			PieceIndex: uint32(200 + i),
			Timestamp:  testTimestamp(time.Duration(10+i) * time.Millisecond),
			TorrentPtr: 0xddd,
		}
	}

	// Send a valid event
	events <- &bpf.WeHaveEvent{PieceIndex: 1, Timestamp: testTimestamp(20 * time.Millisecond)}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}

	// Verify: 5 pre-metadata events + 1 valid post-metadata event = 6 persisted
	var eventCount int
	err := store.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM packet_events WHERE race_id = ?", raceID).Scan(&eventCount)
	if err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if eventCount != 6 {
		t.Errorf("expected 6 persisted events (5 pre-meta + 1 valid post-meta), got %d", eventCount)
	}

	// Verify "metadata resolved" was logged
	logOutput := logBuf.String()
	if !strings.Contains(logOutput, "metadata resolved") {
		t.Errorf("expected 'metadata resolved' log, got: %s", logOutput)
	}
}

func TestProcessEvents_GraceTimerTerminates(t *testing.T) {
	// Verify that the grace timer fires and terminates the race even when
	// events keep arriving (the old idle timer would reset and never fire).
	store, raceID, cleanup := setupTrackerTest(t, "grace_terminates")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 1000)
	downloadCompleteCh := make(chan struct{})
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "grace_terminates", raceID, nil, events, downloadCompleteCh)
	}()

	// Establish a peer connection before download completes
	events <- &bpf.IncomingHaveEvent{
		PieceIndex: 0, Timestamp: testTimestamp(0), ConnPtr: 0xaaa,
	}
	time.Sleep(50 * time.Millisecond)

	// Signal download complete — grace = clamp(elapsed*0.5, 5s, 60s) = 5s (floor)
	close(downloadCompleteCh)
	graceStart := time.Now()
	time.Sleep(50 * time.Millisecond)

	// Pump events every 100ms for 8 seconds — well past the 5s grace period.
	// Under the old idle timer, this would keep the race alive forever.
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 80; i++ {
			select {
			case events <- &bpf.IncomingHaveEvent{
				PieceIndex: uint32(i + 1),
				Timestamp:  testTimestamp(time.Duration(i) * 100 * time.Millisecond),
				ConnPtr:    0xaaa,
			}:
			case <-ctx.Done():
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("processEvents returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("race did not terminate — grace timer failed to fire")
	}

	// Verify the grace timer enforced the expected duration.
	// Should be ~5s (the floor), not instant and not unbounded.
	graceElapsed := time.Since(graceStart)
	if graceElapsed < 4*time.Second {
		t.Errorf("grace period too short: %v (expected ~5s)", graceElapsed)
	}
	if graceElapsed > 8*time.Second {
		t.Errorf("grace period too long: %v (expected ~5s, events should not extend it)", graceElapsed)
	}
}

func TestProcessEvents_EventsRecordedDuringGrace(t *testing.T) {
	store, raceID, cleanup := setupTrackerTest(t, "grace_events")
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events := make(chan bpf.ProbeEvent, 100)
	downloadCompleteCh := make(chan struct{})
	logger := trackerTestLogger()

	errCh := make(chan error, 1)
	go func() {
		errCh <- processEvents(ctx, store, logger, "grace_events", raceID, nil, events, downloadCompleteCh)
	}()

	// Establish peer + send pre-completion event
	events <- &bpf.IncomingHaveEvent{
		PieceIndex: 0, Timestamp: testTimestamp(0), ConnPtr: 0xaaa,
	}
	time.Sleep(50 * time.Millisecond)

	// Signal download complete
	close(downloadCompleteCh)
	time.Sleep(50 * time.Millisecond)

	// Send events from the known peer during grace period
	events <- &bpf.IncomingHaveEvent{
		PieceIndex: 1, Timestamp: testTimestamp(time.Second), ConnPtr: 0xaaa,
	}
	events <- &bpf.IncomingHaveEvent{
		PieceIndex: 2, Timestamp: testTimestamp(2 * time.Second), ConnPtr: 0xaaa,
	}

	close(events)

	if err := <-errCh; err != nil {
		t.Fatalf("processEvents returned error: %v", err)
	}

	// All 3 events from 0xaaa should be persisted (1 pre + 2 during grace)
	var eventCount int
	err := store.DB().QueryRowContext(ctx,
		"SELECT COUNT(*) FROM packet_events WHERE race_id = ?", raceID).Scan(&eventCount)
	if err != nil {
		t.Fatalf("failed to count events: %v", err)
	}
	if eventCount != 3 {
		t.Errorf("expected 3 events (pre + during grace), got %d", eventCount)
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
	raceID, _ := store.CreateRace(ctx, torID, 0)

	logger := trackerTestLogger()

	if err := finalize(ctx, store, logger, raceID); err != nil {
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

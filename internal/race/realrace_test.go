package race

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// Model-level tests for recording only real races: session load, pending
// starts, per-start classification, race timing, dropped events and
// unidentified starts.

// settle gives Run time to take every queued event before a state assertion.
const settle = 200 * time.Millisecond

// answerNew answers every attempt with a torrent added at its start, with
// pieces enough for the test's piece indices.
func answerNew(pieces int) func(string, int) (TorrentMeta, error) {
	return func(string, int) (TorrentMeta, error) {
		return TorrentMeta{Name: "Real.Name", Size: 1000, PieceCount: pieces, AddedAt: newDate}, nil
	}
}

// dashboardCounter is a dashboard that counts notifies.
func dashboardCounter(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	var n atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { n.Add(1) }))
	t.Cleanup(srv.Close)
	return srv, &n
}

// levelCounter counts log records at or above a level.
type levelCounter struct {
	level slog.Level
	n     atomic.Int64
}

func (h *levelCounter) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelCounter) WithAttrs([]slog.Attr) slog.Handler       { return h }
func (h *levelCounter) WithGroup(string) slog.Handler            { return h }
func (h *levelCounter) Handle(_ context.Context, r slog.Record) error {
	if r.Level >= h.level {
		h.n.Add(1)
	}
	return nil
}

func sendWeHaves(events chan<- bpf.ProbeEvent, torrentPtr uint64, n int) {
	for i := range n {
		events <- &bpf.WeHaveEvent{TorrentPtr: torrentPtr, PieceIndex: uint32(i), Timestamp: raceStartKtime + uint64(i)}
	}
}

// onlyRaceID returns the id of the single race in the store.
func onlyRaceID(t *testing.T, store *storage.Store) int64 {
	t.Helper()
	var id int64
	if err := store.DB().QueryRow(`SELECT id FROM races`).Scan(&id); err != nil {
		t.Fatalf("single race id: %v", err)
	}
	return id
}

// waitRaceCompleted polls until the race is finalized.
func waitRaceCompleted(t *testing.T, store *storage.Store, raceID int64, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		r, err := store.GetRace(context.Background(), raceID)
		if err == nil && r.CompletedAt.Valid {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("race %d not finalized within %v", raceID, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestStartDuringSessionLoadIsRestoredWithoutAskingTheAPI(t *testing.T) {
	pending(t)
	srv, notifies := dashboardCounter(t)
	api := &fakeEnrichAPI{answer: answerNew(100)}
	c, store := newClassifyCoordinator(t, nil, srv.URL, api, nil)
	c.SetSessionLoad(testBoot.Add(8*time.Second), 10*time.Second) // start at +8.7 s

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, _ := testInfoHash(301)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	sendWeHaves(eventsChan, 0x1000, 5)
	time.Sleep(settle)

	if n := len(c.QueryState().ActiveRaces); n != 0 {
		t.Errorf("active races = %d, want 0", n)
	}
	if n := api.distinctHashes(); n != 0 {
		t.Errorf("API asked about %d torrents, want 0", n)
	}
	assertNoRaceRows(t, store)
	if n := notifies.Load(); n != 0 {
		t.Errorf("dashboard notified %d times, want 0", n)
	}

	close(eventsChan)
	<-errChan
	assertNoRaceRows(t, store)
}

func TestStartAddedWhileWatchedBecomesARaceHoldingEveryEventSinceItsStart(t *testing.T) {
	pending(t)
	api := &fakeEnrichAPI{gate: make(chan struct{}), answer: answerNew(100)}
	c, store := newClassifyCoordinator(t, nil, "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(302)
	const torrentPtr, connPtr = uint64(0x1000), uint64(0x2000)
	eventsChan <- startedEvent(torrentPtr, hashBytes, raceStartKtime)
	sendWeHaves(eventsChan, torrentPtr, 25)
	peer := &bpf.PeerDetailsEvent{ConnPtr: connPtr}
	binary.LittleEndian.PutUint64(peer.Data[400:], torrentPtr)
	binary.LittleEndian.PutUint16(peer.Data[200:], 2)
	binary.BigEndian.PutUint16(peer.Data[202:], 6881)
	copy(peer.Data[204:], []byte{203, 0, 113, 9})
	eventsChan <- peer
	for i := range 3 {
		eventsChan <- &bpf.IncomingHaveEvent{ConnPtr: connPtr, PieceIndex: uint32(i), Timestamp: raceStartKtime + 1}
	}
	time.Sleep(settle)

	if n := countRows(t, store, "races"); n != 0 {
		t.Fatalf("races has %d rows while the start is pending, want 0", n)
	}

	close(api.gate)
	waitClassified(t, c, hash)
	close(eventsChan)
	<-errChan

	raceID := onlyRaceID(t, store)
	if n := countPieceReceivedEvents(store, ctx, raceID); n != 25 {
		t.Errorf("our piece events = %d, want 25", n)
	}
	if n := countHaveEvents(store, ctx, raceID); n != 3 {
		t.Errorf("peer piece events = %d, want 3", n)
	}
}

func TestStartRestoredByAdditionDateLeavesNoRecordsAndNoDashboardNotice(t *testing.T) {
	pending(t)
	srv, notifies := dashboardCounter(t)
	api := &fakeEnrichAPI{gate: make(chan struct{}), answer: answerAlways(restoredDate)}
	c, store := newClassifyCoordinator(t, nil, srv.URL, api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(303)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	sendWeHaves(eventsChan, 0x1000, 20)
	time.Sleep(settle)
	assertNoRaceRows(t, store)

	close(api.gate)
	deadline := time.Now().Add(3 * time.Second)
	for api.callsFor(hash) == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(settle)

	assertNoRaceRows(t, store)
	if n := notifies.Load(); n != 0 {
		t.Errorf("dashboard notified %d times, want 0", n)
	}

	close(eventsChan)
	<-errChan
}

func TestTorrentFinishingWhilePendingBecomesARaceThatFinalizes(t *testing.T) {
	pending(t)
	api := &fakeEnrichAPI{gate: make(chan struct{}), answer: answerNew(100)}
	c, store := newClassifyCoordinator(t, nil, "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, _ := testInfoHash(304)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	sendWeHaves(eventsChan, 0x1000, 10)
	eventsChan <- &bpf.TorrentFinishedEvent{TorrentPtr: 0x1000}
	time.Sleep(settle)

	if n := countRows(t, store, "races"); n != 0 {
		t.Fatalf("races has %d rows while the start is pending, want 0", n)
	}

	close(api.gate)
	waitForRows(t, store, "races", 1)
	raceID := onlyRaceID(t, store)
	waitRaceCompleted(t, store, raceID, 3*time.Second)
	if n := countPieceReceivedEvents(store, ctx, raceID); n != 10 {
		t.Errorf("our piece events = %d, want 10", n)
	}

	close(eventsChan)
	<-errChan
}

func TestHeldBurstLargerThanARaceChannelLosesNoEvents(t *testing.T) {
	pending(t)
	const burst = 15000 // over the 10,000-event race channel
	api := &fakeEnrichAPI{gate: make(chan struct{}), answer: answerNew(20000)}
	c, store := newClassifyCoordinator(t, nil, "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(305)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	sendWeHaves(eventsChan, 0x1000, burst)
	time.Sleep(settle)

	if n := countRows(t, store, "races"); n != 0 {
		t.Fatalf("races has %d rows while the start is pending, want 0", n)
	}

	close(api.gate)
	waitClassified(t, c, hash)
	close(eventsChan)
	<-errChan

	if n := countPieceReceivedEvents(store, ctx, onlyRaceID(t, store)); n != burst {
		t.Errorf("our piece events = %d, want %d", n, burst)
	}
}

func TestOneUnclassifiableStartDoesNotDelayAnothersClassification(t *testing.T) {
	pending(t)
	stuckBytes, stuck := testInfoHash(306)
	freshBytes, fresh := testInfoHash(307)
	api := &fakeEnrichAPI{answer: func(hash string, _ int) (TorrentMeta, error) {
		if hash == stuck {
			return TorrentMeta{}, errors.New("404 Not Found")
		}
		return TorrentMeta{Name: "Real.Name", AddedAt: newDate}, nil
	}}
	c, _ := newClassifyCoordinator(t, nil, "", api, nil)
	c.metaRetry.budget = 3 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	eventsChan <- startedEvent(0x1000, stuckBytes, raceStartKtime)
	eventsChan <- startedEvent(0x1001, freshBytes, raceStartKtime)

	waitForState(t, c, func(s StateSnapshot) bool {
		return s.ActiveRaces[fresh].Classified
	}, time.Second)

	close(eventsChan)
	<-errChan
}

func TestWithoutTheAPIEveryStartOutsideASessionLoadIsARaceAtOnce(t *testing.T) {
	pending(t)
	c, store := newClassifyCoordinator(t, nil, "", nil, nil)
	c.SetSessionLoad(testBoot.Add(8*time.Second), 10*time.Second) // load ends at +18 s

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	insideBytes, inside := testInfoHash(308)
	outsideBytes, outside := testInfoHash(309)
	eventsChan <- startedEvent(0x1000, insideBytes, raceStartKtime)                         // +8.7 s
	eventsChan <- startedEvent(0x1001, outsideBytes, raceStartKtime+uint64(20*time.Second)) // +28.7 s

	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, ok := s.ActiveRaces[outside]
		return ok
	}, 3*time.Second)
	time.Sleep(settle)
	snap = c.QueryState()

	if _, ok := snap.ActiveRaces[inside]; ok {
		t.Error("start during the session load became a race")
	}
	if n := countRows(t, store, "races"); n != 1 {
		t.Errorf("races has %d rows, want 1", n)
	}

	close(eventsChan)
	<-errChan
}

func TestUnidentifiedStartIsRecordedAsAStartErrorAndNeverBecomesARace(t *testing.T) {
	pending(t)
	errs := &levelCounter{level: slog.LevelError}
	api := &fakeEnrichAPI{answer: answerNew(100)}
	c, store := newClassifyCoordinator(t, slog.New(errs), "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	const torrentPtr = uint64(0x3000)
	eventsChan <- startedEvent(torrentPtr, make([]byte, 20), raceStartKtime)
	sendWeHaves(eventsChan, torrentPtr, 3)
	eventsChan <- &bpf.TorrentFinishedEvent{TorrentPtr: torrentPtr}
	time.Sleep(settle)

	close(eventsChan)
	<-errChan

	assertNoRaceRows(t, store)
	if n := api.distinctHashes(); n != 0 {
		t.Errorf("API asked about %d torrents, want 0", n)
	}
	if n := errs.n.Load(); n < 1 {
		t.Error("unidentified start logged no error")
	}
	got, err := store.ListStartErrors(ctx)
	if err != nil {
		t.Fatalf("list start errors: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("start errors = %d, want 1", len(got))
	}
	se := got[0]
	if se.TorrentPtr != torrentPtr || se.EventCount != 3 || len(se.Dump) != dumpDataSize || se.DetectedAt.IsZero() {
		t.Errorf("start error = {ptr %#x, events %d, dump %d bytes, at %v}, want {%#x, 3, %d, non-zero}",
			se.TorrentPtr, se.EventCount, len(se.Dump), se.DetectedAt, torrentPtr, dumpDataSize)
	}
}

func TestRaceIsTimedFromItsTorrentsStart(t *testing.T) {
	pending(t)
	// The torrent started 31 minutes ago, past the 30-minute cap.
	started := func() time.Time { return time.Now().Add(-31 * time.Minute) }
	api := &fakeEnrichAPI{answer: func(string, int) (TorrentMeta, error) {
		return TorrentMeta{Name: "Real.Name", PieceCount: 100, AddedAt: started().Truncate(time.Second)}, nil
	}}
	c, store := newClassifyCoordinator(t, nil, "", api, nil)
	c.ktimeToWall = func(uint64) time.Time { return started() }

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, _ := testInfoHash(310)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	waitForRows(t, store, "races", 1)
	waitRaceCompleted(t, store, onlyRaceID(t, store), 3*time.Second)

	close(eventsChan)
	<-errChan
}

func TestRaceThatDropsEventsRecordsOneRaceErrorWithTheirCount(t *testing.T) {
	pending(t)
	const sent = 5000
	warns := &countingHandler{msg: msgEventsDropped}
	c, store := newClassifyCoordinator(t, slog.New(warns), "", nil, nil)
	c.raceEventCap = 0 // the race falls behind whenever its tracker isn't waiting

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(311)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	waitForState(t, c, func(s StateSnapshot) bool {
		_, ok := s.ActiveRaces[hash]
		return ok
	}, 3*time.Second)
	sendWeHaves(eventsChan, 0x1000, sent)
	eventsChan <- &bpf.TorrentFinishedEvent{TorrentPtr: 0x1000}
	raceID := onlyRaceID(t, store)
	waitRaceCompleted(t, store, raceID, 10*time.Second)

	close(eventsChan)
	<-errChan

	rows, err := store.DB().Query(`SELECT message FROM race_errors WHERE race_id = ? AND error_type = ?`, raceID, raceErrorEventsDropped)
	if err != nil {
		t.Fatalf("query race errors: %v", err)
	}
	var messages []string
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			t.Fatalf("scan: %v", err)
		}
		messages = append(messages, m)
	}
	rows.Close()
	if len(messages) != 1 {
		t.Fatalf("%s race errors = %d, want 1", raceErrorEventsDropped, len(messages))
	}
	var dropped int
	if _, err := fmt.Sscanf(messages[0], "%d", &dropped); err != nil || dropped <= 0 {
		t.Fatalf("race error message %q doesn't start with a positive count", messages[0])
	}
	if stored := countPieceReceivedEvents(store, ctx, raceID); stored+dropped != sent {
		t.Errorf("stored %d + dropped %d = %d, want %d", stored, dropped, stored+dropped, sent)
	}
	if n := warns.n.Load(); n != 1 {
		t.Errorf("%q logged %d times, want 1", msgEventsDropped, n)
	}
}

func TestStartStillPendingAtShutdownLeavesNoRecords(t *testing.T) {
	pending(t)
	api := &fakeEnrichAPI{gate: make(chan struct{}), answer: answerNew(100)}
	defer close(api.gate)
	c, store := newClassifyCoordinator(t, nil, "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, _ := testInfoHash(312)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	sendWeHaves(eventsChan, 0x1000, 5)
	time.Sleep(settle)

	close(eventsChan)
	<-errChan
	assertNoRaceRows(t, store)
}

package race

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
	"golang.org/x/sys/unix"
)

const classifyHashOffset = 64

// testBoot anchors the fake ktime clock: ktime k is testBoot+k on the wall.
var testBoot = time.Date(2026, 11, 5, 15, 13, 14, 0, time.UTC)

func testKtimeClock(ktime uint64) time.Time { return testBoot.Add(time.Duration(ktime)) }

// raceStartKtime puts the fake torrent::start() at 15:13:22.700 on the wall.
const raceStartKtime = uint64(8700 * time.Millisecond)

func monotonicNow() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		panic(err)
	}
	return uint64(ts.Nano())
}

var (
	restoredDate = testBoot.Add(-30 * 24 * time.Hour)
	// newDate is the whole-second addition_date of a torrent added at raceStart.
	newDate = testKtimeClock(raceStartKtime).Truncate(time.Second)
)

// fakeEnrichAPI answers FetchTorrentMeta from a per-attempt function. A non-nil
// gate holds every call until closed, which keeps the resolver busy for as long
// as a test needs.
type fakeEnrichAPI struct {
	gate   chan struct{}
	answer func(hash string, attempt int) (TorrentMeta, error)

	mu    sync.Mutex
	calls map[string]int
}

func (f *fakeEnrichAPI) FetchTorrentMeta(hash string) (TorrentMeta, error) {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	if f.calls == nil {
		f.calls = make(map[string]int)
	}
	f.calls[hash]++
	attempt := f.calls[hash]
	f.mu.Unlock()
	return f.answer(hash, attempt)
}

func (f *fakeEnrichAPI) callsFor(hash string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[hash]
}

func (f *fakeEnrichAPI) distinctHashes() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

// answerAlways returns meta on every attempt.
func answerAlways(addedAt time.Time) func(string, int) (TorrentMeta, error) {
	return func(string, int) (TorrentMeta, error) {
		return TorrentMeta{Name: "Real.Name", Size: 1000, PieceCount: 10, AddedAt: addedAt}, nil
	}
}

// fakeSeenCache records BPF dedup removals.
type fakeSeenCache struct {
	mu       sync.Mutex
	peers    []netip.AddrPort
	torrents []uint64
}

func (f *fakeSeenCache) ForgetPeer(_ uint64, endpoint netip.AddrPort) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.peers = append(f.peers, endpoint)
	return nil
}

func (f *fakeSeenCache) ForgetTorrent(ptr uint64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.torrents = append(f.torrents, ptr)
	return nil
}

func testInfoHash(i int) ([]byte, string) {
	b := make([]byte, 20)
	binary.BigEndian.PutUint32(b, uint32(i)+1)
	const hexdigits = "0123456789abcdef"
	s := make([]byte, 40)
	for j, v := range b {
		s[2*j], s[2*j+1] = hexdigits[v>>4], hexdigits[v&0xf]
	}
	return b, string(s)
}

func startedEvent(ptr uint64, hash []byte, ktime uint64) *bpf.TorrentStartedEvent {
	ev := makeTorrentStartEvent(ptr, hash, classifyHashOffset)
	ev.Timestamp = ktime
	return ev
}

// newClassifyCoordinator builds a coordinator on a file-backed store with the
// fake clock and a fast retry policy.
func newClassifyCoordinator(t *testing.T, logger *slog.Logger, dashboardURL string, api EnrichmentAPI, seen SeenCache) (*Coordinator, *storage.Store) {
	t.Helper()
	store, err := storage.New(filepath.Join(t.TempDir(), "races.db"))
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	if logger == nil {
		logger = testLogger()
	}
	c := NewCoordinator(store, logger, dashboardURL, testOffsets(classifyHashOffset), api, seen)
	c.ktimeToWall = testKtimeClock
	c.metaRetry = retryPolicy{budget: 100 * time.Millisecond, initial: 5 * time.Millisecond, max: 20 * time.Millisecond}
	return c, store
}

func countRows(t *testing.T, store *storage.Store, table string) int {
	t.Helper()
	var n int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// waitForRows polls until table holds at least want rows.
func waitForRows(t *testing.T, store *storage.Store, table string, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for countRows(t, store, table) < want {
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for %d rows in %s, have %d", want, table, countRows(t, store, table))
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func assertNoRaceRows(t *testing.T, store *storage.Store) {
	t.Helper()
	for _, table := range []string{"packet_events", "connections", "race_errors", "races", "torrents"} {
		if n := countRows(t, store, table); n != 0 {
			t.Errorf("%s has %d rows, want 0", table, n)
		}
	}
}

func waitClassified(t *testing.T, c *Coordinator, hash string) RaceSnap {
	t.Helper()
	snap := waitForState(t, c, func(s StateSnapshot) bool {
		return s.ActiveRaces[hash].Classified
	}, 3*time.Second)
	return snap.ActiveRaces[hash]
}

func waitGone(t *testing.T, c *Coordinator, hash string) {
	t.Helper()
	waitForState(t, c, func(s StateSnapshot) bool {
		_, active := s.ActiveRaces[hash]
		return !active
	}, 3*time.Second)
}

func TestIsRestored(t *testing.T) {
	start := time.Date(2026, 11, 5, 15, 13, 22, 700_000_000, time.UTC)
	tests := []struct {
		name    string
		addedAt time.Time
		want    bool
	}{
		{"weeks before start", start.Add(-30 * 24 * time.Hour), true},
		{"just past the tolerance", start.Add(-restoredTolerance - time.Second), true},
		{"exactly at the tolerance", start.Add(-restoredTolerance), false},
		{"same second, truncated", start.Truncate(time.Second), false},
		{"after start", start.Add(time.Second), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isRestored(tt.addedAt, start); got != tt.want {
				t.Errorf("isRestored(%v, %v) = %v, want %v", tt.addedAt, start, got, tt.want)
			}
		})
	}
}

func TestKtimeToWallClock(t *testing.T) {
	got := ktimeToWallClock(monotonicNow() - uint64(90*time.Second))
	want := time.Now().Add(-90 * time.Second)
	if diff := got.Sub(want).Abs(); diff > 2*time.Second {
		t.Errorf("ktimeToWallClock 90s ago = %v, want about %v (off by %v)", got, want, diff)
	}
}

// TestRestoredTorrentDropped: a torrent whose addition_date predates its start
// event is dropped, with every row it wrote gone and BPF entries forgotten.
func TestRestoredTorrentDropped(t *testing.T) {
	api := &fakeEnrichAPI{gate: make(chan struct{}), answer: answerAlways(restoredDate)}
	seen := &fakeSeenCache{}
	c, store := newClassifyCoordinator(t, nil, "", api, seen)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(1)
	const torrentPtr, connPtr = uint64(0x1000), uint64(0x2000)
	eventsChan <- startedEvent(torrentPtr, hashBytes, raceStartKtime)
	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, ok := s.ActiveRaces[hash]
		return ok
	}, 3*time.Second)
	raceID := snap.ActiveRaces[hash].RaceID

	// The race accumulates every kind of row while the verdict is pending.
	peer := &bpf.PeerDetailsEvent{ConnPtr: connPtr}
	binary.LittleEndian.PutUint64(peer.Data[400:], torrentPtr)
	binary.LittleEndian.PutUint16(peer.Data[200:], 2)
	binary.BigEndian.PutUint16(peer.Data[202:], 6881)
	copy(peer.Data[204:], []byte{203, 0, 113, 9})
	eventsChan <- peer
	eventsChan <- &bpf.IncomingHaveEvent{ConnPtr: connPtr, PieceIndex: 1, Timestamp: 1}
	for i := range 100 {
		eventsChan <- &bpf.WeHaveEvent{TorrentPtr: torrentPtr, PieceIndex: uint32(i), Timestamp: 1}
	}
	waitForRows(t, store, "packet_events", 100)
	waitForRows(t, store, "connections", 2)
	store.InsertRaceError(ctx, raceID, "piece_index_out_of_range", "test")

	close(api.gate)
	waitGone(t, c, hash)
	assertNoRaceRows(t, store)

	seen.mu.Lock()
	defer seen.mu.Unlock()
	if len(seen.torrents) != 1 || seen.torrents[0] != torrentPtr {
		t.Errorf("forgotten torrents = %v, want [%#x]", seen.torrents, torrentPtr)
	}
	want := netip.MustParseAddrPort("203.0.113.9:6881")
	if len(seen.peers) != 1 || seen.peers[0] != want {
		t.Errorf("forgotten peers = %v, want [%v]", seen.peers, want)
	}

	close(eventsChan)
	<-errChan
	assertNoRaceRows(t, store)
}

// TestNewTorrentKept: an addition_date in the same second as the start event
// keeps the race, with its metadata applied.
func TestNewTorrentKept(t *testing.T) {
	api := &fakeEnrichAPI{answer: answerAlways(newDate)}
	c, store := newClassifyCoordinator(t, nil, "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(2)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	raceID := waitClassified(t, c, hash).RaceID

	close(eventsChan)
	<-errChan

	r, err := store.GetRace(ctx, raceID)
	if err != nil {
		t.Fatalf("get race: %v", err)
	}
	if r.Name != "Real.Name" || r.PieceCount != 10 {
		t.Errorf("torrent metadata = (%q, %d), want (Real.Name, 10)", r.Name, r.PieceCount)
	}
	if !r.CompletedAt.Valid {
		t.Error("kept race was not finalized")
	}
}

// TestAPIFailureKeepsRace: an API that never answers is retried within the
// budget, then the race is kept and the failure logged.
func TestAPIFailureKeepsRace(t *testing.T) {
	api := &fakeEnrichAPI{answer: func(string, int) (TorrentMeta, error) {
		return TorrentMeta{}, errors.New("connection refused")
	}}
	counter := &countingHandler{msg: msgClassifyFailed}
	c, store := newClassifyCoordinator(t, slog.New(counter), "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(3)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
	waitClassified(t, c, hash)

	if got := api.callsFor(hash); got < 2 {
		t.Errorf("API attempts = %d, want retries", got)
	}
	if got := counter.n.Load(); got != 1 {
		t.Errorf("%q logged %d times, want 1", msgClassifyFailed, got)
	}
	if n := countRows(t, store, "races"); n != 1 {
		t.Errorf("races has %d rows, want 1", n)
	}

	close(eventsChan)
	<-errChan
}

// TestAPIRecoveryDropsRestored: an API that comes up during the retry window
// still gets to classify the torrent.
func TestAPIRecoveryDropsRestored(t *testing.T) {
	api := &fakeEnrichAPI{answer: func(_ string, attempt int) (TorrentMeta, error) {
		if attempt < 3 {
			return TorrentMeta{}, errors.New("connection refused")
		}
		return TorrentMeta{Name: "Real.Name", AddedAt: restoredDate}, nil
	}}
	c, store := newClassifyCoordinator(t, nil, "", api, nil)
	c.metaRetry.budget = 2 * time.Second

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(4)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)

	// The race's rows appear and go between polls, so wait on the API instead.
	deadline := time.Now().Add(3 * time.Second)
	for api.callsFor(hash) < 3 {
		if time.Now().After(deadline) {
			t.Fatalf("API attempts = %d, want 3", api.callsFor(hash))
		}
		time.Sleep(time.Millisecond)
	}
	waitForState(t, c, func(s StateSnapshot) bool {
		_, active := s.ActiveRaces[hash]
		return !active && countRows(t, store, "races") == 0
	}, 3*time.Second)
	assertNoRaceRows(t, store)

	close(eventsChan)
	<-errChan
}

// TestMissingAdditionDateKeepsRace: qBittorrent answering without a usable date
// can't justify a drop. The client maps -1 to the zero time and an absent field
// to the Unix epoch. The other metadata still applies.
func TestMissingAdditionDateKeepsRace(t *testing.T) {
	for name, date := range map[string]time.Time{"zero": {}, "epoch": time.Unix(0, 0)} {
		t.Run(name, func(t *testing.T) {
			api := &fakeEnrichAPI{answer: answerAlways(date)}
			c, store := newClassifyCoordinator(t, nil, "", api, nil)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			eventsChan, errChan := startRun(c, ctx)

			hashBytes, hash := testInfoHash(5)
			eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)
			raceID := waitClassified(t, c, hash).RaceID

			close(eventsChan)
			<-errChan

			r, err := store.GetRace(ctx, raceID)
			if err != nil {
				t.Fatalf("get race: %v", err)
			}
			if r.Name != "Real.Name" {
				t.Errorf("name = %q, want Real.Name", r.Name)
			}
		})
	}
}

// TestBurstAllClassified: a burst larger than any resolver queue gets classified
// in full, and the event loop stays responsive while the resolver is stuck.
func TestBurstAllClassified(t *testing.T) {
	const burst = 40
	var kept sync.Map
	api := &fakeEnrichAPI{
		gate: make(chan struct{}),
		answer: func(hash string, _ int) (TorrentMeta, error) {
			if _, ok := kept.Load(hash); ok {
				return TorrentMeta{Name: "Real.Name", AddedAt: newDate}, nil
			}
			return TorrentMeta{Name: "Real.Name", AddedAt: restoredDate}, nil
		},
	}
	c, store := newClassifyCoordinator(t, nil, "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	var keptHashes []string
	for i := range burst {
		hashBytes, hash := testInfoHash(100 + i)
		if i%2 == 0 {
			kept.Store(hash, true)
			keptHashes = append(keptHashes, hash)
		}
		eventsChan <- startedEvent(uint64(0x1000+i), hashBytes, raceStartKtime)
	}

	// The gate is shut, so these answers prove Run isn't waiting on the resolver.
	waitForState(t, c, func(s StateSnapshot) bool { return len(s.ActiveRaces) == burst }, 3*time.Second)

	close(api.gate)

	deadline := time.Now().Add(5 * time.Second)
	for api.distinctHashes() < burst && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := api.distinctHashes(); got != burst {
		t.Fatalf("classified %d of %d torrents", got, burst)
	}

	waitForState(t, c, func(s StateSnapshot) bool {
		if len(s.ActiveRaces) != len(keptHashes) {
			return false
		}
		for _, h := range keptHashes {
			if !s.ActiveRaces[h].Classified {
				return false
			}
		}
		return true
	}, 5*time.Second)
	if n := countRows(t, store, "races"); n != len(keptHashes) {
		t.Errorf("races has %d rows, want %d", n, len(keptHashes))
	}

	close(eventsChan)
	<-errChan
}

// TestAPIDownBurstSharesBudget: the retry budget runs from when a request was
// queued, so an API that stays down costs one budget for a whole burst rather
// than one per torrent.
func TestAPIDownBurstSharesBudget(t *testing.T) {
	const burst = 50
	api := &fakeEnrichAPI{answer: func(string, int) (TorrentMeta, error) {
		return TorrentMeta{}, errors.New("connection refused")
	}}
	c, _ := newClassifyCoordinator(t, nil, "", api, nil)
	c.metaRetry.budget = 200 * time.Millisecond // 10s for the burst if per request

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	start := time.Now()
	for i := range burst {
		hashBytes, _ := testInfoHash(200 + i)
		eventsChan <- startedEvent(uint64(0x1000+i), hashBytes, raceStartKtime)
	}
	waitForState(t, c, func(s StateSnapshot) bool {
		if len(s.ActiveRaces) != burst {
			return false
		}
		for _, r := range s.ActiveRaces {
			if !r.Classified {
				return false
			}
		}
		return true
	}, 10*time.Second)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("burst took %v to give up, want about one budget", elapsed)
	}

	close(eventsChan)
	<-errChan
}

// TestLateVerdictDeletesFinishedRace: a verdict can arrive after the tracker has
// finished. It removes that race and leaves a newer race for the same hash alone.
func TestLateVerdictDeletesFinishedRace(t *testing.T) {
	gate := make(chan struct{})
	api := &fakeEnrichAPI{gate: gate, answer: func(_ string, attempt int) (TorrentMeta, error) {
		if attempt == 1 {
			return TorrentMeta{Name: "Real.Name", AddedAt: restoredDate}, nil
		}
		return TorrentMeta{Name: "Real.Name", AddedAt: newDate}, nil
	}}
	c, store := newClassifyCoordinator(t, nil, "", api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, hash := testInfoHash(6)
	const torrentPtr = uint64(0x1000)
	eventsChan <- startedEvent(torrentPtr, hashBytes, raceStartKtime)
	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, ok := s.ActiveRaces[hash]
		return ok
	}, 3*time.Second)
	firstRace := snap.ActiveRaces[hash].RaceID

	// No peers tracked, so torrent::finished() finalizes at once.
	eventsChan <- &bpf.TorrentFinishedEvent{TorrentPtr: torrentPtr}
	waitGone(t, c, hash)

	eventsChan <- startedEvent(torrentPtr, hashBytes, raceStartKtime)
	snap = waitForState(t, c, func(s StateSnapshot) bool {
		_, ok := s.ActiveRaces[hash]
		return ok
	}, 3*time.Second)
	secondRace := snap.ActiveRaces[hash].RaceID
	if secondRace == firstRace {
		t.Fatal("expected a new race")
	}

	close(gate)
	if got := waitClassified(t, c, hash).RaceID; got != secondRace {
		t.Errorf("active race = %d, want %d", got, secondRace)
	}
	if _, err := store.GetRace(ctx, firstRace); !errors.Is(err, storage.ErrRaceNotFound) {
		t.Errorf("first race lookup err = %v, want ErrRaceNotFound", err)
	}
	if n := countRows(t, store, "torrents"); n != 1 {
		t.Errorf("torrents has %d rows, want 1 (still used by the newer race)", n)
	}

	close(eventsChan)
	<-errChan
}

// TestShutdownDeletesDroppedRace: a race marked dropped whose tracker is still
// draining at shutdown has its rows deleted on the way out.
func TestShutdownDeletesDroppedRace(t *testing.T) {
	c, store := newClassifyCoordinator(t, nil, "", nil, nil)
	ctx := context.Background()

	_, hash := testInfoHash(7)
	torrentID, err := store.CreateTorrent(ctx, hash, hash, 0, 0)
	if err != nil {
		t.Fatalf("create torrent: %v", err)
	}
	raceID, err := store.CreateRace(ctx, torrentID, 1)
	if err != nil {
		t.Fatalf("create race: %v", err)
	}
	eventChan := make(chan bpf.ProbeEvent)
	close(eventChan) // dropping a race closes its channel
	c.infoHashToRaceState[hash] = &raceState{
		eventChan: eventChan, hash: hash, raceID: raceID, dropped: true,
		cancel: func() {},
	}
	c.completeChan <- raceComplete{hash: hash}

	if err := c.waitForTrackerCompletions(ctx); err != nil {
		t.Fatalf("waitForTrackerCompletions: %v", err)
	}
	assertNoRaceRows(t, store)
}

// TestRealClockClassification runs the production ktime conversion: start events
// carry real CLOCK_MONOTONIC values, as bpf_ktime_get_ns() produces.
func TestRealClockClassification(t *testing.T) {
	restoredBytes, restored := testInfoHash(8)
	newBytes, fresh := testInfoHash(9)
	wallNow := time.Now()
	api := &fakeEnrichAPI{answer: func(hash string, _ int) (TorrentMeta, error) {
		if hash == restored {
			return TorrentMeta{Name: "Real.Name", AddedAt: wallNow.Add(-time.Hour).Truncate(time.Second)}, nil
		}
		return TorrentMeta{Name: "Real.Name", AddedAt: wallNow.Truncate(time.Second)}, nil
	}}
	c, _ := newClassifyCoordinator(t, nil, "", api, nil)
	c.ktimeToWall = ktimeToWallClock

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	eventsChan <- startedEvent(0x1000, restoredBytes, monotonicNow())
	eventsChan <- startedEvent(0x1001, newBytes, monotonicNow())

	waitClassified(t, c, fresh)
	waitForState(t, c, func(s StateSnapshot) bool {
		_, active := s.ActiveRaces[restored]
		return !active && api.callsFor(restored) > 0
	}, 3*time.Second)

	close(eventsChan)
	<-errChan
}

// TestDroppedRaceNotifiesDashboard: the dashboard reloads its list on a notify,
// so a drop sends one to clear the row the start notify put there.
func TestDroppedRaceNotifiesDashboard(t *testing.T) {
	var notifies atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		notifies.Add(1)
	}))
	defer srv.Close()

	api := &fakeEnrichAPI{answer: answerAlways(restoredDate)}
	c, _ := newClassifyCoordinator(t, nil, srv.URL, api, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	eventsChan, errChan := startRun(c, ctx)

	hashBytes, _ := testInfoHash(10)
	eventsChan <- startedEvent(0x1000, hashBytes, raceStartKtime)

	deadline := time.Now().Add(3 * time.Second)
	for notifies.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := notifies.Load(); got != 2 {
		t.Errorf("dashboard notified %d times, want 2 (start, drop)", got)
	}

	close(eventsChan)
	<-errChan
}

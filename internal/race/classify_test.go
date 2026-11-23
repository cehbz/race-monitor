package race

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
	"golang.org/x/sys/unix"
)

const classifyHashOffset = 64

// testBoot anchors the fake ktime clock: ktime k is testBoot+k on the wall. It
// sits a minute before now, since a race's 30-minute cap runs from its start.
var testBoot = time.Now().Add(-time.Minute)

func testKtimeClock(ktime uint64) time.Time { return testBoot.Add(time.Duration(ktime)) }

// raceStartKtime puts the fake torrent::start() 8.7 s after testBoot.
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

// waitRace waits until hash's start has become an active race.
func waitRace(t *testing.T, c *Coordinator, hash string) RaceSnap {
	t.Helper()
	snap := waitForState(t, c, func(s StateSnapshot) bool {
		_, ok := s.ActiveRaces[hash]
		return ok
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
	raceID := waitRace(t, c, hash).RaceID

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
	waitRace(t, c, hash)

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
			raceID := waitRace(t, c, hash).RaceID

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

	waitRace(t, c, fresh)
	waitForState(t, c, func(s StateSnapshot) bool {
		_, active := s.ActiveRaces[restored]
		return !active && api.callsFor(restored) > 0
	}, 3*time.Second)

	close(eventsChan)
	<-errChan
}

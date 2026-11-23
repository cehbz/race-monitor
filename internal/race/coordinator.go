package race

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// levelTrace is a verbose log level below Debug for per-event tracing.
// Matches capture.LevelTrace; defined here to avoid a dependency on capture.
const levelTrace = slog.LevelDebug - 4

// raceComplete signals that a tracker goroutine has finished.
type raceComplete struct {
	hash string
	err  error
}

// raceState wraps an active race's event channel and metadata.
type raceState struct {
	eventChan          chan bpf.ProbeEvent
	hash               string
	raceID             int64
	downloadCompleteCh chan struct{} // closed by coordinator when torrent::finished() fires
	cancel             context.CancelFunc
	droppedEvents      atomic.Int64 // events dropped because the race fell behind
}

// pendingStart is a started torrent awaiting classification. It holds the
// events routed to it, in order, until its verdict.
type pendingStart struct {
	hash       string
	torrentPtr uint64
	startKtime uint64
	startedAt  time.Time        // wall time of its torrent::start()
	events     []bpf.ProbeEvent // we_have, incoming_have and peer details, in arrival order
	finished   bool             // torrent::finished() fired while pending
}

// raceVerdict is a pending start's classification. Run applies it.
type raceVerdict struct {
	hash     string
	restored bool
	meta     TorrentMeta // what the API answered; zero when it answered nothing
}

// StateSnapshot provides a point-in-time view of coordinator state.
// Used by tests to safely inspect state without data races via QueryState().
type StateSnapshot struct {
	ActiveRaces   map[string]RaceSnap
	ConnEndpoints int // count of resolved peer_connection* → IP:port mappings
	TorrentPtrs   int // count of known torrent_ptr mappings
	ConnToRace    int // count of peer_connection → race mappings
}

// RaceSnap captures a race's metadata at a point in time.
type RaceSnap struct {
	Hash    string
	ChanLen int
	RaceID  int64
}

type stateQuery struct {
	reply chan StateSnapshot
}

// TorrentMeta holds metadata for a torrent returned by the enrichment API.
// AddedAt is qBittorrent's addition_date, in whole seconds.
type TorrentMeta struct {
	Name       string
	Size       int64
	PieceCount int
	AddedAt    time.Time
}

// msgEventsDropped is logged when a race's event channel is full.
const msgEventsDropped = "race event channel full, dropping"

// raceErrorEventsDropped is the race error recording how many events a race
// dropped; its message starts with the count.
const raceErrorEventsDropped = "events_dropped"

// msgClassifyFailed is logged when the API can't say whether a torrent is new.
const msgClassifyFailed = "cannot classify race, keeping it"

// restoredTolerance is how far addition_date may precede torrent::start() in a
// torrent added at that moment. It covers addition_date's truncation to whole
// seconds and the time between qBittorrent recording the addition and the start.
const restoredTolerance = 5 * time.Second

// isRestored reports whether a torrent was already in the session before its
// torrent::start() event, rather than added while being watched.
func isRestored(addedAt, startedAt time.Time) bool {
	return addedAt.Add(restoredTolerance).Before(startedAt)
}

// retryPolicy bounds a start's classification retries. The budget runs from the
// start, so an API that stays down holds each start's events about one budget.
type retryPolicy struct {
	budget  time.Duration
	initial time.Duration
	max     time.Duration
}

var defaultMetaRetry = retryPolicy{
	budget:  60 * time.Second,
	initial: 250 * time.Millisecond,
	max:     8 * time.Second,
}

// errNoAdditionDate marks a properties answer that can't classify a torrent. The
// client maps addition_date -1 to the zero time and an absent field to the epoch.
var errNoAdditionDate = errors.New("no addition_date in torrent properties")

// EnrichmentAPI provides torrent metadata from qBittorrent's web API.
// Used for name and piece_count enrichment and restored-torrent classification,
// not for calibration.
type EnrichmentAPI interface {
	// FetchTorrentMeta fetches per-torrent properties (piece_count, size, addition date).
	FetchTorrentMeta(hash string) (TorrentMeta, error)
}

// SeenCache allows the coordinator to manage BPF dedup map entries.
// When a race completes, stale entries are removed so peers and torrents
// can be rediscovered if they appear in a future race.
type SeenCache interface {
	ForgetPeer(torrentPtr uint64, endpoint netip.AddrPort) error
	ForgetTorrent(ptr uint64) error
}

// Coordinator manages race lifecycle using eBPF events from libtorrent uprobes.
//
// Design: All struct byte offsets are pre-calibrated and loaded at startup.
// A torrent::start() (EVT_TORRENT_STARTED) is pending until classified, then
// becomes a race or is discarded; a race completes after torrent::finished()
// fires (EVT_TORRENT_FINISHED).
//
// we_have events carry obj_ptr = torrent* and are routed via torrentPtrs.
// incoming_have events carry obj_ptr = peer_connection* and are routed
// via connToRace (peer_connection* → torrent* → info_hash → race).
//
// Single-writer pattern: only Run() modifies state maps.
type Coordinator struct {
	store        *storage.Store
	logger       *slog.Logger
	dashboardURL string
	offsets      CalibratedOffsets

	// infoHashToRaceState maps info_hash → raceState for active races.
	infoHashToRaceState map[string]*raceState

	// torrentPtrs maps torrent_ptr (from we_have obj_ptr) → info_hash.
	torrentPtrs map[uint64]string

	// unidentified maps torrent_ptr → unidentified start.
	unidentified map[uint64]*unidentifiedStart

	// knownTorrentPtrs tracks all torrent* pointers we've seen.
	knownTorrentPtrs map[uint64]bool

	// connToRace maps peer_connection* → info_hash for incoming_have routing.
	connToRace map[uint64]string

	// connEndpoints maps peer_connection* → resolved IP:port.
	connEndpoints map[uint64]netip.AddrPort

	completeChan   chan raceComplete
	stateQueryChan chan stateQuery

	// enrichAPI provides torrent names and piece counts from qBittorrent.
	// Nil when webui_url is not configured.
	enrichAPI EnrichmentAPI

	// pending maps info_hash → pending start.
	pending map[string]*pendingStart

	// classifyCtx is set by Run and ends when Run returns.
	classifyCtx context.Context

	// verdictChan carries the classifiers' verdicts back to Run.
	verdictChan chan raceVerdict

	// seenCache manages BPF dedup map entries. Nil when not available
	// (e.g., in tests). Used to clean up seen_peers and seen_torrents
	// entries when races complete, enabling rediscovery.
	seenCache SeenCache

	// ktimeToWall converts a BPF event timestamp to wall-clock time.
	ktimeToWall func(uint64) time.Time
	metaRetry   retryPolicy

	// raceEventCap is the capacity of each race's event channel.
	raceEventCap int

	sessionLoadEnd time.Time // when qBittorrent's session load ends; zero when unknown
}

// NewCoordinator creates a race coordinator with pre-calibrated offsets.
// seenCache is optional (nil in tests); when provided, BPF dedup maps are
// cleaned up on race completion to enable peer/torrent rediscovery.
func NewCoordinator(
	store *storage.Store,
	logger *slog.Logger,
	dashboardURL string,
	offsets CalibratedOffsets,
	enrichAPI EnrichmentAPI,
	seenCache SeenCache,
) *Coordinator {
	return &Coordinator{
		store:               store,
		logger:              logger,
		dashboardURL:        dashboardURL,
		offsets:             offsets,
		infoHashToRaceState: make(map[string]*raceState),
		torrentPtrs:         make(map[uint64]string),
		unidentified:        make(map[uint64]*unidentifiedStart),
		knownTorrentPtrs:    make(map[uint64]bool),
		connToRace:          make(map[uint64]string),
		connEndpoints:       make(map[uint64]netip.AddrPort),
		completeChan:        make(chan raceComplete, 10),
		stateQueryChan:      make(chan stateQuery),
		enrichAPI:           enrichAPI,
		seenCache:           seenCache,
		pending:             make(map[string]*pendingStart),
		verdictChan:         make(chan raceVerdict),
		ktimeToWall:         ktimeToWallClock,
		metaRetry:           defaultMetaRetry,
		raceEventCap:        10000,
	}
}

// SetSessionLoad tells the coordinator when the qBittorrent process started and
// how long its session load lasts: a torrent started within that window was
// restored. A zero processStart means no session load is known. Call before Run.
func (c *Coordinator) SetSessionLoad(processStart time.Time, window time.Duration) {
	if processStart.IsZero() {
		c.sessionLoadEnd = time.Time{}
		return
	}
	c.sessionLoadEnd = processStart.Add(window)
}

func (c *Coordinator) duringSessionLoad(startedAt time.Time) bool {
	return !c.sessionLoadEnd.IsZero() && startedAt.Before(c.sessionLoadEnd)
}

// QueryState returns a snapshot of the coordinator's internal state.
// Must only be called while Run() is active; blocks until Run processes the query.
func (c *Coordinator) QueryState() StateSnapshot {
	reply := make(chan StateSnapshot, 1)
	c.stateQueryChan <- stateQuery{reply: reply}
	return <-reply
}

func (c *Coordinator) snapshotState() StateSnapshot {
	snap := StateSnapshot{
		ActiveRaces:   make(map[string]RaceSnap, len(c.infoHashToRaceState)),
		ConnEndpoints: len(c.connEndpoints),
		TorrentPtrs:   len(c.torrentPtrs),
		ConnToRace:    len(c.connToRace),
	}
	for h, s := range c.infoHashToRaceState {
		snap.ActiveRaces[h] = RaceSnap{
			Hash:    s.hash,
			ChanLen: len(s.eventChan),
			RaceID:  s.raceID,
		}
	}
	return snap
}

// Run is the main event loop. The caller should cancel ctx (via
// context.WithCancelCause) when the target process dies; Run uses
// context.Cause to log the shutdown reason.
func (c *Coordinator) Run(ctx context.Context, events <-chan bpf.ProbeEvent) error {
	c.logger.Info("coordinator started, waiting for eBPF events",
		"sockaddr_offset", c.offsets.SockaddrOffset,
		"peer_id_offset", c.offsets.PeerIDOffset,
		"info_hash_offset", c.offsets.InfoHashOffset,
		"torrent_ptr_offset", c.offsets.TorrentPtrOffset)

	classifyCtx, stopClassify := context.WithCancel(ctx)
	defer stopClassify()
	c.classifyCtx = classifyCtx

	// A stop cancels ctx, and a store call it interrupts mid-write makes
	// database/sql drop the connection with its pragmas, so every store write
	// goes through dbCtx. ctx carries the stop cause and bounds the waits.
	dbCtx := context.WithoutCancel(ctx)

	for {
		select {
		case <-ctx.Done():
			cause := context.Cause(ctx)
			c.logger.Info("coordinator shutting down", "cause", cause)
			c.discardPending()
			c.writeStartErrorCounts(dbCtx)
			c.waitForTrackerCompletions()
			return cause

		case complete := <-c.completeChan:
			c.handleComplete(complete)

		case v := <-c.verdictChan:
			c.handleVerdict(dbCtx, v)

		case q := <-c.stateQueryChan:
			q.reply <- c.snapshotState()

		case ev, ok := <-events:
			if !ok {
				c.logger.Info("event channel closed")
				c.discardPending()
				c.writeStartErrorCounts(dbCtx)
				c.waitForTrackerCompletions()
				return nil
			}
			switch e := ev.(type) {
			case *bpf.WeHaveEvent:
				c.handleWeHave(dbCtx, e)
			case *bpf.IncomingHaveEvent:
				c.handleIncomingHave(e)
			case *bpf.TorrentFinishedEvent:
				c.handleTorrentFinished(dbCtx, e)
			case *bpf.TorrentStartedEvent:
				c.handleTorrentStarted(dbCtx, e)
			case *bpf.TorrentDetailsEvent:
				c.handleTorrentDetails(e)
			case *bpf.PeerDetailsEvent:
				c.handlePeerDetails(dbCtx, e)
			}
		}
	}
}

// discardPending drops the starts still awaiting a verdict, with their events.
func (c *Coordinator) discardPending() {
	if len(c.pending) == 0 {
		return
	}
	c.logger.Info("discarding starts still pending classification", "count", len(c.pending))
	c.pending = make(map[string]*pendingStart)
}

// msgUnidentifiedStart is logged when a torrent starts with an all-zero info hash.
const msgUnidentifiedStart = "torrent started with an all-zero info hash: recorded as a start error, not a race"

// unidentifiedStart is a torrent start whose info hash read as all zeros. Its
// events are counted, not stored.
type unidentifiedStart struct {
	id     int64 // its start_errors row; 0 when the insert failed
	events int
}

// handleTorrentStarted extracts the info_hash from a torrent::start() dump and
// makes the start pending, or a race at once when there is no API to classify it.
func (c *Coordinator) handleTorrentStarted(ctx context.Context, e *bpf.TorrentStartedEvent) {
	ptr := e.TorrentPtr

	// Skip duplicate start events for the same torrent_ptr
	if _, known := c.torrentPtrs[ptr]; known {
		return
	}
	if _, known := c.unidentified[ptr]; known {
		return
	}

	hashBytes, ok := ExtractInfoHash(e.Data, c.offsets.InfoHashOffset)
	if !ok {
		c.logger.Warn("torrent_started: failed to extract info_hash",
			"ptr", fmt.Sprintf("0x%x", ptr))
		return
	}
	if isZeroHash(hashBytes) {
		c.recordUnidentifiedStart(ctx, e)
		return
	}
	hash := hex.EncodeToString(hashBytes)
	if _, exists := c.infoHashToRaceState[hash]; exists {
		return
	}
	if _, exists := c.pending[hash]; exists {
		return
	}
	p := &pendingStart{
		hash:       hash,
		torrentPtr: ptr,
		startKtime: e.Timestamp,
		startedAt:  c.ktimeToWall(e.Timestamp),
	}
	if c.duringSessionLoad(p.startedAt) {
		c.logger.Debug("torrent restored during session load", "hash", hash, "torrent_ptr", fmt.Sprintf("0x%x", ptr))
		return
	}
	c.mapTorrentPtr(ptr, hash)
	if c.enrichAPI == nil {
		c.startRace(ctx, p, TorrentMeta{})
		return
	}
	c.pending[hash] = p
	c.logger.Debug("torrent started, classifying", "hash", hash, "torrent_ptr", fmt.Sprintf("0x%x", ptr))
	go c.classify(c.classifyCtx, hash, p.startedAt)
}

func isZeroHash(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// recordUnidentifiedStart records a start whose info hash is all zeros: an
// unknown failure, recorded with its struct dump and never made a race.
func (c *Coordinator) recordUnidentifiedStart(ctx context.Context, e *bpf.TorrentStartedEvent) {
	id, err := c.store.InsertStartError(ctx, e.TorrentPtr, c.ktimeToWall(e.Timestamp), e.Data[:])
	if err != nil {
		c.logger.Error("failed to record start error", "torrent_ptr", fmt.Sprintf("0x%x", e.TorrentPtr), "error", err)
	}
	c.logger.Error(msgUnidentifiedStart, "torrent_ptr", fmt.Sprintf("0x%x", e.TorrentPtr), "start_error_id", id)
	c.unidentified[e.TorrentPtr] = &unidentifiedStart{id: id}
}

// writeStartErrorCount records how many events an unidentified start has produced.
func (c *Coordinator) writeStartErrorCount(ctx context.Context, u *unidentifiedStart) {
	if u.id == 0 {
		return
	}
	if err := c.store.SetStartErrorEventCount(ctx, u.id, u.events); err != nil {
		c.logger.Error("failed to record start error event count", "start_error_id", u.id, "error", err)
	}
}

// writeStartErrorCounts records every unidentified start's event count.
func (c *Coordinator) writeStartErrorCounts(ctx context.Context) {
	for _, u := range c.unidentified {
		c.writeStartErrorCount(ctx, u)
	}
}

// handleTorrentDetails registers a torrent_ptr → info_hash mapping from
// a we_have torrent struct dump. This handles torrents that were already active
// before the daemon started (torrent_start already fired before we attached).
func (c *Coordinator) handleTorrentDetails(e *bpf.TorrentDetailsEvent) {
	ptr := e.TorrentPtr
	if _, known := c.torrentPtrs[ptr]; known {
		return
	}
	if _, ok := c.unidentified[ptr]; ok {
		return
	}

	hashBytes, ok := ExtractInfoHash(e.Data, c.offsets.InfoHashOffset)
	if !ok {
		return
	}
	hash := hex.EncodeToString(hashBytes)
	c.mapTorrentPtr(ptr, hash)
	c.logger.Debug("registered torrent_ptr from we_have dump",
		"ptr", fmt.Sprintf("0x%x", ptr), "hash", hash)
}

// handlePeerDetails extracts torrent_ptr, sockaddr_in, and peer_id from
// a peer_connection struct dump, then routes the connection to a race.
func (c *Coordinator) handlePeerDetails(ctx context.Context, e *bpf.PeerDetailsEvent) {
	// Extract torrent* to map this peer_connection to a race
	torrentPtr, ok := ExtractTorrentPtr(e.Data, c.offsets.TorrentPtrOffset)
	if !ok {
		return
	}

	hash, ok := c.torrentPtrs[torrentPtr]
	if !ok {
		// This peer_connection belongs to a torrent we're not tracking.
		// If connToRace has a stale mapping for this connPtr (from a previous
		// connection that reused this peer_connection* address), remove it.
		// Without cleanup, incoming_have events for the untracked torrent
		// would be misrouted to the old race via the stale mapping.
		if staleHash, stale := c.connToRace[e.ConnPtr]; stale {
			c.logger.Info("peer_connection* reused for untracked torrent, removing stale routing",
				"conn_ptr", fmt.Sprintf("0x%x", e.ConnPtr),
				"stale_hash", staleHash,
				"new_torrent_ptr", fmt.Sprintf("0x%x", torrentPtr))
			delete(c.connToRace, e.ConnPtr)
			delete(c.connEndpoints, e.ConnPtr)
		}
		return
	}

	c.connToRace[e.ConnPtr] = hash

	// Extract IP:port
	addr, hasAddr := ExtractEndpoint(e.Data, c.offsets.SockaddrOffset)
	if hasAddr {
		c.connEndpoints[e.ConnPtr] = addr
	}

	if p, ok := c.pending[hash]; ok {
		p.events = append(p.events, e)
		return
	}
	state, active := c.infoHashToRaceState[hash]
	if !active {
		return
	}
	c.recordPeer(ctx, state, e)
}

// recordPeer stores a peer_connection dump's endpoint and peer ID on its race's
// connection row.
func (c *Coordinator) recordPeer(ctx context.Context, state *raceState, e *bpf.PeerDetailsEvent) {
	hash := state.hash
	addr, hasAddr := ExtractEndpoint(e.Data, c.offsets.SockaddrOffset)
	peerID, hasPeerID := ExtractPeerID(e.Data, c.offsets.PeerIDOffset)
	client := ""
	if hasPeerID {
		client = DecodePeerClient(peerID)
	}

	connPtr := fmt.Sprintf("%x", e.ConnPtr)
	if hasAddr && hasPeerID {
		if err := c.store.UpdateConnectionPeerInfo(ctx, state.raceID, connPtr, addr.Addr().String(), int(addr.Port()), peerID, client); err != nil {
			c.logger.Debug("failed to update connection peer info", "error", err)
		}
	} else if hasAddr {
		if err := c.store.UpdateConnectionEndpoint(ctx, state.raceID, connPtr, addr.Addr().String(), int(addr.Port())); err != nil {
			c.logger.Debug("failed to update connection endpoint", "error", err)
		}
	}

	// Count connections for this race to log at INFO on first few discoveries
	raceConnCount := 0
	for _, h := range c.connToRace {
		if h == hash {
			raceConnCount++
		}
	}
	if raceConnCount <= 3 {
		c.logger.Info("peer discovered via struct dump",
			"hash", hash,
			"addr", addr.String(),
			"client", client,
			"race_connections", raceConnCount)
	} else {
		torrentPtr, _ := ExtractTorrentPtr(e.Data, c.offsets.TorrentPtrOffset)
		c.logger.Log(ctx, levelTrace, "mapped peer_conn → race",
			"peer_conn", fmt.Sprintf("0x%x", e.ConnPtr),
			"torrent", fmt.Sprintf("0x%x", torrentPtr),
			"hash", hash,
			"addr", addr.String(),
			"client", client)
	}
}

// classify asks the API whether a pending start's torrent was added at its
// start and sends the verdict to Run. Each pending start runs its own, so one
// the API can't answer delays no other.
func (c *Coordinator) classify(ctx context.Context, hash string, startedAt time.Time) {
	meta, err := c.fetchMeta(ctx, hash, time.Now().Add(c.metaRetry.budget))
	if ctx.Err() != nil {
		return
	}
	v := raceVerdict{hash: hash, meta: meta}
	if err != nil {
		c.logger.Warn(msgClassifyFailed, "hash", hash, "error", err)
	} else {
		v.restored = isRestored(meta.AddedAt, startedAt)
	}
	select {
	case c.verdictChan <- v:
	case <-ctx.Done():
	}
}

// fetchMeta asks the API until it gives an answer that can classify the torrent
// or deadline passes, backing off between attempts. On failure it returns the
// last answer with the error, since an answer without a date still carries
// name, size and piece count.
func (c *Coordinator) fetchMeta(ctx context.Context, hash string, deadline time.Time) (TorrentMeta, error) {
	backoff := c.metaRetry.initial
	for {
		meta, err := c.enrichAPI.FetchTorrentMeta(hash)
		if err == nil && meta.AddedAt.Unix() <= 0 {
			err = errNoAdditionDate
		}
		if err == nil {
			return meta, nil
		}

		wait := min(backoff, time.Until(deadline))
		if wait <= 0 {
			return meta, err
		}
		c.logger.Debug("metadata fetch failed, retrying", "hash", hash, "error", err, "wait", wait)
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		case <-time.After(wait):
		}
		backoff = min(backoff*2, c.metaRetry.max)
	}
}

// handleVerdict applies a pending start's classification: restored, it is
// discarded with its events; kept, it becomes a race.
func (c *Coordinator) handleVerdict(ctx context.Context, v raceVerdict) {
	p, ok := c.pending[v.hash]
	if !ok {
		return
	}
	delete(c.pending, v.hash)
	if v.restored {
		c.logger.Debug("torrent was restored, not a race", "hash", v.hash, "held_events", len(p.events))
		c.forgetTorrent(v.hash)
		return
	}
	c.startRace(ctx, p, v.meta)
}

// startRace makes a kept start a race: its rows, the dashboard notice, and its
// tracker, which records the start's held events before live ones.
func (c *Coordinator) startRace(ctx context.Context, p *pendingStart, meta TorrentMeta) {
	name := meta.Name
	if name == "" {
		name = p.hash
	}
	torrentID, err := c.store.CreateTorrent(ctx, p.hash, name, meta.Size, meta.PieceCount)
	if err != nil {
		c.logger.Error("failed to create torrent record", "hash", p.hash, "error", err)
		c.forgetTorrent(p.hash)
		return
	}
	raceID, err := c.store.CreateRace(ctx, torrentID, int64(p.startKtime), p.startedAt)
	if err != nil {
		c.logger.Error("failed to create race record", "hash", p.hash, "error", err)
		c.forgetTorrent(p.hash)
		return
	}
	c.logger.Info("race started", "hash", p.hash, "race_id", raceID,
		"torrent_ptr", fmt.Sprintf("0x%x", p.torrentPtr), "held_events", len(p.events))
	c.notifyDashboard(raceID)

	// The tracker outlives a stop: it closes its channel and waits for it to
	// write what it holds; cancel is for the race's own end. ctx is the
	// caller's store context, which a stop never cancels.
	raceCtx, cancel := context.WithCancel(ctx)
	state := &raceState{
		eventChan:          make(chan bpf.ProbeEvent, c.raceEventCap),
		hash:               p.hash,
		raceID:             raceID,
		downloadCompleteCh: make(chan struct{}),
		cancel:             cancel,
	}
	c.infoHashToRaceState[p.hash] = state

	var backlog []bpf.ProbeEvent
	for _, ev := range p.events {
		if peer, ok := ev.(*bpf.PeerDetailsEvent); ok {
			c.recordPeer(ctx, state, peer)
			continue
		}
		backlog = append(backlog, ev)
	}
	t := &raceTracker{
		store:      c.store,
		logger:     c.logger,
		hash:       p.hash,
		raceID:     raceID,
		startedAt:  p.startedAt,
		pieceCount: meta.PieceCount,
		backlog:    backlog,
		dropped:    &state.droppedEvents,
	}
	go func() {
		err := t.run(raceCtx, state.eventChan, state.downloadCompleteCh)
		c.completeChan <- raceComplete{hash: p.hash, err: err}
	}()
	if p.finished {
		close(state.downloadCompleteCh)
	}
}

// notifyDashboard sends a fire-and-forget POST to the dashboard SSE endpoint.
func (c *Coordinator) notifyDashboard(raceID int64) {
	if c.dashboardURL == "" {
		return
	}
	go func() {
		url := c.dashboardURL + "/api/notify"
		body := fmt.Sprintf(`{"race_id": %d}`, raceID)
		resp, err := http.Post(url, "application/json", strings.NewReader(body))
		if err != nil {
			c.logger.Debug("dashboard notify failed", "error", err)
			return
		}
		resp.Body.Close()
	}()
}

// handleWeHave processes a we_have event. TorrentPtr is the torrent* pointer.
func (c *Coordinator) handleWeHave(ctx context.Context, e *bpf.WeHaveEvent) {
	if u, ok := c.unidentified[e.TorrentPtr]; ok {
		u.events++
		return
	}
	if hash, ok := c.torrentPtrs[e.TorrentPtr]; ok {
		c.holdOrRoute(hash, e)
		return
	}

	c.logger.Log(ctx, levelTrace, "we_have: dropped (unmapped torrent_ptr)",
		"ptr", fmt.Sprintf("0x%x", e.TorrentPtr),
		"active_races", len(c.infoHashToRaceState))
}

// handleIncomingHave routes incoming_have events via exact routing only.
func (c *Coordinator) handleIncomingHave(e *bpf.IncomingHaveEvent) {
	if hash, ok := c.connToRace[e.ConnPtr]; ok && c.holdOrRoute(hash, e) {
		return
	}

	c.logger.Log(context.Background(), levelTrace, "incoming_have: dropped (unmapped peer_conn)",
		"ptr", fmt.Sprintf("0x%x", e.ConnPtr),
		"piece", e.PieceIndex)
}

// handleTorrentFinished signals download completion for a race.
func (c *Coordinator) handleTorrentFinished(ctx context.Context, e *bpf.TorrentFinishedEvent) {
	if u, ok := c.unidentified[e.TorrentPtr]; ok {
		c.writeStartErrorCount(ctx, u)
		return
	}
	hash, ok := c.torrentPtrs[e.TorrentPtr]
	if !ok {
		c.logger.Debug("torrent_finished for unmapped ptr",
			"ptr", fmt.Sprintf("0x%x", e.TorrentPtr))
		return
	}
	if p, ok := c.pending[hash]; ok {
		p.finished = true
		return
	}

	state, ok := c.infoHashToRaceState[hash]
	if !ok {
		c.logger.Debug("torrent_finished for inactive race", "hash", hash)
		return
	}

	c.logger.Info("torrent finished", "hash", hash)
	select {
	case <-state.downloadCompleteCh:
		// Already closed
	default:
		close(state.downloadCompleteCh)
	}
}

// mapTorrentPtr records a torrent_ptr → info_hash mapping.
func (c *Coordinator) mapTorrentPtr(ptr uint64, hash string) {
	c.torrentPtrs[ptr] = hash
	c.knownTorrentPtrs[ptr] = true
}

// handleComplete processes a race tracker completion signal.
func (c *Coordinator) handleComplete(complete raceComplete) {
	if state, exists := c.infoHashToRaceState[complete.hash]; exists {
		state.cancel()
		delete(c.infoHashToRaceState, complete.hash)
		if complete.err != nil && complete.err != context.Canceled {
			c.logger.Error("race tracking failed", "hash", complete.hash, "error", complete.err)
		}
		c.logger.Info("race tracking complete", "hash", complete.hash)
	}
	c.forgetTorrent(complete.hash)
}

// forgetTorrent removes hash's routing and its BPF dedup entries, so its peers
// and torrent can be rediscovered.
func (c *Coordinator) forgetTorrent(hash string) {
	// Collect torrent pointers for this race (needed for BPF cleanup)
	var raceTorrentPtrs []uint64
	for ptr, h := range c.torrentPtrs {
		if h == hash {
			raceTorrentPtrs = append(raceTorrentPtrs, ptr)
		}
	}

	// Clean up BPF seen_peers entries for connections in this race.
	// Reconstruct the BPF key from (torrent_ptr, endpoint) so the peer
	// can be rediscovered if it appears in a future race.
	if c.seenCache != nil && len(raceTorrentPtrs) > 0 {
		var forgetCount int
		for ptr, h := range c.connToRace {
			if h != hash {
				continue
			}
			endpoint, hasEndpoint := c.connEndpoints[ptr]
			if !hasEndpoint {
				continue
			}
			// Try each torrent pointer — normally there's only one per race
			for _, tPtr := range raceTorrentPtrs {
				if err := c.seenCache.ForgetPeer(tPtr, endpoint); err == nil {
					forgetCount++
				}
			}
		}

		// Clean up BPF seen_torrents entries
		for _, tPtr := range raceTorrentPtrs {
			if err := c.seenCache.ForgetTorrent(tPtr); err != nil {
				c.logger.Debug("failed to forget torrent in BPF map",
					"ptr", fmt.Sprintf("0x%x", tPtr), "error", err)
			}
		}

		if forgetCount > 0 {
			c.logger.Debug("cleaned up BPF dedup entries",
				"hash", hash,
				"peers_forgotten", forgetCount,
				"torrents_forgotten", len(raceTorrentPtrs))
		}
	}

	// Clean up torrentPtrs and knownTorrentPtrs for the completed race
	for _, ptr := range raceTorrentPtrs {
		delete(c.torrentPtrs, ptr)
		delete(c.knownTorrentPtrs, ptr)
	}

	// Clean up connToRace and connEndpoints for this race
	for ptr, h := range c.connToRace {
		if h == hash {
			delete(c.connToRace, ptr)
			delete(c.connEndpoints, ptr)
		}
	}
}

// holdOrRoute holds an event for hash's pending start or routes it to hash's
// race. It reports whether either exists.
func (c *Coordinator) holdOrRoute(hash string, ev bpf.ProbeEvent) bool {
	if p, ok := c.pending[hash]; ok {
		p.events = append(p.events, ev)
		return true
	}
	if state, ok := c.infoHashToRaceState[hash]; ok {
		c.routeEvent(state, ev)
		return true
	}
	return false
}

// routeEvent sends an event to an active race's channel. A full channel drops
// the event and counts it; the first drop is logged.
func (c *Coordinator) routeEvent(state *raceState, event bpf.ProbeEvent) {
	select {
	case state.eventChan <- event:
	default:
		if state.droppedEvents.Add(1) == 1 {
			c.logger.Warn(msgEventsDropped, "hash", state.hash, "race_id", state.raceID)
		}
	}
}

// waitForTrackerCompletions closes every race's channel and waits for each
// tracker to write the events it holds, finalize its race and report. It has
// no timeout of its own: systemd's stop timeout bounds a stop that hangs.
func (c *Coordinator) waitForTrackerCompletions() {
	states := c.infoHashToRaceState
	c.infoHashToRaceState = make(map[string]*raceState)
	for hash, state := range states {
		close(state.eventChan)
		c.logger.Debug("closed race tracker", "hash", hash)
	}
	for range states {
		complete := <-c.completeChan
		if complete.err != nil {
			c.logger.Error("race tracking failed", "hash", complete.hash, "error", complete.err)
		}
	}
	for _, state := range states {
		state.cancel()
	}
}

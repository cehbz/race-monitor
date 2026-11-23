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
	classified         bool // the restored-or-new verdict has arrived
	dropped            bool // restored: eventChan is closed, rows go once the tracker exits
}

// metaRequest asks the resolver goroutine to classify a race and fetch its
// torrent metadata asynchronously, delivering pieceCount to the tracker.
type metaRequest struct {
	hash      string
	raceID    int64
	startedAt time.Time  // wall clock of the torrent::start() event
	deadline  time.Time  // API retries stop here; set when the request is queued
	metaChan  chan<- int // one-shot: delivers pieceCount to tracker, then closed
}

// raceVerdict is the resolver's answer for one race. Run applies it, since only
// Run changes coordinator state.
type raceVerdict struct {
	hash     string
	raceID   int64
	restored bool
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
	// Classified reports that the restored-or-new verdict has reached Run.
	Classified bool
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

// retryPolicy bounds the resolver's API retries. The budget runs from when a
// request is queued, so an API that stays down costs a burst about one budget
// in total, and one that comes back serves the whole queue.
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
// Races are created when torrent::start() fires (EVT_TORRENT_STARTED)
// and completed when torrent::finished() fires (EVT_TORRENT_FINISHED).
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

	// metaReqChan feeds the metadata resolver goroutine from pendingMeta, the
	// queue of requests it hasn't taken yet.
	metaReqChan chan metaRequest
	pendingMeta []metaRequest

	// verdictChan carries the resolver's classifications back to Run.
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
		knownTorrentPtrs:    make(map[uint64]bool),
		connToRace:          make(map[uint64]string),
		connEndpoints:       make(map[uint64]netip.AddrPort),
		completeChan:        make(chan raceComplete, 10),
		stateQueryChan:      make(chan stateQuery),
		enrichAPI:           enrichAPI,
		seenCache:           seenCache,
		metaReqChan:         make(chan metaRequest),
		verdictChan:         make(chan raceVerdict),
		ktimeToWall:         ktimeToWallClock,
		metaRetry:           defaultMetaRetry,
		raceEventCap:        10000,
	}
}

// SetSessionLoad tells the coordinator when the qBittorrent process started and
// how long its session load lasts: a torrent started within that window was
// restored. A zero processStart means no session load is known.
func (c *Coordinator) SetSessionLoad(processStart time.Time, window time.Duration) {
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
			Hash:       s.hash,
			ChanLen:    len(s.eventChan),
			RaceID:     s.raceID,
			Classified: s.classified,
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

	// Launch async metadata resolver — classifies races and fetches torrent
	// name/size/pieceCount off the event loop, delivering pieceCount to trackers
	// via channel and verdicts back here.
	resolverCtx, stopResolver := context.WithCancel(ctx)
	defer stopResolver()
	go c.runMetaResolver(resolverCtx)

	for {
		// metaOut stays nil, and its case never fires, while the queue is empty.
		var metaOut chan<- metaRequest
		var nextMeta metaRequest
		if len(c.pendingMeta) > 0 {
			metaOut, nextMeta = c.metaReqChan, c.pendingMeta[0]
		}

		select {
		case <-ctx.Done():
			cause := context.Cause(ctx)
			c.logger.Info("coordinator shutting down", "cause", cause)
			if err := c.waitForTrackerCompletions(ctx); err != nil {
				return err
			}
			return cause

		case complete := <-c.completeChan:
			c.handleComplete(ctx, complete)

		case metaOut <- nextMeta:
			c.pendingMeta = c.pendingMeta[1:]

		case v := <-c.verdictChan:
			c.handleVerdict(ctx, v)

		case q := <-c.stateQueryChan:
			q.reply <- c.snapshotState()

		case ev, ok := <-events:
			if !ok {
				c.logger.Info("event channel closed")
				return c.waitForTrackerCompletions(ctx)
			}
			switch e := ev.(type) {
			case *bpf.WeHaveEvent:
				c.handleWeHave(ctx, e)
			case *bpf.IncomingHaveEvent:
				c.handleIncomingHave(e)
			case *bpf.TorrentFinishedEvent:
				c.handleTorrentFinished(e)
			case *bpf.TorrentStartedEvent:
				c.handleTorrentStarted(ctx, e)
			case *bpf.TorrentDetailsEvent:
				c.handleTorrentDetails(e)
			case *bpf.PeerDetailsEvent:
				c.handlePeerDetails(ctx, e)
			}
		}
	}
}

// handleTorrentStarted extracts the info_hash from a torrent::start() dump
// and creates a race.
func (c *Coordinator) handleTorrentStarted(ctx context.Context, e *bpf.TorrentStartedEvent) {
	ptr := e.TorrentPtr

	// Skip duplicate start events for the same torrent_ptr
	if _, known := c.torrentPtrs[ptr]; known {
		return
	}

	hashBytes, ok := ExtractInfoHash(e.Data, c.offsets.InfoHashOffset)
	if !ok {
		c.logger.Warn("torrent_started: failed to extract info_hash",
			"ptr", fmt.Sprintf("0x%x", ptr))
		return
	}
	hash := hex.EncodeToString(hashBytes)
	c.mapTorrentPtr(ptr, hash)
	c.startRace(ctx, hash, ptr, e.Timestamp)
}

// handleTorrentDetails registers a torrent_ptr → info_hash mapping from
// a we_have torrent struct dump. This handles torrents that were already active
// before the daemon started (torrent_start already fired before we attached).
func (c *Coordinator) handleTorrentDetails(e *bpf.TorrentDetailsEvent) {
	ptr := e.TorrentPtr
	if _, known := c.torrentPtrs[ptr]; known {
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

	// Extract peer_id and decode client
	peerID, hasPeerID := ExtractPeerID(e.Data, c.offsets.PeerIDOffset)
	client := ""
	if hasPeerID {
		client = DecodePeerClient(peerID)
	}

	// Update DB with connection endpoint and peer info
	state, active := c.infoHashToRaceState[hash]
	if !active || state.dropped {
		return
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
		c.logger.Log(ctx, levelTrace, "mapped peer_conn → race",
			"peer_conn", fmt.Sprintf("0x%x", e.ConnPtr),
			"torrent", fmt.Sprintf("0x%x", torrentPtr),
			"hash", hash,
			"addr", addr.String(),
			"client", client)
	}
}

// startRace creates a new race for the given info_hash and torrent_ptr.
// startKtime is the BPF ktime from the torrent::start() event (0 if unavailable).
// Idempotent: does nothing if a race already exists for this hash.
//
// The race is provisional until classified: the metadata resolver goroutine
// fetches metadata (name, size, pieceCount, addition date) asynchronously to keep
// the event loop fast, and handleVerdict drops the race if the torrent turns out
// to be restored rather than added while being watched. With no enrichment API,
// or an API that doesn't answer within its retry budget, the race is kept.
func (c *Coordinator) startRace(ctx context.Context, infoHash string, torrentPtr uint64, startKtime uint64) {
	if _, exists := c.infoHashToRaceState[infoHash]; exists {
		return
	}

	c.logger.Info("race started", "hash", infoHash, "torrent_ptr", fmt.Sprintf("0x%x", torrentPtr))

	// Ensure torrent_ptr mapping exists
	if _, ok := c.torrentPtrs[torrentPtr]; !ok {
		c.mapTorrentPtr(torrentPtr, infoHash)
	}

	// Create DB records immediately with placeholder metadata.
	// The async resolver will UPSERT real values once available.
	torrentID, err := c.store.CreateTorrent(ctx, infoHash, infoHash, 0, 0)
	if err != nil {
		c.logger.Error("failed to create torrent record", "hash", infoHash, "error", err)
		return
	}

	raceID, err := c.store.CreateRace(ctx, torrentID, int64(startKtime), time.Now())
	if err != nil {
		c.logger.Error("failed to create race record", "hash", infoHash, "error", err)
		return
	}

	c.notifyDashboard(raceID)

	downloadCompleteCh := make(chan struct{})
	metaChan := make(chan int, 1)
	raceCtx, cancel := context.WithCancel(ctx)
	state := &raceState{
		eventChan:          make(chan bpf.ProbeEvent, c.raceEventCap),
		hash:               infoHash,
		raceID:             raceID,
		downloadCompleteCh: downloadCompleteCh,
		cancel:             cancel,
	}
	c.infoHashToRaceState[infoHash] = state

	go func(hash string, raceID int64, metaCh <-chan int, eventChan <-chan bpf.ProbeEvent, completeCh <-chan struct{}) {
		err := processEvents(raceCtx, c.store, c.logger, hash, raceID, metaCh, eventChan, completeCh)
		c.completeChan <- raceComplete{hash: hash, err: err}
	}(infoHash, raceID, metaChan, state.eventChan, downloadCompleteCh)

	// Queue async classification and metadata resolution. Run feeds the queue
	// to the resolver as it frees up.
	c.pendingMeta = append(c.pendingMeta, metaRequest{
		hash:      infoHash,
		raceID:    raceID,
		startedAt: c.ktimeToWall(startKtime),
		deadline:  time.Now().Add(c.metaRetry.budget),
		metaChan:  metaChan,
	})
}

// runMetaResolver processes metadata requests off the event loop.
// Runs as a goroutine; exits when ctx is cancelled.
func (c *Coordinator) runMetaResolver(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-c.metaReqChan:
			c.resolveMetadata(ctx, req)
		}
	}
}

// resolveMetadata classifies a race from the API's answer. A restored torrent
// gets a drop verdict and no metadata update. Otherwise it updates the DB,
// delivers pieceCount to the tracker and sends a keep verdict.
func (c *Coordinator) resolveMetadata(ctx context.Context, req metaRequest) {
	defer close(req.metaChan)

	verdict := raceVerdict{hash: req.hash, raceID: req.raceID}
	if c.enrichAPI == nil {
		c.sendVerdict(ctx, verdict)
		return
	}

	meta, err := c.fetchMeta(ctx, req)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		c.logger.Warn(msgClassifyFailed, "hash", req.hash, "error", err)
	} else if isRestored(meta.AddedAt, req.startedAt) {
		verdict.restored = true
		c.sendVerdict(ctx, verdict)
		return
	}

	if meta != (TorrentMeta{}) {
		c.applyMeta(ctx, req, meta)
	}
	c.sendVerdict(ctx, verdict)
}

// fetchMeta asks the API until it gives an answer that can classify the torrent
// or req.deadline passes, backing off between attempts. On failure it returns
// the last answer with the error, since an answer without a date still carries
// name, size and piece count.
func (c *Coordinator) fetchMeta(ctx context.Context, req metaRequest) (TorrentMeta, error) {
	backoff := c.metaRetry.initial
	for {
		meta, err := c.enrichAPI.FetchTorrentMeta(req.hash)
		if err == nil && meta.AddedAt.Unix() <= 0 {
			err = errNoAdditionDate
		}
		if err == nil {
			return meta, nil
		}

		wait := min(backoff, time.Until(req.deadline))
		if wait <= 0 {
			return meta, err
		}
		c.logger.Debug("metadata fetch failed, retrying", "hash", req.hash, "error", err, "wait", wait)
		select {
		case <-ctx.Done():
			return meta, ctx.Err()
		case <-time.After(wait):
		}
		backoff = min(backoff*2, c.metaRetry.max)
	}
}

func (c *Coordinator) sendVerdict(ctx context.Context, v raceVerdict) {
	select {
	case c.verdictChan <- v:
	case <-ctx.Done():
	}
}

// applyMeta stores fetched metadata and delivers pieceCount to the tracker.
func (c *Coordinator) applyMeta(ctx context.Context, req metaRequest, meta TorrentMeta) {
	// UPSERT updates placeholder values in the DB.
	name := meta.Name
	if name == "" {
		name = req.hash
	}
	if _, err := c.store.CreateTorrent(ctx, req.hash, name, meta.Size, meta.PieceCount); err != nil {
		c.logger.Warn("failed to update torrent metadata", "hash", req.hash, "error", err)
	}

	// Deliver pieceCount to tracker for contamination detection.
	if meta.PieceCount > 0 {
		req.metaChan <- meta.PieceCount
	}
}

// handleVerdict applies the resolver's classification of a race. The tracker
// writes to the race's rows, so they can only go once it has exited: closing
// eventChan stops it, and handleComplete deletes the rows. A race whose tracker
// already finished is deleted here. The context stays uncancelled because
// cancelling it during a tracker transaction makes database/sql discard the
// store's single connection, and with it the per-connection PRAGMAs.
func (c *Coordinator) handleVerdict(ctx context.Context, v raceVerdict) {
	state, active := c.infoHashToRaceState[v.hash]
	active = active && state.raceID == v.raceID

	if !v.restored {
		if active {
			state.classified = true
		}
		return
	}

	c.logger.Info("dropping race: torrent was restored, not added", "hash", v.hash, "race_id", v.raceID)
	if !active {
		c.deleteDroppedRace(ctx, v.raceID)
		return
	}
	state.classified = true
	state.dropped = true
	close(state.eventChan)
}

// deleteDroppedRace removes a dropped race's rows and tells the dashboard, which
// reloads its race list on a notify.
func (c *Coordinator) deleteDroppedRace(ctx context.Context, raceID int64) {
	if err := c.store.DeleteRace(ctx, raceID); err != nil {
		c.logger.Error("failed to delete dropped race", "race_id", raceID, "error", err)
		return
	}
	c.notifyDashboard(raceID)
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
	if hash, ok := c.torrentPtrs[e.TorrentPtr]; ok {
		if state, ok := c.infoHashToRaceState[hash]; ok {
			c.routeEvent(state, e)
		}
		return
	}

	c.logger.Log(ctx, levelTrace, "we_have: dropped (unmapped torrent_ptr)",
		"ptr", fmt.Sprintf("0x%x", e.TorrentPtr),
		"active_races", len(c.infoHashToRaceState))
}

// handleIncomingHave routes incoming_have events via exact routing only.
func (c *Coordinator) handleIncomingHave(e *bpf.IncomingHaveEvent) {
	if hash, ok := c.connToRace[e.ConnPtr]; ok {
		if state, ok := c.infoHashToRaceState[hash]; ok {
			c.routeEvent(state, e)
			return
		}
	}

	c.logger.Log(context.Background(), levelTrace, "incoming_have: dropped (unmapped peer_conn)",
		"ptr", fmt.Sprintf("0x%x", e.ConnPtr),
		"piece", e.PieceIndex)
}

// handleTorrentFinished signals download completion for a race.
func (c *Coordinator) handleTorrentFinished(e *bpf.TorrentFinishedEvent) {
	hash, ok := c.torrentPtrs[e.TorrentPtr]
	if !ok {
		c.logger.Debug("torrent_finished for unmapped ptr",
			"ptr", fmt.Sprintf("0x%x", e.TorrentPtr))
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
func (c *Coordinator) handleComplete(ctx context.Context, complete raceComplete) {
	if state, exists := c.infoHashToRaceState[complete.hash]; exists {
		state.cancel()
		delete(c.infoHashToRaceState, complete.hash)
		if complete.err != nil && complete.err != context.Canceled {
			c.logger.Error("race tracking failed", "hash", complete.hash, "error", complete.err)
		}
		c.logger.Info("race tracking complete", "hash", complete.hash)
		if state.dropped {
			c.deleteDroppedRace(ctx, state.raceID)
		}
	}

	// Collect torrent pointers for this race (needed for BPF cleanup)
	var raceTorrentPtrs []uint64
	for ptr, h := range c.torrentPtrs {
		if h == complete.hash {
			raceTorrentPtrs = append(raceTorrentPtrs, ptr)
		}
	}

	// Clean up BPF seen_peers entries for connections in this race.
	// Reconstruct the BPF key from (torrent_ptr, endpoint) so the peer
	// can be rediscovered if it appears in a future race.
	if c.seenCache != nil && len(raceTorrentPtrs) > 0 {
		var forgetCount int
		for ptr, h := range c.connToRace {
			if h != complete.hash {
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
				"hash", complete.hash,
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
		if h == complete.hash {
			delete(c.connToRace, ptr)
			delete(c.connEndpoints, ptr)
		}
	}
}

// routeEvent sends an event to an active race's channel.
func (c *Coordinator) routeEvent(state *raceState, event bpf.ProbeEvent) {
	if state.dropped {
		return
	}
	select {
	case state.eventChan <- event:
	default:
		c.logger.Warn(msgEventsDropped, "hash", state.hash)
	}
}

// waitForTrackerCompletions closes all race channels, waits for processEvents to
// flush and exit (up to 500ms per race), then returns.
func (c *Coordinator) waitForTrackerCompletions(ctx context.Context) error {
	n := len(c.infoHashToRaceState)
	cancels := make([]context.CancelFunc, 0, n)
	for _, state := range c.infoHashToRaceState {
		cancels = append(cancels, state.cancel)
	}
	for hash, state := range c.infoHashToRaceState {
		if state.dropped {
			// Channel already closed. Delete on the way out, whatever the state of ctx.
			defer c.deleteDroppedRace(context.WithoutCancel(ctx), state.raceID)
			continue
		}
		close(state.eventChan)
		c.logger.Debug("closed race tracker", "hash", hash)
	}
	c.infoHashToRaceState = make(map[string]*raceState)

	for range n {
		select {
		case <-c.completeChan:
			continue
		case <-time.After(500 * time.Millisecond):
			for _, cancel := range cancels {
				cancel()
			}
			c.logger.Warn("shutdown timeout waiting for trackers, forcing exit")
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

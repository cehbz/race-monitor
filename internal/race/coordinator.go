package race

import (
	"context"
	"encoding/hex"
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
}

// metaRequest asks the resolver goroutine to fetch torrent metadata
// asynchronously and deliver pieceCount to the tracker.
type metaRequest struct {
	hash     string
	metaChan chan<- int // one-shot: delivers pieceCount to tracker, then closed
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
type TorrentMeta struct {
	Name       string
	Size       int64
	PieceCount int
}

// EnrichmentAPI provides torrent metadata from qBittorrent's web API.
// Used for name and piece_count enrichment only — not for calibration.
type EnrichmentAPI interface {
	// FetchTorrentMeta fetches per-torrent properties (piece_count, size).
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

	// metaReqChan feeds the metadata resolver goroutine.
	metaReqChan chan metaRequest

	// seenCache manages BPF dedup map entries. Nil when not available
	// (e.g., in tests). Used to clean up seen_peers and seen_torrents
	// entries when races complete, enabling rediscovery.
	seenCache SeenCache
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
	}
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

	// Launch async metadata resolver — fetches torrent name/size/pieceCount
	// off the event loop, delivering pieceCount to trackers via channel.
	c.metaReqChan = make(chan metaRequest, 16)
	go c.runMetaResolver(ctx)

	for {
		select {
		case <-ctx.Done():
			cause := context.Cause(ctx)
			c.logger.Info("coordinator shutting down", "cause", cause)
			if err := c.waitForTrackerCompletions(ctx); err != nil {
				return err
			}
			return cause

		case complete := <-c.completeChan:
			c.handleComplete(complete)

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
	if !active {
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
// Metadata (name, size, pieceCount) is resolved asynchronously by the
// metadata resolver goroutine to keep the event loop fast.
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

	raceID, err := c.store.CreateRace(ctx, torrentID, int64(startKtime))
	if err != nil {
		c.logger.Error("failed to create race record", "hash", infoHash, "error", err)
		return
	}

	c.notifyDashboard(raceID)

	downloadCompleteCh := make(chan struct{})
	metaChan := make(chan int, 1)
	raceCtx, cancel := context.WithCancel(ctx)
	state := &raceState{
		eventChan:          make(chan bpf.ProbeEvent, 10000),
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

	// Request async metadata resolution (non-blocking).
	select {
	case c.metaReqChan <- metaRequest{hash: infoHash, metaChan: metaChan}:
	default:
		c.logger.Warn("metadata resolver backlogged, skipping", "hash", infoHash)
		close(metaChan)
	}
}

// runMetaResolver processes metadata requests off the event loop.
// Runs as a goroutine; exits when ctx is cancelled or metaReqChan is closed.
func (c *Coordinator) runMetaResolver(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-c.metaReqChan:
			if !ok {
				return
			}
			c.resolveMetadata(ctx, req)
		}
	}
}

// resolveMetadata fetches torrent metadata from the API, updates the DB,
// and delivers pieceCount to the tracker.
func (c *Coordinator) resolveMetadata(ctx context.Context, req metaRequest) {
	defer close(req.metaChan)

	if c.enrichAPI == nil {
		return
	}

	meta, err := c.enrichAPI.FetchTorrentMeta(req.hash)
	if err != nil {
		c.logger.Warn("async metadata fetch failed", "hash", req.hash, "error", err)
		return
	}

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
func (c *Coordinator) handleComplete(complete raceComplete) {
	if state, exists := c.infoHashToRaceState[complete.hash]; exists {
		state.cancel()
		delete(c.infoHashToRaceState, complete.hash)
		if complete.err != nil && complete.err != context.Canceled {
			c.logger.Error("race tracking failed", "hash", complete.hash, "error", complete.err)
		}
		c.logger.Info("race tracking complete", "hash", complete.hash)
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
	select {
	case state.eventChan <- event:
	default:
		c.logger.Warn("race event channel full, dropping", "hash", state.hash)
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

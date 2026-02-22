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
	eventChan          chan bpf.Event
	hash               string
	pieceCount         int
	raceID             int64
	torrentName        string         // may equal hash if API lookup raced with torrent::start()
	downloadCompleteCh chan struct{}   // closed by coordinator when torrent::finished() fires
	cancel             context.CancelFunc
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
	Hash       string
	PieceCount int
	ChanLen    int
	RaceID     int64
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
	// Sync fetches maindata (uses stored rid). Returns metadata keyed by
	// hex info_hash for changed torrents.
	Sync() (torrents map[string]TorrentMeta, err error)

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

	// torrentMeta caches metadata (name, size, piece_count) from the API.
	torrentMeta map[string]TorrentMeta

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
		torrentMeta:         make(map[string]TorrentMeta),
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
			Hash:       s.hash,
			PieceCount: s.pieceCount,
			ChanLen:    len(s.eventChan),
			RaceID:     s.raceID,
		}
	}
	return snap
}

// Run is the main event loop.
func (c *Coordinator) Run(ctx context.Context, events <-chan bpf.Event, dumps <-chan bpf.DumpEvent, pidDeathCh <-chan error) error {
	c.logger.Info("coordinator started, waiting for eBPF events",
		"sockaddr_offset", c.offsets.SockaddrOffset,
		"peer_id_offset", c.offsets.PeerIDOffset,
		"info_hash_offset", c.offsets.InfoHashOffset,
		"torrent_ptr_offset", c.offsets.TorrentPtrOffset)

	// Prime metadata cache from API so torrent names are available when races start.
	if c.enrichAPI != nil {
		if torrents, err := c.enrichAPI.Sync(); err == nil {
			for h, meta := range torrents {
				c.torrentMeta[h] = meta
			}
			c.logger.Info("metadata cache primed from API", "torrents", len(torrents))
		} else {
			c.logger.Warn("failed to prime metadata cache", "error", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("coordinator shutting down")
			if err := c.waitForTrackerCompletions(ctx); err != nil {
				return err
			}
			return ctx.Err()

		case pidErr := <-pidDeathCh:
			c.logger.Info("PID died, finalizing all races", "error", pidErr)
			if err := c.waitForTrackerCompletions(ctx); err != nil {
				return err
			}
			return pidErr

		case complete := <-c.completeChan:
			c.handleComplete(complete)

		case q := <-c.stateQueryChan:
			q.reply <- c.snapshotState()

		case dump, ok := <-dumps:
			if ok {
				c.handleDump(ctx, dump)
			}

		case event, ok := <-events:
			if !ok {
				c.logger.Info("event channel closed")
				return c.waitForTrackerCompletions(ctx)
			}
			c.handleEvent(ctx, event)
		}
	}
}

// handleDump dispatches struct dump events by type.
// With pre-calibrated offsets, this is purely extraction and routing.
func (c *Coordinator) handleDump(ctx context.Context, dump bpf.DumpEvent) {
	switch dump.EventType {
	case bpf.EventTorrentStarted:
		c.handleTorrentStarted(ctx, dump)
	case bpf.EventTorrentDump:
		// Torrent struct dump from we_have (first encounter of each torrent*).
		// Register the torrent_ptr mapping so peer dumps can resolve it.
		c.handleTorrentDump(dump)
	case bpf.EventPeerDump:
		c.handlePeerDump(ctx, dump)
	}
}

// handleTorrentStarted extracts the info_hash from a torrent::start() dump
// and creates a race.
func (c *Coordinator) handleTorrentStarted(ctx context.Context, dump bpf.DumpEvent) {
	ptr := dump.ObjPtr

	// Skip duplicate start events for the same torrent_ptr
	if _, known := c.torrentPtrs[ptr]; known {
		return
	}

	hashBytes, ok := ExtractInfoHash(dump.Data, c.offsets.InfoHashOffset)
	if !ok {
		c.logger.Warn("torrent_started: failed to extract info_hash",
			"ptr", fmt.Sprintf("0x%x", ptr))
		return
	}
	hash := hex.EncodeToString(hashBytes)
	c.mapTorrentPtr(ptr, hash)
	c.startRace(ctx, hash, ptr, dump.Timestamp)
}

// handleTorrentDump registers a torrent_ptr → info_hash mapping from
// a we_have torrent struct dump. This handles torrents that were already active
// before the daemon started (torrent_start already fired before we attached).
func (c *Coordinator) handleTorrentDump(dump bpf.DumpEvent) {
	ptr := dump.ObjPtr
	if _, known := c.torrentPtrs[ptr]; known {
		return
	}

	hashBytes, ok := ExtractInfoHash(dump.Data, c.offsets.InfoHashOffset)
	if !ok {
		return
	}
	hash := hex.EncodeToString(hashBytes)
	c.mapTorrentPtr(ptr, hash)
	c.logger.Debug("registered torrent_ptr from we_have dump",
		"ptr", fmt.Sprintf("0x%x", ptr), "hash", hash)
}

// handlePeerDump extracts torrent_ptr, sockaddr_in, and peer_id from
// a peer_connection struct dump, then routes the connection to a race.
func (c *Coordinator) handlePeerDump(ctx context.Context, dump bpf.DumpEvent) {
	// Extract torrent* to map this peer_connection to a race
	torrentPtr, ok := ExtractTorrentPtr(dump.Data, c.offsets.TorrentPtrOffset)
	if !ok {
		return
	}

	hash, ok := c.torrentPtrs[torrentPtr]
	if !ok {
		// This peer_connection belongs to a torrent we're not tracking
		return
	}

	c.connToRace[dump.ObjPtr] = hash

	// Extract IP:port
	addr, hasAddr := ExtractEndpoint(dump.Data, c.offsets.SockaddrOffset)
	if hasAddr {
		c.connEndpoints[dump.ObjPtr] = addr
	}

	// Extract peer_id and decode client
	peerID, hasPeerID := ExtractPeerID(dump.Data, c.offsets.PeerIDOffset)
	client := ""
	if hasPeerID {
		client = DecodePeerClient(peerID)
	}

	// Update DB with connection endpoint and peer info
	state, active := c.infoHashToRaceState[hash]
	if !active {
		return
	}

	connPtr := fmt.Sprintf("%x", dump.ObjPtr)
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
			"peer_conn", fmt.Sprintf("0x%x", dump.ObjPtr),
			"torrent", fmt.Sprintf("0x%x", torrentPtr),
			"hash", hash,
			"addr", addr.String(),
			"client", client)
	}
}

// startRace creates a new race for the given info_hash and torrent_ptr.
// startKtime is the BPF ktime from the torrent::start() event (0 if unavailable).
// Idempotent: does nothing if a race already exists for this hash.
func (c *Coordinator) startRace(ctx context.Context, infoHash string, torrentPtr uint64, startKtime uint64) {
	if _, exists := c.infoHashToRaceState[infoHash]; exists {
		return
	}

	c.logger.Info("race started", "hash", infoHash, "torrent_ptr", fmt.Sprintf("0x%x", torrentPtr))

	// Ensure torrent_ptr mapping exists
	if _, ok := c.torrentPtrs[torrentPtr]; !ok {
		c.mapTorrentPtr(torrentPtr, infoHash)
	}

	// Enrich metadata from API cache and per-torrent properties.
	//
	// This lookup may fail for newly-added torrents due to a race condition
	// between libtorrent and qBittorrent's WebUI API. In libtorrent 1.2.x,
	// session_impl::add_torrent() calls torrent::start() (which fires our
	// eBPF probe) BEFORE posting the add_torrent_alert. qBittorrent only
	// inserts the torrent into m_torrents (visible to the sync API) after
	// the alert is dispatched via Qt::QueuedConnection to the main thread.
	// So there is a multi-millisecond window where torrent::start() has
	// fired but the torrent is not yet in the sync API response.
	//
	// When this happens, torrentName remains the raw info_hash. We record
	// it on raceState and retry at race completion — see handleComplete().
	torrentName := infoHash
	var torrentSize int64
	var pieceCount int
	if meta, ok := c.torrentMeta[infoHash]; ok {
		if meta.Name != "" {
			torrentName = meta.Name
		}
		torrentSize = meta.Size
		pieceCount = meta.PieceCount
	} else if c.enrichAPI != nil {
		// Cache miss — re-sync to pick up newly added torrents
		if torrents, err := c.enrichAPI.Sync(); err == nil {
			for h, meta := range torrents {
				c.torrentMeta[h] = meta
			}
			if meta, ok := c.torrentMeta[infoHash]; ok {
				if meta.Name != "" {
					torrentName = meta.Name
				}
				torrentSize = meta.Size
				pieceCount = meta.PieceCount
			}
		} else {
			c.logger.Warn("failed to re-sync metadata cache", "error", err)
		}
	}
	if c.enrichAPI != nil {
		if propsMeta, err := c.enrichAPI.FetchTorrentMeta(infoHash); err == nil {
			if propsMeta.Size > 0 {
				torrentSize = propsMeta.Size
			}
			if propsMeta.PieceCount > 0 {
				pieceCount = propsMeta.PieceCount
			}
		} else {
			c.logger.Debug("failed to fetch torrent properties", "hash", infoHash, "error", err)
		}
	}

	torrentID, err := c.store.CreateTorrent(ctx, infoHash, torrentName, torrentSize, pieceCount)
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
	raceCtx, cancel := context.WithCancel(ctx)
	state := &raceState{
		eventChan:          make(chan bpf.Event, 10000),
		hash:               infoHash,
		pieceCount:         pieceCount,
		raceID:             raceID,
		torrentName:        torrentName,
		downloadCompleteCh: downloadCompleteCh,
		cancel:             cancel,
	}
	c.infoHashToRaceState[infoHash] = state

	go func(hash string, raceID int64, eventChan <-chan bpf.Event, completeCh <-chan struct{}) {
		err := processEvents(raceCtx, c.store, c.logger, hash, raceID, eventChan, completeCh)
		c.completeChan <- raceComplete{hash: hash, err: err}
	}(infoHash, raceID, state.eventChan, downloadCompleteCh)
}

// retryTorrentName re-fetches metadata from the API and updates the torrent
// record if a name is now available. Called at race completion when the initial
// lookup at torrent::start() time failed due to the libtorrent/qBittorrent
// threading race (see comment in startRace).
func (c *Coordinator) retryTorrentName(infoHash string) {
	if torrents, err := c.enrichAPI.Sync(); err == nil {
		for h, meta := range torrents {
			c.torrentMeta[h] = meta
		}
	} else {
		c.logger.Warn("failed to re-sync metadata on completion", "error", err)
		return
	}

	meta, ok := c.torrentMeta[infoHash]
	if !ok || meta.Name == "" {
		c.logger.Warn("torrent name still unavailable at completion", "hash", infoHash)
		return
	}

	ctx := context.Background()
	if _, err := c.store.CreateTorrent(ctx, infoHash, meta.Name, meta.Size, meta.PieceCount); err != nil {
		c.logger.Error("failed to update torrent name", "hash", infoHash, "error", err)
		return
	}
	c.logger.Info("resolved torrent name at completion", "hash", infoHash, "name", meta.Name)
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

// handleEvent routes a single eBPF event.
func (c *Coordinator) handleEvent(ctx context.Context, event bpf.Event) {
	switch event.EventType {
	case bpf.EventWeHave:
		c.handleWeHave(ctx, event)
	case bpf.EventIncomingHave:
		c.handleIncomingHave(event)
	case bpf.EventTorrentFinished:
		c.handleTorrentFinished(event)
	}
}

// handleWeHave processes a we_have event. obj_ptr is the torrent* pointer.
func (c *Coordinator) handleWeHave(ctx context.Context, event bpf.Event) {
	if hash, ok := c.torrentPtrs[event.ObjPtr]; ok {
		if state, ok := c.infoHashToRaceState[hash]; ok {
			c.routeEvent(state, event)
		}
		return
	}

	c.logger.Log(ctx, levelTrace, "we_have: dropped (unmapped torrent_ptr)",
		"ptr", fmt.Sprintf("0x%x", event.ObjPtr),
		"active_races", len(c.infoHashToRaceState))
}

// handleIncomingHave routes incoming_have events via exact routing only.
func (c *Coordinator) handleIncomingHave(event bpf.Event) {
	if hash, ok := c.connToRace[event.ObjPtr]; ok {
		if state, ok := c.infoHashToRaceState[hash]; ok {
			c.routeEvent(state, event)
			return
		}
	}

	c.logger.Log(context.Background(), levelTrace, "incoming_have: dropped (unmapped peer_conn)",
		"ptr", fmt.Sprintf("0x%x", event.ObjPtr),
		"piece", event.PieceIndex)
}

// handleTorrentFinished signals download completion for a race.
func (c *Coordinator) handleTorrentFinished(event bpf.Event) {
	hash, ok := c.torrentPtrs[event.ObjPtr]
	if !ok {
		c.logger.Debug("torrent_finished for unmapped ptr",
			"ptr", fmt.Sprintf("0x%x", event.ObjPtr))
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
		// If the torrent name is still the raw info_hash, retry the API lookup.
		// This handles the race condition where torrent::start() fired before
		// qBittorrent registered the torrent in its WebUI API — by completion
		// time the torrent is guaranteed to be in the API.
		if state.torrentName == state.hash && c.enrichAPI != nil {
			c.retryTorrentName(state.hash)
		}

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
func (c *Coordinator) routeEvent(state *raceState, event bpf.Event) {
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

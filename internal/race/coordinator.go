package race

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/netip"
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
	downloadCompleteCh chan struct{} // closed by coordinator when torrent::finished() fires
	cancel             context.CancelFunc // for shutdown timeout
}

// StateSnapshot provides a point-in-time view of coordinator state.
// Used by tests to safely inspect state without data races via QueryState().
type StateSnapshot struct {
	ActiveRaces        map[string]RaceSnap
	Calibrated         bool
	FullyCalibrated    bool // both sockaddr_in and peer_id offsets discovered
	CalibrationOff     int  // sockaddr_in offset, -1 if uncalibrated
	PeerIDCalibOff     int  // peer_id offset, -1 if uncalibrated
	InfoHashCalibOff   int  // info_hash offset in torrent struct, -1 if uncalibrated
	TorrentPtrCalibOff int  // torrent* offset in peer_connection struct, -1 if uncalibrated
	ConnEndpoints      int  // count of resolved peer_connection* → IP:port mappings
}

// RaceSnap captures a race's metadata at a point in time.
type RaceSnap struct {
	Hash       string
	PieceCount int
	ChanLen    int
	RaceID     int64 // DB race ID, for tests to query persisted events
}

type stateQuery struct {
	reply chan StateSnapshot
}

// Coordinator manages race lifecycle using eBPF events from libtorrent uprobes.
//
// Design: Races are created when torrent::start() fires (EVT_TORRENT_STARTED)
// and completed when torrent::finished() fires (EVT_TORRENT_FINISHED).
// If the lifecycle probes are unavailable, races fall back to first-we_have
// creation and idle-timeout completion.
//
// we_have events carry obj_ptr = torrent* and are routed to per-torrent race
// trackers. incoming_have events carry obj_ptr = peer_connection* and are
// routed via calibration to specific races.
//
// After calibration, incoming_have events are routed exactly via peer_connection* →
// IP:port → race mapping. Before calibration, best-effort routing by piece_index range.
//
// Single-writer pattern: only Run() modifies state maps.
type Coordinator struct {
	store        *storage.Store
	logger       *slog.Logger
	dashboardURL string

	// infoHashToRaceState maps info_hash → raceState for active races.
	infoHashToRaceState map[string]*raceState

	// torrentPtrs maps torrent_ptr (from we_have obj_ptr) → info_hash for routing.
	torrentPtrs map[uint64]string

	completeChan   chan raceComplete
	stateQueryChan chan stateQuery

	// --- Calibration state ---

	// calibration tracks the auto-discovery of the sockaddr_in offset
	// within the peer_connection struct.
	calibration *calibrationState

	// connEndpoints maps peer_connection* → resolved IP:port.
	// Populated from calibration events after the offset is locked in.
	connEndpoints map[uint64]netip.AddrPort

	// connToRace maps peer_connection* → info_hash for exact incoming_have routing.
	// Populated by looking up connEndpoints against knownPeerAddrs.
	connToRace map[uint64]string

	// knownPeerAddrs maps IP:port → set of info_hashes. Built from eBPF events
	// and calibration, used for both calibration matching and exact routing.
	knownPeerAddrs map[netip.AddrPort]map[string]bool

	// knownPeerIDs maps IP:port → raw BT peer_id string from calibration.
	// Used for peer_id offset calibration (phase 2).
	knownPeerIDs map[netip.AddrPort]string

	// --- Torrent calibration state ---

	// torrentCalib tracks discovery of info_hash offset within torrent struct
	// and torrent* offset within peer_connection struct.
	torrentCalib *torrentCalibrationState

	// knownTorrentPtrs is the set of torrent* pointers seen from we_have events.
	// Used for torrent_ptr offset calibration in peer_connection dumps.
	knownTorrentPtrs map[uint64]bool

	// knownInfoHashes maps torrent_ptr → binary info_hash (20 bytes).
	// Built from torrent::start() dumps once info_hash offset is calibrated.
	knownInfoHashes map[uint64][]byte

	// infoHashBytes maps hex-encoded info_hash → binary SHA-1 bytes (20 bytes).
	// Populated by startRace when an info_hash is extracted from a torrent dump.
	infoHashBytes map[string][]byte

	// pendingStarts buffers EVT_TORRENT_STARTED events received before
	// info_hash calibration completes. Once calibration locks in, these are
	// reprocessed to extract hashes and create races retroactively.
	pendingStarts []bpf.CalibrationEvent

	// binaryHash is the SHA256 of the qBittorrent binary, used as the key
	// for the persistent calibration cache.
	binaryHash string

	// calibCachePath is the filesystem path to the calibration cache JSON file.
	calibCachePath string

	// torrentCalibAPI provides known info_hashes from qBittorrent's sync API.
	// When set, used for API-based info_hash offset calibration instead of
	// struct correlation. Nil when webui_url is not configured.
	torrentCalibAPI TorrentCalibrationAPI

	// knownHashesFromAPI accumulates hashes from Sync() calls for API-based
	// calibration. Sync returns only changed torrents, so we merge across calls.
	knownHashesFromAPI map[string]bool

	// torrentMeta caches metadata (name, size) from the calibration API.
	// Keyed by hex info_hash. Populated by Sync() calls, consumed by startRace.
	torrentMeta map[string]TorrentMeta
}

// TorrentMeta holds metadata for a torrent returned by the calibration API.
type TorrentMeta struct {
	Name       string
	Size       int64
	PieceCount int
}

// PeerInfo holds a peer's network address and BT peer_id string.
type PeerInfo struct {
	Addr   netip.AddrPort
	PeerID string
}

// TorrentCalibrationAPI provides known info_hashes and metadata from
// qBittorrent's sync API for torrent struct offset calibration and
// race enrichment (name, size, piece_count).
type TorrentCalibrationAPI interface {
	// Sync fetches maindata (uses stored rid). Returns metadata keyed by
	// hex info_hash for changed torrents. Caller does not need to track rid.
	Sync() (torrents map[string]TorrentMeta, err error)

	// FetchTorrentMeta fetches per-torrent properties (piece_count, size).
	// Name may be empty; caller should fall back to the Sync cache.
	FetchTorrentMeta(hash string) (TorrentMeta, error)

	// SyncPeers fetches the current peer list for a torrent.
	// Used to populate knownPeerAddrs for sockaddr_in calibration.
	SyncPeers(hash string) ([]PeerInfo, error)
}

// NewCoordinator creates a race coordinator.
//
// binaryHash is the SHA256 of the qBittorrent binary (for calibration cache).
// calibCachePath is the path to the calibration cache JSON file. Both may be
// empty to disable persistent caching (e.g. in tests).
// torrentCalibAPI is optional; when set, enables API-based info_hash calibration.
func NewCoordinator(
	store *storage.Store,
	logger *slog.Logger,
	dashboardURL string,
	binaryHash string,
	calibCachePath string,
	torrentCalibAPI TorrentCalibrationAPI,
) *Coordinator {
	calibration := newCalibrationState()
	torrentCalib := newTorrentCalibrationState()

	// Try to load cached calibration offsets
	if binaryHash != "" && calibCachePath != "" {
		if cache := LoadCalibrationCache(calibCachePath); cache != nil && cache.BinaryHash == binaryHash {
			calibration = newCalibratedState(cache.SockaddrOffset, cache.PeerIDOffset)
			if cache.InfoHashOffset != nil {
				torrentCalib.infoHashOffset = *cache.InfoHashOffset
			}
			if cache.TorrentPtrOffset != nil {
				torrentCalib.torrentPtrOffset = *cache.TorrentPtrOffset
			}
			logger.Info("loaded cached calibration",
				"sockaddr_offset", cache.SockaddrOffset,
				"peer_id_offset", cache.PeerIDOffset,
				"info_hash_offset", torrentCalib.infoHashOffset,
				"torrent_ptr_offset", torrentCalib.torrentPtrOffset,
				"binary_hash", binaryHash)
		}
	}

	return &Coordinator{
		store:                 store,
		logger:                logger,
		dashboardURL:          dashboardURL,
		infoHashToRaceState:   make(map[string]*raceState),
		torrentPtrs:           make(map[uint64]string),
		completeChan:          make(chan raceComplete, 10),
		stateQueryChan:        make(chan stateQuery),
		calibration:           calibration,
		connEndpoints:         make(map[uint64]netip.AddrPort),
		connToRace:            make(map[uint64]string),
		knownPeerAddrs:        make(map[netip.AddrPort]map[string]bool),
		knownPeerIDs:          make(map[netip.AddrPort]string),
		torrentCalib:          torrentCalib,
		knownTorrentPtrs:      make(map[uint64]bool),
		knownInfoHashes:       make(map[uint64][]byte),
		infoHashBytes:         make(map[string][]byte),
		binaryHash:            binaryHash,
		calibCachePath:        calibCachePath,
		torrentCalibAPI:       torrentCalibAPI,
		knownHashesFromAPI:    make(map[string]bool),
		torrentMeta:           make(map[string]TorrentMeta),
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
		ActiveRaces:        make(map[string]RaceSnap, len(c.infoHashToRaceState)),
		Calibrated:         c.calibration.isCalibrated(),
		FullyCalibrated:    c.calibration.isFullyCalibrated(),
		CalibrationOff:     c.calibration.offset,
		PeerIDCalibOff:     c.calibration.peerIDOffset,
		InfoHashCalibOff:   c.torrentCalib.infoHashOffset,
		TorrentPtrCalibOff: c.torrentCalib.torrentPtrOffset,
		ConnEndpoints:      len(c.connEndpoints),
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

// Run is the main event loop. Reads raw eBPF events, calibration events,
// and PID death signals. Race lifecycle is driven entirely by libtorrent uprobes:
// torrent::start() creates races, torrent::finished() signals completion.
func (c *Coordinator) Run(ctx context.Context, events <-chan bpf.Event, calibrations <-chan bpf.CalibrationEvent, pidDeathCh <-chan error) error {
	c.logger.Info("coordinator started, waiting for eBPF events")
	if !c.torrentCalib.isInfoHashCalibrated() {
		c.logger.Info("calibration requires 2+ torrents: nothing will be recorded until at least two downloads have been seen (primes the cache for future runs)")
	}

	// Prime metadata cache from API so torrent names are available when races start.
	if c.torrentCalibAPI != nil {
		if torrents, err := c.torrentCalibAPI.Sync(); err == nil {
			for h, meta := range torrents {
				c.knownHashesFromAPI[h] = true
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

		case cal, ok := <-calibrations:
			if ok {
				c.handleCalibration(ctx, cal)
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

// handleTorrentStarted processes an EVT_TORRENT_STARTED calibration event.
// If info_hash calibration is complete, extracts the hash and creates a race
// immediately. Otherwise, buffers the event and attempts multi-dump correlation.
func (c *Coordinator) handleTorrentStarted(ctx context.Context, cal bpf.CalibrationEvent) {
	ptr := cal.ObjPtr

	// Skip duplicate start events for the same torrent_ptr
	if _, known := c.torrentPtrs[ptr]; known {
		return
	}

	if c.torrentCalib.isInfoHashCalibrated() {
		// Fast path: extract hash and create race immediately
		hashBytes, ok := c.torrentCalib.extractInfoHash(cal.Data)
		if !ok {
			c.logger.Warn("torrent_started: failed to extract info_hash despite calibration",
				"ptr", fmt.Sprintf("0x%x", ptr))
			return
		}
		infoHash := hex.EncodeToString(hashBytes)
		c.registerTorrentMapping(ptr, hashBytes)
		c.startRace(ctx, infoHash, ptr)
		return
	}

	// Slow path: buffer for correlation-based calibration
	c.pendingStarts = append(c.pendingStarts, cal)
	c.tryTorrentCorrelation(ctx, cal)
}

// tryTorrentCorrelation adds a torrent struct dump to the correlation buffer
// and attempts to discover the info_hash offset. On success, reprocesses all
// buffered starts and pending peer dumps.
//
// When torrentCalibAPI is set, uses API-based calibration (sync/maindata hashes).
// Otherwise falls back to struct correlation (requires 2+ dumps, unique candidate).
func (c *Coordinator) tryTorrentCorrelation(ctx context.Context, cal bpf.CalibrationEvent) {
	c.torrentCalib.pendingTorrentDumps = append(c.torrentCalib.pendingTorrentDumps, cal)
	n := len(c.torrentCalib.pendingTorrentDumps)
	c.logger.Debug("torrent calibration: received dump",
		"ptr", fmt.Sprintf("0x%x", cal.ObjPtr),
		"pending_torrent_dumps", n)

	// Try API-based calibration first when available
	if c.torrentCalibAPI != nil {
		torrents, err := c.torrentCalibAPI.Sync()
		if err != nil {
			c.logger.Debug("torrent calibration: sync API failed, falling back to correlation",
				"error", err)
		} else {
			for h, meta := range torrents {
				c.knownHashesFromAPI[h] = true
				c.torrentMeta[h] = meta
			}
			c.logger.Debug("torrent calibration: sync/maindata",
				"this_call", len(torrents),
				"known_total", len(c.knownHashesFromAPI))
			knownList := make([]string, 0, len(c.knownHashesFromAPI))
			for h := range c.knownHashesFromAPI {
				knownList = append(knownList, h)
			}
			off, apiCandidates, apiOk := c.torrentCalib.tryCalibrateInfoHashFromAPI(c.torrentCalib.pendingTorrentDumps, knownList)
			if apiOk {
				c.torrentCalib.infoHashOffset = off
				c.logger.Info("torrent calibration: info_hash offset locked via API",
					"offset", off)
				c.finishTorrentCalibration(ctx)
				return
			}
			c.logger.Debug("torrent calibration: API calibration did not lock in",
				"dumps", len(c.torrentCalib.pendingTorrentDumps),
				"unique_ptrs", n,
				"known_hashes", len(c.knownHashesFromAPI),
				"api_candidates", apiCandidates)
		}
	}

	// Fallback: struct correlation (no API or API had no matches)
	ok, numCandidates := c.torrentCalib.tryCalibrateInfoHashByCorrelation(c.torrentCalib.pendingTorrentDumps)
	if !ok {
		if numCandidates > 0 {
			c.logger.Debug("torrent calibration: correlation inconclusive, waiting for more dumps",
				"candidates", numCandidates)
		}
		return
	}

	c.logger.Info("torrent calibration: info_hash offset locked via correlation",
		"offset", c.torrentCalib.infoHashOffset)
	c.finishTorrentCalibration(ctx)
}

// finishTorrentCalibration runs after info_hash offset is locked: save cache,
// extract hashes from dumps, create races, reprocess pending peer dumps.
func (c *Coordinator) finishTorrentCalibration(ctx context.Context) {
	c.saveTorrentCalibrationCache()

	// Extract hashes from all buffered torrent dumps and register mappings
	for _, d := range c.torrentCalib.pendingTorrentDumps {
		if hashBytes, ok := c.torrentCalib.extractInfoHash(d.Data); ok {
			c.registerTorrentMapping(d.ObjPtr, hashBytes)
		}
	}
	c.torrentCalib.pendingTorrentDumps = nil

	// Create races for all pending starts
	for _, d := range c.pendingStarts {
		if hashBytes, ok := c.torrentCalib.extractInfoHash(d.Data); ok {
			infoHash := hex.EncodeToString(hashBytes)
			c.startRace(ctx, infoHash, d.ObjPtr)
		}
	}
	c.pendingStarts = nil

	// Reprocess pending peer_connection dumps for torrent_ptr offset discovery
	c.reprocessPendingTorrentPtrCalibrations()
}

// startRace creates a new race for the given info_hash and torrent_ptr.
// Idempotent: does nothing if a race already exists for this hash.
func (c *Coordinator) startRace(ctx context.Context, infoHash string, torrentPtr uint64) {
	if _, exists := c.infoHashToRaceState[infoHash]; exists {
		return
	}

	c.logger.Info("race started", "hash", infoHash, "torrent_ptr", fmt.Sprintf("0x%x", torrentPtr))

	// Store binary hash bytes for future calibration matching
	if hashBytes, err := hex.DecodeString(infoHash); err == nil && len(hashBytes) == infoHashSize {
		c.infoHashBytes[infoHash] = hashBytes
	}

	// Ensure torrent_ptr mapping exists
	if _, ok := c.torrentPtrs[torrentPtr]; !ok {
		c.mapTorrentPtr(torrentPtr, infoHash)
	}

	// Enrich metadata: fetch per-torrent properties for piece_count + size,
	// then merge with Sync cache (which has the name).
	torrentName := infoHash
	var torrentSize int64
	var pieceCount int
	if meta, ok := c.torrentMeta[infoHash]; ok {
		if meta.Name != "" {
			torrentName = meta.Name
		}
		torrentSize = meta.Size
		pieceCount = meta.PieceCount
	}
	if c.torrentCalibAPI != nil {
		if propsMeta, err := c.torrentCalibAPI.FetchTorrentMeta(infoHash); err == nil {
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

	raceID, err := c.store.CreateRace(ctx, torrentID)
	if err != nil {
		c.logger.Error("failed to create race record", "hash", infoHash, "error", err)
		return
	}

	downloadCompleteCh := make(chan struct{})
	raceCtx, cancel := context.WithCancel(ctx)
	state := &raceState{
		eventChan:          make(chan bpf.Event, 10000),
		hash:               infoHash,
		pieceCount:         pieceCount,
		raceID:             raceID,
		downloadCompleteCh: downloadCompleteCh,
		cancel:             cancel,
	}
	c.infoHashToRaceState[infoHash] = state

	go func(hash string, raceID int64, eventChan <-chan bpf.Event, completeCh <-chan struct{}) {
		err := processEvents(raceCtx, c.store, c.logger, hash, raceID, eventChan, completeCh)
		c.completeChan <- raceComplete{hash: hash, err: err}
	}(infoHash, raceID, state.eventChan, downloadCompleteCh)

	// Poll peers from API for sockaddr_in calibration bootstrap.
	// This populates knownPeerAddrs which enables the sockaddr_in
	// calibration path as an alternative to torrent_ptr routing.
	c.pollPeersForCalibration(infoHash)
}

// handleTorrentFinished processes an EVT_TORRENT_FINISHED event.
// Looks up torrent_ptr → info_hash → race and signals download completion.
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
// Routes via exact torrent_ptr mapping only. The mapping is established by
// startRace (from torrent::start() calibration), so we_have events for the
// active race's torrent always have a known pointer. Unknown pointers belong
// to other torrents and are dropped.
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

// mapTorrentPtr records a new torrent_ptr → info_hash mapping and updates
// the calibration-related data structures for torrent struct calibration.
func (c *Coordinator) mapTorrentPtr(ptr uint64, hash string) {
	c.torrentPtrs[ptr] = hash
	c.knownTorrentPtrs[ptr] = true

	// Copy pre-decoded binary info_hash bytes for torrent calibration matching.
	if hashBytes, ok := c.infoHashBytes[hash]; ok {
		c.knownInfoHashes[ptr] = hashBytes
	}

	// If we just learned a new torrent_ptr and have pending peer_connection
	// dumps, attempt torrent_ptr offset calibration.
	if !c.torrentCalib.isTorrentPtrCalibrated() && len(c.torrentCalib.pendingPeerDumps) > 0 {
		c.reprocessPendingTorrentPtrCalibrations()
	}
}

// handleIncomingHave routes incoming_have events via exact routing only.
// peer_connection* must be mapped to a race via connToRace (populated by
// torrent_ptr calibration). Unmapped connections are dropped — qBittorrent
// may have hundreds of active torrents whose peers would pollute race data.
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

	// Clean up torrentPtrs, knownTorrentPtrs, and knownInfoHashes
	// for the completed race to avoid stale mappings.
	for ptr, h := range c.torrentPtrs {
		if h == complete.hash {
			delete(c.torrentPtrs, ptr)
			delete(c.knownTorrentPtrs, ptr)
			delete(c.knownInfoHashes, ptr)
		}
	}
	delete(c.infoHashBytes, complete.hash)

	// Clean up connToRace entries for this race
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

// handleCalibration dispatches calibration events by type.
func (c *Coordinator) handleCalibration(ctx context.Context, cal bpf.CalibrationEvent) {
	switch cal.EventType {
	case bpf.EventTorrentStarted:
		c.handleTorrentStarted(ctx, cal)
	case bpf.EventTorrentCalibration:
		c.handleTorrentCalibration(ctx, cal)
	case bpf.EventCalibration:
		c.handlePeerCalibration(ctx, cal)
	}
}

// handleTorrentCalibration processes a torrent struct dump from we_have
// (fallback path when torrent::start() probe is unavailable). Uses the same
// multi-dump correlation as handleTorrentStarted for info_hash offset discovery.
func (c *Coordinator) handleTorrentCalibration(ctx context.Context, cal bpf.CalibrationEvent) {
	if c.torrentCalib.isInfoHashCalibrated() {
		// Already calibrated — extract info_hash from this torrent dump
		hashBytes, ok := c.torrentCalib.extractInfoHash(cal.Data)
		if ok {
			c.registerTorrentMapping(cal.ObjPtr, hashBytes)
		}
		return
	}

	// Buffer for correlation and attempt calibration
	c.tryTorrentCorrelation(ctx, cal)
}

// registerTorrentMapping maps a torrent_ptr to the given binary info_hash bytes,
// updating all relevant data structures (torrentPtrs, knownTorrentPtrs, knownInfoHashes).
func (c *Coordinator) registerTorrentMapping(ptr uint64, hashBytes []byte) {
	infoHash := hex.EncodeToString(hashBytes)
	c.knownInfoHashes[ptr] = hashBytes
	if _, exists := c.torrentPtrs[ptr]; !exists {
		c.mapTorrentPtr(ptr, infoHash)
		c.logger.Debug("mapped torrent_ptr via calibrated info_hash",
			"ptr", fmt.Sprintf("0x%x", ptr), "hash", infoHash)
	}
}

// reprocessPendingTorrentPtrCalibrations attempts to discover the torrent*
// offset in peer_connection dumps now that we have known torrent pointers.
func (c *Coordinator) reprocessPendingTorrentPtrCalibrations() {
	if c.torrentCalib.isTorrentPtrCalibrated() {
		// Already calibrated — extract torrent_ptr from each pending dump
		for _, pending := range c.torrentCalib.pendingPeerDumps {
			c.resolvePeerConnTorrent(pending)
		}
		c.torrentCalib.pendingPeerDumps = nil
		return
	}

	for _, pending := range c.torrentCalib.pendingPeerDumps {
		if c.torrentCalib.tryCalibrateTorrentPtr(pending, c.knownTorrentPtrs) {
			c.logger.Info("torrent calibration: torrent_ptr offset locked",
				"offset", c.torrentCalib.torrentPtrOffset)
			// Extract from all pending
			for _, p := range c.torrentCalib.pendingPeerDumps {
				c.resolvePeerConnTorrent(p)
			}
			c.torrentCalib.pendingPeerDumps = nil
			return
		}
	}
}

// resolvePeerConnTorrent extracts the torrent* from a peer_connection dump
// and maps peer_connection → torrent → info_hash → race.
func (c *Coordinator) resolvePeerConnTorrent(cal bpf.CalibrationEvent) {
	torrentPtr, ok := c.torrentCalib.extractTorrentPtr(cal.Data)
	if !ok {
		return
	}

	if hash, ok := c.torrentPtrs[torrentPtr]; ok {
		c.connToRace[cal.ObjPtr] = hash
		c.logger.Debug("mapped peer_conn → race via torrent_ptr",
			"peer_conn", fmt.Sprintf("0x%x", cal.ObjPtr),
			"torrent", fmt.Sprintf("0x%x", torrentPtr),
			"hash", hash)
	}
}

// attemptTorrentPtrCalibration tries to discover the torrent* offset in a
// peer_connection dump, or buffers the dump for later if we don't have
// enough known torrent pointers yet.
func (c *Coordinator) attemptTorrentPtrCalibration(cal bpf.CalibrationEvent) {
	if c.torrentCalib.isTorrentPtrCalibrated() {
		// Already calibrated — extract and resolve directly.
		c.resolvePeerConnTorrent(cal)
		return
	}

	if len(c.knownTorrentPtrs) == 0 {
		// No known torrent pointers yet — buffer for later.
		c.torrentCalib.pendingPeerDumps = append(c.torrentCalib.pendingPeerDumps, cal)
		return
	}

	if c.torrentCalib.tryCalibrateTorrentPtr(cal, c.knownTorrentPtrs) {
		c.logger.Info("torrent calibration: torrent_ptr offset locked",
			"offset", c.torrentCalib.torrentPtrOffset)
		// Extract from this event
		c.resolvePeerConnTorrent(cal)
		// Reprocess all pending peer dumps
		for _, p := range c.torrentCalib.pendingPeerDumps {
			c.resolvePeerConnTorrent(p)
		}
		c.torrentCalib.pendingPeerDumps = nil
		c.saveTorrentCalibrationCache()
	} else {
		c.torrentCalib.pendingPeerDumps = append(c.torrentCalib.pendingPeerDumps, cal)
	}
}

// handlePeerCalibration processes a peer_connection calibration event.
// Handles sockaddr_in and peer_id offset discovery, and also attempts
// torrent_ptr offset discovery to enable exact incoming_have routing.
//
// Without API peer polling, sockaddr_in calibration works only if:
// - Cached calibration exists (loaded on startup), OR
// - Peers are discovered via torrent calibration → info_hash → known addrs.
func (c *Coordinator) handlePeerCalibration(ctx context.Context, cal bpf.CalibrationEvent) {
	// Always attempt torrent_ptr offset calibration on peer_connection dumps.
	// This runs independently of sockaddr_in calibration.
	c.attemptTorrentPtrCalibration(cal)

	if c.calibration.isFullyCalibrated() {
		// Fully calibrated — extract endpoint + peer_id, resolve to race
		c.extractAndResolve(ctx, cal)
		return
	}

	if c.calibration.isCalibrated() && !c.calibration.isFullyCalibrated() {
		// sockaddr_in calibrated but peer_id not yet — extract endpoint
		// (writes ip/port to DB) and try peer_id calibration.
		c.extractAndResolve(ctx, cal)

		if c.calibration.tryCalibratePeerID(cal, c.knownPeerIDs) {
			c.logger.Info("calibration: peer_id offset locked",
				"offset", c.calibration.peerIDOffset,
				"votes", c.calibration.peerIDVotes[c.calibration.peerIDOffset])
			c.onFullCalibration(ctx)
			// Reprocess pending for peer_id extraction
			c.reprocessPendingCalibrations(ctx)
		} else {
			// Buffer for peer_id calibration rescan
			c.calibration.pending = append(c.calibration.pending, cal)
		}
		return
	}

	// Not yet sockaddr_in calibrated — build known peer set and try
	knownPeers := make(map[netip.AddrPort]bool, len(c.knownPeerAddrs))
	for addr := range c.knownPeerAddrs {
		knownPeers[addr] = true
	}

	if len(knownPeers) == 0 {
		c.calibration.pending = append(c.calibration.pending, cal)
		c.logger.Debug("calibration: buffered (no known peers yet)",
			"ptr", fmt.Sprintf("0x%x", cal.ObjPtr),
			"pending", len(c.calibration.pending))
		return
	}

	if c.calibration.tryCalibrate(cal, knownPeers) {
		c.logger.Info("calibration: sockaddr_in offset locked",
			"offset", c.calibration.offset,
			"votes", c.calibration.votes[c.calibration.offset])

		// Extract endpoint from this event and write to DB
		c.extractAndResolve(ctx, cal)

		// Try peer_id calibration immediately (may succeed if we have peer_id data)
		if c.calibration.tryCalibratePeerID(cal, c.knownPeerIDs) {
			c.logger.Info("calibration: peer_id offset locked",
				"offset", c.calibration.peerIDOffset,
				"votes", c.calibration.peerIDVotes[c.calibration.peerIDOffset])
			c.onFullCalibration(ctx)
		} else {
			// Buffer this event for later peer_id extraction
			c.calibration.pending = append(c.calibration.pending, cal)
		}

		// Reprocess pending calibration events
		c.reprocessPendingCalibrations(ctx)
	} else {
		c.calibration.pending = append(c.calibration.pending, cal)
	}
}

// extractAndResolve extracts IP:port and peer_id from a calibration event
// after calibration, and resolves the connection to a race.
//
// Always updates the connection endpoint in the DB when the endpoint is
// extractable. Peer_id/client are added when peer_id calibration is complete.
func (c *Coordinator) extractAndResolve(ctx context.Context, cal bpf.CalibrationEvent) {
	addr, ok := c.calibration.extractEndpoint(cal.Data)
	if !ok {
		return
	}
	c.connEndpoints[cal.ObjPtr] = addr
	c.resolveConnToRace(cal.ObjPtr, addr)

	connPtr := fmt.Sprintf("%x", cal.ObjPtr)
	ip := addr.Addr().String()
	port := int(addr.Port())

	// Extract peer_id and decode client (requires full calibration)
	peerID, hasPeerID := c.calibration.extractPeerID(cal.Data)
	client := ""
	if hasPeerID {
		client = decodePeerClient(peerID)
	}

	// Get the raceID for this connection from connToRace
	var raceID int64
	if hash, ok := c.connToRace[cal.ObjPtr]; ok {
		if state, ok := c.infoHashToRaceState[hash]; ok {
			raceID = state.raceID
		}
	}

	// Always update the connection record with at least the endpoint.
	// When peer_id is available, include it; otherwise just set ip/port.
	if hasPeerID {
		if err := c.store.UpdateConnectionPeerInfo(ctx, raceID, connPtr, ip, port, peerID, client); err != nil {
			c.logger.Debug("failed to update connection peer info", "error", err)
		}
	} else {
		if err := c.store.UpdateConnectionEndpoint(ctx, raceID, connPtr, ip, port); err != nil {
			c.logger.Debug("failed to update connection endpoint", "error", err)
		}
	}

	c.logger.Debug("calibration: resolved connection",
		"ptr", fmt.Sprintf("0x%x", cal.ObjPtr),
		"addr", addr.String(),
		"client", client,
		"has_peer_id", hasPeerID)
}

// onFullCalibration is called when both sockaddr_in and peer_id offsets have
// been discovered. Persists the calibration cache.
func (c *Coordinator) onFullCalibration(ctx context.Context) {
	c.logger.Info("calibration: fully calibrated",
		"sockaddr_offset", c.calibration.offset,
		"peer_id_offset", c.calibration.peerIDOffset)

	c.saveCalibrationCache()
}

// saveCalibrationCache persists all known calibration offsets to disk.
func (c *Coordinator) saveCalibrationCache() {
	if c.binaryHash == "" || c.calibCachePath == "" {
		return
	}
	err := SaveCalibrationCache(
		c.calibCachePath,
		c.binaryHash,
		c.calibration.offset,
		c.calibration.peerIDOffset,
		c.torrentCalib.infoHashOffset,
		c.torrentCalib.torrentPtrOffset,
	)
	if err != nil {
		c.logger.Warn("failed to save calibration cache", "error", err)
	} else {
		c.logger.Info("calibration: cache saved", "path", c.calibCachePath)
	}
}

// saveTorrentCalibrationCache is called when a torrent calibration offset
// is locked. Re-saves the full cache including any previously locked peer
// calibration offsets.
func (c *Coordinator) saveTorrentCalibrationCache() {
	c.saveCalibrationCache()
}


// pollPeersForCalibration fetches the current peer list from the qBittorrent API
// and populates knownPeerAddrs and knownPeerIDs. This bootstraps sockaddr_in
// calibration by providing ground-truth IP:port → info_hash mappings.
//
// Called from startRace when a new race begins. The peer data enables two things:
// 1. sockaddr_in offset discovery (matching dump bytes against known IP:port)
// 2. peer_id offset discovery (matching dump bytes against known peer_id)
//
// After populating, reprocesses any buffered peer_connection calibration dumps.
func (c *Coordinator) pollPeersForCalibration(infoHash string) {
	if c.torrentCalibAPI == nil {
		return
	}

	peers, err := c.torrentCalibAPI.SyncPeers(infoHash)
	if err != nil {
		c.logger.Debug("peer polling failed", "hash", infoHash, "error", err)
		return
	}

	newAddrs := 0
	for _, peer := range peers {
		if _, exists := c.knownPeerAddrs[peer.Addr]; !exists {
			c.knownPeerAddrs[peer.Addr] = make(map[string]bool)
		}
		if !c.knownPeerAddrs[peer.Addr][infoHash] {
			c.knownPeerAddrs[peer.Addr][infoHash] = true
			newAddrs++
		}
		if peer.PeerID != "" {
			c.knownPeerIDs[peer.Addr] = peer.PeerID
		}
	}

	c.logger.Info("peer polling for calibration",
		"hash", infoHash,
		"peers", len(peers),
		"new_addrs", newAddrs,
		"total_known", len(c.knownPeerAddrs))

	// Reprocess buffered calibration events now that we have known peers
	if newAddrs > 0 && len(c.calibration.pending) > 0 {
		c.reprocessPendingForSockaddr()
	}
}

// reprocessPendingForSockaddr retries sockaddr_in calibration against
// buffered peer_connection dumps now that knownPeerAddrs has been populated.
func (c *Coordinator) reprocessPendingForSockaddr() {
	if c.calibration.isCalibrated() {
		return // Already calibrated
	}

	knownPeers := make(map[netip.AddrPort]bool, len(c.knownPeerAddrs))
	for addr := range c.knownPeerAddrs {
		knownPeers[addr] = true
	}
	if len(knownPeers) == 0 {
		return
	}

	c.logger.Debug("reprocessing pending calibrations with known peers",
		"pending", len(c.calibration.pending),
		"known_peers", len(knownPeers))

	pending := c.calibration.pending
	c.calibration.pending = nil

	for _, cal := range pending {
		if c.calibration.isCalibrated() {
			// Sockaddr_in just locked — switch to full extraction path
			c.calibration.pending = append(c.calibration.pending, cal)
			continue
		}
		if c.calibration.tryCalibrate(cal, knownPeers) {
			c.logger.Info("calibration: sockaddr_in offset locked (from peer poll)",
				"offset", c.calibration.offset,
				"votes", c.calibration.votes[c.calibration.offset])
			// Buffer remaining for extractAndResolve
			c.calibration.pending = append(c.calibration.pending, cal)
		} else {
			c.calibration.pending = append(c.calibration.pending, cal)
		}
	}

	// If we just locked sockaddr_in, reprocess all pending for endpoint extraction
	if c.calibration.isCalibrated() {
		c.reprocessPendingCalibrations(context.Background())
	}
}

// reprocessPendingCalibrations extracts endpoints (and optionally peer_id)
// from buffered calibration events after offsets have been locked in.
//
// Pending events are only cleared when fully calibrated. During partial
// calibration (sockaddr_in only), events are kept so they can be
// reprocessed through the full path once peer_id calibration completes.
func (c *Coordinator) reprocessPendingCalibrations(ctx context.Context) {
	pending := c.calibration.pending

	if c.calibration.isFullyCalibrated() {
		// Clear: all events will get the full extractAndResolve treatment.
		c.calibration.pending = nil
	}
	// else: keep pending for reprocessing once peer_id calibration completes.

	for _, cal := range pending {
		// extractAndResolve handles both partial (ip/port only) and full
		// (ip/port/peer_id/client) calibration, always writing to the DB.
		c.extractAndResolve(ctx, cal)

		// During partial calibration, also try peer_id offset discovery.
		if c.calibration.isCalibrated() && !c.calibration.isFullyCalibrated() {
			c.calibration.tryCalibratePeerID(cal, c.knownPeerIDs)
		}
	}

	c.logger.Debug("calibration: reprocessed pending events",
		"count", len(pending),
		"fully_calibrated", c.calibration.isFullyCalibrated(),
		"resolved", len(c.connEndpoints))
}

// resolveConnToRace maps a peer_connection* to its owning race by looking up
// the resolved IP:port in the known peer address map. This only handles
// in-memory routing; DB updates are handled by extractAndResolve.
func (c *Coordinator) resolveConnToRace(ptr uint64, addr netip.AddrPort) {
	races, ok := c.knownPeerAddrs[addr]
	if !ok || len(races) == 0 {
		return
	}

	// If the peer belongs to exactly one active race, map directly.
	// If multiple races share this peer, pick the first active one.
	for hash := range races {
		if _, active := c.infoHashToRaceState[hash]; active {
			c.connToRace[ptr] = hash
			return
		}
	}
}

// waitForTrackerCompletions closes all race channels, waits for processEvents to
// flush and exit (up to 500ms per race), then returns. On timeout, cancels
// remaining trackers and returns nil.
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

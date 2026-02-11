package race

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	qbt "github.com/cehbz/qbittorrent"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// QBittorrentClient defines the interface for interacting with qBittorrent.
type QBittorrentClient interface {
	TorrentsPropertiesCtx(ctx context.Context, hash string) (*qbt.TorrentsProperties, error)
	TorrentsInfoCtx(ctx context.Context, params ...*qbt.TorrentsInfoParams) ([]qbt.TorrentInfo, error)
	SyncTorrentPeersCtx(ctx context.Context, hash string, rid int) (*qbt.TorrentPeers, error)
}

// raceState wraps an active race's event channel and metadata.
type raceState struct {
	eventChan  chan bpf.Event
	hash       string
	pieceCount int
	raceID     int64
}

// peerInfo carries a peer's endpoint and BT peer_id from the API.
type peerInfo struct {
	Addr   netip.AddrPort
	PeerID string // raw BT peer_id string from API (may be empty)
}

// peerAddrsUpdate carries known peer data from a tracker's peer poll
// back to the coordinator for use in calibration pattern matching.
type peerAddrsUpdate struct {
	hash  string
	peers []peerInfo
}

// raceComplete signals that a race tracker goroutine has finished.
type raceComplete struct {
	hash string
	err  error
}

// discoveryResult carries the result of an async API query for downloading torrents.
type discoveryResult struct {
	torrents []qbt.TorrentInfo
	err      error
}

// StateSnapshot provides a point-in-time view of coordinator state.
// Used by tests to safely inspect state without data races via QueryState().
type StateSnapshot struct {
	ActiveRaces        map[string]RaceSnap
	TorrentPtrs        map[uint64]string
	PendingCounts      map[uint64]int
	Discovering        bool
	Calibrated         bool
	FullyCalibrated    bool // both sockaddr_in and peer_id offsets discovered
	CalibrationOff     int  // sockaddr_in offset, -1 if uncalibrated
	PeerIDCalibOff     int  // peer_id offset, -1 if uncalibrated
	ConnEndpoints      int  // count of resolved peer_connection* → IP:port mappings
	KnownPeerAddrs     int  // count of known peer addresses for calibration
}

// RaceSnap captures a race's metadata at a point in time.
type RaceSnap struct {
	Hash       string
	PieceCount int
	ChanLen    int
}

type stateQuery struct {
	reply chan StateSnapshot
}

// Coordinator manages race lifecycle using eBPF events and the qBittorrent API.
//
// Design: we_have events carry obj_ptr = torrent* (unique per torrent). The
// coordinator learns torrent_ptr → info_hash mappings via API queries and uses
// them to route events to per-torrent race trackers.
//
// incoming_have events carry obj_ptr = peer_connection* (no torrent affinity).
// After calibration, these are routed exactly via peer_connection* → IP:port
// → race mapping. Before calibration, best-effort routing by piece_index range.
//
// Single-writer pattern: only Run() modifies state maps.
type Coordinator struct {
	store        *storage.Store
	qbtClient    QBittorrentClient
	logger       *slog.Logger
	dashboardURL string

	// torrentPtrs maps torrent_ptr (from we_have obj_ptr) → info_hash.
	// Learned via API discovery. Once set, stable for the torrent's lifetime.
	torrentPtrs map[uint64]string

	// activeRaces holds running race trackers, keyed by info_hash.
	activeRaces map[string]*raceState

	// pendingEvents buffers events for unknown torrent_ptrs during API discovery.
	pendingEvents map[uint64][]bpf.Event

	completeChan   chan raceComplete
	discoveryChan  chan discoveryResult
	stateQueryChan chan stateQuery
	discovering    bool

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

	// knownPeerAddrs maps IP:port → set of info_hashes. Built from tracker
	// peer poll results, used for both calibration matching and exact routing.
	knownPeerAddrs map[netip.AddrPort]map[string]bool

	// knownPeerIDs maps IP:port → raw BT peer_id string from the API.
	// Used for peer_id offset calibration (phase 2).
	knownPeerIDs map[netip.AddrPort]string

	// peerAddrsChan receives peer address updates from tracker goroutines.
	peerAddrsChan chan peerAddrsUpdate

	// calibratedChan is closed when full calibration completes (both offsets
	// discovered). Trackers monitor this to stop sync/peers polling.
	calibratedChan chan struct{}

	// binaryHash is the SHA256 of the qBittorrent binary, used as the key
	// for the persistent calibration cache.
	binaryHash string

	// calibCachePath is the filesystem path to the calibration cache JSON file.
	calibCachePath string
}

// NewCoordinator creates a race coordinator.
//
// binaryHash is the SHA256 of the qBittorrent binary (for calibration cache).
// calibCachePath is the path to the calibration cache JSON file. Both may be
// empty to disable persistent caching (e.g. in tests).
func NewCoordinator(
	store *storage.Store,
	qbtClient QBittorrentClient,
	logger *slog.Logger,
	dashboardURL string,
	binaryHash string,
	calibCachePath string,
) *Coordinator {
	calibration := newCalibrationState()
	calibratedChan := make(chan struct{})

	// Try to load cached calibration offsets
	if binaryHash != "" && calibCachePath != "" {
		if cache := LoadCalibrationCache(calibCachePath); cache != nil && cache.BinaryHash == binaryHash {
			calibration = newCalibratedState(cache.SockaddrOffset, cache.PeerIDOffset)
			close(calibratedChan) // signal that calibration is already complete
			logger.Info("loaded cached calibration",
				"sockaddr_offset", cache.SockaddrOffset,
				"peer_id_offset", cache.PeerIDOffset,
				"binary_hash", binaryHash)
		}
	}

	return &Coordinator{
		store:          store,
		qbtClient:      qbtClient,
		logger:         logger,
		dashboardURL:   dashboardURL,
		torrentPtrs:    make(map[uint64]string),
		activeRaces:    make(map[string]*raceState),
		pendingEvents:  make(map[uint64][]bpf.Event),
		completeChan:   make(chan raceComplete, 10),
		discoveryChan:  make(chan discoveryResult, 1),
		stateQueryChan: make(chan stateQuery),
		calibration:    calibration,
		connEndpoints:  make(map[uint64]netip.AddrPort),
		connToRace:     make(map[uint64]string),
		knownPeerAddrs: make(map[netip.AddrPort]map[string]bool),
		knownPeerIDs:   make(map[netip.AddrPort]string),
		peerAddrsChan:  make(chan peerAddrsUpdate, 20),
		calibratedChan: calibratedChan,
		binaryHash:     binaryHash,
		calibCachePath: calibCachePath,
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
		TorrentPtrs:     make(map[uint64]string, len(c.torrentPtrs)),
		ActiveRaces:     make(map[string]RaceSnap, len(c.activeRaces)),
		PendingCounts:   make(map[uint64]int, len(c.pendingEvents)),
		Discovering:     c.discovering,
		Calibrated:      c.calibration.isCalibrated(),
		FullyCalibrated: c.calibration.isFullyCalibrated(),
		CalibrationOff:  c.calibration.offset,
		PeerIDCalibOff:  c.calibration.peerIDOffset,
		ConnEndpoints:   len(c.connEndpoints),
		KnownPeerAddrs:  len(c.knownPeerAddrs),
	}
	for k, v := range c.torrentPtrs {
		snap.TorrentPtrs[k] = v
	}
	for h, s := range c.activeRaces {
		snap.ActiveRaces[h] = RaceSnap{
			Hash:       s.hash,
			PieceCount: s.pieceCount,
			ChanLen:    len(s.eventChan),
		}
	}
	for k, v := range c.pendingEvents {
		snap.PendingCounts[k] = len(v)
	}
	return snap
}

// Run is the main event loop. Reads raw eBPF events and calibration events,
// and manages race lifecycle. The calibrations channel may be nil if
// calibration is not available (e.g. in tests).
func (c *Coordinator) Run(ctx context.Context, events <-chan bpf.Event, calibrations <-chan bpf.CalibrationEvent) error {
	c.logger.Info("coordinator started, waiting for eBPF events")

	pollTicker := time.NewTicker(5 * time.Second)
	defer pollTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			c.logger.Info("coordinator shutting down")
			c.closeAllRaces()
			return ctx.Err()

		case complete := <-c.completeChan:
			c.handleComplete(complete)

		case result := <-c.discoveryChan:
			c.handleDiscoveryResult(ctx, result)

		case <-pollTicker.C:
			// Periodic poll: discover new downloads even if no we_have seen yet
			// (handles case where events arrive slightly before we start listening)
			if !c.discovering {
				c.startDiscovery(ctx)
			}

		case q := <-c.stateQueryChan:
			q.reply <- c.snapshotState()

		case cal, ok := <-calibrations:
			if ok {
				c.handleCalibration(ctx, cal)
			}

		case update := <-c.peerAddrsChan:
			c.handlePeerAddrsUpdate(update)

		case event, ok := <-events:
			if !ok {
				c.logger.Info("event channel closed")
				c.closeAllRaces()
				return nil
			}

			c.handleEvent(ctx, event)
		}
	}
}

// handleEvent routes a single eBPF event.
func (c *Coordinator) handleEvent(ctx context.Context, event bpf.Event) {
	switch event.EventType {
	case bpf.EventWeHave:
		c.handleWeHave(ctx, event)
	case bpf.EventIncomingHave:
		c.handleIncomingHave(event)
	}
}

// handleWeHave processes a we_have event. obj_ptr is the torrent* pointer.
func (c *Coordinator) handleWeHave(ctx context.Context, event bpf.Event) {
	// Known torrent_ptr? Route directly.
	if hash, ok := c.torrentPtrs[event.ObjPtr]; ok {
		if state, ok := c.activeRaces[hash]; ok {
			c.routeEvent(state, event)
		}
		return
	}

	// Unknown torrent_ptr — buffer and trigger discovery.
	c.pendingEvents[event.ObjPtr] = append(c.pendingEvents[event.ObjPtr], event)

	if !c.discovering {
		c.startDiscovery(ctx)
	}
}

// handleIncomingHave routes incoming_have events. If calibration has resolved
// this peer_connection* to a specific race, route exactly to that race.
// Otherwise, fall back to best-effort routing by piece_index range.
func (c *Coordinator) handleIncomingHave(event bpf.Event) {
	// Exact routing: peer_connection* → race hash (post-calibration)
	if hash, ok := c.connToRace[event.ObjPtr]; ok {
		if state, ok := c.activeRaces[hash]; ok {
			c.routeEvent(state, event)
			return
		}
	}

	// Best-effort fallback: route to all races with valid piece_index
	for _, state := range c.activeRaces {
		if state.pieceCount <= 0 || int(event.PieceIndex) < state.pieceCount {
			c.routeEvent(state, event)
		}
	}
}

// handleComplete processes a race tracker completion signal.
func (c *Coordinator) handleComplete(complete raceComplete) {
	if _, exists := c.activeRaces[complete.hash]; exists {
		delete(c.activeRaces, complete.hash)
		if complete.err != nil && complete.err != context.Canceled {
			c.logger.Error("race tracking failed", "hash", complete.hash, "error", complete.err)
		}
		c.logger.Info("race tracking complete", "hash", complete.hash)
	}

	// Clean up torrentPtrs pointing to this hash so future races for the
	// same torrent (re-download) will trigger fresh API discovery.
	for ptr, h := range c.torrentPtrs {
		if h == complete.hash {
			delete(c.torrentPtrs, ptr)
		}
	}
}

// startDiscovery launches an async goroutine to query the qBittorrent API
// for downloading torrents. Non-blocking: results arrive via discoveryChan.
func (c *Coordinator) startDiscovery(ctx context.Context) {
	c.discovering = true
	go func() {
		queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		torrents, err := c.qbtClient.TorrentsInfoCtx(queryCtx, &qbt.TorrentsInfoParams{
			Filter: "downloading",
		})
		c.discoveryChan <- discoveryResult{torrents: torrents, err: err}
	}()
}

// handleDiscoveryResult processes the result of an async API query.
// Creates races for newly discovered torrents, assigns torrent_ptr → hash
// mappings, and flushes buffered events.
func (c *Coordinator) handleDiscoveryResult(ctx context.Context, result discoveryResult) {
	c.discovering = false

	if result.err != nil {
		c.logger.Warn("discovery query failed", "error", result.err)
		return
	}

	if len(result.torrents) == 0 {
		c.logger.Debug("no downloading torrents found")
		// Clear pending events — no download to attribute them to
		c.pendingEvents = make(map[uint64][]bpf.Event)
		return
	}

	// Identify new torrents not yet tracked
	var newHashes []string
	for _, t := range result.torrents {
		hash := strings.ToLower(string(t.Hash))
		if _, exists := c.activeRaces[hash]; !exists {
			newHashes = append(newHashes, hash)
			c.promoteToActive(ctx, hash)
		}
	}

	if len(newHashes) == 0 && len(c.pendingEvents) > 0 {
		// All downloading torrents already have active races.
		// Try to assign unknown ptrs to existing races by piece_index.
		c.assignPendingPtrs()
		return
	}

	// Attempt to assign pending torrent_ptrs to newly created races.
	c.assignPendingPtrs()
}

// assignPendingPtrs tries to assign buffered torrent_ptrs to active races.
//
// Strategy:
//   - If exactly one pending ptr and one unassigned race, direct match.
//   - Otherwise, use piece_index < piece_count to narrow candidates.
//   - If still ambiguous, leave pending for future disambiguation.
func (c *Coordinator) assignPendingPtrs() {
	for ptr, events := range c.pendingEvents {
		if _, alreadyAssigned := c.torrentPtrs[ptr]; alreadyAssigned {
			c.flushPending(ptr)
			continue
		}

		// Find candidate races: piece_index from buffered events must be valid
		candidates := c.findCandidateRaces(events)

		if len(candidates) == 1 {
			hash := candidates[0]
			c.torrentPtrs[ptr] = hash
			c.logger.Info("mapped torrent_ptr to hash",
				"ptr", fmt.Sprintf("0x%x", ptr), "hash", hash)
			c.flushPending(ptr)
		} else if len(candidates) == 0 {
			// No valid race for these events — discard
			c.logger.Debug("no candidate race for pending ptr, discarding",
				"ptr", fmt.Sprintf("0x%x", ptr), "events", len(events))
			delete(c.pendingEvents, ptr)
		}
		// len(candidates) > 1: ambiguous, leave pending for later
	}
}

// findCandidateRaces returns hashes of active races that could own the given events,
// based on piece_index range and whether the race already has a ptr assigned.
func (c *Coordinator) findCandidateRaces(events []bpf.Event) []string {
	// Collect all unassigned active race hashes
	assignedHashes := make(map[string]bool)
	for _, h := range c.torrentPtrs {
		assignedHashes[h] = true
	}

	var candidates []string
	for hash, state := range c.activeRaces {
		if assignedHashes[hash] {
			continue // already has a ptr assigned
		}
		// Check if all event piece indices are valid for this race
		valid := true
		for _, ev := range events {
			if state.pieceCount > 0 && int(ev.PieceIndex) >= state.pieceCount {
				valid = false
				break
			}
		}
		if valid {
			candidates = append(candidates, hash)
		}
	}
	return candidates
}

// flushPending sends all buffered events for a ptr to its assigned race.
func (c *Coordinator) flushPending(ptr uint64) {
	events, ok := c.pendingEvents[ptr]
	if !ok {
		return
	}
	delete(c.pendingEvents, ptr)

	hash, ok := c.torrentPtrs[ptr]
	if !ok {
		return
	}
	state, ok := c.activeRaces[hash]
	if !ok {
		return
	}

	for _, event := range events {
		c.routeEvent(state, event)
	}
	c.logger.Debug("flushed pending events", "ptr", fmt.Sprintf("0x%x", ptr), "count", len(events))
}

// promoteToActive creates a race record and starts a tracker goroutine.
func (c *Coordinator) promoteToActive(ctx context.Context, hash string) {
	propsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	props, err := c.qbtClient.TorrentsPropertiesCtx(propsCtx, hash)
	if err != nil {
		c.logger.Error("failed to fetch torrent metadata", "hash", hash, "error", err)
		return
	}

	c.logger.Info("starting race",
		"hash", hash,
		"name", props.Name,
		"size", props.TotalSize,
		"pieces", props.PiecesNum)

	torrentID, err := c.store.CreateTorrent(ctx, hash, props.Name, props.TotalSize, int(props.PiecesNum))
	if err != nil {
		c.logger.Error("failed to create torrent record", "hash", hash, "error", err)
		return
	}

	raceID, err := c.store.CreateRace(ctx, torrentID)
	if err != nil {
		c.logger.Error("failed to create race record", "hash", hash, "error", err)
		return
	}

	state := &raceState{
		eventChan:  make(chan bpf.Event, 10000),
		hash:       hash,
		pieceCount: int(props.PiecesNum),
		raceID:     raceID,
	}
	c.activeRaces[hash] = state

	go func(hash string, raceID int64, pieceCount int, eventChan <-chan bpf.Event, peerAddrsChan chan<- peerAddrsUpdate, calibratedChan <-chan struct{}) {
		err := processEvents(ctx, c.store, c.qbtClient, c.logger, hash, raceID, pieceCount, eventChan, peerAddrsChan, calibratedChan)
		c.completeChan <- raceComplete{hash: hash, err: err}
	}(hash, raceID, int(props.PiecesNum), state.eventChan, c.peerAddrsChan, c.calibratedChan)
}

// routeEvent sends an event to an active race's channel.
func (c *Coordinator) routeEvent(state *raceState, event bpf.Event) {
	select {
	case state.eventChan <- event:
	default:
		c.logger.Warn("race event channel full, dropping", "hash", state.hash)
	}
}

// handleCalibration processes a calibration event from eBPF. Handles three
// calibration phases:
//
//  1. sockaddr_in offset discovery: scan dumps for known IP:port patterns
//  2. peer_id offset discovery: correlate dumps with known peer_ids via IP:port
//  3. Post-calibration extraction: extract IP:port and peer_id from every new connection
func (c *Coordinator) handleCalibration(ctx context.Context, cal bpf.CalibrationEvent) {
	if c.calibration.isFullyCalibrated() {
		// Fully calibrated — extract endpoint + peer_id, resolve to race
		c.extractAndResolve(ctx, cal)
		return
	}

	if c.calibration.isCalibrated() && !c.calibration.isFullyCalibrated() {
		// sockaddr_in calibrated but peer_id not yet — try peer_id calibration
		// then extract endpoint
		addr, ok := c.calibration.extractEndpoint(cal.Data)
		if ok {
			c.connEndpoints[cal.ObjPtr] = addr
			c.resolveConnToRace(ctx, cal.ObjPtr, addr)
		}

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

		// Extract endpoint from this event
		if addr, ok := c.calibration.extractEndpoint(cal.Data); ok {
			c.connEndpoints[cal.ObjPtr] = addr
			c.resolveConnToRace(ctx, cal.ObjPtr, addr)
		}

		// Try peer_id calibration immediately (may succeed if we have peer_id data)
		if c.calibration.tryCalibratePeerID(cal, c.knownPeerIDs) {
			c.logger.Info("calibration: peer_id offset locked",
				"offset", c.calibration.peerIDOffset,
				"votes", c.calibration.peerIDVotes[c.calibration.peerIDOffset])
			c.onFullCalibration(ctx)
		}

		// Reprocess pending calibration events
		c.reprocessPendingCalibrations(ctx)
	} else {
		c.calibration.pending = append(c.calibration.pending, cal)
	}
}

// extractAndResolve extracts IP:port and peer_id from a calibration event
// after full calibration, and resolves the connection to a race.
func (c *Coordinator) extractAndResolve(ctx context.Context, cal bpf.CalibrationEvent) {
	addr, ok := c.calibration.extractEndpoint(cal.Data)
	if !ok {
		return
	}
	c.connEndpoints[cal.ObjPtr] = addr
	c.resolveConnToRace(ctx, cal.ObjPtr, addr)

	// Extract peer_id and decode client
	peerID, ok := c.calibration.extractPeerID(cal.Data)
	if !ok {
		return
	}
	client := decodePeerClient(peerID)

	// Update connection record with full peer info
	connPtr := fmt.Sprintf("%x", cal.ObjPtr)
	if err := c.store.UpdateConnectionPeerInfo(ctx, connPtr, addr.Addr().String(), int(addr.Port()), peerID, client); err != nil {
		c.logger.Debug("failed to update connection peer info", "error", err)
	}

	// Upsert into race_peers for the dashboard
	if hash, ok := c.connToRace[cal.ObjPtr]; ok {
		if state, ok := c.activeRaces[hash]; ok {
			if err := c.store.UpsertRacePeerFromCapture(ctx, state.raceID, addr.Addr().String(), int(addr.Port()), client, peerID); err != nil {
				c.logger.Debug("failed to upsert race peer from capture", "error", err)
			}
		}
	}

	c.logger.Debug("calibration: resolved connection (full)",
		"ptr", fmt.Sprintf("0x%x", cal.ObjPtr),
		"addr", addr.String(),
		"client", client)
}

// onFullCalibration is called when both sockaddr_in and peer_id offsets have
// been discovered. Persists the calibration cache and signals trackers to
// stop API polling.
func (c *Coordinator) onFullCalibration(ctx context.Context) {
	c.logger.Info("calibration: fully calibrated",
		"sockaddr_offset", c.calibration.offset,
		"peer_id_offset", c.calibration.peerIDOffset)

	// Persist to cache
	if c.binaryHash != "" && c.calibCachePath != "" {
		if err := SaveCalibrationCache(c.calibCachePath, c.binaryHash, c.calibration.offset, c.calibration.peerIDOffset); err != nil {
			c.logger.Warn("failed to save calibration cache", "error", err)
		} else {
			c.logger.Info("calibration: cache saved", "path", c.calibCachePath)
		}
	}

	// Signal trackers to stop peer polling
	select {
	case <-c.calibratedChan:
		// Already closed (e.g. loaded from cache)
	default:
		close(c.calibratedChan)
	}
}

// handlePeerAddrsUpdate processes peer data from a tracker's peer poll.
// Updates the known peer address and peer_id maps, then re-scans pending
// calibration events for both sockaddr_in and peer_id offset discovery.
func (c *Coordinator) handlePeerAddrsUpdate(update peerAddrsUpdate) {
	for _, p := range update.peers {
		if c.knownPeerAddrs[p.Addr] == nil {
			c.knownPeerAddrs[p.Addr] = make(map[string]bool)
		}
		c.knownPeerAddrs[p.Addr][update.hash] = true

		// Track peer_id for peer_id offset calibration
		if p.PeerID != "" {
			c.knownPeerIDs[p.Addr] = p.PeerID
		}
	}

	// Phase 1: Try sockaddr_in calibration from pending events
	if !c.calibration.isCalibrated() && len(c.calibration.pending) > 0 && len(c.knownPeerAddrs) > 0 {
		knownPeers := make(map[netip.AddrPort]bool, len(c.knownPeerAddrs))
		for addr := range c.knownPeerAddrs {
			knownPeers[addr] = true
		}

		for _, cal := range c.calibration.pending {
			if c.calibration.tryCalibrate(cal, knownPeers) {
				c.logger.Info("calibration: sockaddr_in offset locked (from pending rescan)",
					"offset", c.calibration.offset,
					"votes", c.calibration.votes[c.calibration.offset])
				c.reprocessPendingCalibrations(context.Background())
				break
			}
		}
	}

	// Phase 2: Try peer_id calibration from pending events (requires sockaddr_in first)
	if c.calibration.isCalibrated() && !c.calibration.isFullyCalibrated() && len(c.calibration.pending) > 0 && len(c.knownPeerIDs) > 0 {
		for _, cal := range c.calibration.pending {
			if c.calibration.tryCalibratePeerID(cal, c.knownPeerIDs) {
				c.logger.Info("calibration: peer_id offset locked (from pending rescan)",
					"offset", c.calibration.peerIDOffset,
					"votes", c.calibration.peerIDVotes[c.calibration.peerIDOffset])
				c.onFullCalibration(context.Background())
				c.reprocessPendingCalibrations(context.Background())
				break
			}
		}
	}

	// Resolve any connEndpoints that weren't yet mapped to a race
	if c.calibration.isCalibrated() {
		for ptr, addr := range c.connEndpoints {
			if _, resolved := c.connToRace[ptr]; !resolved {
				c.resolveConnToRace(context.Background(), ptr, addr)
			}
		}
	}
}

// reprocessPendingCalibrations extracts endpoints (and optionally peer_id)
// from buffered calibration events after offsets have been locked in.
func (c *Coordinator) reprocessPendingCalibrations(ctx context.Context) {
	pending := c.calibration.pending
	c.calibration.pending = nil

	for _, cal := range pending {
		if c.calibration.isFullyCalibrated() {
			c.extractAndResolve(ctx, cal)
		} else if c.calibration.isCalibrated() {
			addr, ok := c.calibration.extractEndpoint(cal.Data)
			if !ok {
				continue
			}
			c.connEndpoints[cal.ObjPtr] = addr
			c.resolveConnToRace(ctx, cal.ObjPtr, addr)

			// Also try peer_id calibration on pending events
			c.calibration.tryCalibratePeerID(cal, c.knownPeerIDs)
		}
	}

	c.logger.Debug("calibration: reprocessed pending events",
		"count", len(pending),
		"resolved", len(c.connEndpoints))
}

// resolveConnToRace maps a peer_connection* to its owning race by looking up
// the resolved IP:port in the known peer address map.
func (c *Coordinator) resolveConnToRace(_ context.Context, ptr uint64, addr netip.AddrPort) {
	races, ok := c.knownPeerAddrs[addr]
	if !ok || len(races) == 0 {
		return
	}

	// If the peer belongs to exactly one active race, map directly.
	// If multiple races share this peer, pick the first active one.
	for hash := range races {
		if _, active := c.activeRaces[hash]; active {
			c.connToRace[ptr] = hash

			// Also update the connection record in the DB with the resolved endpoint.
			connPtr := fmt.Sprintf("%x", ptr)
			ip := addr.Addr().String()
			port := int(addr.Port())
			if err := c.store.UpdateConnectionEndpoint(context.Background(), connPtr, ip, port); err != nil {
				c.logger.Debug("failed to update connection endpoint", "error", err)
			}
			return
		}
	}
}

// closeAllRaces closes all active race trackers during shutdown.
func (c *Coordinator) closeAllRaces() {
	for hash, state := range c.activeRaces {
		close(state.eventChan)
		c.logger.Debug("closed race tracker", "hash", hash)
	}
	c.activeRaces = make(map[string]*raceState)
}

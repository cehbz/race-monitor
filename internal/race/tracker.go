package race

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// peerPollResult carries peer data from an async poll goroutine back to
// the main select loop. Keeping the API call off the select loop ensures
// that the event channel is never blocked during peer polling (the 3-second
// timeout could otherwise stall ~9,000 events at peak rate).
type peerPollResult struct {
	peers []storage.RacePeer
	rid   int
	err   error
}

// processEvents is the main event processing loop for a single race.
// It receives raw eBPF events, converts them to storage events, and persists them.
// It also periodically polls the qBittorrent API for peer data asynchronously,
// using delta mode (RID) to minimize payload size after the initial full snapshot.
//
// If peerAddrsChan is non-nil, peer data from each poll is sent to the
// coordinator for calibration pattern matching.
//
// If calibratedChan is non-nil, the tracker stops peer polling when the channel
// is closed (indicating that full calibration has completed and all peer metadata
// can be extracted from eBPF captures).
func processEvents(
	ctx context.Context,
	store *storage.Store,
	qbtClient QBittorrentClient,
	logger *slog.Logger,
	hash string,
	raceID int64,
	pieceCount int,
	events <-chan bpf.Event,
	peerAddrsChan chan<- peerAddrsUpdate,
	calibratedChan <-chan struct{},
) error {
	const (
		batchSize    = 100
		idleTimeout  = 10 * time.Second
		peerPollFreq = 5 * time.Second
	)

	var (
		bootTime = estimateBootTime()
		// connMap tracks conn_ptr → db connection ID for incoming_have events
		connMap = make(map[uint64]int64)
		// selfConnID is the connection record for our own piece completions
		selfConnID int64

		have           = make(map[int]bool)
		loggedComplete bool
		maxTimer       = time.NewTimer(30 * time.Minute)
		idleTimer      = time.NewTimer(idleTimeout)
		peerPollTimer  = time.NewTimer(peerPollFreq)
		eventBatch     = make([]storage.Event, 0, batchSize)

		totalEvents   uint64
		weHaveCount   uint64
		peerHaveCount uint64
		startTime     = time.Now()
		lastLogTime   = time.Now()
		logInterval   = 30 * time.Second

		// Delta mode: track the response ID from sync/torrentPeers.
		// rid=0 requests a full peer snapshot. Each response returns a
		// new rid; passing it on the next call yields only peers that
		// changed since the previous response.
		lastRID        int
		pollInFlight   bool
		peerResultCh   = make(chan peerPollResult, 1)
		pollingStopped bool // set when calibratedChan fires
	)

	defer maxTimer.Stop()
	defer idleTimer.Stop()
	defer peerPollTimer.Stop()

	// Create a "self" connection record for our piece completions
	var err error
	selfConnID, err = store.InsertConnection(ctx, "self", time.Now())
	if err != nil {
		return fmt.Errorf("inserting self connection: %w", err)
	}

	flushEvents := func() error {
		if len(eventBatch) == 0 {
			return nil
		}
		if err := store.InsertPacketEvents(ctx, eventBatch); err != nil {
			return fmt.Errorf("inserting events: %w", err)
		}
		eventBatch = eventBatch[:0]
		return nil
	}

	// Check if calibration is already complete (calibratedChan already closed)
	if calibratedChan != nil {
		select {
		case <-calibratedChan:
			pollingStopped = true
			logger.Debug("peer polling skipped (calibration already complete)", "hash", hash)
		default:
		}
	}

	// startPeerPoll launches an async goroutine to poll the qBittorrent
	// sync/torrentPeers endpoint. Results arrive on peerResultCh and are
	// processed in the main select loop, keeping the event channel
	// unblocked during API calls.
	startPeerPoll := func() {
		if qbtClient == nil || pollInFlight || pollingStopped {
			return
		}
		pollInFlight = true
		currentRID := lastRID
		go func() {
			pollCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			peersResult, err := qbtClient.SyncTorrentPeersCtx(pollCtx, hash, currentRID)
			if err != nil {
				peerResultCh <- peerPollResult{err: err}
				return
			}

			if peersResult == nil {
				peerResultCh <- peerPollResult{}
				return
			}

			now := time.Now()
			racePeers := make([]storage.RacePeer, 0, len(peersResult.Peers))
			for _, p := range peersResult.Peers {
				racePeers = append(racePeers, storage.RacePeer{
					IP:        p.IP,
					Port:      p.Port,
					Client:    p.Client,
					PeerID:    p.PeerIDClient,
					Country:   p.Country,
					Progress:  p.Progress,
					DLSpeed:   p.DLSpeed,
					UPSpeed:   p.UPSpeed,
					FirstSeen: now,
					LastSeen:  now,
				})
			}

			peerResultCh <- peerPollResult{peers: racePeers, rid: peersResult.Rid}
		}()
	}

	// Initial peer poll (async — result handled in select loop)
	startPeerPoll()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-maxTimer.C:
			logger.Info("max duration reached", "hash", hash)
			if err := flushEvents(); err != nil {
				logger.Warn("failed to flush final events", "error", err)
			}
			return finalize(ctx, store, logger, raceID, pieceCount)

		case <-idleTimer.C:
			logger.Info("race idle timeout",
				"hash", hash,
				"we_have", weHaveCount,
				"peer_have", peerHaveCount,
				"piece_count", pieceCount)
			if err := flushEvents(); err != nil {
				logger.Warn("failed to flush final events", "error", err)
			}
			return finalize(ctx, store, logger, raceID, pieceCount)

		case <-peerPollTimer.C:
			if !pollingStopped {
				startPeerPoll()
			}
			peerPollTimer.Reset(peerPollFreq)

		case result := <-peerResultCh:
			pollInFlight = false
			if result.err != nil {
				logger.Debug("peer poll failed", "hash", hash, "error", result.err)
			} else {
				lastRID = result.rid
				if len(result.peers) > 0 {
					if err := store.UpsertRacePeers(ctx, raceID, result.peers); err != nil {
						logger.Warn("failed to upsert race peers", "hash", hash, "error", err)
					} else {
						logger.Debug("peer poll complete", "hash", hash, "peers", len(result.peers), "rid", lastRID)
					}

					// Notify coordinator of peer data for calibration
					if peerAddrsChan != nil {
						peers := make([]peerInfo, 0, len(result.peers))
						for _, p := range result.peers {
							if addr, err := netip.ParseAddr(p.IP); err == nil {
								peers = append(peers, peerInfo{
									Addr:   netip.AddrPortFrom(addr, uint16(p.Port)),
									PeerID: p.PeerID,
								})
							}
						}
						select {
						case peerAddrsChan <- peerAddrsUpdate{hash: hash, peers: peers}:
						default:
							// Non-blocking: drop if coordinator is busy
						}
					}
				}
			}

		case event, ok := <-events:
			if !ok {
				logger.Debug("event channel closed",
					"total_events", totalEvents,
					"we_have", weHaveCount,
					"peer_have", peerHaveCount)
				if err := flushEvents(); err != nil {
					logger.Warn("failed to flush final events", "error", err)
				}
				return finalize(ctx, store, logger, raceID, pieceCount)
			}

			// Reset idle timer on every event
			if !idleTimer.Stop() {
				select {
				case <-idleTimer.C:
				default:
				}
			}
			idleTimer.Reset(idleTimeout)

			totalEvents++
			ts := bootTime.Add(time.Duration(event.Timestamp))

			if time.Since(lastLogTime) >= logInterval {
				logger.Debug("race stats",
					"hash", hash,
					"elapsed", time.Since(startTime).Round(time.Second),
					"total_events", totalEvents,
					"we_have", weHaveCount,
					"peer_have", peerHaveCount,
					"connections", len(connMap),
					"pieces_done", len(have))
				lastLogTime = time.Now()
			}

			var dbEvent storage.Event
			dbEvent.RaceID = raceID
			dbEvent.Timestamp = ts
			dbEvent.PieceIndex = int(event.PieceIndex)

			switch event.EventType {
			case bpf.EventWeHave:
				weHaveCount++
				have[int(event.PieceIndex)] = true
				dbEvent.EventType = storage.EventTypePieceReceived
				dbEvent.ConnectionID = selfConnID

			case bpf.EventIncomingHave:
				peerHaveCount++
				connDBID, exists := connMap[event.ObjPtr]
				if !exists {
					if loggedComplete {
						continue // Ignore new connections after download completes
					}
					connPtr := fmt.Sprintf("%x", event.ObjPtr)
					connDBID, err = store.InsertConnection(ctx, connPtr, ts)
					if err != nil {
						logger.Warn("failed to insert connection", "error", err, "ptr", event.ObjPtr)
						continue
					}
					connMap[event.ObjPtr] = connDBID
				}
				dbEvent.EventType = storage.EventTypeHave
				dbEvent.ConnectionID = connDBID

			default:
				continue
			}

			eventBatch = append(eventBatch, dbEvent)

			if len(eventBatch) >= batchSize {
				if err := flushEvents(); err != nil {
					logger.Warn("failed to flush event batch", "error", err)
				}
			}

			if pieceCount > 0 && len(have) >= pieceCount && !loggedComplete {
				loggedComplete = true
				logger.Info("all pieces completed",
					"elapsed", time.Since(startTime),
					"piece_count", pieceCount,
					"connections", len(connMap),
					"total_events", totalEvents)
			}
		}
	}
}

func finalize(ctx context.Context, store *storage.Store, logger *slog.Logger, raceID int64, pieceCount int) error {
	if err := store.CompleteRace(ctx, raceID); err != nil {
		return fmt.Errorf("completing race: %w", err)
	}

	race, err := store.GetRace(ctx, raceID)
	if err != nil {
		logger.Warn("failed to get race info", "error", err)
		return nil
	}

	var duration time.Duration
	if race.CompletedAt.Valid {
		duration = race.CompletedAt.Time.Sub(race.StartedAt)
	}

	logger.Info("race recording complete",
		"name", race.Name,
		"duration", duration,
		"piece_count", pieceCount)

	return nil
}

// estimateBootTime returns the approximate system boot time by subtracting
// uptime from wall-clock time. eBPF's bpf_ktime_get_ns() returns nanoseconds
// since boot (CLOCK_BOOTTIME), so we use this to convert to wall-clock timestamps.
func estimateBootTime() time.Time {
	now := time.Now()
	uptimeNs, err := readProcUptime()
	if err != nil {
		// Fallback: this is inaccurate but won't crash. Timestamps will
		// be offset but relative ordering (which matters for analysis) is preserved.
		return now
	}
	return now.Add(-time.Duration(uptimeNs))
}

// readProcUptime reads /proc/uptime and returns nanoseconds since boot.
// Format: "uptime_seconds idle_seconds\n" — we parse the first float.
func readProcUptime() (int64, error) {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, err
	}

	var upSec float64
	if _, err := fmt.Sscanf(string(data), "%f", &upSec); err != nil {
		return 0, err
	}

	return int64(upSec * 1e9), nil
}

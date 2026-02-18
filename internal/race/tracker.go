package race

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// processEvents is the main event processing loop for a single race.
// It receives raw eBPF events, converts them to storage events, and persists them.
//
// The downloadCompleteCh is closed by the coordinator when the download
// completes (torrent::finished() event). After that, the tracker begins per-peer idle
// monitoring and finalizes when all tracked peers have been idle for 10 seconds.
//
// New signature:
//
//	func processEvents(
//	    ctx context.Context,
//	    store *storage.Store,
//	    logger *slog.Logger,
//	    hash string,
//	    raceID int64,
//	    events <-chan bpf.Event,
//	    downloadCompleteCh <-chan struct{},
//	) error
func processEvents(
	ctx context.Context,
	store *storage.Store,
	logger *slog.Logger,
	hash string,
	raceID int64,
	events <-chan bpf.Event,
	downloadCompleteCh <-chan struct{},
) error {
	const (
		batchSize       = 100
		postCompleteIdleTimeout = 10 * time.Second
		maxDuration     = 30 * time.Minute
	)

	var (
		// connMap tracks conn_ptr → db connection ID for incoming_have events
		connMap = make(map[uint64]int64)
		// selfConnID is the connection record for our own piece completions
		selfConnID int64

		have                  = make(map[int]bool)
		loggedComplete        bool
		downloadCompleted     bool
		downloadCompleteSel   = downloadCompleteCh // local copy we nil after receiving
		maxTimer              = time.NewTimer(maxDuration)
		eventBatch            = make([]storage.Event, 0, batchSize)

		totalEvents   uint64
		weHaveCount   uint64
		peerHaveCount uint64
		startTime     = time.Now()
		lastLogTime   = time.Now()
		logInterval   = 30 * time.Second

		// Post-completion idle tracking: lastEventTime[connPtr] = timestamp
		lastEventTime = make(map[uint64]int64)
		idleTimer     *time.Timer                     // initialized after download completes
		idleTimerCh   <-chan time.Time                 // nil until idleTimer is created (nil channels block forever in select)
	)

	defer maxTimer.Stop()

	// Create a "self" connection record for our piece completions
	var err error
	selfConnID, err = store.InsertConnection(ctx, raceID, "self", time.Now())
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

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-maxTimer.C:
			logger.Info("max duration reached", "hash", hash)
			if err := flushEvents(); err != nil {
				logger.Warn("failed to flush final events", "error", err)
			}
			return finalize(ctx, store, logger, raceID)

		case <-downloadCompleteSel:
			// Download is complete. Start monitoring per-peer idle.
			downloadCompleted = true
			downloadCompleteSel = nil // prevent re-entry (closed channels are always selectable)
			logger.Info("download completed, starting idle monitoring",
				"hash", hash,
				"elapsed", time.Since(startTime),
				"connections", len(connMap))
			// No peers to monitor — finalize immediately
			if len(connMap) == 0 {
				if err := flushEvents(); err != nil {
					logger.Warn("failed to flush final events", "error", err)
				}
				return finalize(ctx, store, logger, raceID)
			}
			// Initialize idle timer for post-completion monitoring
			idleTimer = time.NewTimer(postCompleteIdleTimeout)
			idleTimerCh = idleTimer.C
			defer idleTimer.Stop()

		case <-idleTimerCh:
			if downloadCompleted {
				// All tracked peers have been idle for the timeout
				logger.Info("all peers idle after download completion",
					"hash", hash,
					"idle_timeout", postCompleteIdleTimeout,
					"connections", len(connMap))
				if err := flushEvents(); err != nil {
					logger.Warn("failed to flush final events", "error", err)
				}
				return finalize(ctx, store, logger, raceID)
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
				// If download hasn't completed yet, finalize as abandoned
				if !downloadCompleted {
					return finalize(ctx, store, logger, raceID)
				}
				// Otherwise, return the normal finalize result
				return finalize(ctx, store, logger, raceID)
			}

			totalEvents++

			// Track event timestamp for idle monitoring (post-completion)
			if downloadCompleted && event.ObjPtr > 0 {
				lastEventTime[event.ObjPtr] = int64(event.Timestamp)
			}

			// Reset idle timer after download completes (for per-peer monitoring)
			if downloadCompleted && idleTimer != nil {
				if !idleTimer.Stop() {
					select {
					case <-idleTimer.C:
					default:
					}
				}
				idleTimer.Reset(postCompleteIdleTimeout)
			}

			if time.Since(lastLogTime) >= logInterval {
				logger.Debug("race stats",
					"hash", hash,
					"elapsed", time.Since(startTime).Round(time.Second),
					"total_events", totalEvents,
					"we_have", weHaveCount,
					"peer_have", peerHaveCount,
					"connections", len(connMap),
					"pieces_done", len(have),
					"download_completed", downloadCompleted)
				lastLogTime = time.Now()
			}

			var dbEvent storage.Event
			dbEvent.RaceID = raceID
			dbEvent.Timestamp = int64(event.Timestamp)
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
					connDBID, err = store.InsertConnection(ctx, raceID, connPtr, time.Now())
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

			// Log when all pieces are received (before or during download)
			if len(have) > 0 && !loggedComplete {
				// Don't flag as complete until torrent::finished() fires
				// but track that we've seen all pieces
			}
		}
	}
}

func finalize(ctx context.Context, store *storage.Store, logger *slog.Logger, raceID int64) error {
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
		"duration", duration)

	return nil
}

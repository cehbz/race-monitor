package race

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// Grace period constants for post-download event capture.
const (
	graceFraction = 0.5
	graceMin      = 5 * time.Second
	graceMax      = 60 * time.Second
)

// graceDuration computes the post-download grace period: 50% of the download
// duration, clamped to [5s, 60s].
func graceDuration(downloadElapsed time.Duration) time.Duration {
	d := time.Duration(float64(downloadElapsed) * graceFraction)
	if d < graceMin {
		return graceMin
	}
	if d > graceMax {
		return graceMax
	}
	return d
}

// processEvents is the main event processing loop for a single race.
// It receives typed eBPF probe events, converts them to storage events, and
// persists them in batches.
//
// The downloadCompleteCh is closed by the coordinator when the download
// completes (torrent::finished() event). After that, the tracker runs a
// proportional grace period — 50% of the download duration, clamped to
// [5s, 60s] — then finalizes unconditionally. The grace timer never resets.
func processEvents(
	ctx context.Context,
	store *storage.Store,
	logger *slog.Logger,
	hash string,
	raceID int64,
	metaChan <-chan int,
	events <-chan bpf.ProbeEvent,
	downloadCompleteCh <-chan struct{},
) error {
	const (
		batchSize   = 100
		maxDuration = 30 * time.Minute

		// A few out-of-range events per source are expected from cross-CPU
		// perf buffer interleaving during peer_connection* reuse. Sustained
		// contamination above this threshold indicates a routing bug.
		contaminationThreshold = 10
	)

	var (
		// connMap tracks conn_ptr → db connection ID for incoming_have events
		connMap = make(map[uint64]int64)
		// selfConnID is the connection record for our own piece completions
		selfConnID int64

		// pieceCount is delivered asynchronously via metaChan. Zero until
		// metadata resolves; contamination detection is inactive until then.
		pieceCount int

		have                = make(map[int]bool)
		downloadCompleted   bool
		downloadCompleteSel = downloadCompleteCh // local copy we nil after receiving
		maxTimer            = time.NewTimer(maxDuration)
		eventBatch          = make([]storage.Event, 0, batchSize)

		// contaminationCount tracks out-of-range piece_index events per source
		// (conn_ptr for incoming_have, torrent_ptr for we_have). A few are
		// expected from cross-CPU timing; many indicate a bug.
		contaminationCount = make(map[uint64]int)

		totalEvents   uint64
		weHaveCount   uint64
		peerHaveCount uint64
		startTime     = time.Now()
		lastLogTime   = time.Now()
		logInterval   = 30 * time.Second

		// Post-completion grace timer: fires once after a proportional delay,
		// never resets. nil channel blocks forever in select until initialized.
		graceTimer   *time.Timer
		graceTimerCh <-chan time.Time
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

		case pc, ok := <-metaChan:
			if ok {
				pieceCount = pc
				metaChan = nil // one-shot; stop selecting
				logger.Info("metadata resolved", "hash", hash, "piece_count", pieceCount)
			}

		case <-maxTimer.C:
			logger.Info("max duration reached", "hash", hash)
			if err := flushEvents(); err != nil {
				logger.Warn("failed to flush final events", "error", err)
			}
			return finalize(ctx, store, logger, raceID)

		case <-downloadCompleteSel:
			// Download is complete. Start a proportional grace period.
			downloadCompleted = true
			downloadCompleteSel = nil // prevent re-entry (closed channels are always selectable)
			elapsed := time.Since(startTime)

			// No peers to monitor — finalize immediately
			if len(connMap) == 0 {
				logger.Info("download completed, no peers tracked",
					"hash", hash, "elapsed", elapsed)
				if err := flushEvents(); err != nil {
					logger.Warn("failed to flush final events", "error", err)
				}
				return finalize(ctx, store, logger, raceID)
			}

			// Grace = 50% of download duration, clamped to [5s, 60s]
			grace := graceDuration(elapsed)
			graceTimer = time.NewTimer(grace)
			graceTimerCh = graceTimer.C
			defer graceTimer.Stop()
			logger.Info("download completed, grace period started",
				"hash", hash, "elapsed", elapsed,
				"grace", grace, "connections", len(connMap))

		case <-graceTimerCh:
			logger.Info("grace period expired",
				"hash", hash, "connections", len(connMap))
			if err := flushEvents(); err != nil {
				logger.Warn("failed to flush final events", "error", err)
			}
			return finalize(ctx, store, logger, raceID)

		case ev, ok := <-events:
			if !ok {
				logger.Debug("event channel closed",
					"total_events", totalEvents,
					"we_have", weHaveCount,
					"peer_have", peerHaveCount)
				if err := flushEvents(); err != nil {
					logger.Warn("failed to flush final events", "error", err)
				}
				return finalize(ctx, store, logger, raceID)
			}

			totalEvents++

			var dbEvent storage.Event
			dbEvent.RaceID = raceID

			switch e := ev.(type) {
			case *bpf.WeHaveEvent:
				if pieceCount > 0 && int(e.PieceIndex) >= pieceCount {
					contaminationCount[e.TorrentPtr]++
					n := contaminationCount[e.TorrentPtr]
					if n == contaminationThreshold {
						logger.Error("CONTAMINATION: sustained we_have piece_index out of range",
							"hash", hash, "race_id", raceID,
							"piece_index", e.PieceIndex, "piece_count", pieceCount,
							"torrent_ptr", fmt.Sprintf("0x%x", e.TorrentPtr),
							"count", n)
						store.InsertRaceError(ctx, raceID, "piece_index_out_of_range",
							fmt.Sprintf("we_have piece_index %d >= piece_count %d from torrent_ptr 0x%x (%d events)",
								e.PieceIndex, pieceCount, e.TorrentPtr, n))
					}
					continue
				}
				weHaveCount++
				have[int(e.PieceIndex)] = true
				dbEvent.EventType = storage.EventTypePieceReceived
				dbEvent.ConnectionID = selfConnID
				dbEvent.Timestamp = int64(e.Timestamp)
				dbEvent.PieceIndex = int(e.PieceIndex)

			case *bpf.IncomingHaveEvent:
				if pieceCount > 0 && int(e.PieceIndex) >= pieceCount {
					contaminationCount[e.ConnPtr]++
					n := contaminationCount[e.ConnPtr]
					if n == contaminationThreshold {
						logger.Error("CONTAMINATION: sustained incoming_have piece_index out of range",
							"hash", hash, "race_id", raceID,
							"piece_index", e.PieceIndex, "piece_count", pieceCount,
							"conn_ptr", fmt.Sprintf("0x%x", e.ConnPtr),
							"count", n)
						store.InsertRaceError(ctx, raceID, "piece_index_out_of_range",
							fmt.Sprintf("incoming_have piece_index %d >= piece_count %d from conn_ptr 0x%x (%d events)",
								e.PieceIndex, pieceCount, e.ConnPtr, n))
					}
					continue
				}
				peerHaveCount++
				connDBID, exists := connMap[e.ConnPtr]
				if !exists {
					connPtr := fmt.Sprintf("%x", e.ConnPtr)
					connDBID, err = store.InsertConnection(ctx, raceID, connPtr, time.Now())
					if err != nil {
						logger.Warn("failed to insert connection", "error", err, "ptr", e.ConnPtr)
						continue
					}
					connMap[e.ConnPtr] = connDBID
				}
				dbEvent.EventType = storage.EventTypeHave
				dbEvent.ConnectionID = connDBID
				dbEvent.Timestamp = int64(e.Timestamp)
				dbEvent.PieceIndex = int(e.PieceIndex)

			default:
				continue
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

			eventBatch = append(eventBatch, dbEvent)

			if len(eventBatch) >= batchSize {
				if err := flushEvents(); err != nil {
					logger.Warn("failed to flush event batch", "error", err)
				}
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

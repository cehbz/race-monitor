package race

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/cehbz/race-monitor/internal/bpf"
	"github.com/cehbz/race-monitor/internal/storage"
)

// msgMetadataUnavailable is logged when the metadata channel closes without
// delivering a piece count.
const msgMetadataUnavailable = "metadata unavailable, contamination detection inactive"

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

// raceTracker records one race: the events held while its start was pending,
// then live events, until it is finalized.
type raceTracker struct {
	store      *storage.Store
	logger     *slog.Logger
	hash       string
	raceID     int64
	startedAt  time.Time        // when the race's torrent started
	pieceCount int              // 0 when unknown: contamination detection is off
	backlog    []bpf.ProbeEvent // events held while the start was pending
	metaChan   <-chan int       // piece count delivered after the race started; nil when none
	dropped    *atomic.Int64    // events the coordinator dropped because the race fell behind
}

// run is the main event processing loop for a single race.
// It receives typed eBPF probe events, converts them to storage events, and
// persists them in batches.
//
// The downloadCompleteCh is closed by the coordinator when the download
// completes (torrent::finished() event). After that, the tracker runs a
// proportional grace period — 50% of the download duration, clamped to
// [5s, 60s] — then finalizes unconditionally. The grace timer never resets.
func (t *raceTracker) run(ctx context.Context, events <-chan bpf.ProbeEvent, downloadCompleteCh <-chan struct{}) error {
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

		// pieceCount starts at t.pieceCount; metaChan may set it later.
		// Zero means unknown: contamination detection is inactive.
		pieceCount = t.pieceCount
		metaChan   = t.metaChan

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
	selfConnID, err = t.store.InsertConnection(ctx, t.raceID, "self", time.Now())
	if err != nil {
		return fmt.Errorf("inserting self connection: %w", err)
	}

	flushEvents := func() error {
		if len(eventBatch) == 0 {
			return nil
		}
		if err := t.store.InsertPacketEvents(ctx, eventBatch); err != nil {
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
			metaChan = nil // one-shot: a closed channel is always ready, so stop selecting it
			if ok {
				pieceCount = pc
				t.logger.Info("metadata resolved", "hash", t.hash, "piece_count", pieceCount)
			} else {
				t.logger.Debug(msgMetadataUnavailable, "hash", t.hash)
			}

		case <-maxTimer.C:
			t.logger.Info("max duration reached", "hash", t.hash)
			if err := flushEvents(); err != nil {
				t.logger.Warn("failed to flush final events", "error", err)
			}
			return t.finalize(ctx)

		case <-downloadCompleteSel:
			// Download is complete. Start a proportional grace period.
			downloadCompleted = true
			downloadCompleteSel = nil // prevent re-entry (closed channels are always selectable)
			elapsed := time.Since(startTime)

			// No peers to monitor — finalize immediately
			if len(connMap) == 0 {
				t.logger.Info("download completed, no peers tracked",
					"hash", t.hash, "elapsed", elapsed)
				if err := flushEvents(); err != nil {
					t.logger.Warn("failed to flush final events", "error", err)
				}
				return t.finalize(ctx)
			}

			// Grace = 50% of download duration, clamped to [5s, 60s]
			grace := graceDuration(elapsed)
			graceTimer = time.NewTimer(grace)
			graceTimerCh = graceTimer.C
			defer graceTimer.Stop()
			t.logger.Info("download completed, grace period started",
				"hash", t.hash, "elapsed", elapsed,
				"grace", grace, "connections", len(connMap))

		case <-graceTimerCh:
			t.logger.Info("grace period expired",
				"hash", t.hash, "connections", len(connMap))
			if err := flushEvents(); err != nil {
				t.logger.Warn("failed to flush final events", "error", err)
			}
			return t.finalize(ctx)

		case ev, ok := <-events:
			if !ok {
				t.logger.Debug("event channel closed",
					"total_events", totalEvents,
					"we_have", weHaveCount,
					"peer_have", peerHaveCount)
				if err := flushEvents(); err != nil {
					t.logger.Warn("failed to flush final events", "error", err)
				}
				return t.finalize(ctx)
			}

			totalEvents++

			var dbEvent storage.Event
			dbEvent.RaceID = t.raceID

			switch e := ev.(type) {
			case *bpf.WeHaveEvent:
				if pieceCount > 0 && int(e.PieceIndex) >= pieceCount {
					contaminationCount[e.TorrentPtr]++
					n := contaminationCount[e.TorrentPtr]
					if n == contaminationThreshold {
						t.logger.Error("CONTAMINATION: sustained we_have piece_index out of range",
							"hash", t.hash, "race_id", t.raceID,
							"piece_index", e.PieceIndex, "piece_count", pieceCount,
							"torrent_ptr", fmt.Sprintf("0x%x", e.TorrentPtr),
							"count", n)
						t.store.InsertRaceError(ctx, t.raceID, "piece_index_out_of_range",
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
						t.logger.Error("CONTAMINATION: sustained incoming_have piece_index out of range",
							"hash", t.hash, "race_id", t.raceID,
							"piece_index", e.PieceIndex, "piece_count", pieceCount,
							"conn_ptr", fmt.Sprintf("0x%x", e.ConnPtr),
							"count", n)
						t.store.InsertRaceError(ctx, t.raceID, "piece_index_out_of_range",
							fmt.Sprintf("incoming_have piece_index %d >= piece_count %d from conn_ptr 0x%x (%d events)",
								e.PieceIndex, pieceCount, e.ConnPtr, n))
					}
					continue
				}
				peerHaveCount++
				connDBID, exists := connMap[e.ConnPtr]
				if !exists {
					connPtr := fmt.Sprintf("%x", e.ConnPtr)
					connDBID, err = t.store.InsertConnection(ctx, t.raceID, connPtr, time.Now())
					if err != nil {
						t.logger.Warn("failed to insert connection", "error", err, "ptr", e.ConnPtr)
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
				t.logger.Debug("race stats",
					"hash", t.hash,
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
					t.logger.Warn("failed to flush event batch", "error", err)
				}
			}
		}
	}
}

// finalize records the race's dropped events, if any, then completes it.
func (t *raceTracker) finalize(ctx context.Context) error {
	if t.dropped != nil {
		if n := t.dropped.Load(); n > 0 {
			t.store.InsertRaceError(ctx, t.raceID, raceErrorEventsDropped,
				fmt.Sprintf("%d events dropped: the race's event channel was full", n))
		}
	}
	return finalize(ctx, t.store, t.logger, t.raceID)
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

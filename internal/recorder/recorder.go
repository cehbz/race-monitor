// Package recorder implements race recording logic.
package recorder

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/cehbz/qbittorrent"
	"github.com/cehbz/race-monitor/internal/storage"
)

var (
	ErrTorrentNotFound = errors.New("torrent not found")
)

// Snapshot represents a point-in-time capture of torrent and peer data.
type Snapshot struct {
	Torrent   *qbittorrent.TorrentInfo
	PeersResp *qbittorrent.TorrentPeers
	Timestamp time.Time
}

// QBitClient defines the interface for qBittorrent operations needed by the recorder.
// This allows for easier testing with mock implementations.
type QBitClient interface {
	TorrentsInfo(params ...*qbittorrent.TorrentsInfoParams) ([]qbittorrent.TorrentInfo, error)
	SyncTorrentPeers(hash string, rid int) (*qbittorrent.TorrentPeers, error)
}

// Config holds recorder configuration.
type Config struct {
	// PollInterval is how often to sample (default 500ms).
	PollInterval time.Duration
	// MaxDuration is the maximum time to record a race.
	MaxDuration time.Duration
	// PostCompletionDuration is how long to record after 100%.
	PostCompletionDuration time.Duration
	// MinUploadRate stops recording if upload drops below this for StopAfterLowActivity.
	MinUploadRate int64
	// StopAfterLowActivity stops if upload is below MinUploadRate for this duration.
	StopAfterLowActivity time.Duration
	// DashboardURL is the URL to notify when a race starts (empty disables notifications).
	DashboardURL string
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{
		PollInterval:           500 * time.Millisecond,
		MaxDuration:            30 * time.Minute,
		PostCompletionDuration: 15 * time.Minute,
		MinUploadRate:          1024 * 1024, // 1 MB/s
		StopAfterLowActivity:   5 * time.Minute,
	}
}

// Recorder records race data.
type Recorder struct {
	client QBitClient
	store  *storage.Store
	config Config
	logger *slog.Logger
}

// New creates a new recorder.
func New(client QBitClient, store *storage.Store, config Config, logger *slog.Logger) *Recorder {
	return &Recorder{
		client: client,
		store:  store,
		config: config,
		logger: logger,
	}
}

// getTorrent retrieves a single torrent by hash.
func (r *Recorder) getTorrent(hash string) (*qbittorrent.TorrentInfo, error) {
	torrents, err := r.client.TorrentsInfo(&qbittorrent.TorrentsInfoParams{
		Hashes: []string{hash},
	})
	if err != nil {
		return nil, err
	}
	if len(torrents) == 0 {
		return nil, ErrTorrentNotFound
	}
	return &torrents[0], nil
}

// fetcher polls qBittorrent and sends snapshots to the channel.
// Runs in a separate goroutine.
func (r *Recorder) fetcher(ctx context.Context, hash string, snapshots chan<- Snapshot) {
	ticker := time.NewTicker(r.config.PollInterval)
	defer ticker.Stop()
	defer close(snapshots)

	rid := 0

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			torrent, err := r.getTorrent(hash)
			if err != nil {
				r.logger.Warn("failed to get torrent info", "error", err)
				continue
			}

			peersResp, err := r.client.SyncTorrentPeers(hash, rid)
			if err != nil {
				r.logger.Warn("failed to get peers", "error", err)
				continue
			}
			rid = peersResp.Rid

			snapshots <- Snapshot{
				Torrent:   torrent,
				PeersResp: peersResp,
				Timestamp: time.Now(),
			}
		}
	}
}

// Record starts recording a race for the given torrent hash.
// It blocks until the race is complete or the context is cancelled.
func (r *Recorder) Record(ctx context.Context, hash string) error {
	// Get initial torrent info
	torrent, err := r.getTorrent(hash)
	if err != nil {
		return err
	}

	r.logger.Info("starting race recording",
		"hash", hash,
		"name", torrent.Name,
		"size", torrent.Size)

	// Create race record
	raceID, err := r.store.CreateRace(ctx, hash, torrent.Name, torrent.Size)
	if err != nil {
		return err
	}

	// Notify dashboard of new race (fire-and-forget)
	if r.config.DashboardURL != "" {
		go func() {
			payload := map[string]int64{"race_id": raceID}
			data, _ := json.Marshal(payload)
			client := &http.Client{Timeout: 2 * time.Second}
			client.Post(r.config.DashboardURL+"/api/notify", "application/json", bytes.NewBuffer(data))
		}()
	}

	// Start fetcher goroutine
	snapshots := make(chan Snapshot, 30) // Buffer for ~15 seconds at 500ms
	fetcherCtx, cancelFetcher := context.WithCancel(ctx)
	defer cancelFetcher()

	go r.fetcher(fetcherCtx, hash, snapshots)

	// Process snapshots
	return r.processor(ctx, raceID, hash, snapshots)
}

// processor handles snapshot processing, initial swarm tracking, and termination logic.
func (r *Recorder) processor(ctx context.Context, raceID int64, hash string, snapshots <-chan Snapshot) error {
	var (
		startTime        = time.Now()
		peers            = make(map[string]qbittorrent.TorrentPeer)
		initialSwarm     = make(map[string]bool)      // Track peers seen while downloading
		initialSwarmDone = make(map[string]time.Time) // Track when peers completed/disappeared
		stillDownloading = true
		peerLastSeen     = make(map[string]time.Time)
		prevSample       *storage.Sample // Track previous sample to skip duplicates
	)

	const peerDisappearThreshold = 2 * time.Minute

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("recording cancelled", "hash", hash)
			return ctx.Err()

		case snapshot, ok := <-snapshots:
			if !ok {
				// Fetcher closed channel (shouldn't happen normally)
				return r.finalize(ctx, raceID)
			}

			elapsed := time.Since(startTime)
			torrent := snapshot.Torrent
			now := snapshot.Timestamp

			// Check max duration safety valve
			if elapsed > r.config.MaxDuration {
				r.logger.Info("max duration reached", "hash", hash, "elapsed", elapsed)
				return r.finalize(ctx, raceID)
			}

			// Merge peer updates
			if snapshot.PeersResp.FullUpdate {
				peers = snapshot.PeersResp.Peers
			} else {
				for k, v := range snapshot.PeersResp.Peers {
					peers[k] = v
				}
			}

			// Update peer last seen times
			for key := range peers {
				peerLastSeen[key] = now
			}

			// Track initial swarm: add peers seen while we're still downloading
			if stillDownloading {
				for key := range peers {
					if !initialSwarm[key] {
						initialSwarm[key] = true
						r.logger.Debug("added peer to initial swarm", "peer", key)
					}
				}
			}

			// Check if we've completed downloading
			if torrent.Progress >= 1.0 && stillDownloading {
				stillDownloading = false
				r.logger.Info("download completed, initial swarm locked",
					"hash", hash,
					"time_to_complete", elapsed,
					"initial_swarm_size", len(initialSwarm))
			}

			// Track initial swarm completion/disappearance
			if !stillDownloading {
				for peerKey := range initialSwarm {
					if _, done := initialSwarmDone[peerKey]; done {
						continue
					}

					peer, exists := peers[peerKey]
					if exists {
						// Peer still present
						if peer.Progress >= 1.0 {
							initialSwarmDone[peerKey] = now
							r.logger.Debug("initial swarm peer completed", "peer", peerKey)
						}
					} else {
						// Peer disappeared - check if beyond threshold
						lastSeen, seen := peerLastSeen[peerKey]
						if seen && now.Sub(lastSeen) > peerDisappearThreshold {
							initialSwarmDone[peerKey] = now
							r.logger.Debug("initial swarm peer disappeared", "peer", peerKey)
						}
					}
				}

				// Check if all initial swarm peers are done
				if len(initialSwarmDone) >= len(initialSwarm) {
					r.logger.Info("all initial swarm peers completed",
						"hash", hash,
						"elapsed", elapsed,
						"initial_swarm_size", len(initialSwarm))
					return r.finalize(ctx, raceID)
				}
			}

			// Calculate our rank among uploaders
			rank := r.calculateRank(torrent.UpSpeed, peers)

			// Record our sample (skip if unchanged from previous to avoid 1Hz API duplication)
			sample := &storage.Sample{
				RaceID:       raceID,
				Timestamp:    now,
				UploadRate:   torrent.UpSpeed,
				DownloadRate: torrent.DLSpeed,
				Progress:     torrent.Progress,
				Uploaded:     torrent.Uploaded,
				Downloaded:   torrent.Downloaded,
				PeerCount:    int(torrent.NumLeechs),
				SeedCount:    int(torrent.NumSeeds),
				MyRank:       rank,
			}

			// Skip if data unchanged from previous sample (qBittorrent API updates at 1Hz)
			skipSample := prevSample != nil &&
				prevSample.Uploaded == sample.Uploaded &&
				prevSample.Downloaded == sample.Downloaded &&
				prevSample.Progress == sample.Progress

			if !skipSample {
				if err := r.store.InsertSample(ctx, sample); err != nil {
					r.logger.Warn("failed to insert sample", "error", err)
				}
				prevSample = sample
			}

			// Normalize and record peer samples
			if err := r.recordPeerSamples(ctx, raceID, now, peers); err != nil {
				r.logger.Warn("failed to insert peer samples", "error", err)
			}

			// Log progress periodically (every 10 seconds)
			if int(elapsed.Seconds())%10 == 0 && elapsed.Milliseconds()%1000 < int64(r.config.PollInterval.Milliseconds()) {
				swarmStatus := "tracking"
				if !stillDownloading {
					swarmStatus = fmt.Sprintf("%d/%d done", len(initialSwarmDone), len(initialSwarm))
				}
				r.logger.Info("race progress",
					"hash", truncateHash(hash),
					"progress", torrent.Progress,
					"upload", formatRate(torrent.UpSpeed),
					"download", formatRate(torrent.DLSpeed),
					"rank", rank,
					"peers", len(peers),
					"swarm", swarmStatus)
			}
		}
	}
}

// recordPeerSamples normalizes peer data and inserts into database.
func (r *Recorder) recordPeerSamples(ctx context.Context, raceID int64, timestamp time.Time, peers map[string]qbittorrent.TorrentPeer) error {
	if len(peers) == 0 {
		return nil
	}

	// Map to store peer IDs
	peerIDs := make(map[string]int64)

	// First, upsert all peers to get their IDs
	for key, p := range peers {
		peer := &storage.Peer{
			IP:         p.IP,
			Port:       p.Port,
			Client:     p.Client,
			Country:    p.Country,
			Connection: p.Connection,
			Flags:      p.Flags,
		}

		peerID, err := r.store.UpsertPeer(ctx, peer)
		if err != nil {
			return fmt.Errorf("upserting peer %s: %w", key, err)
		}
		peerIDs[key] = peerID
	}

	// Build peer samples with peer IDs
	peerSamples := make([]storage.PeerSample, 0, len(peers))
	for key, p := range peers {
		// Record all peers (not just uploaders) to track download performance
		peerSamples = append(peerSamples, storage.PeerSample{
			RaceID:       raceID,
			PeerID:       peerIDs[key],
			Timestamp:    timestamp,
			UploadRate:   p.UPSpeed,
			DownloadRate: p.DLSpeed,
			Progress:     p.Progress,
			Uploaded:     p.Uploaded,
			Downloaded:   p.Downloaded,
		})
	}

	return r.store.InsertPeerSamples(ctx, peerSamples)
}

// CalculateRank determines our position among uploaders (exported for testing).
// Returns 1 if we're the top uploader, 2 if second, etc.
func (r *Recorder) CalculateRank(myUploadSpeed int64, peers map[string]qbittorrent.TorrentPeer) int {
	return r.calculateRank(myUploadSpeed, peers)
}

// calculateRank determines our position among uploaders.
// Returns 1 if we're the top uploader, 2 if second, etc.
func (r *Recorder) calculateRank(myUploadSpeed int64, peers map[string]qbittorrent.TorrentPeer) int {
	// Collect upload speeds of all peers who are seeding (uploading to others)
	var speeds []int64
	for _, p := range peers {
		// Peers with progress >= 1.0 are seeders, their UPSpeed is their upload to others
		if p.Progress >= 1.0 && p.UPSpeed > 0 {
			speeds = append(speeds, p.UPSpeed)
		}
	}

	// Sort descending
	slices.SortFunc(speeds, func(a, b int64) int {
		if b > a {
			return 1
		} else if b < a {
			return -1
		}
		return 0
	})

	// Find our rank
	rank := 1
	for _, speed := range speeds {
		if speed > myUploadSpeed {
			rank++
		} else {
			break
		}
	}

	return rank
}

func (r *Recorder) finalize(ctx context.Context, raceID int64) error {
	if err := r.store.CompleteRace(ctx, raceID); err != nil {
		return err
	}

	stats, err := r.store.GetRaceStats(ctx, raceID)
	if err != nil {
		r.logger.Warn("failed to compute stats", "error", err)
		return nil
	}

	r.logger.Info("race complete",
		"name", stats.Name,
		"time_to_complete", stats.TimeToComplete,
		"total_uploaded", formatBytes(stats.TotalUploaded),
		"peak_upload", formatRate(stats.PeakUploadRate),
		"avg_upload", formatRate(stats.AvgUploadRate),
		"best_rank", stats.BestRank,
		"completion_rank", stats.CompletionRank,
		"upload_rank", stats.UploadRank,
		"uploaded_5m", formatBytes(stats.UploadedFirst5m),
		"uploaded_15m", formatBytes(stats.UploadedFirst15m))

	return nil
}

func truncateHash(hash string) string {
	if len(hash) > 8 {
		return hash[:8]
	}
	return hash
}

func formatRate(bytesPerSec int64) string {
	return formatBytes(bytesPerSec) + "/s"
}

func formatBytes(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	var val float64
	var unit string

	switch {
	case bytes >= GB:
		val, unit = float64(bytes)/GB, "GB"
	case bytes >= MB:
		val, unit = float64(bytes)/MB, "MB"
	case bytes >= KB:
		val, unit = float64(bytes)/KB, "KB"
	default:
		val, unit = float64(bytes), "B"
	}

	// Format with 1 decimal place using string manipulation
	whole := int64(val)
	frac := int64((val - float64(whole)) * 10)
	if frac < 0 {
		frac = -frac
	}

	return intToStr(whole) + "." + intToStr(frac) + " " + unit
}

func intToStr(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	digits := make([]byte, 0, 20)
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

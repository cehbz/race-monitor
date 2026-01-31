// Package recorder implements race recording logic.
package recorder

import (
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/cehbz/qbittorrent"
	"github.com/cehbz/race-monitor/internal/storage"
)

var (
	ErrTorrentNotFound = errors.New("torrent not found")
)

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

	// Track state for stop conditions
	var (
		completedAt      time.Time
		lowActivitySince time.Time
		lastRank         int
		rid              int // For sync API delta updates
		peers            = make(map[string]qbittorrent.TorrentPeer)
	)

	ticker := time.NewTicker(r.config.PollInterval)
	defer ticker.Stop()

	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			r.logger.Info("recording cancelled", "hash", hash)
			return ctx.Err()

		case <-ticker.C:
			elapsed := time.Since(startTime)

			// Check max duration
			if elapsed > r.config.MaxDuration {
				r.logger.Info("max duration reached", "hash", hash, "elapsed", elapsed)
				return r.finalize(ctx, raceID, lastRank)
			}

			// Check post-completion duration
			if !completedAt.IsZero() && time.Since(completedAt) > r.config.PostCompletionDuration {
				r.logger.Info("post-completion recording complete",
					"hash", hash,
					"time_since_complete", time.Since(completedAt))
				return r.finalize(ctx, raceID, lastRank)
			}

			// Get current torrent state
			torrent, err = r.getTorrent(hash)
			if err != nil {
				r.logger.Warn("failed to get torrent info", "error", err)
				continue
			}

			// Get peer data using sync endpoint
			peersResp, err := r.client.SyncTorrentPeers(hash, rid)
			if err != nil {
				r.logger.Warn("failed to get peers", "error", err)
				continue
			}
			rid = peersResp.Rid

			// Merge peer updates
			if peersResp.FullUpdate {
				peers = peersResp.Peers
			} else {
				for k, v := range peersResp.Peers {
					peers[k] = v
				}
			}

			// Calculate our rank among uploaders
			rank := r.calculateRank(torrent.UpSpeed, peers)
			lastRank = rank

			now := time.Now()

			// Record sample
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
			if err := r.store.InsertSample(ctx, sample); err != nil {
				r.logger.Warn("failed to insert sample", "error", err)
			}

			// Record peer samples (only seeders/uploaders matter for racing)
			peerSamples := make([]storage.PeerSample, 0, len(peers))
			for _, p := range peers {
				// Only record peers that are uploading (our competition)
				if p.UPSpeed > 0 || p.Progress >= 1.0 {
					peerSamples = append(peerSamples, storage.PeerSample{
						RaceID:     raceID,
						Timestamp:  now,
						PeerIP:     p.IP,
						PeerClient: p.Client,
						UploadRate: p.UPSpeed,
						Progress:   p.Progress,
						Uploaded:   p.Uploaded,
					})
				}
			}
			if err := r.store.InsertPeerSamples(ctx, peerSamples); err != nil {
				r.logger.Warn("failed to insert peer samples", "error", err)
			}

			// Track completion
			if torrent.Progress >= 1.0 && completedAt.IsZero() {
				completedAt = now
				r.logger.Info("torrent completed",
					"hash", hash,
					"time_to_complete", elapsed,
					"rank", rank)
			}

			// Track low activity
			if torrent.UpSpeed < r.config.MinUploadRate {
				if lowActivitySince.IsZero() {
					lowActivitySince = now
				} else if time.Since(lowActivitySince) > r.config.StopAfterLowActivity {
					r.logger.Info("stopping due to low activity",
						"hash", hash,
						"upload_rate", torrent.UpSpeed)
					return r.finalize(ctx, raceID, lastRank)
				}
			} else {
				lowActivitySince = time.Time{}
			}

			// Log progress periodically (every 10 seconds)
			if int(elapsed.Seconds())%10 == 0 && elapsed.Milliseconds()%1000 < int64(r.config.PollInterval.Milliseconds()) {
				r.logger.Info("race progress",
					"hash", truncateHash(hash),
					"progress", torrent.Progress,
					"upload", formatRate(torrent.UpSpeed),
					"download", formatRate(torrent.DLSpeed),
					"rank", rank,
					"peers", len(peers))
			}
		}
	}
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

func (r *Recorder) finalize(ctx context.Context, raceID int64, finalRank int) error {
	if err := r.store.CompleteRace(ctx, raceID, finalRank); err != nil {
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
		"final_rank", stats.FinalRank,
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

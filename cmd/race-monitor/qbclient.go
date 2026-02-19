package main

import (
	"fmt"
	"log/slog"
	"sync"

	"github.com/cehbz/qbittorrent"
	"github.com/cehbz/race-monitor/internal/race"
)

// qbSyncClient implements race.EnrichmentAPI using qBittorrent's web API.
// Provides torrent names and piece counts for race enrichment.
type qbSyncClient struct {
	client *qbittorrent.Client
	logger *slog.Logger
	rid    int
	mu     sync.Mutex
}

// newQBSyncClient creates a client for API-based enrichment. Returns nil if
// webuiURL is empty or client creation fails.
func newQBSyncClient(webuiURL, user, pass string, logger *slog.Logger) (race.EnrichmentAPI, error) {
	if webuiURL == "" {
		return nil, nil
	}
	client, err := qbittorrent.NewClient(user, pass, webuiURL)
	if err != nil {
		return nil, err
	}
	return &qbSyncClient{client: client, logger: logger, rid: 0}, nil
}

// Sync implements race.EnrichmentAPI.
func (q *qbSyncClient) Sync() (map[string]race.TorrentMeta, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	mainData, err := q.client.SyncMainData(q.rid)
	if err != nil {
		return nil, err
	}
	q.rid = mainData.Rid

	result := make(map[string]race.TorrentMeta, len(mainData.Torrents))
	for h, info := range mainData.Torrents {
		result[h] = race.TorrentMeta{
			Name: info.Name,
			Size: info.Size,
		}
		if q.logger != nil && q.logger.Enabled(nil, slog.LevelDebug) {
			q.logger.Debug("enrichment: sync torrent",
				"hash", h,
				"name", info.Name,
				"size", info.Size)
		}
	}
	return result, nil
}

// FetchTorrentMeta implements race.EnrichmentAPI.
// Calls TorrentsProperties for piece_count (PiecesNum) and total_size.
// Name is NOT populated by the properties endpoint; caller should fall back
// to the Sync cache for the torrent name.
func (q *qbSyncClient) FetchTorrentMeta(hash string) (race.TorrentMeta, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	props, err := q.client.TorrentsProperties(hash)
	if err != nil {
		return race.TorrentMeta{}, fmt.Errorf("fetching torrent properties: %w", err)
	}
	return race.TorrentMeta{
		Size:       props.TotalSize,
		PieceCount: int(props.PiecesNum),
	}, nil
}

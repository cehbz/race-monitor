package main

import (
	"fmt"
	"log/slog"

	"github.com/cehbz/qbittorrent"
	"github.com/cehbz/race-monitor/internal/race"
)

// qbClient implements race.EnrichmentAPI using qBittorrent's web API.
// Provides torrent names and piece counts for race enrichment.
type qbClient struct {
	client *qbittorrent.Client
	logger *slog.Logger
}

// newQBClient creates a client for API-based enrichment. Returns nil if
// webuiURL is empty or client creation fails.
func newQBClient(webuiURL, user, pass string, logger *slog.Logger) (race.EnrichmentAPI, error) {
	if webuiURL == "" {
		return nil, nil
	}
	client, err := qbittorrent.NewClient(user, pass, webuiURL)
	if err != nil {
		return nil, err
	}
	return &qbClient{client: client, logger: logger}, nil
}

// FetchTorrentMeta implements race.EnrichmentAPI.
// Calls TorrentsProperties for name, piece_count (PiecesNum), and total_size.
func (q *qbClient) FetchTorrentMeta(hash string) (race.TorrentMeta, error) {
	props, err := q.client.TorrentsProperties(hash)
	if err != nil {
		return race.TorrentMeta{}, fmt.Errorf("fetching torrent properties: %w", err)
	}
	return race.TorrentMeta{
		Name:       props.Name,
		Size:       props.TotalSize,
		PieceCount: int(props.PiecesNum),
	}, nil
}

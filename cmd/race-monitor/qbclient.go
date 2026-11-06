package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/cehbz/qbittorrent/v2"
	"github.com/cehbz/race-monitor/internal/race"
)

// qbResponseTimeout bounds how long the WebUI may take to start answering.
const qbResponseTimeout = 5 * time.Second

// qbClient implements race.EnrichmentAPI using qBittorrent's web API.
// Provides torrent names, piece counts and addition dates for race enrichment.
// It logs in on first use, since the WebUI may not be up when the daemon starts,
// so a failed call can succeed on retry. Not safe for concurrent use: the
// coordinator's metadata resolver is the only caller.
type qbClient struct {
	webuiURL string
	user     string
	pass     string
	http     *http.Client
	client   *qbittorrent.Client // nil until a login succeeds
}

// newQBClient creates a client for API-based enrichment.
func newQBClient(webuiURL, user, pass string, responseTimeout time.Duration) *qbClient {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.ResponseHeaderTimeout = responseTimeout
	return &qbClient{
		webuiURL: webuiURL,
		user:     user,
		pass:     pass,
		http:     &http.Client{Transport: transport},
	}
}

// FetchTorrentMeta implements race.EnrichmentAPI.
// Calls TorrentsProperties for name, piece_count (PiecesNum), total_size and
// addition_date.
func (q *qbClient) FetchTorrentMeta(hash string) (race.TorrentMeta, error) {
	if q.client == nil {
		client, err := qbittorrent.NewClient(q.user, q.pass, q.webuiURL, q.http)
		if err != nil {
			return race.TorrentMeta{}, fmt.Errorf("connecting to qBittorrent: %w", err)
		}
		q.client = client
	}
	props, err := q.client.TorrentsProperties(hash)
	if err != nil {
		return race.TorrentMeta{}, fmt.Errorf("fetching torrent properties: %w", err)
	}
	return race.TorrentMeta{
		Name:       props.Name,
		Size:       props.TotalSize,
		PieceCount: int(props.PiecesNum),
		AddedAt:    props.AdditionDate,
	}, nil
}

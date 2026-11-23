package main

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/cehbz/qbittorrent/v2"
	"github.com/cehbz/race-monitor/internal/race"
)

// qbResponseTimeout bounds how long the WebUI may take to start answering.
const qbResponseTimeout = 5 * time.Second

// qbClient implements race.EnrichmentAPI using qBittorrent's web API.
// Provides torrent names, piece counts and addition dates for race enrichment.
// It logs in on first use, since the WebUI may not be up when the daemon starts,
// so a failed call can succeed on retry. Safe for concurrent use: each pending
// start's classifier calls it from its own goroutine.
type qbClient struct {
	webuiURL string
	user     string
	pass     string
	http     *http.Client

	mu     sync.Mutex
	client *qbittorrent.Client // nil until a login succeeds; guarded by mu
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
	client, err := q.loggedIn()
	if err != nil {
		return race.TorrentMeta{}, err
	}
	props, err := client.TorrentsProperties(hash)
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

// loggedIn returns the client, logging in first if no login has succeeded. The
// login runs outside the lock, so concurrent callers don't queue behind a hung
// one; the first to succeed is kept and any duplicate is discarded.
func (q *qbClient) loggedIn() (*qbittorrent.Client, error) {
	q.mu.Lock()
	client := q.client
	q.mu.Unlock()
	if client != nil {
		return client, nil
	}

	client, err := qbittorrent.NewClient(q.user, q.pass, q.webuiURL, q.http)
	if err != nil {
		return nil, fmt.Errorf("connecting to qBittorrent: %w", err)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.client == nil {
		q.client = client
	}
	return q.client, nil
}

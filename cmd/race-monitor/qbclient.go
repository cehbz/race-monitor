package main

import (
	"log/slog"
	"net/netip"
	"strconv"
	"sync"

	"github.com/cehbz/qbittorrent"
	"github.com/cehbz/race-monitor/internal/race"
)

// qbSyncClient implements race.TorrentCalibrationAPI using qBittorrent's
// sync/maindata endpoint. Maintains rid internally for incremental sync.
type qbSyncClient struct {
	client    *qbittorrent.Client
	logger    *slog.Logger
	rid       int
	peerRids  map[string]int // hash -> rid for SyncTorrentPeers
	mu        sync.Mutex
}

// newQBSyncClient creates a client for API-based calibration. Returns nil if
// webuiURL is empty or client creation fails.
func newQBSyncClient(webuiURL, user, pass string, logger *slog.Logger) (race.TorrentCalibrationAPI, error) {
	if webuiURL == "" {
		return nil, nil
	}
	client, err := qbittorrent.NewClient(user, pass, webuiURL)
	if err != nil {
		return nil, err
	}
	return &qbSyncClient{client: client, logger: logger, rid: 0, peerRids: make(map[string]int)}, nil
}

// Sync implements race.TorrentCalibrationAPI.
func (q *qbSyncClient) Sync() (map[string]race.TorrentMeta, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	mainData, err := q.client.SyncMainData(q.rid)
	if err != nil {
		return nil, err
	}
	q.rid = mainData.Rid

	torrents := make(map[string]race.TorrentMeta, len(mainData.Torrents))
	for h, info := range mainData.Torrents {
		torrents[h] = race.TorrentMeta{
			Name: info.Name,
			Size: info.Size,
		}
		if q.logger != nil && q.logger.Enabled(nil, slog.LevelDebug) {
			q.logger.Debug("torrent calibration: sync/maindata torrent",
				"hash", h,
				"name", info.Name)
		}
	}
	return torrents, nil
}

// FetchTorrentMeta implements race.TorrentCalibrationAPI.
func (q *qbSyncClient) FetchTorrentMeta(hash string) (race.TorrentMeta, error) {
	props, err := q.client.TorrentsProperties(hash)
	if err != nil {
		return race.TorrentMeta{}, err
	}
	return race.TorrentMeta{
		Name:       props.Name,
		Size:       props.TotalSize,
		PieceCount: int(props.PiecesNum),
	}, nil
}

// SyncPeers implements race.TorrentCalibrationAPI.
func (q *qbSyncClient) SyncPeers(hash string) ([]race.PeerInfo, error) {
	q.mu.Lock()
	rid := q.peerRids[hash]
	q.mu.Unlock()

	peersData, err := q.client.SyncTorrentPeers(hash, rid)
	if err != nil {
		return nil, err
	}

	q.mu.Lock()
	q.peerRids[hash] = peersData.Rid
	q.mu.Unlock()

	out := make([]race.PeerInfo, 0, len(peersData.Peers))
	for _, p := range peersData.Peers {
		addr, err := netip.ParseAddrPort(p.IP + ":" + strconv.Itoa(p.Port))
		if err != nil {
			continue
		}
		out = append(out, race.PeerInfo{
			Addr:   addr,
			PeerID: p.PeerIDClient,
		})
	}
	return out, nil
}

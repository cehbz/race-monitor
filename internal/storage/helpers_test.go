package storage

import (
	"context"
)

// Test-only methods on Store. These are not part of the production API but are
// used by storage_test (external test package) to verify internal state.

// GetRacePeers returns all API-sourced peers for a race.
func (s *Store) GetRacePeers(ctx context.Context, raceID int64) ([]RacePeer, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, race_id, ip, port, client, peer_id, country,
		        progress, dl_speed, up_speed, first_seen, last_seen
		FROM race_peers WHERE race_id = ?
		ORDER BY ip, port`, raceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []RacePeer
	for rows.Next() {
		var p RacePeer
		if err := rows.Scan(&p.ID, &p.RaceID, &p.IP, &p.Port,
			&p.Client, &p.PeerID, &p.Country,
			&p.Progress, &p.DLSpeed, &p.UPSpeed,
			&p.FirstSeen, &p.LastSeen); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}

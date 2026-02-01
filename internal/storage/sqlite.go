// Package storage provides SQLite storage for race data.
package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

var ErrRaceNotFound = errors.New("race not found")

// Store handles SQLite storage operations.
type Store struct {
	db *sql.DB
}

// Race represents a recorded race.
type Race struct {
	ID          int64
	Hash        string
	Name        string
	Size        int64
	StartedAt   time.Time
	CompletedAt sql.NullTime
}

// Sample represents a point-in-time snapshot during a race.
type Sample struct {
	RaceID        int64
	Timestamp     time.Time
	UploadRate    int64
	DownloadRate  int64
	Progress      float64
	Uploaded      int64
	Downloaded    int64
	PeerCount     int
	SeedCount     int
	MyRank        int // Position among uploaders (1 = top)
}

// Peer represents a unique peer identified by IP and port.
type Peer struct {
	ID         int64
	IP         string
	Port       int
	Client     string
	Country    string
	Connection string
	Flags      string
}

// PeerSample represents a peer's state at a point in time.
type PeerSample struct {
	RaceID       int64
	PeerID       int64
	Timestamp    time.Time
	UploadRate   int64
	DownloadRate int64
	Progress     float64
	Uploaded     int64
	Downloaded   int64
}

// New creates a new SQLite store.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Enable WAL mode for better concurrent performance
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	// Set busy timeout to handle concurrent writes
	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting busy timeout: %w", err)
	}

	// Enable foreign keys
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration: %w", err)
	}

	return s, nil
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS races (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hash TEXT NOT NULL,
		name TEXT NOT NULL,
		size INTEGER NOT NULL,
		started_at TIMESTAMP NOT NULL,
		completed_at TIMESTAMP,
		UNIQUE(hash, started_at)
	);

	CREATE INDEX IF NOT EXISTS idx_races_hash ON races(hash);
	CREATE INDEX IF NOT EXISTS idx_races_started_at ON races(started_at);

	CREATE TABLE IF NOT EXISTS samples (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		race_id INTEGER NOT NULL REFERENCES races(id) ON DELETE CASCADE,
		ts TIMESTAMP NOT NULL,
		upload_rate INTEGER NOT NULL,
		download_rate INTEGER NOT NULL,
		progress REAL NOT NULL,
		uploaded INTEGER NOT NULL,
		downloaded INTEGER NOT NULL,
		peer_count INTEGER NOT NULL,
		seed_count INTEGER NOT NULL,
		my_rank INTEGER NOT NULL,
		UNIQUE(race_id, ts)
	);

	CREATE INDEX IF NOT EXISTS idx_samples_race_id ON samples(race_id);
	CREATE INDEX IF NOT EXISTS idx_samples_race_ts ON samples(race_id, ts);

	CREATE TABLE IF NOT EXISTS peers (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip TEXT NOT NULL,
		port INTEGER NOT NULL,
		client TEXT NOT NULL,
		country TEXT,
		connection TEXT,
		flags TEXT,
		UNIQUE(ip, port)
	);

	CREATE INDEX IF NOT EXISTS idx_peers_ip ON peers(ip);
	CREATE INDEX IF NOT EXISTS idx_peers_client ON peers(client);

	CREATE TABLE IF NOT EXISTS peer_samples (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		race_id INTEGER NOT NULL REFERENCES races(id) ON DELETE CASCADE,
		peer_id INTEGER NOT NULL REFERENCES peers(id),
		ts TIMESTAMP NOT NULL,
		upload_rate INTEGER NOT NULL,
		download_rate INTEGER NOT NULL,
		progress REAL NOT NULL,
		uploaded INTEGER NOT NULL,
		downloaded INTEGER NOT NULL,
		UNIQUE(race_id, peer_id, ts)
	);

	CREATE INDEX IF NOT EXISTS idx_peer_samples_race_peer ON peer_samples(race_id, peer_id);
	CREATE INDEX IF NOT EXISTS idx_peer_samples_peer_ts ON peer_samples(peer_id, ts);
	CREATE INDEX IF NOT EXISTS idx_peer_samples_race_ts ON peer_samples(race_id, ts);
	`

	_, err := s.db.Exec(schema)
	return err
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// CreateRace creates a new race record.
func (s *Store) CreateRace(ctx context.Context, hash, name string, size int64) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		"INSERT INTO races (hash, name, size, started_at) VALUES (?, ?, ?, ?)",
		hash, name, size, time.Now().UTC())
	if err != nil {
		return 0, fmt.Errorf("inserting race: %w", err)
	}
	return result.LastInsertId()
}

// CompleteRace marks a race as completed.
func (s *Store) CompleteRace(ctx context.Context, raceID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE races SET completed_at = ? WHERE id = ?`,
		time.Now().UTC(), raceID)
	return err
}

// InsertSample inserts a sample for a race.
func (s *Store) InsertSample(ctx context.Context, sample *Sample) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO samples
		(race_id, ts, upload_rate, download_rate, progress, uploaded, downloaded, peer_count, seed_count, my_rank)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		sample.RaceID, sample.Timestamp.UTC(), sample.UploadRate, sample.DownloadRate,
		sample.Progress, sample.Uploaded, sample.Downloaded,
		sample.PeerCount, sample.SeedCount, sample.MyRank)
	return err
}

// UpsertPeer inserts or updates a peer and returns its ID.
func (s *Store) UpsertPeer(ctx context.Context, peer *Peer) (int64, error) {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO peers (ip, port, client, country, connection, flags)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(ip, port) DO UPDATE SET
			client = excluded.client,
			country = excluded.country,
			connection = excluded.connection,
			flags = excluded.flags`,
		peer.IP, peer.Port, peer.Client, peer.Country, peer.Connection, peer.Flags)
	if err != nil {
		return 0, fmt.Errorf("upserting peer: %w", err)
	}

	// Get the peer ID
	var peerID int64
	err = s.db.QueryRowContext(ctx,
		"SELECT id FROM peers WHERE ip = ? AND port = ?",
		peer.IP, peer.Port).Scan(&peerID)
	if err != nil {
		return 0, fmt.Errorf("getting peer ID: %w", err)
	}

	return peerID, nil
}

// InsertPeerSamples inserts multiple peer samples in a single transaction.
// Assumes peer records already exist (call UpsertPeer first).
func (s *Store) InsertPeerSamples(ctx context.Context, samples []PeerSample) error {
	if len(samples) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO peer_samples (race_id, peer_id, ts, upload_rate, download_rate, progress, uploaded, downloaded)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	for _, ps := range samples {
		if _, err := stmt.ExecContext(ctx,
			ps.RaceID, ps.PeerID, ps.Timestamp.UTC(),
			ps.UploadRate, ps.DownloadRate, ps.Progress, ps.Uploaded, ps.Downloaded); err != nil {
			return fmt.Errorf("inserting peer sample: %w", err)
		}
	}

	return tx.Commit()
}

// GetRace retrieves a race by ID.
func (s *Store) GetRace(ctx context.Context, id int64) (*Race, error) {
	var r Race
	err := s.db.QueryRowContext(ctx,
		`SELECT id, hash, name, size, started_at, completed_at FROM races WHERE id = ?`,
		id).Scan(&r.ID, &r.Hash, &r.Name, &r.Size, &r.StartedAt, &r.CompletedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRaceNotFound
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// ListRecentRaces lists races from the last N days.
func (s *Store) ListRecentRaces(ctx context.Context, days int) ([]Race, error) {
	since := time.Now().AddDate(0, 0, -days)
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, hash, name, size, started_at, completed_at
		FROM races WHERE started_at > ? ORDER BY started_at DESC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var races []Race
	for rows.Next() {
		var r Race
		if err := rows.Scan(&r.ID, &r.Hash, &r.Name, &r.Size, &r.StartedAt, &r.CompletedAt); err != nil {
			return nil, err
		}
		races = append(races, r)
	}
	return races, rows.Err()
}

// GetRaceSamples retrieves all samples for a race.
func (s *Store) GetRaceSamples(ctx context.Context, raceID int64) ([]Sample, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT race_id, ts, upload_rate, download_rate, progress, uploaded, downloaded, peer_count, seed_count, my_rank
		FROM samples WHERE race_id = ? ORDER BY ts`, raceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var samples []Sample
	for rows.Next() {
		var s Sample
		if err := rows.Scan(&s.RaceID, &s.Timestamp, &s.UploadRate, &s.DownloadRate,
			&s.Progress, &s.Uploaded, &s.Downloaded, &s.PeerCount, &s.SeedCount, &s.MyRank); err != nil {
			return nil, err
		}
		samples = append(samples, s)
	}
	return samples, rows.Err()
}

// RaceStats contains computed statistics for a race.
type RaceStats struct {
	RaceID           int64
	Name             string
	Duration         time.Duration
	TimeToComplete   time.Duration
	TotalUploaded    int64
	PeakUploadRate   int64
	AvgUploadRate    int64
	BestRank         int
	AvgRank          float64
	CompletionRank   int   // Rank based on download completion time (1 = first to finish)
	UploadRank       int   // Rank based on total upload during initial swarm (1 = most uploaded)
	UploadedFirst5m  int64
	UploadedFirst15m int64
}

// GetRaceStats computes statistics for a race.
func (s *Store) GetRaceStats(ctx context.Context, raceID int64) (*RaceStats, error) {
	race, err := s.GetRace(ctx, raceID)
	if err != nil {
		return nil, err
	}

	samples, err := s.GetRaceSamples(ctx, raceID)
	if err != nil {
		return nil, err
	}

	if len(samples) == 0 {
		return nil, fmt.Errorf("no samples for race %d", raceID)
	}

	stats := &RaceStats{
		RaceID:   raceID,
		Name:     race.Name,
		BestRank: 999999,
	}

	if race.CompletedAt.Valid {
		stats.Duration = race.CompletedAt.Time.Sub(race.StartedAt)
	}

	var totalRank int64
	var completedAt time.Time

	for _, sample := range samples {
		if sample.UploadRate > stats.PeakUploadRate {
			stats.PeakUploadRate = sample.UploadRate
		}
		if sample.MyRank < stats.BestRank && sample.MyRank > 0 {
			stats.BestRank = sample.MyRank
		}
		totalRank += int64(sample.MyRank)

		elapsed := sample.Timestamp.Sub(race.StartedAt)
		if elapsed <= 5*time.Minute {
			stats.UploadedFirst5m = sample.Uploaded
		}
		if elapsed <= 15*time.Minute {
			stats.UploadedFirst15m = sample.Uploaded
		}

		if sample.Progress >= 1.0 && completedAt.IsZero() {
			completedAt = sample.Timestamp
			stats.TimeToComplete = completedAt.Sub(race.StartedAt)
		}
	}

	lastSample := samples[len(samples)-1]
	stats.TotalUploaded = lastSample.Uploaded
	stats.AvgRank = float64(totalRank) / float64(len(samples))

	totalTime := lastSample.Timestamp.Sub(samples[0].Timestamp).Seconds()
	if totalTime > 0 {
		stats.AvgUploadRate = int64(float64(lastSample.Uploaded) / totalTime)
	}

	// Compute completion rank and upload rank from peer data
	if !completedAt.IsZero() {
		completionRank, uploadRank, err := s.computeRankings(ctx, raceID, completedAt, stats.TotalUploaded)
		if err != nil {
			// Log error but don't fail - rankings are optional
			stats.CompletionRank = 0
			stats.UploadRank = 0
		} else {
			stats.CompletionRank = completionRank
			stats.UploadRank = uploadRank
		}
	}

	return stats, nil
}

// computeRankings calculates completion and upload rankings based on peer performance.
// Uses linear extrapolation to infer completion for peers who disappeared before reaching 100%.
func (s *Store) computeRankings(ctx context.Context, raceID int64, ourCompletionTime time.Time, ourTotalUpload int64) (completionRank, uploadRank int, err error) {
	// Get all initial swarm peers (those who appeared before we completed)
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT peer_id
		FROM peer_samples
		WHERE race_id = ? AND ts <= ?
	`, raceID, ourCompletionTime)
	if err != nil {
		return 0, 0, fmt.Errorf("querying initial swarm: %w", err)
	}
	defer rows.Close()

	var peerIDs []int64
	for rows.Next() {
		var peerID int64
		if err := rows.Scan(&peerID); err != nil {
			return 0, 0, err
		}
		peerIDs = append(peerIDs, peerID)
	}
	if err := rows.Err(); err != nil {
		return 0, 0, err
	}

	completedBeforeUs := 0
	uploadedMoreThanUs := 0

	// For each peer, determine completion time and total upload
	for _, peerID := range peerIDs {
		// Get all samples for this peer, ordered by time
		sampleRows, err := s.db.QueryContext(ctx, `
			SELECT ts, progress, uploaded
			FROM peer_samples
			WHERE race_id = ? AND peer_id = ?
			ORDER BY ts
		`, raceID, peerID)
		if err != nil {
			return 0, 0, fmt.Errorf("querying peer %d samples: %w", peerID, err)
		}

		var samples []struct {
			ts       time.Time
			progress float64
			uploaded int64
		}
		for sampleRows.Next() {
			var s struct {
				ts       time.Time
				progress float64
				uploaded int64
			}
			if err := sampleRows.Scan(&s.ts, &s.progress, &s.uploaded); err != nil {
				sampleRows.Close()
				return 0, 0, err
			}
			samples = append(samples, s)
		}
		sampleRows.Close()

		if len(samples) == 0 {
			continue
		}

		// Determine completion time
		var completionTime *time.Time
		maxUploaded := samples[len(samples)-1].uploaded

		// Check for explicit completion (progress >= 1.0)
		for _, s := range samples {
			if s.progress >= 1.0 {
				completionTime = &s.ts
				break
			}
		}

		// If no explicit completion, try to extrapolate from last two samples
		if completionTime == nil && len(samples) >= 2 {
			last := samples[len(samples)-1]
			prev := samples[len(samples)-2]

			// Extrapolate if progress was increasing and not yet complete
			if last.progress > prev.progress && last.progress < 1.0 {
				progressDelta := last.progress - prev.progress
				timeDelta := last.ts.Sub(prev.ts).Seconds()

				if progressDelta > 0 && timeDelta > 0 {
					// Time to reach 100% from last sample
					remainingProgress := 1.0 - last.progress
					timeToComplete := remainingProgress * timeDelta / progressDelta
					extrapolated := last.ts.Add(time.Duration(timeToComplete * float64(time.Second)))

					// Only count if extrapolated completion was before our completion and they disappeared
					if extrapolated.Before(ourCompletionTime) {
						completionTime = &extrapolated
					}
				}
			}
		}

		// Count peers who finished before us
		if completionTime != nil && completionTime.Before(ourCompletionTime) {
			completedBeforeUs++
		}

		// Count peers who uploaded more than us
		if maxUploaded > ourTotalUpload {
			uploadedMoreThanUs++
		}
	}

	// Rank is 1 + number of peers who did better
	completionRank = completedBeforeUs + 1
	uploadRank = uploadedMoreThanUs + 1

	return completionRank, uploadRank, nil
}

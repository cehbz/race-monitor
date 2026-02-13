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

const schemaVersion = 4

// Store handles SQLite storage operations.
type Store struct {
	db *sql.DB
}

// DB returns the underlying *sql.DB for direct queries.
func (s *Store) DB() *sql.DB {
	return s.db
}

// formatTS formats a time.Time as RFC 3339 with millisecond precision.
// Produces timestamps like "2026-02-09T05:18:37.753Z" directly parseable
// by JavaScript's Date constructor and Python's datetime.
func formatTS(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000Z")
}

// New creates a new SQLite store, running schema migration if needed.
func New(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	// Single connection: SQLite only supports one writer at a time, and
	// PRAGMAs are per-connection. Single connection serializes all access
	// at the Go level while allowing the viz dashboard to read concurrently
	// via WAL from its own process.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting WAL mode: %w", err)
	}

	if _, err := db.Exec("PRAGMA busy_timeout=5000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("setting busy timeout: %w", err)
	}

	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enabling foreign keys: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrating schema: %w", err)
	}

	return s, nil
}

// migrate checks the schema version and creates/recreates tables as needed.
func (s *Store) migrate() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return fmt.Errorf("reading schema version: %w", err)
	}

	if version == schemaVersion {
		return nil // already up to date
	}

	if version != 0 {
		// Existing schema from older version — drop all tables and recreate.
		// Data from test runs is transient; clean recreation is acceptable.
		if err := s.dropAll(); err != nil {
			return fmt.Errorf("dropping old schema: %w", err)
		}
	}

	if err := s.createSchema(); err != nil {
		return err
	}

	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", schemaVersion)); err != nil {
		return fmt.Errorf("setting schema version: %w", err)
	}

	return s.populateEventTypes()
}

// dropAll removes all known tables for clean recreation.
func (s *Store) dropAll() error {
	tables := []string{
		"packet_events", "race_peers", "connections",
		"races", "torrents", "event_types",
	}
	for _, t := range tables {
		if _, err := s.db.Exec("DROP TABLE IF EXISTS " + t); err != nil {
			return fmt.Errorf("dropping table %s: %w", t, err)
		}
	}
	return nil
}

// createSchema creates all tables and indexes.
func (s *Store) createSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS event_types (
		id          INTEGER PRIMARY KEY,
		name        TEXT UNIQUE NOT NULL,
		description TEXT NOT NULL
	);

	CREATE TABLE IF NOT EXISTS torrents (
		id          INTEGER PRIMARY KEY AUTOINCREMENT,
		info_hash   TEXT UNIQUE NOT NULL,
		name        TEXT NOT NULL,
		size        INTEGER NOT NULL,
		piece_count INTEGER NOT NULL DEFAULT 0
	);

	CREATE TABLE IF NOT EXISTS races (
		id           INTEGER PRIMARY KEY AUTOINCREMENT,
		torrent_id   INTEGER NOT NULL REFERENCES torrents(id),
		started_at   TIMESTAMP NOT NULL,
		completed_at TIMESTAMP,
		UNIQUE(torrent_id, started_at)
	);

	CREATE TABLE IF NOT EXISTS connections (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		conn_ptr   TEXT UNIQUE NOT NULL,
		first_seen TIMESTAMP NOT NULL,
		ip         TEXT,
		port       INTEGER,
		peer_id    TEXT,
		client     TEXT
	);

	CREATE TABLE IF NOT EXISTS race_peers (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		race_id    INTEGER NOT NULL REFERENCES races(id) ON DELETE CASCADE,
		ip         TEXT NOT NULL,
		port       INTEGER NOT NULL,
		client     TEXT,
		peer_id    TEXT,
		country    TEXT,
		progress   REAL,
		dl_speed   INTEGER,
		up_speed   INTEGER,
		first_seen TIMESTAMP NOT NULL,
		last_seen  TIMESTAMP NOT NULL,
		UNIQUE(race_id, ip, port)
	);

	CREATE TABLE IF NOT EXISTS packet_events (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		race_id       INTEGER NOT NULL REFERENCES races(id) ON DELETE CASCADE,
		connection_id INTEGER NOT NULL REFERENCES connections(id),
		ts            TIMESTAMP NOT NULL,
		event_type_id INTEGER NOT NULL REFERENCES event_types(id),
		piece_index   INTEGER,
		data          INTEGER
	);

	CREATE INDEX IF NOT EXISTS idx_races_torrent ON races(torrent_id);
	CREATE INDEX IF NOT EXISTS idx_races_started ON races(started_at);
	CREATE INDEX IF NOT EXISTS idx_events_race ON packet_events(race_id);
	CREATE INDEX IF NOT EXISTS idx_events_race_ts ON packet_events(race_id, ts);
	CREATE INDEX IF NOT EXISTS idx_events_conn ON packet_events(connection_id);
	CREATE INDEX IF NOT EXISTS idx_events_type ON packet_events(event_type_id);
	CREATE INDEX IF NOT EXISTS idx_race_peers_race ON race_peers(race_id);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("creating schema: %w", err)
	}
	return nil
}

// populateEventTypes inserts all known event types.
func (s *Store) populateEventTypes() error {
	eventTypes := []struct {
		id          int
		name        string
		description string
	}{
		{int(EventTypeHave), "have", "Peer announced piece completion (eBPF incoming_have probe)"},
		{int(EventTypePieceReceived), "piece_received", "We completed and verified a piece (eBPF we_have probe)"},
	}

	for _, et := range eventTypes {
		_, err := s.db.Exec(
			`INSERT OR IGNORE INTO event_types (id, name, description) VALUES (?, ?, ?)`,
			et.id, et.name, et.description)
		if err != nil {
			return fmt.Errorf("inserting event type %s: %w", et.name, err)
		}
	}
	return nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// --- Torrent operations ---

// CreateTorrent inserts torrent metadata and returns its database ID.
// If the torrent already exists (by info_hash), returns the existing ID.
func (s *Store) CreateTorrent(ctx context.Context, infoHash, name string, size int64, pieceCount int) (int64, error) {
	// Try insert first
	result, err := s.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO torrents (info_hash, name, size, piece_count)
		VALUES (?, ?, ?, ?)`,
		infoHash, name, size, pieceCount)
	if err != nil {
		return 0, fmt.Errorf("inserting torrent: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		return result.LastInsertId()
	}

	// Already exists — fetch the ID
	var id int64
	err = s.db.QueryRowContext(ctx,
		`SELECT id FROM torrents WHERE info_hash = ?`, infoHash).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("fetching torrent id: %w", err)
	}
	return id, nil
}

// --- Race operations ---

// CreateRace creates a new race record and returns its ID.
func (s *Store) CreateRace(ctx context.Context, torrentID int64) (int64, error) {
	result, err := s.db.ExecContext(ctx,
		`INSERT INTO races (torrent_id, started_at) VALUES (?, ?)`,
		torrentID, formatTS(time.Now()))
	if err != nil {
		return 0, fmt.Errorf("inserting race: %w", err)
	}
	return result.LastInsertId()
}

// CompleteRace marks a race as completed.
func (s *Store) CompleteRace(ctx context.Context, raceID int64) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE races SET completed_at = ? WHERE id = ?`,
		formatTS(time.Now()), raceID)
	return err
}

// GetRace retrieves a race by ID with denormalized torrent metadata.
func (s *Store) GetRace(ctx context.Context, id int64) (*Race, error) {
	var r Race
	err := s.db.QueryRowContext(ctx,
		`SELECT r.id, r.torrent_id, t.info_hash, t.name, t.size, t.piece_count,
		        r.started_at, r.completed_at
		FROM races r
		JOIN torrents t ON r.torrent_id = t.id
		WHERE r.id = ?`, id).Scan(
		&r.ID, &r.TorrentID, &r.InfoHash, &r.Name, &r.Size, &r.PieceCount,
		&r.StartedAt, &r.CompletedAt)
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
	since := formatTS(time.Now().AddDate(0, 0, -days))
	rows, err := s.db.QueryContext(ctx,
		`SELECT r.id, r.torrent_id, t.info_hash, t.name, t.size, t.piece_count,
		        r.started_at, r.completed_at
		FROM races r
		JOIN torrents t ON r.torrent_id = t.id
		WHERE r.started_at > ?
		ORDER BY r.started_at DESC`, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var races []Race
	for rows.Next() {
		var r Race
		if err := rows.Scan(&r.ID, &r.TorrentID, &r.InfoHash, &r.Name, &r.Size, &r.PieceCount,
			&r.StartedAt, &r.CompletedAt); err != nil {
			return nil, err
		}
		races = append(races, r)
	}
	return races, rows.Err()
}

// --- Connection operations ---

// InsertConnection inserts or retrieves an eBPF connection and returns its DB ID.
func (s *Store) InsertConnection(ctx context.Context, connPtr string, firstSeen time.Time) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO connections (conn_ptr, first_seen)
		VALUES (?, ?)
		ON CONFLICT(conn_ptr) DO UPDATE SET conn_ptr = conn_ptr
		RETURNING id`,
		connPtr, formatTS(firstSeen)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("inserting connection: %w", err)
	}
	return id, nil
}

// --- Race peer operations ---

// UpsertRacePeers batch-upserts API-sourced peer data for a race.
func (s *Store) UpsertRacePeers(ctx context.Context, raceID int64, peers []RacePeer) error {
	if len(peers) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO race_peers (race_id, ip, port, client, peer_id, country,
		                         progress, dl_speed, up_speed, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(race_id, ip, port) DO UPDATE SET
			client = excluded.client,
			peer_id = excluded.peer_id,
			country = excluded.country,
			progress = excluded.progress,
			dl_speed = excluded.dl_speed,
			up_speed = excluded.up_speed,
			last_seen = excluded.last_seen`)
	if err != nil {
		return fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	now := formatTS(time.Now())
	for _, p := range peers {
		firstSeen := now
		if !p.FirstSeen.IsZero() {
			firstSeen = formatTS(p.FirstSeen)
		}
		lastSeen := now
		if !p.LastSeen.IsZero() {
			lastSeen = formatTS(p.LastSeen)
		}

		if _, err := stmt.ExecContext(ctx,
			raceID, p.IP, p.Port, p.Client, p.PeerID, p.Country,
			p.Progress, p.DLSpeed, p.UPSpeed, firstSeen, lastSeen); err != nil {
			return fmt.Errorf("upserting race peer: %w", err)
		}
	}

	return tx.Commit()
}

// UpdateConnectionEndpoint sets the resolved IP:port on a connection record.
// Called after auto-calibration maps a peer_connection* to a real endpoint.
// Uses upsert because the calibration event may arrive before the tracker
// goroutine creates the connection row (race condition between coordinator
// and tracker goroutines).
func (s *Store) UpdateConnectionEndpoint(ctx context.Context, connPtr string, ip string, port int) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO connections (conn_ptr, first_seen, ip, port)
		VALUES (?, datetime('now'), ?, ?)
		ON CONFLICT(conn_ptr) DO UPDATE SET ip = excluded.ip, port = excluded.port`,
		connPtr, ip, port)
	return err
}

// UpdateConnectionPeerInfo sets the resolved IP:port, peer_id, and client on
// a connection record. Called after full calibration (both sockaddr_in and
// peer_id offsets discovered) maps a peer_connection* to a real endpoint
// and client identity.
// Uses upsert because the calibration event may arrive before the tracker
// goroutine creates the connection row (race condition between coordinator
// and tracker goroutines).
func (s *Store) UpdateConnectionPeerInfo(ctx context.Context, connPtr string, ip string, port int, peerID string, client string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO connections (conn_ptr, first_seen, ip, port, peer_id, client)
		VALUES (?, datetime('now'), ?, ?, ?, ?)
		ON CONFLICT(conn_ptr) DO UPDATE SET
			ip = excluded.ip, port = excluded.port,
			peer_id = excluded.peer_id, client = excluded.client`,
		connPtr, ip, port, peerID, client)
	return err
}

// UpsertRacePeerFromCapture inserts or updates a race_peers record using data
// extracted from eBPF calibration events (IP, port, client, peer_id). Used
// after calibration to populate peer data without API polling.
func (s *Store) UpsertRacePeerFromCapture(ctx context.Context, raceID int64, ip string, port int, client string, peerID string) error {
	now := formatTS(time.Now())
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO race_peers (race_id, ip, port, client, peer_id, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(race_id, ip, port) DO UPDATE SET
			client = excluded.client,
			peer_id = excluded.peer_id,
			last_seen = excluded.last_seen`,
		raceID, ip, port, client, peerID, now, now)
	return err
}

// --- Packet event operations ---

// InsertPacketEvents inserts multiple packet events in a single transaction.
func (s *Store) InsertPacketEvents(ctx context.Context, events []Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO packet_events (race_id, connection_id, ts, event_type_id, piece_index, data)
		VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return fmt.Errorf("preparing statement: %w", err)
	}
	defer stmt.Close()

	for _, pe := range events {
		if _, err := stmt.ExecContext(ctx,
			pe.RaceID, pe.ConnectionID, formatTS(pe.Timestamp),
			int(pe.EventType), pe.PieceIndex, pe.Data); err != nil {
			return fmt.Errorf("inserting packet event: %w", err)
		}
	}

	return tx.Commit()
}

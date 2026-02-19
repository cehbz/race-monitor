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

const schemaVersion = 6

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
		"packet_events", "connections",
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
		id               INTEGER PRIMARY KEY AUTOINCREMENT,
		torrent_id       INTEGER NOT NULL REFERENCES torrents(id),
		started_at       TIMESTAMP NOT NULL,
		completed_at     TIMESTAMP,
		start_wallclock  TEXT,
		start_ktime      INTEGER,
		UNIQUE(torrent_id, started_at)
	);

	CREATE TABLE IF NOT EXISTS connections (
		id         INTEGER PRIMARY KEY AUTOINCREMENT,
		race_id    INTEGER REFERENCES races(id),
		conn_ptr   TEXT UNIQUE NOT NULL,
		first_seen TIMESTAMP NOT NULL,
		ip         TEXT,
		port       INTEGER,
		peer_id    TEXT,
		client     TEXT
	);

	CREATE TABLE IF NOT EXISTS packet_events (
		id            INTEGER PRIMARY KEY AUTOINCREMENT,
		race_id       INTEGER NOT NULL REFERENCES races(id) ON DELETE CASCADE,
		connection_id INTEGER NOT NULL REFERENCES connections(id),
		ts            INTEGER NOT NULL,
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
	CREATE INDEX IF NOT EXISTS idx_events_peer_piece ON packet_events(race_id, event_type_id, connection_id, piece_index, ts);
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

// CreateTorrent inserts or updates torrent metadata and returns its database ID.
// On conflict (existing info_hash), updates name/size/piece_count only when the
// new value is "better" (non-empty name that isn't just the hash, non-zero size/piece_count).
func (s *Store) CreateTorrent(ctx context.Context, infoHash, name string, size int64, pieceCount int) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO torrents (info_hash, name, size, piece_count)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(info_hash) DO UPDATE SET
			name = CASE WHEN excluded.name != excluded.info_hash AND excluded.name != ''
			            THEN excluded.name ELSE torrents.name END,
			size = CASE WHEN excluded.size > 0 THEN excluded.size ELSE torrents.size END,
			piece_count = CASE WHEN excluded.piece_count > 0
			                  THEN excluded.piece_count ELSE torrents.piece_count END
		RETURNING id`,
		infoHash, name, size, pieceCount).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("upserting torrent: %w", err)
	}
	return id, nil
}

// --- Race operations ---

// CreateRace creates a new race record and returns its ID.
// startKtime is the BPF ktime_get_ns timestamp from the torrent::start() event.
// Pass 0 if no ktime is available (e.g. fallback race creation).
func (s *Store) CreateRace(ctx context.Context, torrentID int64, startKtime int64) (int64, error) {
	var result sql.Result
	var err error
	if startKtime > 0 {
		result, err = s.db.ExecContext(ctx,
			`INSERT INTO races (torrent_id, started_at, start_ktime) VALUES (?, ?, ?)`,
			torrentID, formatTS(time.Now()), startKtime)
	} else {
		result, err = s.db.ExecContext(ctx,
			`INSERT INTO races (torrent_id, started_at) VALUES (?, ?)`,
			torrentID, formatTS(time.Now()))
	}
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

// MarkAbandonedRaces marks all incomplete races as completed with the current timestamp.
func (s *Store) MarkAbandonedRaces(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE races SET completed_at = datetime('now') WHERE completed_at IS NULL`)
	return err
}

// SetRaceStartWallclock sets the RFC 3339 wallclock timestamp for a race,
// typically called from a hook to record when the race logically started.
func (s *Store) SetRaceStartWallclock(ctx context.Context, raceID int64, wallclock string) error {
	_, err := s.db.ExecContext(ctx,
		`UPDATE races SET start_wallclock = ? WHERE id = ?`,
		wallclock, raceID)
	return err
}

// GetRace retrieves a race by ID with denormalized torrent metadata.
func (s *Store) GetRace(ctx context.Context, id int64) (*Race, error) {
	var r Race
	err := s.db.QueryRowContext(ctx,
		`SELECT r.id, r.torrent_id, t.info_hash, t.name, t.size, t.piece_count,
		        r.started_at, r.completed_at, r.start_ktime
		FROM races r
		JOIN torrents t ON r.torrent_id = t.id
		WHERE r.id = ?`, id).Scan(
		&r.ID, &r.TorrentID, &r.InfoHash, &r.Name, &r.Size, &r.PieceCount,
		&r.StartedAt, &r.CompletedAt, &r.StartKtime)
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
		        r.started_at, r.completed_at, r.start_ktime
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
			&r.StartedAt, &r.CompletedAt, &r.StartKtime); err != nil {
			return nil, err
		}
		races = append(races, r)
	}
	return races, rows.Err()
}

// --- Connection operations ---

// InsertConnection inserts or retrieves an eBPF connection and returns its DB ID.
func (s *Store) InsertConnection(ctx context.Context, raceID int64, connPtr string, firstSeen time.Time) (int64, error) {
	var id int64
	err := s.db.QueryRowContext(ctx,
		`INSERT INTO connections (race_id, conn_ptr, first_seen)
		VALUES (?, ?, ?)
		ON CONFLICT(conn_ptr) DO UPDATE SET conn_ptr = conn_ptr
		RETURNING id`,
		raceID, connPtr, formatTS(firstSeen)).Scan(&id)
	if err != nil {
		return 0, fmt.Errorf("inserting connection: %w", err)
	}
	return id, nil
}

// UpdateConnectionEndpoint sets the resolved IP:port on a connection record.
// Called after auto-calibration maps a peer_connection* to a real endpoint.
// Uses upsert because the calibration event may arrive before the tracker
// goroutine creates the connection row (race condition between coordinator
// and tracker goroutines).
func (s *Store) UpdateConnectionEndpoint(ctx context.Context, raceID int64, connPtr string, ip string, port int) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO connections (race_id, conn_ptr, first_seen, ip, port)
		VALUES (?, ?, datetime('now'), ?, ?)
		ON CONFLICT(conn_ptr) DO UPDATE SET ip = excluded.ip, port = excluded.port`,
		raceID, connPtr, ip, port)
	return err
}

// UpdateConnectionPeerInfo sets the resolved IP:port, peer_id, and client on
// a connection record. Called after full calibration (both sockaddr_in and
// peer_id offsets discovered) maps a peer_connection* to a real endpoint
// and client identity.
// Uses upsert because the calibration event may arrive before the tracker
// goroutine creates the connection row (race condition between coordinator
// and tracker goroutines).
func (s *Store) UpdateConnectionPeerInfo(ctx context.Context, raceID int64, connPtr string, ip string, port int, peerID string, client string) error {
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO connections (race_id, conn_ptr, first_seen, ip, port, peer_id, client)
		VALUES (?, ?, datetime('now'), ?, ?, ?, ?)
		ON CONFLICT(conn_ptr) DO UPDATE SET
			ip = excluded.ip, port = excluded.port,
			peer_id = excluded.peer_id, client = excluded.client`,
		raceID, connPtr, ip, port, peerID, client)
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
			pe.RaceID, pe.ConnectionID, pe.Timestamp,
			int(pe.EventType), pe.PieceIndex, pe.Data); err != nil {
			return fmt.Errorf("inserting packet event: %w", err)
		}
	}

	return tx.Commit()
}

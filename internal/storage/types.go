// Package storage provides SQLite storage for race data.
package storage

import (
	"database/sql"
	"errors"
	"time"
)

var ErrRaceNotFound = errors.New("race not found")

// EventType represents the type of event as an integer matching the DB event_types.id.
type EventType int

const (
	EventTypeHave          EventType = 1 // Peer announced piece (incoming_have probe)
	EventTypePieceReceived EventType = 2 // We completed a piece (we_have probe)
)

// Torrent represents torrent metadata.
type Torrent struct {
	ID         int64
	InfoHash   string
	Name       string
	Size       int64
	PieceCount int
}

// Race represents a race instance with denormalized torrent metadata for reads.
type Race struct {
	ID          int64
	TorrentID   int64
	Name        string // denormalized from torrents
	Size        int64  // denormalized from torrents
	PieceCount  int    // denormalized from torrents
	InfoHash    string // denormalized from torrents
	StartedAt   time.Time
	CompletedAt sql.NullTime
	StartKtime  sql.NullInt64 // BPF ktime_get_ns from torrent::start(), nullable
}

// Connection represents an eBPF-observed connection (opaque pointer identifier).
// IP, Port, PeerID, and Client are populated by auto-calibration once the
// struct offsets have been discovered, linking the opaque eBPF pointer to a
// real peer endpoint and client identity.
type Connection struct {
	ID        int64
	RaceID    int64  // FK to races.id
	ConnPtr   string // hex of peer_connection* from eBPF
	FirstSeen time.Time
	IP        *string // nullable: set after calibration resolves endpoint
	Port      *int    // nullable: set after calibration resolves endpoint
	PeerID    *string // nullable: raw 20-byte BT peer_id (set after peer_id calibration)
	Client    *string // nullable: decoded client name from peer_id (e.g. "qBittorrent 4530")
}

// Event represents a stored packet event in the database.
type Event struct {
	ID           int64
	RaceID       int64
	ConnectionID int64     // FK to connections.id
	Timestamp    int64     // nanoseconds since boot (BPF ktime), stored as int64
	EventType    EventType // integer matching event_types.id
	PieceIndex   int
	Data         int64
}

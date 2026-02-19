"""Database access layer for race-monitor visualization.

Encapsulates all SQLite queries behind named functions that return plain
Python data structures. No Flask dependency — can be tested or reused
independently.

Schema v5 notes:
  - packet_events.ts is int64 nanoseconds since boot (BPF ktime_get_ns)
  - race_peers table has been removed (API dependency eliminated)
  - Covering index is now created by the Go daemon at schema init time
  - races.start_wallclock records the hook-observed wallclock time
"""

import sqlite3
from analysis import decode_peer_id


# Nanoseconds per second — BPF timestamps are ktime_get_ns() int64 values.
_NS_PER_SEC = 1_000_000_000


def get_db(db_path):
    """Open a SQLite connection configured for the race-monitor schema."""
    conn = sqlite3.connect(db_path)
    conn.text_factory = lambda b: b.decode('utf-8', errors='replace')
    conn.row_factory = sqlite3.Row
    return conn


def fetch_races(conn):
    """Fast race list: JOIN torrents only, no expensive COUNT over packet_events.

    Returns list of dicts with: id, info_hash, name, size, piece_count,
    started_at, completed_at.
    """
    cursor = conn.execute('''
        SELECT r.id, t.info_hash, t.name, t.size, t.piece_count,
               r.started_at, r.completed_at
        FROM races r
        JOIN torrents t ON r.torrent_id = t.id
        ORDER BY r.started_at DESC
        LIMIT 50
    ''')
    return [dict(row) for row in cursor.fetchall()]


def fetch_race_counts(conn, race_ids):
    """Event and peer counts for a batch of race IDs.

    peer_count: distinct eBPF connections with incoming_have events.
    event_count: total packet_events.
    Returns {race_id: {'peer_count': N, 'event_count': N}}.
    """
    if not race_ids:
        return {}

    placeholders = ','.join('?' * len(race_ids))

    # Event counts from packet_events
    event_cursor = conn.execute(f'''
        SELECT race_id, COUNT(*) as event_count
        FROM packet_events
        WHERE race_id IN ({placeholders})
        GROUP BY race_id
    ''', race_ids)
    result = {}
    for row in event_cursor.fetchall():
        result[row['race_id']] = {
            'peer_count': 0,
            'event_count': row['event_count'],
        }

    # Peer counts from eBPF connections (all calibration-discovered connections,
    # excluding the synthetic "self" connection used for our own piece completions)
    peer_cursor = conn.execute(f'''
        SELECT race_id, COUNT(*) as peer_count
        FROM connections
        WHERE race_id IN ({placeholders}) AND conn_ptr != 'self'
        GROUP BY race_id
    ''', race_ids)
    for row in peer_cursor.fetchall():
        rid = row['race_id']
        if rid in result:
            result[rid]['peer_count'] = row['peer_count']
        else:
            result[rid] = {'peer_count': row['peer_count'], 'event_count': 0}

    return result


def fetch_race_detail(conn, race_id):
    """Race metadata joined with torrent info. Returns dict or None."""
    cursor = conn.execute('''
        SELECT r.id, r.started_at, r.completed_at, r.start_wallclock,
               r.start_ktime, t.info_hash, t.name, t.size, t.piece_count
        FROM races r
        JOIN torrents t ON r.torrent_id = t.id
        WHERE r.id = ?
    ''', (race_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def fetch_timeline(conn, race_id):
    """1-second bucketed timeline of have/piece_received counts.

    Timestamps are int64 nanoseconds since boot. We compute elapsed seconds
    relative to the race's start_ktime (from torrent::start()) when available,
    falling back to the first event timestamp. Using start_ktime captures
    the latency between torrent start and first piece verification.

    Returns ~600 rows for a 10-minute race instead of 26M raw events.
    """
    cursor = conn.execute('''
        WITH race_start AS (
            SELECT COALESCE(
                (SELECT r.start_ktime FROM races r WHERE r.id = ?),
                (SELECT MIN(ts) FROM packet_events WHERE race_id = ?)
            ) as t0
        )
        SELECT
            CAST((pe.ts - rs.t0) / ? AS INTEGER) as elapsed_sec,
            SUM(CASE WHEN pe.event_type_id = 1 THEN 1 ELSE 0 END) as have_count,
            SUM(CASE WHEN pe.event_type_id = 2 THEN 1 ELSE 0 END) as piece_received
        FROM packet_events pe, race_start rs
        WHERE pe.race_id = ?
        GROUP BY elapsed_sec
        ORDER BY elapsed_sec
    ''', (race_id, race_id, _NS_PER_SEC, race_id))
    return [dict(row) for row in cursor.fetchall()]


def fetch_self_pieces(conn, race_id):
    """First timestamp per piece for our we_have events (event_type_id=2).

    Returns rows with piece_index and first_ts (int64 nanoseconds since boot).
    """
    cursor = conn.execute('''
        SELECT piece_index, MIN(ts) as first_ts
        FROM packet_events
        WHERE race_id = ? AND event_type_id = 2
        GROUP BY piece_index
    ''', (race_id,))
    return cursor.fetchall()


def fetch_peer_pieces(conn, race_id):
    """First timestamp per (connection_id, piece_index) for incoming_have.

    Uses idx_events_peer_piece covering index. For 202 peers x 856 pieces
    this returns ~173K rows — manageable in Python.

    Returns rows with connection_id, piece_index, first_ts (int64 ns since boot).
    """
    cursor = conn.execute('''
        SELECT pe.connection_id, pe.piece_index, MIN(pe.ts) as first_ts
        FROM packet_events pe
        WHERE pe.race_id = ? AND pe.event_type_id = 1
        GROUP BY pe.connection_id, pe.piece_index
    ''', (race_id,))
    return cursor.fetchall()


def fetch_connection_meta(conn, race_id):
    """Connection metadata from eBPF calibration.

    Returns {connection_id: {conn_ptr, ip, port, client, peer_id, label}}.
    Includes all calibration-discovered connections, not just those with
    incoming_have events (seeders never send HAVE but are still peers).
    """
    cursor = conn.execute('''
        SELECT c.id, c.conn_ptr, c.ip, c.port, c.peer_id, c.client
        FROM connections c
        WHERE c.race_id = ? AND c.conn_ptr != 'self'
    ''', (race_id,))

    meta = {}
    for r in cursor.fetchall():
        ip = r['ip'] or ''
        port = r['port'] or 0
        client = r['client'] or ''
        label = client or (f"{ip}:{port}" if ip else f"conn_{r['id']}")
        meta[r['id']] = {
            'conn_ptr': r['conn_ptr'] or '',
            'ip': ip,
            'port': port,
            'client': client,
            'peer_id': decode_peer_id(r['peer_id']),
            'label': label,
        }
    return meta


def fetch_peer_count(conn, race_id):
    """Peer count from calibration-discovered eBPF connections (excludes self)."""
    cursor = conn.execute('''
        SELECT COUNT(*) as peer_count
        FROM connections
        WHERE race_id = ? AND conn_ptr != 'self'
    ''', (race_id,))
    return cursor.fetchone()['peer_count']


def ktime_to_elapsed_sec(ts_ns, epoch_ns):
    """Convert BPF ktime nanoseconds to elapsed seconds relative to epoch."""
    return (ts_ns - epoch_ns) / _NS_PER_SEC

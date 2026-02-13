"""Database access layer for race-monitor visualization.

Encapsulates all SQLite queries behind named functions that return plain
Python data structures. No Flask dependency — can be tested or reused
independently.
"""

import sqlite3
from analysis import decode_peer_id


def get_db(db_path):
    """Open a SQLite connection configured for the race-monitor schema."""
    conn = sqlite3.connect(db_path)
    conn.text_factory = lambda b: b.decode('utf-8', errors='replace')
    conn.row_factory = sqlite3.Row
    return conn


def ensure_indexes(db_path):
    """Create read-side performance indexes.

    These are viz-app optimizations — they don't touch the Go daemon's schema
    version. The covering index on (race_id, event_type_id, connection_id,
    piece_index, ts) makes per-peer GROUP BY queries ~30x faster on 26M+ rows.
    """
    conn = sqlite3.connect(db_path)
    conn.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_peer_piece
        ON packet_events(race_id, event_type_id, connection_id, piece_index, ts)
    ''')
    conn.commit()
    conn.close()


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
    """Peer/event counts for a batch of race IDs.

    peer_count: from race_peers (API-polled, most comprehensive).
    event_count: from packet_events (eBPF captured).
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

    # Peer counts from race_peers (API-polled, richer than eBPF connections)
    peer_cursor = conn.execute(f'''
        SELECT race_id, COUNT(*) as peer_count
        FROM race_peers
        WHERE race_id IN ({placeholders})
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
        SELECT r.id, r.started_at, r.completed_at,
               t.info_hash, t.name, t.size, t.piece_count
        FROM races r
        JOIN torrents t ON r.torrent_id = t.id
        WHERE r.id = ?
    ''', (race_id,))
    row = cursor.fetchone()
    return dict(row) if row else None


def fetch_timeline(conn, race_id):
    """1-second bucketed timeline of have/piece_received counts.

    Uses idx_events_race_ts for efficient scanning. Returns ~600 rows for a
    10-minute race instead of 26M raw events.
    """
    cursor = conn.execute('''
        WITH race_start AS (
            SELECT MIN(ts) as t0 FROM packet_events WHERE race_id = ?
        )
        SELECT
            CAST((julianday(pe.ts) - julianday(rs.t0)) * 86400 AS INTEGER) as elapsed_sec,
            SUM(CASE WHEN pe.event_type_id = 1 THEN 1 ELSE 0 END) as have_count,
            SUM(CASE WHEN pe.event_type_id = 2 THEN 1 ELSE 0 END) as piece_received
        FROM packet_events pe, race_start rs
        WHERE pe.race_id = ?
        GROUP BY elapsed_sec
        ORDER BY elapsed_sec
    ''', (race_id, race_id))
    return [dict(row) for row in cursor.fetchall()]


def fetch_self_pieces(conn, race_id):
    """First timestamp per piece for our we_have events (event_type_id=2)."""
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
    """
    cursor = conn.execute('''
        SELECT pe.connection_id, pe.piece_index, MIN(pe.ts) as first_ts
        FROM packet_events pe
        WHERE pe.race_id = ? AND pe.event_type_id = 1
        GROUP BY pe.connection_id, pe.piece_index
    ''', (race_id,))
    return cursor.fetchall()


def fetch_connection_meta(conn, race_id):
    """Connection metadata with LEFT JOIN to race_peers for richer client names.

    Returns {connection_id: {conn_ptr, ip, port, client, peer_id, label}}.
    """
    cursor = conn.execute('''
        SELECT c.id, c.conn_ptr, c.ip, c.port, c.peer_id,
               COALESCE(rp.client, c.client) as client
        FROM connections c
        LEFT JOIN race_peers rp
            ON rp.race_id = ? AND rp.ip = c.ip AND rp.port = c.port
        WHERE c.id IN (
            SELECT DISTINCT connection_id FROM packet_events
            WHERE race_id = ? AND event_type_id = 1
        )
    ''', (race_id, race_id))

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
    """Peer count: prefers race_peers (API-polled) for accuracy, falls back
    to eBPF connection count."""
    cursor = conn.execute('''
        SELECT COUNT(*) as cnt FROM race_peers WHERE race_id = ?
    ''', (race_id,))
    api_count = cursor.fetchone()['cnt']
    if api_count > 0:
        return api_count

    cursor = conn.execute('''
        SELECT COUNT(DISTINCT connection_id) as peer_count
        FROM packet_events
        WHERE race_id = ? AND event_type_id = 1
    ''', (race_id,))
    return cursor.fetchone()['peer_count']


def fetch_race_peers(conn, race_id):
    """All API-polled peers for a race (from race_peers table).

    Returns list of dicts with: ip, port, client, peer_id, country,
    progress, dl_speed, up_speed.
    """
    cursor = conn.execute('''
        SELECT ip, port, client, peer_id, country,
               progress, dl_speed, up_speed
        FROM race_peers
        WHERE race_id = ?
        ORDER BY progress DESC, ip, port
    ''', (race_id,))
    return [dict(row) for row in cursor.fetchall()]

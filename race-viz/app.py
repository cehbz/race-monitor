#!/usr/bin/env python3
"""Race Monitor Visualization Dashboard - Flask Backend

 eBPF architecture:
- Two event types: have (peer announced piece) and piece_received (we completed piece)
- Peers identified by opaque conn_ptr (peer_<hex> / conn_<hex>)
- Self peer (conn_ptr="self") represents our own piece completions
- Timestamps are RFC 3339 (e.g. "2026-02-09T05:18:37.753Z")
"""

import os
import sqlite3
import queue
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from flask import Flask, jsonify, render_template, Response, request
from flask_cors import CORS
import toml

app = Flask(__name__)
CORS(app)


def decode_peer_id(raw):
    """Decode BT peer_id BLOB for display.

    Client prefix (e.g. '-qB4530-') is ASCII; remaining bytes are arbitrary.
    Returns the ASCII-safe prefix plus hex for any non-printable tail bytes.
    """
    if raw is None:
        return ''
    if isinstance(raw, str):
        return raw  # legacy TEXT row
    prefix = []
    for b in raw:
        if 0x20 <= b < 0x7F:
            prefix.append(chr(b))
        else:
            break
    tail = raw[len(prefix):]
    return ''.join(prefix) + (tail.hex() if tail else '')


def parse_rfc3339(ts):
    """Parse RFC 3339 timestamp string into a datetime. Returns None on failure."""
    if not ts or not isinstance(ts, str):
        return None
    try:
        return datetime.fromisoformat(ts.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        return None


# SSE client management
sse_clients = []

# Load configuration
def load_config():
    """Load configuration from config.toml with sensible defaults."""
    config_path = Path(__file__).parent / 'config.toml'

    defaults = {
        'race_db': str(Path.home() / '.local/share/race-monitor/races.db'),
        'bind_host': '0.0.0.0',
        'bind_port': 8080,
        'debug': True
    }

    if config_path.exists():
        try:
            config = toml.load(config_path)
            if 'race_db' in config:
                config['race_db'] = str(Path(config['race_db']).expanduser())
            return {**defaults, **config}
        except Exception as e:
            print(f"Warning: Error loading config.toml: {e}")
            print("Using default configuration")
            return defaults
    else:
        print(f"Warning: {config_path} not found, using defaults")
        return defaults

config = load_config()

DB_PATH = config['race_db']
BIND_HOST = config['bind_host']
BIND_PORT = config['bind_port']
DEBUG = config['debug']


def ensure_indexes(db_path):
    """Create performance indexes for aggregation queries.

    These are read-side optimizations added by the viz app. They do not
    modify the Go daemon's schema version, so no migration is triggered.
    The covering index on (race_id, event_type_id, connection_id, piece_index, ts)
    makes per-peer GROUP BY queries ~30x faster on large races (26M+ events).
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_events_peer_piece
        ON packet_events(race_id, event_type_id, connection_id, piece_index, ts)
    ''')
    conn.commit()
    conn.close()


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.text_factory = lambda b: b.decode('utf-8', errors='replace')
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/')
def index():
    """Serve the dashboard."""
    return render_template('index.html')


@app.route('/api/races')
def list_races():
    """List all races in reverse chronological order."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            r.id,
            t.info_hash,
            t.name,
            t.size,
            t.piece_count,
            r.started_at,
            r.completed_at,
            COUNT(DISTINCT rp.id) as peer_count,
            COUNT(pe.id) as event_count
        FROM races r
        JOIN torrents t ON r.torrent_id = t.id
        LEFT JOIN race_peers rp ON r.id = rp.race_id
        LEFT JOIN packet_events pe ON r.id = pe.race_id
        GROUP BY r.id
        ORDER BY r.started_at DESC
        LIMIT 50
    ''')

    races = []
    for row in cursor.fetchall():
        races.append({
            'id': row['id'],
            'hash': row['info_hash'],
            'name': row['name'],
            'size': row['size'],
            'piece_count': row['piece_count'],
            'started_at': row['started_at'],
            'completed_at': row['completed_at'],
            'peer_count': row['peer_count'],
            'event_count': row['event_count']
        })

    conn.close()
    return jsonify(races)


@app.route('/api/race/<int:race_id>')
def get_race_data(race_id):
    """Get race metadata and full timeline aggregated in SQL.

    Timeline uses 1-second buckets computed entirely in SQL, avoiding
    loading millions of raw events into Python. No event limit.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Get race metadata
    cursor.execute('''
        SELECT r.*, t.name, t.size, t.piece_count
        FROM races r
        JOIN torrents t ON r.torrent_id = t.id
        WHERE r.id = ?
    ''', (race_id,))
    race_row = cursor.fetchone()

    if not race_row:
        conn.close()
        return jsonify({'error': 'Race not found'}), 404

    race = {
        'id': race_row['id'],
        'name': race_row['name'],
        'size': race_row['size'],
        'piece_count': race_row['piece_count'],
        'started_at': race_row['started_at'],
        'completed_at': race_row['completed_at']
    }

    # Full timeline aggregated in SQL using 1-second buckets.
    # Uses idx_events_race_ts(race_id, ts) for efficient scanning.
    cursor.execute('''
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

    timeline = []
    for row in cursor.fetchall():
        timeline.append({
            'elapsed_sec': row['elapsed_sec'],
            'have_count': row['have_count'],
            'piece_received': row['piece_received'],
        })

    # Get peer count from connections table (eBPF-observed peers)
    cursor.execute('''
        SELECT COUNT(DISTINCT connection_id) as peer_count
        FROM packet_events
        WHERE race_id = ? AND event_type_id = 1
    ''', (race_id,))
    peer_count = cursor.fetchone()['peer_count']

    conn.close()

    return jsonify({
        'race': race,
        'timeline': timeline,
        'peer_count': peer_count,
    })


@app.route('/api/race/<int:race_id>/peers')
def get_race_peers(race_id):
    """Get peer statistics for a race from race_peers table."""
    conn = get_db()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT
            rp.id,
            rp.ip,
            rp.port,
            rp.client,
            rp.country,
            rp.progress,
            rp.dl_speed,
            rp.up_speed,
            rp.first_seen,
            rp.last_seen
        FROM race_peers rp
        WHERE rp.race_id = ?
        ORDER BY rp.progress DESC, rp.first_seen ASC
    ''', (race_id,))

    peers = []
    for row in cursor.fetchall():
        peers.append({
            'id': row['id'],
            'ip': row['ip'],
            'port': row['port'],
            'client': row['client'],
            'country': row['country'],
            'progress': row['progress'],
            'dl_speed': row['dl_speed'],
            'up_speed': row['up_speed'],
            'first_seen': row['first_seen'],
            'last_seen': row['last_seen']
        })

    conn.close()
    return jsonify(peers)


@app.route('/api/race/<int:race_id>/peer_progress')
def get_peer_progress(race_id):
    """Per-peer cumulative completion % over time.

    Two-phase approach:
    1. SQL: find first timestamp each peer announced each piece (GROUP BY connection_id, piece_index)
    2. Python: build cumulative timelines sampled at 1-second intervals

    Uses covering index idx_events_peer_piece for efficient aggregation.
    For 202 peers x 856 pieces = ~173K rows — manageable in Python.
    """
    conn = get_db()
    cursor = conn.cursor()

    # Get piece_count for percentage calculation
    cursor.execute('''
        SELECT t.piece_count
        FROM races r JOIN torrents t ON r.torrent_id = t.id
        WHERE r.id = ?
    ''', (race_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Race not found'}), 404
    piece_count = row['piece_count'] or 1

    # Self pieces: first time we completed each piece (event_type_id=2)
    cursor.execute('''
        SELECT piece_index, MIN(ts) as first_ts
        FROM packet_events
        WHERE race_id = ? AND event_type_id = 2
        GROUP BY piece_index
    ''', (race_id,))
    self_pieces = cursor.fetchall()

    # Peer pieces: first time each peer announced each piece (event_type_id=1)
    # Uses idx_events_peer_piece covering index
    cursor.execute('''
        SELECT pe.connection_id, pe.piece_index, MIN(pe.ts) as first_ts
        FROM packet_events pe
        WHERE pe.race_id = ? AND pe.event_type_id = 1
        GROUP BY pe.connection_id, pe.piece_index
    ''', (race_id,))
    peer_pieces = cursor.fetchall()

    # Get connection metadata for labels
    cursor.execute('''
        SELECT id, conn_ptr, ip, port, client
        FROM connections
        WHERE id IN (
            SELECT DISTINCT connection_id FROM packet_events
            WHERE race_id = ? AND event_type_id = 1
        )
    ''', (race_id,))
    conn_meta = {}
    for r in cursor.fetchall():
        label = r['client'] or (f"{r['ip']}:{r['port']}" if r['ip'] else f"conn_{r['id']}")
        conn_meta[r['id']] = {
            'label': label,
            'ip': r['ip'] or '',
            'port': r['port'] or 0,
            'client': r['client'] or '',
        }

    conn.close()

    # Find the global earliest timestamp (race epoch)
    all_ts = []
    for r in self_pieces:
        dt = parse_rfc3339(r['first_ts'])
        if dt:
            all_ts.append(dt)
    for r in peer_pieces:
        dt = parse_rfc3339(r['first_ts'])
        if dt:
            all_ts.append(dt)

    if not all_ts:
        return jsonify({'piece_count': piece_count, 'self': None, 'peers': []})

    epoch = min(all_ts)

    def build_timeline(pieces_rows, ts_col='first_ts'):
        """Build cumulative completion % timeline from sorted piece rows."""
        # Parse and sort by timestamp
        parsed = []
        for r in pieces_rows:
            dt = parse_rfc3339(r[ts_col])
            if dt:
                elapsed = (dt - epoch).total_seconds()
                parsed.append(elapsed)
        parsed.sort()

        if not parsed:
            return [], []

        # Build cumulative % at each second boundary
        elapsed_secs = []
        completion_pcts = []
        piece_idx = 0
        max_sec = int(parsed[-1]) + 1

        for sec in range(0, max_sec + 1):
            while piece_idx < len(parsed) and parsed[piece_idx] <= sec:
                piece_idx += 1
            if piece_idx > 0 and (not elapsed_secs or piece_idx != int(completion_pcts[-1] * piece_count / 100) if completion_pcts else True):
                elapsed_secs.append(sec)
                completion_pcts.append(round(100.0 * piece_idx / piece_count, 2))

        # Ensure we have at least start and end points
        if not elapsed_secs:
            return [], []

        return elapsed_secs, completion_pcts

    # Build self timeline
    self_elapsed, self_pcts = build_timeline(self_pieces)
    self_data = {
        'elapsed_secs': self_elapsed,
        'completion_pcts': self_pcts,
    } if self_elapsed else None

    # Group peer pieces by connection_id
    peer_groups = defaultdict(list)
    for r in peer_pieces:
        peer_groups[r['connection_id']].append(r)

    # Build peer timelines
    peers_data = []
    for conn_id, pieces in peer_groups.items():
        elapsed, pcts = build_timeline(pieces)
        if not elapsed:
            continue
        meta = conn_meta.get(conn_id, {'label': f'conn_{conn_id}', 'ip': '', 'port': 0, 'client': ''})
        peers_data.append({
            'id': conn_id,
            'label': meta['label'],
            'ip': meta['ip'],
            'port': meta['port'],
            'client': meta['client'],
            'total_pieces': len(pieces),
            'elapsed_secs': elapsed,
            'completion_pcts': pcts,
        })

    # Sort peers by total pieces descending (most active first)
    peers_data.sort(key=lambda p: p['total_pieces'], reverse=True)

    race_duration = max(
        self_elapsed[-1] if self_elapsed else 0,
        max((p['elapsed_secs'][-1] for p in peers_data), default=0)
    )

    return jsonify({
        'piece_count': piece_count,
        'race_duration_secs': race_duration,
        'self': self_data,
        'peers': peers_data,
    })


@app.route('/api/race/<int:race_id>/faster_peers')
def get_faster_peers(race_id):
    """Identify peers whose cumulative completion curve is above ours.

    Compares cumulative piece counts at each second of the race. A peer is
    'faster' only if their curve is above ours for a sustained period — not
    merely because they downloaded some pieces in a different order.

    Classification:
    - seeder: had >= 80% of piece_count before our first we_have
    - competitive: curve above ours for >= 10% of race duration with avg lead >= 2%
    """
    conn = get_db()
    cursor = conn.cursor()

    # Get piece_count
    cursor.execute('''
        SELECT t.piece_count
        FROM races r JOIN torrents t ON r.torrent_id = t.id
        WHERE r.id = ?
    ''', (race_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Race not found'}), 404
    piece_count = row['piece_count'] or 1

    # Our pieces: first time we completed each piece (event_type_id=2)
    cursor.execute('''
        SELECT piece_index, MIN(ts) as first_ts
        FROM packet_events
        WHERE race_id = ? AND event_type_id = 2
        GROUP BY piece_index
    ''', (race_id,))
    self_pieces = cursor.fetchall()

    if not self_pieces:
        conn.close()
        return jsonify({
            'faster_peers': [],
            'stats': {
                'total_peers': 0,
                'peers_faster_than_us': 0,
                'seeders_detected': 0,
                'competitive_peers': 0,
                'note': 'No we_have events found — download may not have started.',
            }
        })

    # Peer pieces: first time each peer announced each piece (event_type_id=1)
    cursor.execute('''
        SELECT pe.connection_id, pe.piece_index, MIN(pe.ts) as first_ts
        FROM packet_events pe
        WHERE pe.race_id = ? AND pe.event_type_id = 1
        GROUP BY pe.connection_id, pe.piece_index
    ''', (race_id,))
    peer_pieces = cursor.fetchall()

    # Connection metadata (with race_peers LEFT JOIN for richer client name)
    cursor.execute('''
        SELECT c.id, c.conn_ptr, c.ip, c.port, c.peer_id,
               COALESCE(rp.client, c.client) as client
        FROM connections c
        LEFT JOIN race_peers rp ON rp.race_id = ? AND rp.ip = c.ip AND rp.port = c.port
        WHERE c.id IN (
            SELECT DISTINCT connection_id FROM packet_events
            WHERE race_id = ? AND event_type_id = 1
        )
    ''', (race_id, race_id))
    conn_meta = {}
    for r in cursor.fetchall():
        conn_meta[r['id']] = {
            'conn_ptr': r['conn_ptr'] or '',
            'ip': r['ip'] or '',
            'port': r['port'] or 0,
            'client': r['client'] or '',
            'peer_id': decode_peer_id(r['peer_id']),
        }

    total_peers = len(conn_meta)
    conn.close()

    # --- Build cumulative curves and compare ---

    # Parse our piece times relative to our first we_have (race_start)
    our_times = []
    for r in self_pieces:
        dt = parse_rfc3339(r['first_ts'])
        if dt:
            our_times.append(dt)

    if not our_times:
        return jsonify({
            'faster_peers': [],
            'stats': {
                'total_peers': total_peers,
                'peers_faster_than_us': 0,
                'seeders_detected': 0,
                'competitive_peers': 0,
            }
        })

    race_start = min(our_times)

    # Build our cumulative curve: our_curve[t] = pieces completed by second t
    our_elapsed = sorted((dt - race_start).total_seconds() for dt in our_times)
    race_duration = int(our_elapsed[-1]) + 1 if our_elapsed else 1

    our_curve = [0] * (race_duration + 1)
    cum = 0
    ei = 0
    for sec in range(race_duration + 1):
        while ei < len(our_elapsed) and our_elapsed[ei] <= sec:
            cum += 1
            ei += 1
        our_curve[sec] = cum

    # Group peer pieces by connection_id
    peer_groups = defaultdict(list)
    for r in peer_pieces:
        dt = parse_rfc3339(r['first_ts'])
        if dt:
            elapsed = (dt - race_start).total_seconds()
            peer_groups[r['connection_id']].append(elapsed)

    # Compare each peer's curve against ours
    faster_peers = []
    seeders = 0
    competitive_count = 0

    for conn_id, times in peer_groups.items():
        times.sort()
        total = len(times)
        meta = conn_meta.get(conn_id, {
            'conn_ptr': '', 'ip': '', 'port': 0, 'client': '', 'peer_id': '',
        })

        # Count pre-race pieces (announced before our first we_have)
        pre_race = sum(1 for t in times if t < 0)

        # Is this a seeder? (had >= 80% of piece_count before we started)
        is_seeder = pre_race >= piece_count * 0.8

        # Build peer cumulative curve up to our race_duration
        peer_curve = [0] * (race_duration + 1)
        cum = 0
        ei = 0
        for sec in range(race_duration + 1):
            while ei < total and times[ei] <= sec:
                cum += 1
                ei += 1
            peer_curve[sec] = cum

        # Compare curves: count seconds where peer is ahead
        ahead_secs = 0
        total_lead_pct = 0.0
        max_lead_pct = 0.0

        for sec in range(race_duration + 1):
            our_pct = 100.0 * our_curve[sec] / piece_count
            peer_pct = 100.0 * peer_curve[sec] / piece_count
            lead = peer_pct - our_pct
            if lead > 0:
                ahead_secs += 1
                total_lead_pct += lead
                if lead > max_lead_pct:
                    max_lead_pct = lead

        avg_lead_pct = total_lead_pct / ahead_secs if ahead_secs > 0 else 0

        # Classify: seeder, competitive, or skip
        if is_seeder:
            category = 'seeder'
            seeders += 1
        elif ahead_secs >= max(5, race_duration * 0.10) and avg_lead_pct >= 2.0:
            category = 'competitive'
            competitive_count += 1
        else:
            continue  # not meaningfully faster — skip

        faster_peers.append({
            'connection_id': conn_id,
            'conn_ptr': meta['conn_ptr'],
            'ip': meta['ip'],
            'port': meta['port'],
            'client': meta['client'],
            'peer_id': meta['peer_id'],
            'total_pieces': total,
            'ahead_secs': ahead_secs,
            'avg_lead_pct': round(avg_lead_pct, 1),
            'max_lead_pct': round(max_lead_pct, 1),
            'category': category,
        })

    # Sort: competitive first (by avg_lead_pct desc), then seeders
    faster_peers.sort(key=lambda p: (
        0 if p['category'] == 'competitive' else 1,
        -p['avg_lead_pct'],
    ))

    return jsonify({
        'faster_peers': faster_peers,
        'stats': {
            'total_peers': total_peers,
            'peers_faster_than_us': len(faster_peers),
            'seeders_detected': seeders,
            'competitive_peers': competitive_count,
            'race_duration_secs': race_duration,
        }
    })


@app.route('/api/events')
def sse_stream():
    """Server-Sent Events stream for real-time updates."""
    def event_stream():
        q = queue.Queue()
        sse_clients.append(q)

        try:
            yield f"data: {{'type': 'connected'}}\n\n"

            while True:
                try:
                    msg = q.get(timeout=30)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            sse_clients.remove(q)

    return Response(event_stream(), mimetype='text/event-stream')


@app.route('/api/notify', methods=['POST'])
def notify():
    """Endpoint for race-monitor to notify of new races."""
    try:
        data = request.get_json() or {}
        race_id = data.get('race_id')

        event = f'{{"type": "race_added", "race_id": {race_id}}}'
        for client_queue in sse_clients:
            try:
                client_queue.put_nowait(event)
            except queue.Full:
                pass

        return jsonify({'status': 'notified', 'clients': len(sse_clients)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found at {DB_PATH}")
        print("Update 'race_db' in config.toml to specify database path")
        exit(1)

    # Create performance indexes for aggregation queries
    print(f"Ensuring performance indexes...")
    ensure_indexes(DB_PATH)

    print(f"Starting Race Monitor Dashboard")
    print(f"Database: {DB_PATH}")
    print(f"Listening on: http://{BIND_HOST}:{BIND_PORT}")
    print(f"Debug mode: {DEBUG}")
    print(f"")
    print(f"Schema: eBPF uprobe architecture")
    print(f"  Event types: have (peer announced piece), piece_received (we completed piece)")
    print(f"  - races, torrents, connections, race_peers, packet_events, event_types")

    app.run(host=BIND_HOST, port=BIND_PORT, debug=DEBUG)

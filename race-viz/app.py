#!/usr/bin/env python3
"""Race Monitor Visualization Dashboard - Flask Backend

 eBPF architecture:
- Two event types: have (peer announced piece) and piece_received (we completed piece)
- Peers identified by opaque conn_ptr (peer_<hex> / conn_<hex>)
- Self peer (peer_id="self") represents our own piece completions
- Timestamps are RFC 3339 (e.g. "2026-02-09T05:18:37.753Z")
"""

import os
import sqlite3
import queue
import time
from datetime import datetime, timezone
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
    # raw is bytes from BLOB column
    # Find the readable ASCII prefix, hex-encode the rest
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


def window_key(dt):
    """Round a datetime down to the nearest 100ms boundary, return as ISO string."""
    # Truncate microseconds to nearest 100ms
    ms = dt.microsecond // 100_000 * 100_000
    w = dt.replace(microsecond=ms)
    ms_str = f'{ms // 1000:03d}'
    return w.strftime(f'%Y-%m-%dT%H:%M:%S.{ms_str}Z') if w.tzinfo else w.strftime(f'%Y-%m-%dT%H:%M:%S.{ms_str}')


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
            # Expand ~ in race_db path
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


def get_db():
    """Get database connection."""
    conn = sqlite3.connect(DB_PATH)
    # BT peer IDs contain arbitrary binary — replace non-UTF-8 bytes
    # rather than crashing. New data is hex-encoded, but old rows may not be.
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
    """Get detailed race data including packet events."""
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

    # Get packet events with peer and connection info
    cursor.execute('''
        SELECT
            pe.id,
            pe.ts,
            et.name as event_type,
            pe.piece_index,
            pe.data,
            c.conn_ptr,
            c.id as connection_id
        FROM packet_events pe
        JOIN event_types et ON pe.event_type_id = et.id
        LEFT JOIN connections c ON pe.connection_id = c.id
        WHERE pe.race_id = ?
        ORDER BY pe.ts
        LIMIT 10000
    ''', (race_id,))

    events = []
    peers_dict = {}

    for row in cursor.fetchall():
        conn_ptr = row['conn_ptr'] or 'unknown'
        connection_id = row['connection_id']

        # Track unique peers by connection
        if connection_id and connection_id not in peers_dict:
            peers_dict[connection_id] = {
                'connection_id': connection_id,
                'conn_ptr': conn_ptr,
                'piece_count': 0,
                'events': []
            }

        event = {
            'id': row['id'],
            'ts': row['ts'],
            'event_type': row['event_type'],
            'piece_index': row['piece_index'],
            'data': row['data'],
            'connection_id': connection_id
        }

        events.append(event)

        if connection_id:
            peers_dict[connection_id]['events'].append(event)

            # Track peer progress from have events
            if row['event_type'] == 'have':
                peers_dict[connection_id]['piece_count'] += 1

    # Compute aggregated timeline (group events by 100ms windows)
    timeline = {}
    for event in events:
        dt = parse_rfc3339(event['ts'])
        if dt is None:
            continue
        wk = window_key(dt)

        if wk not in timeline:
            timeline[wk] = {
                'ts': wk,
                'have_count': 0,
                'piece_received': 0,
            }

        if event['event_type'] == 'have':
            timeline[wk]['have_count'] += 1
        elif event['event_type'] == 'piece_received':
            timeline[wk]['piece_received'] += 1

    conn.close()

    return jsonify({
        'race': race,
        'events': events[:1000],  # Limit to first 1000 for browser performance
        'timeline': sorted(timeline.values(), key=lambda x: x['ts']),
        'peers': list(peers_dict.values())
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


@app.route('/api/events')
def sse_stream():
    """Server-Sent Events stream for real-time updates."""
    def event_stream():
        # Create a queue for this client
        q = queue.Queue()
        sse_clients.append(q)

        try:
            # Send initial connection confirmation
            yield f"data: {{'type': 'connected'}}\n\n"

            # Keep connection alive and send events
            while True:
                try:
                    # Wait for event with timeout to send keepalive
                    msg = q.get(timeout=30)
                    yield f"data: {msg}\n\n"
                except queue.Empty:
                    # Send keepalive comment every 30s
                    yield ": keepalive\n\n"
        finally:
            # Clean up when client disconnects
            sse_clients.remove(q)

    return Response(event_stream(), mimetype='text/event-stream')


@app.route('/api/notify', methods=['POST'])
def notify():
    """Endpoint for race-monitor to notify of new races."""
    try:
        data = request.get_json() or {}
        race_id = data.get('race_id')

        # Broadcast to all connected SSE clients
        event = f'{{"type": "race_added", "race_id": {race_id}}}'
        for client_queue in sse_clients:
            try:
                client_queue.put_nowait(event)
            except queue.Full:
                pass  # Skip if queue is full

        return jsonify({'status': 'notified', 'clients': len(sse_clients)}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found at {DB_PATH}")
        print("Update 'race_db' in config.toml to specify database path")
        exit(1)

    print(f"Starting Race Monitor Dashboard")
    print(f"Database: {DB_PATH}")
    print(f"Listening on: http://{BIND_HOST}:{BIND_PORT}")
    print(f"Debug mode: {DEBUG}")
    print(f"")
    print(f"Schema: eBPF uprobe architecture")
    print(f"  Event types: have (peer announced piece), piece_received (we completed piece)")
    print(f"  - races, torrents, connections, race_peers, packet_events, event_types")

    app.run(host=BIND_HOST, port=BIND_PORT, debug=DEBUG)

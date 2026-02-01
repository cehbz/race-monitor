#!/usr/bin/env python3
"""Race Monitor Visualization Dashboard - Flask Backend"""

import os
import sqlite3
import queue
import time
from pathlib import Path
from flask import Flask, jsonify, render_template, Response, request
from flask_cors import CORS
import toml

app = Flask(__name__)
CORS(app)

# SSE client management
sse_clients = []

# Load configuration
def load_config():
    """Load configuration from config.toml with sensible defaults."""
    config_path = Path(__file__).parent / 'config.toml'

    defaults = {
        'race_db': str(Path.home() / '.local/share/race-monitor/races.db'),
        'bind_host': '10.112.227.3',
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
            r.hash,
            r.name,
            r.size,
            r.started_at,
            r.completed_at,
            COUNT(s.id) as sample_count,
            MAX(s.uploaded) as total_uploaded,
            MAX(s.progress) as final_progress
        FROM races r
        LEFT JOIN samples s ON r.id = s.race_id
        GROUP BY r.id
        ORDER BY r.started_at DESC
    ''')

    races = []
    for row in cursor.fetchall():
        races.append({
            'id': row['id'],
            'hash': row['hash'],
            'name': row['name'],
            'size': row['size'],
            'started_at': row['started_at'],
            'completed_at': row['completed_at'],
            'sample_count': row['sample_count'],
            'total_uploaded': row['total_uploaded'],
            'final_progress': row['final_progress']
        })

    conn.close()
    return jsonify(races)


@app.route('/api/race/<int:race_id>')
def get_race_data(race_id):
    """Get detailed race data including all samples."""
    conn = get_db()
    cursor = conn.cursor()

    # Get race metadata
    cursor.execute('SELECT * FROM races WHERE id = ?', (race_id,))
    race_row = cursor.fetchone()

    if not race_row:
        conn.close()
        return jsonify({'error': 'Race not found'}), 404

    race = {
        'id': race_row['id'],
        'hash': race_row['hash'],
        'name': race_row['name'],
        'size': race_row['size'],
        'started_at': race_row['started_at'],
        'completed_at': race_row['completed_at']
    }

    # Get our samples (from samples table)
    cursor.execute('''
        SELECT
            ts,
            upload_rate,
            download_rate,
            progress,
            uploaded,
            downloaded,
            peer_count,
            seed_count,
            my_rank
        FROM samples
        WHERE race_id = ?
        ORDER BY ts
    ''', (race_id,))

    our_samples = []
    for row in cursor.fetchall():
        our_samples.append({
            'ts': row['ts'],
            'upload_rate': row['upload_rate'],
            'download_rate': row['download_rate'],
            'progress': row['progress'],
            'uploaded': row['uploaded'],
            'downloaded': row['downloaded'],
            'peer_count': row['peer_count'],
            'seed_count': row['seed_count'],
            'my_rank': row['my_rank']
        })

    # Get peer samples (from peer_samples + peers table)
    cursor.execute('''
        SELECT
            ps.peer_id,
            ps.ts,
            ps.upload_rate,
            ps.download_rate,
            ps.progress,
            ps.uploaded,
            ps.downloaded,
            p.ip,
            p.port,
            p.client,
            p.country,
            p.connection,
            p.flags
        FROM peer_samples ps
        JOIN peers p ON ps.peer_id = p.id
        WHERE ps.race_id = ?
        ORDER BY ps.peer_id, ps.ts
    ''', (race_id,))

    # Group peer samples by peer_id
    peers = {}
    for row in cursor.fetchall():
        peer_id = row['peer_id']

        if peer_id not in peers:
            peers[peer_id] = {
                'peer_id': peer_id,
                'ip': row['ip'],
                'port': row['port'],
                'client': row['client'],
                'country': row['country'],
                'connection': row['connection'],
                'flags': row['flags'],
                'samples': []
            }

        peers[peer_id]['samples'].append({
            'ts': row['ts'],
            'upload_rate': row['upload_rate'],
            'download_rate': row['download_rate'],
            'progress': row['progress'],
            'uploaded': row['uploaded'],
            'downloaded': row['downloaded']
        })

    conn.close()

    return jsonify({
        'race': race,
        'our_samples': our_samples,
        'peers': list(peers.values())
    })


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

    app.run(host=BIND_HOST, port=BIND_PORT, debug=DEBUG)

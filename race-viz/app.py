#!/usr/bin/env python3
"""Race Monitor Visualization Dashboard — Flask routes.

Thin routing layer that delegates to:
  - analysis.py for pure computation (curve building, classification, extrapolation)
  - db.py for all SQL queries

eBPF architecture:
  - Two event types: have (peer announced piece) and piece_received (we completed)
  - Peers identified by opaque conn_ptr (hex address from eBPF uprobe)
  - Self peer (conn_ptr="self") represents our own piece completions
  - Timestamps in packet_events are int64 nanoseconds since boot (BPF ktime)
  - Race wallclock time recorded from hooks as start_wallclock
"""

import os
import queue
from collections import defaultdict
from pathlib import Path

from flask import Flask, jsonify, render_template, Response, request
from flask_cors import CORS
import toml

from analysis import (
    parse_rfc3339,
    decode_peer_id,
    build_cumulative_curve,
    build_piece_count_curve,
    classify_peer,
    extrapolate_finish_time,
)
import db

app = Flask(__name__)
CORS(app)

# SSE client management
sse_clients = []

# Nanoseconds per second for BPF timestamp conversion.
_NS_PER_SEC = 1_000_000_000


def load_config():
    """Load configuration from ~/.config/race-monitor/viz.toml with sensible defaults."""
    config_path = Path.home() / '.config' / 'race-monitor' / 'viz.toml'
    defaults = {
        'race_db': str(Path.home() / '.local/share/race-monitor/races.db'),
        'bind_host': '0.0.0.0',
        'bind_port': 8080,
        'debug': False,
    }
    if config_path.exists():
        try:
            config = toml.load(config_path)
            if 'race_db' in config:
                config['race_db'] = str(Path(config['race_db']).expanduser())
            return {**defaults, **config}
        except Exception as e:
            print(f"Warning: Error loading {config_path}: {e}")
    return defaults


config = load_config()
DB_PATH = config['race_db']
BIND_HOST = config['bind_host']
BIND_PORT = config['bind_port']
DEBUG = config['debug']


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Serve the dashboard."""
    return render_template('index.html')


@app.route('/api/races')
def list_races():
    """Fast race list — no expensive COUNT joins over packet_events."""
    conn = db.get_db(DB_PATH)
    races = db.fetch_races(conn)
    conn.close()
    return jsonify(races)


@app.route('/api/races/counts')
def race_counts():
    """Lazy enrichment of race list with peer/event counts.

    Query param: ids=1,2,3 (comma-separated race IDs).
    """
    ids_param = request.args.get('ids', '')
    try:
        race_ids = [int(x) for x in ids_param.split(',') if x.strip()]
    except ValueError:
        return jsonify({'error': 'ids must be comma-separated integers'}), 400

    conn = db.get_db(DB_PATH)
    counts = db.fetch_race_counts(conn, race_ids)
    conn.close()
    return jsonify({str(k): v for k, v in counts.items()})


@app.route('/api/race/<int:race_id>')
def get_race_data(race_id):
    """Race metadata, 1-second bucketed timeline, and peer count."""
    conn = db.get_db(DB_PATH)
    race = db.fetch_race_detail(conn, race_id)
    if not race:
        conn.close()
        return jsonify({'error': 'Race not found'}), 404

    timeline = db.fetch_timeline(conn, race_id)
    peer_count = db.fetch_peer_count(conn, race_id)
    conn.close()

    return jsonify({
        'race': race,
        'timeline': timeline,
        'peer_count': peer_count,
    })


@app.route('/api/race/<int:race_id>/peer_progress')
def get_peer_progress(race_id):
    """Per-peer cumulative completion % over time.

    Two-phase approach:
    1. SQL: first timestamp each peer announced each piece (int64 ns since boot)
    2. Python: build cumulative timelines sampled at 1-second intervals
    """
    conn = db.get_db(DB_PATH)
    race = db.fetch_race_detail(conn, race_id)
    if not race:
        conn.close()
        return jsonify({'error': 'Race not found'}), 404
    piece_count = race['piece_count'] or 1

    self_pieces = db.fetch_self_pieces(conn, race_id)
    peer_pieces = db.fetch_peer_pieces(conn, race_id)
    conn_meta = db.fetch_connection_meta(conn, race_id)
    conn.close()

    # Use start_ktime (from torrent::start()) as epoch when available,
    # falling back to earliest event timestamp. start_ktime captures the
    # latency between torrent start and first piece verification.
    all_ts = []
    for r in self_pieces:
        ts = r['first_ts']
        if ts is not None:
            all_ts.append(ts)
    for r in peer_pieces:
        ts = r['first_ts']
        if ts is not None:
            all_ts.append(ts)

    if not all_ts:
        # No events at all, but still report discovered peers
        peers_data = []
        for conn_id, meta in conn_meta.items():
            peers_data.append({
                'id': conn_id,
                'label': meta['label'],
                'ip': meta['ip'],
                'port': meta['port'],
                'client': meta['client'],
                'total_pieces': 0,
                'elapsed_secs': [],
                'piece_counts': [],
                'seeder': True,
            })
        return jsonify({
            'piece_count': piece_count,
            'self': None,
            'peers': peers_data,
        })

    epoch_ns = race.get('start_ktime') or min(all_ts)

    # Build self timeline (elapsed seconds from epoch)
    self_times = []
    for r in self_pieces:
        ts = r['first_ts']
        if ts is not None:
            self_times.append((ts - epoch_ns) / _NS_PER_SEC)

    self_elapsed, self_pieces = build_cumulative_curve(self_times, piece_count)
    self_data = {
        'elapsed_secs': self_elapsed,
        'piece_counts': self_pieces,
    } if self_elapsed else None

    # Group peer pieces by connection_id, build timelines
    peer_groups = defaultdict(list)
    for r in peer_pieces:
        ts = r['first_ts']
        if ts is not None:
            peer_groups[r['connection_id']].append((ts - epoch_ns) / _NS_PER_SEC)

    peers_data = []
    # Peers with per-piece HAVE data (leechers in a race)
    for conn_id, times in peer_groups.items():
        elapsed, pcts = build_cumulative_curve(times, piece_count)
        if not elapsed:
            continue
        meta = conn_meta.get(conn_id, {
            'label': f'conn_{conn_id}', 'ip': '', 'port': 0, 'client': '',
        })
        peers_data.append({
            'id': conn_id,
            'label': meta['label'],
            'ip': meta['ip'],
            'port': meta['port'],
            'client': meta['client'],
            'total_pieces': len(times),
            'elapsed_secs': elapsed,
            'piece_counts': pcts,
            'seeder': False,
        })

    # Peers discovered via calibration but without HAVE data (seeders)
    tracked_ids = {p['id'] for p in peers_data}
    for conn_id, meta in conn_meta.items():
        if conn_id in tracked_ids:
            continue
        peers_data.append({
            'id': conn_id,
            'label': meta['label'],
            'ip': meta['ip'],
            'port': meta['port'],
            'client': meta['client'],
            'total_pieces': 0,
            'elapsed_secs': [],
            'piece_counts': [],
            'seeder': True,
        })

    peers_data.sort(key=lambda p: (-p['total_pieces'], p['label']))

    race_duration = max(
        self_elapsed[-1] if self_elapsed else 0,
        max((p['elapsed_secs'][-1] for p in peers_data if p['elapsed_secs']), default=0),
    )

    return jsonify({
        'piece_count': piece_count,
        'race_duration_secs': race_duration,
        'self': self_data,
        'peers': peers_data,
    })


@app.route('/api/race/<int:race_id>/peers')
def get_peers(race_id):
    """Unified peer table: all race participants ordered by finish time.

    Returns every peer (including self) with finish time or projection.
    Seeders (no individual HAVE data) get finish_sec=0, sorted first.
    """
    conn = db.get_db(DB_PATH)
    race = db.fetch_race_detail(conn, race_id)
    if not race:
        conn.close()
        return jsonify({'error': 'Race not found'}), 404
    piece_count = race['piece_count'] or 1

    self_pieces = db.fetch_self_pieces(conn, race_id)
    peer_pieces = db.fetch_peer_pieces(conn, race_id)
    conn_meta = db.fetch_connection_meta(conn, race_id)

    # Collect peer IPs for enrichment lookup
    peer_ips = {meta['ip'] for meta in conn_meta.values() if meta.get('ip')}
    enrichment = db.fetch_ip_enrichment(conn, peer_ips)
    conn.close()

    # Compute race epoch
    all_ts = []
    for r in self_pieces:
        if r['first_ts'] is not None:
            all_ts.append(r['first_ts'])
    for r in peer_pieces:
        if r['first_ts'] is not None:
            all_ts.append(r['first_ts'])

    epoch_ns = race.get('start_ktime') or (min(all_ts) if all_ts else 0)

    # --- Self entry ---
    our_finish_sec = None
    if all_ts and epoch_ns:
        our_ts = [r['first_ts'] for r in self_pieces if r['first_ts'] is not None]
        our_elapsed = sorted((ts - epoch_ns) / _NS_PER_SEC for ts in our_ts)

        # Prefer wallclock finish if available
        completed_at = parse_rfc3339(race.get('completed_at'))
        start_wc = parse_rfc3339(race.get('start_wallclock'))
        if completed_at and start_wc:
            our_finish_sec = round((completed_at - start_wc).total_seconds(), 1)
        elif our_elapsed:
            our_finish_sec = round(our_elapsed[-1], 1)

    # Build self piece timestamp map: piece_index → first_ts (raw ns)
    self_piece_ts = {}
    for r in self_pieces:
        if r['first_ts'] is not None:
            self_piece_ts[r['piece_index']] = r['first_ts']

    # --- Group peer pieces by connection_id ---
    # Store both elapsed time and raw ts + piece_index for ahead calculation
    peer_groups = defaultdict(list)
    peer_raw = defaultdict(list)  # conn_id → [(piece_index, raw_ts), ...]
    for r in peer_pieces:
        if r['first_ts'] is not None:
            peer_groups[r['connection_id']].append(
                (r['first_ts'] - epoch_ns) / _NS_PER_SEC
            )
            peer_raw[r['connection_id']].append(
                (r['piece_index'], r['first_ts'])
            )

    participants = []

    # Self
    self_pieces_count = len([r for r in self_pieces if r['first_ts'] is not None])
    participants.append({
        'label': 'Us',
        'ip': '(self)',
        'port': 0,
        'client': '',
        'type': 'self',
        'pieces': self_pieces_count,
        'ahead': piece_count // 2,
        'finish_sec': our_finish_sec,
    })

    # Peers with HAVE data
    tracked_ids = set()
    for conn_id, times in peer_groups.items():
        tracked_ids.add(conn_id)
        times.sort()
        meta = conn_meta.get(conn_id, {
            'ip': '', 'port': 0, 'client': '',
        })

        # Classify: if they had >= 80% pieces before our first we_have, seeder
        pre_race = sum(1 for t in times if t < 0)
        is_seeder = pre_race >= piece_count * 0.8

        if is_seeder:
            finish_sec = 0.0
        else:
            # Project finish via extrapolation
            peer_elapsed, peer_pieces = build_cumulative_curve(times, piece_count)
            finish_sec = extrapolate_finish_time(peer_elapsed, peer_pieces, piece_count)

        # Count pieces where this peer announced before we verified
        ahead = 0
        for pidx, pts in peer_raw[conn_id]:
            our_ts = self_piece_ts.get(pidx)
            if our_ts is not None and pts < our_ts:
                ahead += 1

        label = meta.get('client') or (f"{meta.get('ip', '')}:{meta.get('port', 0)}" if meta.get('ip') else f'conn_{conn_id}')
        participants.append({
            'label': label,
            'ip': meta.get('ip', ''),
            'port': meta.get('port', 0),
            'client': meta.get('client', ''),
            'type': 'seeder' if is_seeder else 'leecher',
            'pieces': len(times),
            'ahead': ahead,
            'finish_sec': round(finish_sec, 1) if finish_sec is not None else None,
        })

    # Peers without HAVE data (seeders discovered via struct dumps only)
    for conn_id, meta in conn_meta.items():
        if conn_id in tracked_ids:
            continue
        label = meta.get('client') or (f"{meta.get('ip', '')}:{meta.get('port', 0)}" if meta.get('ip') else f'conn_{conn_id}')
        participants.append({
            'label': label,
            'ip': meta.get('ip', ''),
            'port': meta.get('port', 0),
            'client': meta.get('client', ''),
            'type': 'seeder',
            'pieces': 0,
            'ahead': 0,
            'finish_sec': 0.0,
        })

    # Merge enrichment data into participants
    for p in participants:
        ip = p.get('ip', '')
        net = enrichment.get(ip)
        if net:
            p['network'] = net
        else:
            p['network'] = None

    # Sort: seeders first (finish=0, by pieces desc), then all others
    # (including self) by finish_sec ascending, unknown last
    def sort_key(p):
        if p['type'] == 'seeder' and p['finish_sec'] == 0:
            return (0, -p['pieces'])
        if p['finish_sec'] is not None:
            return (1, p['finish_sec'])
        return (2, 0)

    participants.sort(key=sort_key)

    return jsonify({
        'piece_count': piece_count,
        'our_finish_sec': our_finish_sec,
        'participants': participants,
    })


# ---------------------------------------------------------------------------
# SSE
# ---------------------------------------------------------------------------

@app.route('/api/events')
def sse_stream():
    """Server-Sent Events stream for real-time race notifications."""
    def event_stream():
        q = queue.Queue()
        sse_clients.append(q)
        try:
            yield "data: {'type': 'connected'}\n\n"
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
    """Endpoint for race-monitor daemon to notify of new races."""
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


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    if not os.path.exists(DB_PATH):
        print(f"Error: Database not found at {DB_PATH}")
        print("Update 'race_db' in config.toml to specify database path")
        exit(1)

    print(f"Starting Race Monitor Dashboard")
    print(f"Database: {DB_PATH}")
    print(f"Listening on: http://{BIND_HOST}:{BIND_PORT}")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=DEBUG)

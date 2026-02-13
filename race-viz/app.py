#!/usr/bin/env python3
"""Race Monitor Visualization Dashboard — Flask routes.

Thin routing layer that delegates to:
  - analysis.py for pure computation (curve building, classification, extrapolation)
  - db.py for all SQL queries

eBPF architecture:
  - Two event types: have (peer announced piece) and piece_received (we completed)
  - Peers identified by opaque conn_ptr (hex address from eBPF uprobe)
  - Self peer (conn_ptr="self") represents our own piece completions
  - Timestamps are RFC 3339 (e.g. "2026-02-09T05:18:37.753Z")
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


def load_config():
    """Load configuration from config.toml with sensible defaults."""
    config_path = Path(__file__).parent / 'config.toml'
    defaults = {
        'race_db': str(Path.home() / '.local/share/race-monitor/races.db'),
        'bind_host': '0.0.0.0',
        'bind_port': 8080,
        'debug': True,
    }
    if config_path.exists():
        try:
            config = toml.load(config_path)
            if 'race_db' in config:
                config['race_db'] = str(Path(config['race_db']).expanduser())
            return {**defaults, **config}
        except Exception as e:
            print(f"Warning: Error loading config.toml: {e}")
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
    race_peers = db.fetch_race_peers(conn, race_id)
    conn.close()

    return jsonify({
        'race': race,
        'timeline': timeline,
        'peer_count': peer_count,
        'race_peers': race_peers,
    })


@app.route('/api/race/<int:race_id>/peer_progress')
def get_peer_progress(race_id):
    """Per-peer cumulative completion % over time.

    Two-phase approach:
    1. SQL: first timestamp each peer announced each piece
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

    # Find global epoch (earliest timestamp across all events)
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

    # Build self timeline
    self_times = []
    for r in self_pieces:
        dt = parse_rfc3339(r['first_ts'])
        if dt:
            self_times.append((dt - epoch).total_seconds())

    self_elapsed, self_pcts = build_cumulative_curve(self_times, piece_count)
    self_data = {
        'elapsed_secs': self_elapsed,
        'completion_pcts': self_pcts,
    } if self_elapsed else None

    # Group peer pieces by connection_id, build timelines
    peer_groups = defaultdict(list)
    for r in peer_pieces:
        dt = parse_rfc3339(r['first_ts'])
        if dt:
            peer_groups[r['connection_id']].append((dt - epoch).total_seconds())

    peers_data = []
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
            'completion_pcts': pcts,
        })

    peers_data.sort(key=lambda p: p['total_pieces'], reverse=True)

    race_duration = max(
        self_elapsed[-1] if self_elapsed else 0,
        max((p['elapsed_secs'][-1] for p in peers_data), default=0),
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

    Compares cumulative piece counts at each second. A peer is 'faster' only
    if their curve leads ours for a sustained period — not merely because they
    downloaded pieces in a different order.

    Also projects each peer's finish time via linear extrapolation and reports
    whether they finished before us.
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
    total_peers = db.fetch_peer_count(conn, race_id)
    conn.close()

    if not self_pieces:
        return jsonify({
            'faster_peers': [],
            'stats': {
                'total_peers': 0,
                'peers_faster_than_us': 0,
                'seeders_detected': 0,
                'competitive_peers': 0,
                'finished_before_us_count': 0,
                'note': 'No we_have events found — download may not have started.',
            },
        })

    # Parse our piece times and find race_start
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
                'finished_before_us_count': 0,
            },
        })

    race_start = min(our_times)
    our_elapsed = sorted((dt - race_start).total_seconds() for dt in our_times)
    race_duration = int(our_elapsed[-1]) + 1 if our_elapsed else 1

    # Our authoritative finish time: completed_at if available, else last observed
    completed_at = parse_rfc3339(race.get('completed_at'))
    if completed_at:
        our_finish_sec = (completed_at - race_start).total_seconds()
    else:
        our_finish_sec = our_elapsed[-1]

    our_curve = build_piece_count_curve(our_elapsed, race_duration)

    # Group peer pieces by connection_id
    peer_groups = defaultdict(list)
    for r in peer_pieces:
        dt = parse_rfc3339(r['first_ts'])
        if dt:
            peer_groups[r['connection_id']].append((dt - race_start).total_seconds())

    # Compare each peer
    faster_peers = []
    seeders = 0
    competitive_count = 0
    finished_before_us_count = 0

    for conn_id, times in peer_groups.items():
        times.sort()
        total = len(times)
        meta = conn_meta.get(conn_id, {
            'conn_ptr': '', 'ip': '', 'port': 0, 'client': '', 'peer_id': '',
        })

        pre_race = sum(1 for t in times if t < 0)
        peer_curve = build_piece_count_curve(times, race_duration)

        result = classify_peer(peer_curve, our_curve, piece_count, race_duration, pre_race)
        if result is None:
            continue

        # Build cumulative curve for extrapolation
        peer_elapsed, peer_pcts = build_cumulative_curve(times, piece_count)
        proj_finish = extrapolate_finish_time(peer_elapsed, peer_pcts, piece_count)
        finished_before_us = proj_finish is not None and proj_finish < our_finish_sec

        if finished_before_us:
            finished_before_us_count += 1

        if result['category'] == 'seeder':
            seeders += 1
        else:
            competitive_count += 1

        faster_peers.append({
            'connection_id': conn_id,
            'conn_ptr': meta['conn_ptr'],
            'ip': meta['ip'],
            'port': meta['port'],
            'client': meta['client'],
            'peer_id': meta['peer_id'],
            'total_pieces': total,
            'ahead_secs': result['ahead_secs'],
            'avg_lead_pct': result['avg_lead_pct'],
            'max_lead_pct': result['max_lead_pct'],
            'category': result['category'],
            'projected_finish_sec': proj_finish,
            'finished_before_us': finished_before_us,
        })

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
            'finished_before_us_count': finished_before_us_count,
            'race_duration_secs': race_duration,
            'our_finish_sec': round(our_finish_sec, 1),
        },
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

    print("Ensuring performance indexes...")
    db.ensure_indexes(DB_PATH)

    print(f"Starting Race Monitor Dashboard")
    print(f"Database: {DB_PATH}")
    print(f"Listening on: http://{BIND_HOST}:{BIND_PORT}")
    app.run(host=BIND_HOST, port=BIND_PORT, debug=DEBUG)

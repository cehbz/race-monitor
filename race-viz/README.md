# Race Monitor Dashboard

Web-based visualization for race-monitor SQLite data. Shows piece-level progress for each peer during a torrent race.

## Features

- Race list with metadata (name, size, pieces, duration, peer count)
- Per-peer cumulative piece progress curves with adaptive resolution
- Combined progress chart (all peers overlaid)
- Peer table with IP, client, ASN, network segment, provider, city/country
- Enrichment data from rDNS, Team Cymru, and ipapi.is
- Self-row highlighting (gold accent) based on configured IP
- Server-Sent Events for real-time race notifications
- Plotly.js interactive charts with dark theme

## Installation

```bash
pip install -r requirements.txt
```

## Configuration

`~/.config/race-monitor/viz.toml`:

```toml
race_db = "~/.local/share/race-monitor/races.db"
bind_host = "0.0.0.0"
bind_port = 8080
debug = false
our_ip = ""   # your public IP for self-row identification
```

## Usage

```bash
python3 app.py
```

Or via systemd: `systemctl start race-viz@$USER`

## Architecture

- **Backend**: Flask with SQLite (WAL mode, read-only)
- **Frontend**: Single-page HTML/JS with Plotly.js
- **Modules**: `app.py` (routes, SSE), `db.py` (SQL queries), `analysis.py` (computation)
- **API**: `/api/races`, `/api/race/<id>/events`, `/api/race/<id>/peers`, `/events` (SSE)

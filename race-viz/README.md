# Race Monitor Visualization Dashboard

Web-based visualization dashboard for race-monitor SQLite data.

## Features

- Browse all races in reverse chronological order
- Interactive Plotly.js visualizations:
  - Download rate (bytes since previous sample) per peer
  - Upload rate (bytes since previous sample) per peer
  - Progress percentage over time per peer
- Synchronized zoom/pan across all charts
- Tooltips with detailed peer information
- Dark theme optimized for readability

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Or using a virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
# Run with default settings (binds to 10.112.227.3:8080)
python3 app.py

# Or activate virtual environment first
source venv/bin/activate
python3 app.py
```

The dashboard will be accessible at: `http://10.112.227.3:8080`

## Configuration

Edit `config.toml` to customize settings:

```toml
# Path to the SQLite database
race_db = "~/.local/share/race-monitor/races.db"

# Network bind address (IP to listen on)
# Use "0.0.0.0" to listen on all interfaces
# Use specific IP like "10.112.227.3" to restrict to that interface
bind_host = "10.112.227.3"

# Port to listen on
bind_port = 8080

# Enable Flask debug mode (shows detailed errors, auto-reloads on code changes)
# Set to false in production
debug = true
```

## Architecture

- **Backend**: Flask with SQLite
- **Frontend**: Single-page HTML/JS with Plotly.js
- **API Endpoints**:
  - `GET /` - Dashboard UI
  - `GET /api/races` - List all races
  - `GET /api/race/<id>` - Get detailed race data

## Data Processing

- Download/upload deltas calculated client-side from cumulative totals
- "You" (your client) shown as distinct trace with bold line
- Each peer gets unique color and label (IP:port + client)
- Progress normalized to 0-100% scale

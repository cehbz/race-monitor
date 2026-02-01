# race-monitor

Torrent racing analytics for qBittorrent. Records high-frequency performance data during races and provides tools for analysis.

## Features

- Configurable polling interval (default 500ms) for detailed race metrics
- Asynchronous architecture with separate fetcher and processor goroutines
- Tracks your rank among seeders in real-time
- Two success criteria:
  - **Completion rank**: Who finished downloading first
  - **Upload rank**: Who uploaded the most during the initial swarm
- Normalized SQLite schema for efficient peer analysis
- Tracks initial swarm performance (peers seen while downloading)
- CSV export for external analysis tools
- Automatic stop conditions (initial swarm completion, max duration)

## Installation

```bash
go install github.com/cehbz/race-monitor/cmd/race-monitor@latest
```

Or build from source:

```bash
git clone https://github.com/cehbz/race-monitor
cd race-monitor
make install
```

## Configuration

Create `~/.config/race-monitor/config.toml`:

```toml
qbt_url = "http://127.0.0.1:8080"
qbt_user = "admin"
qbt_pass = "adminadmin"
race_db = "~/.local/share/race-monitor/races.db"  # Optional, this is the default
```

If `qbt_url` is not specified, it defaults to `http://127.0.0.1:8080`. If `race_db` is not specified, it defaults to `~/.local/share/race-monitor/races.db`.

## qBittorrent Setup

Add the following to **Options → Downloads → Run external program on torrent added**:

```
race-monitor record %I
```

This starts recording automatically when a new torrent is added.

## Usage

### List recent races

```bash
race-monitor list
race-monitor list -days 30
```

### View race statistics

```bash
race-monitor stats 42
```

Output:
```
Race #42: Some.Torrent.2024.1080p.BluRay

  Time to complete:    2m34s
  Recording duration:  17m34s

  Total uploaded:      2.3 GB
  Uploaded (5 min):    890.2 MB
  Uploaded (15 min):   1.8 GB

  Peak upload rate:    125.4 MB/s
  Avg upload rate:     89.2 MB/s

  Best rank:           #1
  Average rank:        1.4

  Completion rank:     #2 (download finish order)
  Upload rank:         #3 (total uploaded in swarm)
```

### Export to CSV

```bash
race-monitor export 42 -o race42.csv
```

## Recorded Metrics

Each sample (every 500ms by default) captures:

**Your stats:**
- Upload/download rate
- Progress percentage
- Total uploaded/downloaded
- Peer and seed counts
- Your rank among uploaders

**Peer stats** (normalized in separate table):
- IP address, port, client version
- Upload/download rate
- Progress percentage
- Total uploaded/downloaded
- Connection type, country, flags

All peer data during the initial swarm is recorded, allowing detailed post-race analysis of competitor performance.

## Command-line Options

### record

```bash
race-monitor record [options] <hash>
  -poll duration      Poll interval (default 500ms)
  -max duration       Max recording duration safety valve (default 30m)
  -log-level string   Log level: debug, info, warn, error (default info)
```

Recording automatically stops when all peers in the initial swarm (peers seen while you were downloading) have either completed or disappeared from the swarm.

### list

```bash
race-monitor list [options]
  -days int    Show races from last N days (default 7)
```

### export

```bash
race-monitor export [options] <race_id>
  -o string    Output file (default: stdout)
  -peers       Include peer samples (TODO)
```

## License

MIT

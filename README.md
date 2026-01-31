# race-monitor

Torrent racing analytics for qBittorrent. Records high-frequency performance data during races and provides tools for analysis.

## Features

- 500ms polling interval for detailed race metrics
- Tracks your rank among seeders in real-time
- SQLite storage for historical analysis
- CSV export for external analysis tools
- Automatic stop conditions (completion, low activity, max duration)

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

Set environment variables:

```bash
export QBT_URL="http://127.0.0.1:8080"   # qBittorrent WebUI URL
export QBT_USER="admin"                   # WebUI username
export QBT_PASS="adminadmin"              # WebUI password
export RACE_DB="~/.local/share/race-monitor/races.db"  # Optional, this is the default
```

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
  Final rank:          #2
```

### Export to CSV

```bash
race-monitor export 42 -o race42.csv
```

## Recorded Metrics

Each sample (every 500ms by default) captures:

- Upload/download rate
- Progress percentage
- Total uploaded/downloaded
- Peer and seed counts
- Your rank among seeders

Peer data is also recorded for seeders, allowing post-race analysis of competitor performance.

## Command-line Options

### record

```bash
race-monitor record [options] <hash>
  -poll duration         Poll interval (default 500ms)
  -max duration          Max recording duration (default 30m)
  -post-complete duration Time to record after 100% (default 15m)
  -log-level string      Log level: debug, info, warn, error (default info)
```

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

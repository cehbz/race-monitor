# race-monitor

eBPF-based BitTorrent race performance monitor. Attaches uprobes to qBittorrent's libtorrent C++ library to record when each peer obtains torrent pieces, with sub-millisecond precision and ~1-2% CPU overhead. Events are stored in SQLite and visualized via a Flask dashboard.

## Architecture

Three binaries with distinct responsibilities:

- **`race-calibrate`** — Offline tool that discovers 4 struct byte offsets by correlating eBPF memory dumps against the qBittorrent WebUI API. Run once per binary; results cached to `~/.config/race-monitor/calibration.json` keyed by binary SHA256.
- **`race-monitor`** — Long-running daemon that attaches eBPF uprobes and records race data. Requires pre-calibrated offsets. PID is the first positional argument. Enqueues new peer IPs for enrichment.
- **`race-enricher`** — Long-running daemon that resolves peer IPs to ISP/datacenter/seedbox provider. Two-queue pipeline: IP queue (rDNS + Team Cymru, free) then prefix queue (ipapi.is, rate-limited). Wakes via inotify on sentinel file.

Data flows strictly downward:

```
eBPF Probes (kernel C, probe.c) — 5 uprobes on libtorrent symbols
  ↓ perf buffer (256 KB/CPU)
Capture Layer — ELF symbol resolution, uprobe attachment, event decoding
  ↓ two channels (slim events + 4KB struct dumps)
Coordinator — single-writer event router, all state mutations
  ↓ per-race goroutines
Trackers — per-race event processing, SQLite batch writes
  ↓
SQLite (WAL mode) — concurrent dashboard reads
  ↓                    ↓
Dashboard (Flask)    Enricher (rDNS, Cymru, ipapi.is)
```

## Requirements

- **Linux kernel >= 5.8** with eBPF uprobe support
- **clang** + **linux-headers** (build-time only, for compiling eBPF C)
- **qBittorrent with symbol table** (binary must not be stripped)
- **Go 1.24+**
- **Python 3.11+** (dashboard only)
- Capabilities: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_SYS_ADMIN`

## Installation

```bash
git clone https://github.com/cehbz/race-monitor
cd race-monitor
make build          # compile eBPF C + Go binaries
make install        # build + install to ~/bin + sudo setcap
make install-services  # install + venv + systemd units
```

Use `make build-quick` to skip eBPF recompilation when only Go code changed.

## Configuration

`~/.config/race-monitor/config.toml` (shared by all binaries):

```toml
binary = "/usr/bin/qbittorrent-nox"
webui_url = "http://127.0.0.1:8080"
webui_user = ""
webui_pass = ""
race_db = "~/.local/share/race-monitor/races.db"
```

`~/.config/race-monitor/viz.toml` (dashboard):

```toml
race_db = "~/.local/share/race-monitor/races.db"
bind_host = "0.0.0.0"
bind_port = 8080
our_ip = ""   # your public IP, shown as highlighted "self" row
```

## Usage

### 1. Calibrate (once per binary)

Requires at least one active download for peer_connection discovery:

```bash
race-calibrate --pid $(pgrep -f 'qbittorrent-nox$')
```

Discovers 4 struct offsets: `info_hash`, `torrent_ptr`, `sockaddr_in`, `peer_id`. Results cached in `~/.config/race-monitor/calibration.json`.

### 2. Monitor

```bash
race-monitor $(pgrep -f 'qbittorrent-nox$') --detach --log-file ~/race-monitor.log
race-monitor $(pgrep -f 'qbittorrent-nox$') --log-level debug  # foreground
```

### 3. Enrich

```bash
race-enricher                    # long-running daemon, inotify wakeup
race-enricher --backfill --once  # enrich all existing IPs and exit
race-enricher --once             # process current queue and exit
```

### 4. Dashboard

```bash
cd race-viz && python3 app.py    # http://localhost:8080
```

### Systemd services

```bash
systemctl start race-monitor@$USER
systemctl start race-enricher@$USER
systemctl start race-viz@$USER
```

## How It Works

### eBPF Probes

Five uprobes attach to mangled C++ symbols in libtorrent:

| Probe | Fires when | Event |
|-------|-----------|-------|
| `trace_we_have` | We complete+verify a piece | `EventWeHave` + torrent struct dump on first encounter |
| `trace_incoming_have` | Peer announces a piece (HAVE) | `EventIncomingHave` + peer struct dump on first encounter |
| `trace_incoming_bitfield` | Peer sends BITFIELD at connect | Peer struct dump only (catches seeders) |
| `trace_torrent_start` | Torrent starts downloading | `EventTorrentStarted` + torrent struct dump |
| `trace_torrent_finished` | All pieces verified | `EventTorrentFinished` |

Probes read CPU registers (RDI=`this`, RSI=`piece_index` on x86_64) plus calibrated struct offsets for identity-based peer dedup. No hardcoded struct layouts.

### Calibration

Two-phase offset discovery from 4KB eBPF memory dumps:

1. **Torrent struct**: scan for 20-byte info_hash sequences matching known torrents from the API. Vote on offset; lock after 2+ matches.
2. **Peer connection struct**: scan for `sockaddr_in` patterns matching known peers (Phase 1), then peer_id bytes (Phase 2). Same voting/locking.

Offsets cached by binary SHA256. Re-running `race-calibrate` is only needed after qBittorrent recompilation.

### Race Lifecycle

1. `torrent::start()` fires — coordinator creates race, fetches metadata from qBittorrent API
2. Events stream in — coordinator routes `we_have` by torrent pointer, `incoming_have` by peer connection pointer
3. `torrent::finished()` fires — tracker starts a proportional grace period: 50% of download duration, clamped to [5s, 60s]
4. Grace timer expires — race finalized, BPF dedup maps cleaned for peer/torrent rediscovery

### Enrichment Pipeline

Two-queue design, each IP/prefix processed once:

1. **IP queue** (free): rDNS lookup + Team Cymru BGP/ASN resolution
2. **Prefix queue** (rate-limited): ipapi.is for ISP, datacenter, geo, provider

Three-tier provider identification: rDNS hostname patterns (highest confidence) > brand alias map (ASN/domain) > raw datacenter passthrough.

## Design Decisions

**Why eBPF uprobes over packet capture?** Uprobes operate at the application semantic level — `incoming_have()` fires after libtorrent has done TCP reassembly, BT framing, and protocol parsing. Eliminates an entire protocol layer. Handles protocol encryption transparently. At 505 MiB/s with ~100 peers: eBPF captures 100% of events at ~1-2% CPU; pcap could not keep up (19-29% capture rate).

**Why calibration is separate from monitoring.** `race-calibrate` runs once interactively; `race-monitor` loads cached offsets and never touches the API for calibration. Keeps the daemon simple and fast. Binary recompilation only requires re-running calibrate, not code changes.

**Why single-writer coordinator.** One goroutine owns all state maps. No mutexes on the ~3K events/sec hot path. Tracker goroutines communicate via channels.

**Why identity-based peer dedup.** BPF `seen_peers` uses `(torrent_ptr, ip, port)` instead of raw `peer_connection*` pointers. Prevents cross-race event contamination when libtorrent reuses freed connection addresses.

**Why two peer discovery probes.** Seeders never send individual HAVE messages — they use BITFIELD/HAVE-ALL at connect time. `incoming_bitfield` catches these; `incoming_have` catches leechers. Both share the `seen_peers` dedup map.

**Why schema recreation over migration.** Race data is transient; migration complexity is not justified. Schema version mismatch drops and recreates all tables.

**Why sentinel file wakeup for enrichment.** Daemon touches `enrichment.notify` only when enqueuing new IPs. Enricher watches via inotify. Avoids polling and false wakes from SQLite WAL writes.

## Project Structure

```
cmd/
  race-monitor/       Daemon entry point (PID arg, --detach, --log-level)
  race-calibrate/     Offline calibration tool (--pid)
  race-enricher/      IP enrichment daemon (--backfill, --once)
internal/
  bpf/                eBPF C program + Go code generation
    probe.c           5 uprobe handlers, 6 event types, identity-based dedup
    gen.go            bpf2go generation directive + event constants
  capture/            eBPF loader, symbol resolution, perf reader
  race/               Coordinator + tracker + calibration
  storage/            SQLite schema and operations
  enrichment/         rDNS, Cymru, ipapi.is, provider detection
race-viz/             Flask dashboard (app.py, db.py, analysis.py)
```

## License

MIT

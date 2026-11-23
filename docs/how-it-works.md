# How race-monitor works

The domain model is in [DESIGN.md](../DESIGN.md).

## Architecture

Three binaries with distinct responsibilities:

- **`race-calibrate`**: offline tool that discovers 4 struct byte offsets by correlating eBPF memory dumps against the qBittorrent WebUI API. Run once per binary; results cached to `~/.config/race-monitor/calibration.json` keyed by binary SHA256.
- **`race-monitor`**: long-running daemon that attaches eBPF uprobes and records race data. Requires pre-calibrated offsets. PID is the first positional argument. Enqueues new peer IPs for enrichment.
- **`race-enricher`**: long-running daemon that resolves peer IPs to ISP/datacenter/seedbox provider. Two-queue pipeline: IP queue (rDNS + Team Cymru, free) then prefix queue (ipapi.is, rate-limited). Wakes via inotify on sentinel file.

Data flows strictly downward:

```
eBPF Probes (kernel C, probe.c): 5 uprobes on libtorrent symbols
  ↓ perf buffer (256 KB/CPU)
Capture Layer: ELF symbol resolution, uprobe attachment, event decoding
  ↓ two channels (slim events + 4KB struct dumps)
Coordinator: single-writer event router, all state mutations
  ↓ per-race goroutines (10,000-event channel each)
Trackers: per-race event processing, SQLite batch writes
  ↓
SQLite (WAL mode): concurrent dashboard reads
  ↓                    ↓
Dashboard (Flask)    Enricher (rDNS, Cymru, ipapi.is)
```

## eBPF Probes

Five uprobes attach to mangled C++ symbols in libtorrent:

| Probe | Fires when | Event |
|-------|-----------|-------|
| `trace_we_have` | We complete+verify a piece | `EventWeHave` + torrent struct dump on first encounter |
| `trace_incoming_have` | Peer announces a piece (HAVE) | `EventIncomingHave` + peer struct dump on first encounter |
| `trace_incoming_bitfield` | Peer sends BITFIELD at connect | Peer struct dump only (catches seeders) |
| `trace_torrent_start` | A torrent is added, or restored when qBittorrent loads its session | `EventTorrentStarted` + torrent struct dump |
| `trace_torrent_finished` | All pieces verified | `EventTorrentFinished` |

Probes read CPU registers (RDI=`this`, RSI=`piece_index` on x86_64) plus calibrated struct offsets for identity-based peer dedup. No hardcoded struct layouts.

## Calibration

Two-phase offset discovery from 4KB eBPF memory dumps:

1. **Torrent struct**: scan for 20-byte info_hash sequences matching known torrents from the API. Vote on offset; lock after 2+ matches.
2. **Peer connection struct**: scan for `sockaddr_in` patterns matching known peers (Phase 1), then peer_id bytes (Phase 2). Same voting/locking.

Offsets cached by binary SHA256. Re-running `race-calibrate` is only needed after qBittorrent recompilation.

## Race Lifecycle

1. `torrent::start()` fires: the start is pending. Its piece events, peer details and finish are held in order, and a classifier of its own fetches name, size, piece count and addition date from the qBittorrent API.
2. Classification: a race is a torrent added while being watched. If `addition_date` is more than 5s before the `torrent::start()` event (BPF ktime converted to wall clock), the torrent was restored from the session: the start is discarded with its held events, leaves no rows, and BPF dedup maps are cleaned as on completion. Otherwise it becomes a race whose tracker records the held events before live ones. API failures are retried with backoff for up to 60s from the start; a start the API can't classify in that time becomes a race and the failure is logged. Without `webui_url` every start becomes a race at once. Starts still pending at shutdown are discarded. A start whose info hash reads as all zeros is never classified or made a race: it is recorded in `start_errors` with its struct dump and the count of its `we_have` events, and logged as an error.
3. Events stream in: the coordinator routes `we_have` by torrent pointer and `incoming_have` by peer connection pointer to the race's tracker. An event arriving when the race's 10,000-event channel is full is dropped and counted: the first drop is logged, and the race records the count as one `events_dropped` race error when it is finalized.
4. `torrent::finished()` fires: with no peer seen, the race is finalized at once; otherwise the tracker starts a grace period of 50% of download duration, clamped to [5s, 60s], which never resets.
5. Grace timer expires, or 30 minutes pass: the race is finalized and BPF dedup maps are cleaned for peer/torrent rediscovery.

## Enrichment Pipeline

Two-queue design, each IP/prefix processed once:

1. **IP queue** (free): rDNS lookup + Team Cymru BGP/ASN resolution
2. **Prefix queue** (rate-limited): ipapi.is for ISP, datacenter, geo, provider

Three-tier provider identification: rDNS hostname patterns (highest confidence) > brand alias map (ASN/domain) > raw datacenter passthrough.

## Design Decisions

**Why calibration is separate from monitoring.** `race-calibrate` runs once interactively; `race-monitor` loads cached offsets and never touches the API for calibration. Keeps the daemon simple and fast. Binary recompilation only requires re-running calibrate, not code changes.

**Why single-writer coordinator.** One goroutine owns all state maps. No mutexes on the ~3K events/sec hot path. Tracker goroutines communicate via channels.

**Why identity-based peer dedup.** BPF `seen_peers` uses `(torrent_ptr, ip, port)` instead of raw `peer_connection*` pointers. Prevents cross-race event contamination when libtorrent reuses freed connection addresses.

**Why two peer discovery probes.** Seeders never send individual HAVE messages; they use BITFIELD/HAVE-ALL at connect time. `incoming_bitfield` catches these; `incoming_have` catches leechers. Both share the `seen_peers` dedup map.

**Why schema recreation over migration.** Race data is transient; migration complexity is not justified. Schema version mismatch drops and recreates all tables.

**Why sentinel file wakeup for enrichment.** Daemon touches `enrichment.notify` only when enqueuing new IPs. Enricher watches via inotify. Avoids polling and false wakes from SQLite WAL writes.

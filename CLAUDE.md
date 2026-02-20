# CLAUDE.md

This file provides guidance to Claude Code when working with code in this repository.

## What This Project Does

**race-monitor** is an eBPF-based BitTorrent race performance monitor. It attaches uprobes to qBittorrent's libtorrent C++ library to record when each peer obtains torrent pieces, with sub-millisecond precision and ~1-2% CPU overhead. Events are stored in SQLite and visualized via a Flask dashboard.

Module: `github.com/cehbz/race-monitor` (Go 1.24.0)

## Two-Binary Architecture

The system is split into two binaries with distinct responsibilities:

- **`race-calibrate`** (`cmd/race-calibrate/main.go`, ~600 lines) — Offline tool that discovers 4 struct byte offsets by correlating eBPF memory dumps against the qBittorrent WebUI API. Run once per binary; results cached to `~/.config/race-monitor/calibration.json` keyed by binary SHA256.
- **`race-monitor`** (`cmd/race-monitor/main.go`, ~320 lines) — Long-running daemon that attaches eBPF uprobes and records race data. Requires pre-calibrated offsets from `race-calibrate`. No subcommands; PID is the first positional argument.

## Build Commands

```bash
make generate       # Compile eBPF C (probe.c) → bytecode; requires clang + linux-headers
make build          # generate + go build (both race-monitor and race-calibrate)
make build-quick    # Go build only (skips eBPF compilation, uses pre-generated .o)
make install        # build + install to ~/bin + sudo setcap (sets BPF capabilities)
make check          # fmt + vet + test
```

eBPF bytecode is generated but gitignored (`internal/bpf/probe_bpfel.o`, `probe_bpfel.go`). Run `make generate` after changing `internal/bpf/probe.c` or after a fresh clone.

## Test Commands

```bash
make test             # All tests
make test-verbose     # With -v flag
make test-coverage    # Coverage report
make test-race        # Race detector
make test-short       # Skip slow integration tests (passes -short to go test)
```

To run a single test:
```bash
go test ./internal/race/ -run TestCoordinatorRouting -v
```

## Running

### Calibration (one-time per binary)

```bash
# Requires CAP_BPF + CAP_PERFMON + CAP_SYS_RESOURCE + CAP_SYS_ADMIN (or root)
# make install sets these capabilities automatically via setcap
# Requires at least one active download for peer_connection discovery
race-calibrate --pid $(pgrep -f 'qbittorrent-nox$')
```

Discovers 4 offsets: `info_hash` (torrent struct), `torrent_ptr` (peer_connection struct), `sockaddr_in` (peer_connection struct), `peer_id` (peer_connection struct). The info_hash and torrent_ptr offsets are discovered from torrent struct dumps; sockaddr_in and peer_id from peer_connection struct dumps correlated with the qBittorrent API.

### Monitoring

```bash
race-monitor $(pgrep -f 'qbittorrent-nox$') --detach --log-file ~/race-monitor.log
race-monitor $(pgrep -f 'qbittorrent-nox$') --log-level debug  # foreground with debug logging
```

### Dashboard

```bash
cd race-viz && python3 app.py  # serves on http://localhost:8080
```

### Config

`~/.config/race-monitor/config.toml` (shared by both binaries):
```toml
binary = "/usr/bin/qbittorrent-nox"
webui_url = "http://127.0.0.1:8080"
webui_user = ""
webui_pass = ""
race_db = "~/.local/share/race-monitor/races.db"
```

Calibration cache: `~/.config/race-monitor/calibration.json`
Database: `~/.local/share/race-monitor/races.db` (SQLite, WAL mode)

## Architecture

Data flows strictly downward through five layers:

```
eBPF Probes (kernel C, internal/bpf/probe.c)
  ↓ perf buffer (256 KB/CPU)
Capture Layer (internal/capture/ebpf.go) — ELF symbol resolution, uprobe attachment, event decoding, BPF config
  ↓ CaptureHandle: two channels (events + dumps) + BPF map handles
Coordinator (internal/race/coordinator.go) — single-writer event router, all state mutations here
  ↓ per-race goroutines
Trackers (internal/race/tracker.go) — per-race event processing, SQLite batch writes
  ↓
SQLite (internal/storage/store.go) — WAL mode for concurrent dashboard reads
  ↓
Dashboard (race-viz/) — Python Flask + Plotly.js
```

### eBPF Probes and Event Types

`probe.c` attaches **6 uprobes** to mangled C++ symbols in qBittorrent's libtorrent:

| Probe | Symbol | Fires when | Event type |
|-------|--------|-----------|------------|
| `trace_we_have` | `torrent::we_have()` | We complete+verify a piece | Slim `EventWeHave` (1) + `EventTorrentDump` (4) on first encounter |
| `trace_incoming_have` | `peer_connection::incoming_have()` | Peer announces a piece via HAVE message | Slim `EventIncomingHave` (2) + `EventPeerDump` (3) on first encounter |
| `trace_incoming_piece` | `peer_connection::incoming_piece()` | We receive a piece fragment from a peer | `EventPeerDump` (3) only — no slim event |
| `trace_incoming_bitfield` | `peer_connection::incoming_bitfield()` | Peer sends BITFIELD at connect time | `EventPeerDump` (3) only — no slim event |
| `trace_torrent_start` | `torrent::start()` | Torrent transitions to started state | `EventTorrentStarted` (5) with struct dump |
| `trace_torrent_finished` | `torrent::finished()` | All pieces downloaded and verified | Slim `EventTorrentFinished` (6) |

**6 event types** (defined in `probe.c` and `internal/bpf/gen.go`):
- `EventWeHave` (1) — slim 24B: piece verified by us
- `EventIncomingHave` (2) — slim 24B: peer announced piece
- `EventPeerDump` (3) — 4KB dump: peer_connection struct (from `incoming_have`/`incoming_piece`/`incoming_bitfield`)
- `EventTorrentDump` (4) — 4KB dump: torrent struct (from `we_have` first encounter)
- `EventTorrentStarted` (5) — 4KB dump: torrent struct + triggers race creation
- `EventTorrentFinished` (6) — slim 24B: download complete

**Critical constraint:** eBPF code reads only CPU registers (RDI=`this`, RSI=`piece_index` on x86_64 System V ABI). In monitor mode, peer probes also read `torrent_ptr` and `sockaddr_in` at calibrated offsets for identity-based dedup (two `bpf_probe_read_user` calls per event). Struct field extraction for peer_id and info_hash happens in userspace via the calibration system.

**BPF maps:**
- `probe_config` (array, 1 entry) — calibrated offsets (`torrent_ptr_offset`, `sockaddr_offset`) written by userspace at startup. Zero values = calibration mode (pointer-based dedup).
- `seen_peers` (LRU hash, max 4096) — dedup key is `struct peer_key {torrent_ptr, ip, port}` in monitor mode (identity-based), or `{ptr, 0, 0}` in calibration mode (pointer-based). The `emit_peer_dump_if_new()` helper reads the config map to decide which mode to use.
- `seen_torrents` (LRU hash, max 256) — dedup by torrent* pointer (unchanged).
- `dump_scratch` (per-CPU array, 1 entry) — scratch space for 4KB struct dumps.

**Peer discovery:** Three probes collaborate to discover all peer_connection* pointers: `incoming_have` (fires for individual HAVE messages from leechers), `incoming_piece` (fires when we receive piece data — catches peers in active transfer), and `incoming_bitfield` (fires when peers send BITFIELD at connect time — catches seeders who never send individual HAVE messages). All three call `emit_peer_dump_if_new()` which handles dedup and dump emission.

### Calibration System

Two separate calibration paths discover 4 offsets total:

**Torrent struct calibration** (info_hash + torrent_ptr):
- `EventTorrentStarted`/`EventTorrentDump` carry 4KB torrent struct dumps
- Userspace scans for 20-byte sequences matching known info_hashes from the API
- Voting system: each matching offset gets a vote; locks after ≥2 matches with same offset
- torrent_ptr offset discovered by scanning peer_connection dumps for known torrent* pointers

**Peer connection struct calibration** (sockaddr_in + peer_id):
- `EventPeerDump` carries 4KB peer_connection struct dumps (from `incoming_have`/`incoming_piece`/`incoming_bitfield`)
- Phase 1: Scans dump for `sockaddr_in` patterns (AF_INET=2, non-zero port, valid IP) matching known peers from the qBittorrent API. Votes on offset; locks after ≥2 matches.
- Phase 2: After Phase 1 locks, extracts IP:port at known offset, matches to API peer data, finds 20-byte Azureus-format peer_id in dump. Locks after ≥2 matches.

Calibration offsets are cached at `~/.config/race-monitor/calibration.json` keyed by binary SHA256.

### Coordinator Pattern

`coordinator.go` is a **single-writer event loop** — all state mutations happen in one goroutine's `select {}` loop. This eliminates mutex contention on the ~3K events/sec hot path. Key state maps:

- `torrentPtrs`: `torrent*` → info_hash (from `torrent_start` and `we_have` calibration events)
- `connToRace`: `peer_connection*` → info_hash (populated by peer calibration dumps)
- `infoHashToRaceState`: active races by info_hash
- `connEndpoints`: `peer_connection*` → resolved IP:port
- `torrentMeta`: info_hash → {Name, Size, PieceCount} (cached from qBittorrent API)

Event routing: `we_have` events route via `torrentPtrs` (obj_ptr is torrent*). `incoming_have` events route via `connToRace` (obj_ptr is peer_connection*). Dump events extract struct fields and populate these routing maps.

**SeenCache cleanup:** On race completion, the coordinator calls `ForgetPeer()` and `ForgetTorrent()` on the `SeenCache` interface (implemented by `CaptureHandle`) to delete BPF dedup map entries for the completed race. This allows peers and torrents to be rediscovered if they appear in a future race, preventing stale pointer-based entries from blocking new dumps.

### EnrichmentAPI

`race.EnrichmentAPI` interface (implemented by `qbSyncClient` in `cmd/race-monitor/qbclient.go`):
- `Sync()` — incremental maindata fetch (uses stored rid); returns metadata keyed by hex info_hash for changed torrents. Provides torrent Name, Size.
- `FetchTorrentMeta(hash)` — per-torrent properties (PieceCount, Size only — not Name).

The coordinator primes the metadata cache at startup via `Sync()`. On cache miss (newly-added torrent), it re-syncs to pick up the new entry.

### Storage Schema

SQLite with 5 tables. Schema version 5 — version mismatch drops and recreates all tables (intentional; no migration path needed for this use case).

| Table | Purpose |
|-------|---------|
| `event_types` | Lookup: 1=have (peer announced), 2=piece_received (we verified) |
| `torrents` | info_hash, name, size, piece_count (UPSERT on conflict) |
| `races` | FK→torrents, started_at, completed_at, start_wallclock |
| `connections` | FK→races, conn_ptr (hex), first_seen, ip, port, peer_id, client |
| `packet_events` | FK→races+connections, ts (int64 ns ktime), event_type_id, piece_index |

Indexes: `idx_events_race_ts` for timeline queries, `idx_events_peer_piece` covering index for per-peer piece queries.

## Key Files

| File | Lines | Purpose |
|------|-------|---------|
| `internal/bpf/probe.c` | 280 | eBPF uprobe programs (C) — 6 probes, 6 event types, identity-based dedup |
| `internal/bpf/probe_bpfel.go` | 185 | Auto-generated Go bindings (do not edit; gitignored) |
| `internal/bpf/gen.go` | 32 | Event type constants and `go:generate` directive |
| `internal/capture/ebpf.go` | 340 | ELF symbol resolution, uprobe attachment, perf reader, CaptureHandle, ProbeConfig |
| `internal/race/coordinator.go` | 600 | Single-writer event router — all state mutations, SeenCache cleanup |
| `internal/race/tracker.go` | 257 | Per-race event processing, batch SQLite writes, idle monitoring |
| `internal/race/calibration.go` | 564 | Two-phase offset discovery (sockaddr, peer_id, info_hash, torrent_ptr) |
| `internal/race/calibration_cache.go` | 81 | JSON persistence of calibrated offsets |
| `internal/race/offsets.go` | 127 | CalibratedOffsets struct + Extract* functions |
| `internal/race/pidwatch.go` | 40 | pidfd_open-based process death detection |
| `internal/storage/store.go` | 391 | SQLite schema, CRUD, UPSERT for connections |
| `internal/storage/types.go` | 65 | Race, Event, connection type definitions |
| `cmd/race-monitor/main.go` | 317 | Daemon entry point — config, calibration loading, signal handling |
| `cmd/race-monitor/qbclient.go` | 77 | EnrichmentAPI implementation (qBittorrent WebUI) |
| `cmd/race-calibrate/main.go` | 597 | Standalone calibration tool — interactive offset discovery |
| `race-viz/app.py` | 425 | Flask dashboard routes, SSE, peer progress/faster-peers analysis |
| `race-viz/db.py` | 202 | All SQL queries for dashboard (no Flask dependency) |
| `race-viz/analysis.py` | — | Pure computation: cumulative curves, classification, extrapolation |

## Dependencies

- `github.com/cilium/ebpf` — eBPF loader and uprobe attachment
- `modernc.org/sqlite` — Pure Go SQLite driver (CGo-free)
- `github.com/cehbz/qbittorrent` — qBittorrent WebUI API client
- `github.com/BurntSushi/toml` — Config parsing
- `golang.org/x/sys` — Linux syscalls (pidfd_open for process death detection)

System requirements: Linux ≥ 5.8, `clang` (build only), qBittorrent binary with symbol table (not stripped).
Capabilities: `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE`, `CAP_SYS_ADMIN` (set by `make install` via `setcap`).

## Design Decisions

- **Calibration separated from monitoring**: `race-calibrate` runs once interactively; `race-monitor` loads cached offsets and never touches the API for calibration. This keeps the daemon simple and fast.
- **No struct offset hardcoding**: All struct field access goes through calibrated offsets. Binary recompilation only requires re-running `race-calibrate`, not code changes.
- **Single-writer coordinator**: One goroutine owns all state maps. No mutexes on the hot path. Tracker goroutines communicate via channels.
- **Schema recreation over migration**: Schema v5 drops and recreates all tables on version mismatch. Race data is transient; migration complexity is not justified.
- **Three peer discovery probes**: `incoming_have` (fires when peers send HAVE), `incoming_piece` (fires when we receive piece data), and `incoming_bitfield` (fires when peers send BITFIELD at connect time). Seeders never send individual HAVE messages — they use BITFIELD/HAVE-ALL — so `incoming_bitfield` is essential for discovering seeder connections. `incoming_piece` catches peers during active transfer. All three share the `seen_peers` dedup map.
- **Identity-based peer dedup**: BPF `seen_peers` uses `(torrent_ptr, ip, port)` as the dedup key instead of raw `peer_connection*` pointers. This prevents cross-race event contamination when libtorrent frees a connection and reuses the address for a different torrent. A `probe_config` BPF map passes calibrated offsets from userspace so probes can read these fields. Falls back to pointer-based dedup when offsets are unknown (calibration mode).

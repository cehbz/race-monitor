# race-monitor

**eBPF-Based BitTorrent Race Performance Monitor**

Design Document — February 2026 — Version 3.0

---

## 1. High-Level Goals

race-monitor is a passive observation tool that records the real-time progress of BitTorrent downloads at piece-level granularity. Its purpose is to answer the question: during a competitive race to complete a torrent, which peers obtained pieces before us, how quickly, and why?

The tool addresses three core goals:

1. Capture every piece completion event (we_have) and every peer piece announcement (incoming_have) with sub-millisecond timestamps, enabling precise ordering of who got each piece first.
2. Enrich raw eBPF events with peer metadata (IP address, client software, geographic location, transfer speeds) from the qBittorrent API, enabling analysis of which peer characteristics correlate with faster piece acquisition.
3. Support simultaneous monitoring of multiple concurrent downloads without interference, since competitive racing often involves several torrents downloading in parallel.

Non-goals: race-monitor does not modify torrent behavior, inject traffic, or interact with the BitTorrent protocol. It is strictly read-only.

---

## 2. Detailed Requirements

### 2.1 Functional Requirements

- Attach eBPF uprobes to `libtorrent::torrent::we_have()` and `libtorrent::peer_connection::incoming_have()` inside the qBittorrent binary at runtime.
- Capture event_type, piece_index, timestamp (CLOCK_BOOTTIME nanoseconds), and obj_ptr (this pointer) for every probe hit.
- Convert CLOCK_BOOTTIME timestamps to wall-clock time via /proc/uptime estimation.
- Discover active downloads by polling the qBittorrent WebUI API (`TorrentsInfoCtx` with `filter=downloading`).
- Map opaque `torrent*` pointers from we_have events to info_hash values via API correlation.
- Route incoming_have events (which carry `peer_connection*` with no torrent affinity) to all plausible active races using piece_index range filtering.
- Persist all data in a normalized SQLite database with integer primary keys and strict foreign key constraints.
- Poll the qBittorrent `/api/v2/sync/torrentPeers` endpoint periodically during active races to capture peer metadata (IP, port, client, country, progress, speeds).
- Provide a web dashboard for visualizing race timelines, piece completion progress, event activity, and peer statistics.
- Support daemon mode with background execution, log file output, and graceful signal handling (SIGINT/SIGTERM).

### 2.2 Non-Functional Requirements

- Zero impact on torrent performance: all observation is passive (eBPF read-only probes, no data injection).
- Handle peak incoming_have rates of ~3,000 events/second without sample loss.
- Support concurrent monitoring of 2–5 simultaneous races without cross-talk.
- Tolerate qBittorrent API unavailability gracefully (log warnings, retry on next poll cycle).

---

## 3. High-Level Architecture

The system consists of four layers:

| Layer | Description |
|-------|-------------|
| **eBPF Probes** | Two uprobes in `probe.c` attach to libtorrent functions inside the qBittorrent binary. They read CPU register values (this pointer, piece_index) and emit events via a shared perf buffer. No struct dereferences, no memory writes to the target process. |
| **Capture Layer** | Go package (`internal/capture`) loads eBPF objects, resolves mangled C++ symbols from the ELF symbol table, attaches uprobes, and reads from the perf buffer into a typed Go channel. Handles PID filtering, perf reader lifecycle, and lost sample tracking. |
| **Race Layer** | Go package (`internal/race`) contains the Coordinator and per-race Tracker. The Coordinator routes events to race-specific goroutines, manages torrent_ptr discovery, and handles race lifecycle. Each Tracker processes events, maintains connection maps, batches writes, polls for peer data, and detects completion. |
| **Storage Layer** | Go package (`internal/storage`) manages a normalized SQLite database with six tables. Single-writer with WAL mode enables concurrent reads from the dashboard. |
| **Dashboard** | Python Flask application (`race-viz/`) reads the SQLite database and serves a single-page web UI with Plotly.js charts. Server-Sent Events provide real-time race notifications. |

Data flows strictly downward: eBPF probes → perf buffer → capture channel → coordinator → tracker goroutines → SQLite. The dashboard reads SQLite independently via WAL.

---

## 4. Detailed Design

### 4.1 eBPF Probes (probe.c)

Two `SEC("uprobe/...")` programs attach to mangled C++ symbols:

| Probe | Symbol Prefix | RDI (this) | RSI (arg1) |
|-------|--------------|------------|------------|
| `trace_we_have` | `_ZN10libtorrent7torrent7we_haveE` | `torrent*` | `piece_index_t` |
| `trace_incoming_have` | `_ZN10libtorrent15peer_connection13incoming_haveE` | `peer_connection*` | `piece_index_t` |

The `event_t` struct (32 bytes) contains: event_type (u32), piece_index (u32), timestamp (u64 from `bpf_ktime_get_ns`), obj_ptr (u64). Events are emitted via `bpf_perf_event_output` to a shared `BPF_MAP_TYPE_PERF_EVENT_ARRAY`.

The perf buffer is sized at 256 KB per CPU (increased from 64 KB after observing ~3% sample loss at peak incoming_have rates). Each event is 32 bytes, giving ~8,000 events of buffer capacity per CPU.

A third event type (`EVT_CALIBRATION`, 536 bytes) is emitted once per new `peer_connection*` to support auto-calibration of the `m_remote` struct offset. The `incoming_have` probe uses an LRU hashmap (`seen_peers`, max 4096 entries) to track which pointers have been seen. On first encounter, it reads 512 bytes of raw struct data via `bpf_probe_read_user` and emits a `calibration_event_t` containing the raw bytes plus metadata. Calibration events are infrequent (~50 per race) and their extra buffer usage (~26 KB total) is negligible relative to the 256 KB per-CPU buffer.

### 4.2 Capture Layer (internal/capture)

The `Capture()` function performs the following sequence:

1. Re-enable `PR_SET_DUMPABLE` (setcap binaries are marked non-dumpable by the kernel, blocking /proc/self access needed by cilium/ebpf).
2. Remove the memlock rlimit (requires `CAP_SYS_RESOURCE`).
3. Resolve mangled C++ symbols by scanning the ELF symbol table for prefix matches, skipping `.cold` split functions.
4. Load eBPF programs and attach uprobes via `cilium/ebpf/link`, optionally filtered to a specific PID.
5. Start a goroutine that reads perf records with polymorphic event decoding: the first 4 bytes determine the event type. Normal events (`event_t`, 32 bytes) are sent on an event channel (capacity 10,000). Calibration events (`calibration_event_t`, 536 bytes) are sent on a separate calibration channel (capacity 100).
6. Track cumulative lost samples and log warnings when the kernel reports perf buffer overflows.

### 4.3 Coordinator (internal/race)

The Coordinator is the central event router. It runs a single-threaded select loop (single-writer pattern) that handles:

- Context cancellation (graceful shutdown, closes all race trackers)
- Race completion signals from tracker goroutines (cleanup torrent_ptr mappings)
- Discovery results from async API queries (create races, assign ptr mappings)
- Periodic poll ticker (5s interval, triggers discovery for new downloads)
- Raw eBPF events (route we_have by torrent_ptr, route incoming_have by piece_index range)

#### 4.3.1 Torrent Pointer Discovery

When a we_have event arrives with an unknown obj_ptr, the coordinator buffers the event in `pendingEvents` and launches an async goroutine that queries `TorrentsInfoCtx(filter=downloading)`. The result arrives via `discoveryChan`. For each newly discovered torrent, the coordinator calls `TorrentsPropertiesCtx` to get name, size, and piece_count, then creates database records (torrent + race) and starts a tracker goroutine.

Pending pointer assignment uses a process-of-elimination strategy: if there is exactly one unassigned race whose piece_count accommodates all buffered piece indices, the pointer is assigned. If multiple candidates exist (overlapping piece ranges), the events remain buffered for future disambiguation as more data arrives.

#### 4.3.2 incoming_have Routing

incoming_have events carry a `peer_connection*` pointer which has no inherent torrent affinity. Without reading libtorrent struct internals, the coordinator cannot determine which torrent a peer_connection belongs to. After auto-calibration (Section 4.7) determines the `m_remote` struct offset, incoming_have events are routed exactly: the coordinator maintains a `connToRace` mapping from `peer_connection*` to info_hash via extracted IP:port matching against known peers. Once fully calibrated (both sockaddr_in and peer_id offsets discovered), the coordinator also extracts peer_id from each connection, decodes the BT client name, and persists full peer metadata to the database without further API polling. Before calibration is complete, best-effort routing by piece_index range is used as a fallback, routing the event to every active race where `piece_index < piece_count`.

#### 4.3.3 Race Lifecycle

A race transitions through: discovered → active → complete. Active races have a dedicated goroutine running `processEvents`. Completion occurs when the tracker goroutine returns (idle timeout, max duration, context cancellation, or channel close). On completion, the coordinator removes the race from `activeRaces` and cleans up all torrent_ptr mappings for that hash, ensuring future re-downloads trigger fresh discovery.

### 4.4 Tracker (internal/race)

Each active race runs a `processEvents` goroutine that:

1. Creates a "self" connection record (`conn_ptr = "self"`) for our own piece completions.
2. Maintains a `connMap` (`peer_connection*` → database connection ID) for incoming_have events, inserting new connections on first encounter.
3. Converts eBPF timestamps (CLOCK_BOOTTIME nanoseconds) to wall-clock time by estimating boot time from /proc/uptime.
4. Batches events (100 per batch) and flushes to SQLite via `InsertPacketEvents`.
5. Tracks piece completion (`have` map) and logs when all pieces are received.
6. After `loggedComplete`, ignores incoming_have from new `peer_connection*` pointers (suppresses noise from late-joining peers).
7. Polls qBittorrent `SyncTorrentPeersCtx` every 5 seconds asynchronously (goroutine with 3-second timeout, results via channel) using delta mode (`rid` from previous response). Upserts results to `race_peers` on the main goroutine. Sends peer data (including peer_id) to the coordinator via `peerAddrsChan` for calibration. Monitors `calibratedChan` — when full calibration completes (channel closed), peer polling stops because all peer metadata is extracted from eBPF captures.
8. Terminates on idle timeout (10 seconds with no events), max duration (30 minutes), context cancellation, or channel close.
9. Calls `finalize()` on exit, which marks the race as completed in the database.

### 4.5 Storage Schema

The database is normalized to strict 3NF with six tables. All primary keys are `INTEGER AUTOINCREMENT` (except `event_types` which uses fixed IDs matching Go constants). Foreign keys are enforced with `ON DELETE CASCADE` for race-scoped data.

| Table | Primary Key | Purpose |
|-------|------------|---------|
| `event_types` | id (fixed: 1=have, 2=piece_received) | Lookup table for event type names/descriptions |
| `torrents` | id AUTOINCREMENT, UNIQUE(info_hash) | Torrent metadata (hash, name, size, piece_count) |
| `races` | id AUTOINCREMENT, FK torrent_id | Race instances with start/complete timestamps |
| `connections` | id AUTOINCREMENT, UNIQUE(conn_ptr) | eBPF-observed peer_connection* identifiers with IP/port/peer_id/client (schema v4) |
| `race_peers` | id AUTOINCREMENT, UNIQUE(race_id, ip, port) | API-sourced peer metadata per race |
| `packet_events` | id AUTOINCREMENT, FK race_id, connection_id | Individual piece events with timestamps |

### 4.6 Dashboard (race-viz)

A Flask application serves a single-page UI that reads the SQLite database via WAL mode (concurrent reads while the daemon writes). Features include:

- Race list with metadata (name, size, pieces, peer count, event count)
- Piece completion progress chart (cumulative we_have over time)
- Event activity chart (stacked area: piece_received vs. have per 5-second window)
- Peer statistics table showing IP, port, client, country, and progress from race_peers
- Server-Sent Events for real-time notification when new races start
- Plotly.js interactive charts with dark theme matching the dashboard UI

### 4.7 Auto-Calibration

The core challenge in peer correlation is that eBPF-observed `peer_connection*` pointers have no inherent torrent affinity, while the API-sourced peer metadata (IP, port, client) is tied to specific torrents. The auto-calibration system addresses this by mapping `peer_connection*` to (IP, port, peer_id) through two-phase struct field discovery.

**Problem:** The `peer_connection` struct contains `m_remote` (a `tcp::endpoint` with socket address) and a BT protocol peer_id (20 bytes encoding client software). Both field offsets are version-specific and not available to the eBPF program at compile time.

**Solution:** Emit memory dumps from the first encounter of each `peer_connection*`, then perform offline two-phase analysis to identify both offsets via pattern matching. Cache discovered offsets keyed by the SHA256 hash of the qBittorrent binary.

**Algorithm:**

1. **Capture phase (eBPF):** When `incoming_have` fires on a previously unseen `peer_connection*`:
   - Check the LRU hashmap `seen_peers` (max 4,096 entries).
   - If not present, mark the pointer as seen and emit `calibration_event_t` containing:
     - The `peer_connection*` pointer itself
     - 512 bytes of raw struct data read from the pointer via `bpf_probe_read_user`
     - Metadata (timestamp, event_type=EVT_CALIBRATION)
   - Calibration events are sent on a separate channel to avoid congestion (capacity 100, vs. 10,000 for normal events).

2. **Phase 1 — sockaddr_in offset discovery (daemon):** After capturing calibration events, cross-reference with the API-sourced peer list:
   - For each calibration event, treat the 512-byte dump as a sequence of potential `sockaddr_in` structures (AF_INET=2 LE, port BE, IPv4 addr BE).
   - Match against known peer IP:port pairs from `sync/torrentPeers` API responses.
   - Each match at a given byte offset from a unique `peer_connection*` counts as one vote.
   - Once ≥2 calibration events match at the same byte offset, lock in that offset as the `m_remote` location.

3. **Phase 2 — peer_id offset discovery (daemon):** After sockaddr_in is locked:
   - For each calibration event, extract the IP:port from the now-known sockaddr_in offset.
   - Look up the expected peer_id for that IP:port from the API's `PeerIDClient` field.
   - Search the 512-byte dump for those peer_id bytes (minimum 8-byte match, Azureus-style prefix).
   - Vote and lock the peer_id offset after ≥2 independent matches, same as Phase 1.

4. **Post-calibration extraction:** With both offsets locked, every new `peer_connection*` calibration event yields:
   - IP:port (for routing incoming_have to the correct race)
   - peer_id (20 bytes, decoded to client name via Azureus-style parsing)
   - The coordinator updates the `connections` table with full peer info and upserts `race_peers` from eBPF data directly, without API polling.

5. **Calibration-only API polling:** Tracker goroutines poll `sync/torrentPeers` only until full calibration completes. The coordinator signals completion by closing `calibratedChan`. Trackers check this channel at startup (if cached calibration is loaded, polling never starts) and in their poll timer handler. After calibration, all peer metadata comes from eBPF captures.

6. **Persistent caching:** Calibration offsets are cached in `~/.config/race-monitor/calibration.json`, keyed by the SHA256 hash of the qBittorrent binary. On daemon restart, if the binary hash matches, offsets are loaded from cache and calibration is skipped entirely. The cache is stored as a JSON file (not in the race DB) because the DB's migration strategy drops all tables on schema changes.

7. **Client decoding:** The 20-byte BT peer_id is decoded using Azureus-style format: `-XXYYYY-` where XX is a 2-letter client code (qB=qBittorrent, DE=Deluge, TR=Transmission, UT=uTorrent, etc.) and YYYY is the version string.

**Performance:** Calibration events are rare (~50 per race). The 512-byte struct dumps incur ~26 KB total buffer overhead per race, negligible relative to the 256 KB per-CPU perf buffer. Phase 1 typically locks within the first 2-3 calibration events. Phase 2 locks immediately after Phase 1 if peer_id data is available from the API. With cached calibration, there is zero calibration overhead on restart — peer metadata extraction begins immediately.

---

## 5. Design Decisions and Rationale

### 5.1 Why eBPF Uprobes (Not Network Capture)

Alternative considered: tcpdump/pcap on the BitTorrent TCP streams, parsing BT protocol messages to extract HAVE and PIECE messages.

eBPF uprobes were chosen because they operate at the application semantic level. A HAVE message in the wire protocol requires TCP reassembly, BT message framing, and protocol parsing. An uprobe on `incoming_have()` fires after libtorrent has already done all of that work. This eliminates an entire protocol parsing layer, avoids encryption/obfuscation issues (libtorrent supports protocol encryption), and gives us the exact piece_index as a register value.

The cost is coupling to libtorrent internals (mangled C++ symbols, ABI dependence). This is acceptable because the target is a single binary on a controlled server.

### 5.2 Why peer_has Was Rejected

Alternative considered: hooking `torrent::peer_has(piece_index_t)` instead of `peer_connection::incoming_have(piece_index_t)`. The `peer_has` function is called on the torrent object, which would give us torrent affinity (solving the incoming_have routing problem).

This was rejected because `peer_has` fires per-bit during BITFIELD message processing. When a new peer connects and sends its bitfield (common: ~1,000 pieces set), `peer_has` fires ~1,000 times in a tight loop. With 50 peers connecting during a race start, this produces ~50,000 events in seconds — a 1,000x volume increase over incoming_have (which only fires for individual HAVE messages after the initial bitfield). The perf buffer would overflow catastrophically.

### 5.3 Single-Writer Coordinator Pattern

All Coordinator state (`torrentPtrs`, `activeRaces`, `pendingEvents`) is mutated only within the `Run()` select loop, on a single goroutine. This eliminates the need for mutexes on hot-path data structures. Tracker goroutines communicate back via channels (`completeChan`). API queries run in detached goroutines and send results via `discoveryChan`.

This was chosen over a mutex-based design because the coordinator is the critical routing path for all events at ~3K/sec. Lock contention on every event would add measurable latency.

### 5.4 SQLite With WAL (Not Postgres)

SQLite was chosen because the system runs on a single seedbox with no need for remote access, replication, or concurrent writers. WAL mode enables the dashboard to read concurrently without blocking the daemon's writes. A single Go connection with `SetMaxOpenConns(1)` serializes all writes at the application level, avoiding SQLite's internal locking complexity.

Event batching (100 events per INSERT transaction) amortizes SQLite's per-transaction overhead. At 3K events/sec, this means ~30 transactions/sec — well within SQLite's write throughput on SSD.

### 5.5 Integer Primary Keys (Not Info Hash)

The v1 schema used info_hash strings as primary keys. This was replaced with `INTEGER AUTOINCREMENT` for three reasons: B-tree index efficiency (integer comparisons are faster than 40-char hex string comparisons), reduced storage for foreign keys in the high-volume `packet_events` table, and proper normalization (info_hash is a natural key on torrents, but a synthetic key on races and events).

### 5.6 Perf Buffer Sizing

The original 64 KB per-CPU perf buffer lost ~3% of events (36 of 1,157 pieces) during a real race. At 32 bytes per event, 64 KB holds ~2,000 events per CPU. During incoming_have bursts (~3K/sec), a CPU could accumulate events faster than userspace drains them.

Increasing to 256 KB (8,000 events per CPU) provides 4x headroom. Combined with the 10,000-element Go channel buffer, the system can absorb ~2.6 seconds of peak burst before any loss, which exceeds the worst observed burst duration.

---

## 6. Performance Requirements and Constraints

### 6.1 Event Throughput

| Metric | Observed | Design Capacity |
|--------|----------|----------------|
| Peak incoming_have rate | ~3,000 events/sec | ~8,000 events/sec (256KB buffer) |
| we_have rate | ~10–50 events/sec | Negligible overhead |
| Perf buffer lost samples | ~3% at 64KB (v1) | Target: <0.1% at 256KB (v2) |
| SQLite write throughput | ~30 batch txns/sec | SQLite WAL: ~1,000 txns/sec on SSD |
| Go channel capacity | 10,000 events | ~3 sec burst absorption |

### 6.2 Peer Polling Performance

`SyncTorrentPeersCtx` is a localhost HTTP GET to qBittorrent's WebUI (`/api/v2/sync/torrentPeers`). Characteristics:

- Network latency: sub-millisecond (localhost loopback)
- Response size: ~200 bytes per peer (JSON), ~10 KB for a 50-peer swarm
- API call duration: 1–5ms including JSON decode
- SQLite UpsertRacePeers: single transaction, ~1–2ms for 50 peers
- Total per-poll cost: <10ms every 5 seconds = <0.2% of wall-clock time

Delta mode is enabled: the tracker stores the `rid` returned by each `SyncTorrentPeersCtx` response and passes it on the next call. The first call uses `rid=0` (full snapshot); subsequent calls receive only new or changed peers. This reduces payload size from ~10 KB to a few hundred bytes for a stable 50-peer swarm.

Peer polling runs asynchronously in a dedicated goroutine. The tracker's `startPeerPoll` function launches a goroutine that performs the API call and marshals peer data into a `peerPollResult` struct. Results arrive on a buffered channel (`peerResultCh`, capacity 1) and are processed in the main select loop alongside eBPF events. A `pollInFlight` flag prevents concurrent polls. This ensures the event channel is never blocked during API calls — even a worst-case 3-second timeout no longer risks filling the 10,000-element event buffer at 3K events/sec.

### 6.3 Platform Constraints

| Constraint | Details |
|-----------|---------|
| Kernel | Debian 6.1.0-42-amd64. Requires `perf_event_paranoid <= 1` for uprobe `perf_event_open`. |
| Capabilities | `setcap cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_admin+ep`. CAP_SYS_ADMIN needed on kernel <6.7 because the uprobe PMU `perf_event_open` path checks SYS_ADMIN instead of PERFMON. |
| Binary requirements | qBittorrent binary must retain symbol table (not stripped). Mangled C++ symbols are resolved via ELF symbol table scan. |
| ABI coupling | Probe correctness depends on x86_64 System V calling convention (RDI=this, RSI=arg1). Only valid for x86_64 targets. |
| Host | Seedbox at 212.7.200.67, Debian 12, dedicated hardware. |

---

## 7. Investigation Results and Future Work

### 7.1 Concurrency Fix (Completed)

**Problem:** The v1 coordinator used `ensureRace()` which blocked when any race was active. Only the first simultaneous download was recorded.

**Root cause:** `ensureRace()` was a synchronous gate that created exactly one race and refused to create more while one existed.

**Solution:** Complete coordinator rewrite with torrent_ptr-based routing. we_have events carry `torrent*` (unique per torrent), enabling exact routing once the ptr → hash mapping is learned. Multiple races run as independent goroutines with per-race event channels. Discovery is async and non-blocking.

### 7.2 Missing Pieces Investigation (Completed)

**Problem:** 1,121 of 1,157 expected we_have events were captured (36 missing, ~3% loss).

**Root cause:** Perf buffer overflow. The kernel reported lost samples during incoming_have bursts. At 32 bytes/event, the 64 KB buffer held ~2,000 events per CPU. Burst rates of 3K events/sec could exceed drain capacity.

**Solution:** Increased perf buffer to 256 KB per CPU (4x headroom). Added cumulative lost sample tracking with structured logging for ongoing monitoring.

### 7.3 Peer Correlation Gap (Implemented: auto-calibration)

**Problem:** The eBPF-observed `peer_connection*` pointers cannot be linked to the API-sourced peer metadata (IP, port, client). The `connections` table and `race_peers` table have no join key.

**Solution:** Implemented two-phase auto-calibration (Section 4.7) with persistent caching. Phase 1 discovers the `m_remote` sockaddr_in offset by scanning 512-byte eBPF memory dumps for known peer IP:port patterns. Phase 2 discovers the peer_id offset by correlating each dump's extracted IP:port with the known peer_id from the API. Once both offsets are locked, the coordinator extracts IP:port and peer_id from every new `peer_connection*`, decodes the BT client name, and populates both `connections` (with ip, port, peer_id, client) and `race_peers` directly from eBPF data. API polling (`sync/torrentPeers`) is used only during initial calibration, then stopped. Calibration offsets are cached in JSON keyed by binary SHA256, eliminating re-calibration on daemon restart.

### 7.4 Remaining Validation

The following must be verified on the seedbox:

- `go vet ./...` — static analysis for common errors
- `go test -race ./...` — unit tests with race detector
- `go build -o race-monitor ./cmd/race-monitor` — compilation verification
- Live capture test with concurrent downloads to verify the concurrency fix
- Dashboard functionality with the new schema (peer table, updated queries)

---

## 8. Project Structure

| Path | Purpose |
|------|---------|
| `cmd/race-monitor/main.go` | CLI entry point: daemon and list commands |
| `internal/bpf/probe.c` | eBPF C source: two uprobe programs |
| `internal/bpf/gen.go` | Go type definitions + bpf2go generate directive |
| `internal/capture/ebpf.go` | ELF symbol resolution, uprobe attachment, perf reader |
| `internal/race/coordinator.go` | Event routing, torrent_ptr discovery, race lifecycle |
| `internal/race/coordinator_test.go` | 22 tests covering routing, discovery, lifecycle |
| `internal/race/calibration.go` | Two-phase offset discovery: sockaddr_in and peer_id |
| `internal/race/calibration_cache.go` | Persistent calibration cache (JSON, keyed by binary SHA256) |
| `internal/race/tracker.go` | Per-race event processing, peer polling, completion |
| `internal/race/tracker_test.go` | Event processing, peer polling, timeout tests |
| `internal/race/calibration_test.go` | Calibration state machine, peer_id extraction, client decoding tests |
| `internal/storage/types.go` | Domain types: Torrent, Race, Connection, RacePeer, Event |
| `internal/storage/store.go` | SQLite schema, all CRUD operations |
| `internal/storage/store_test.go` | Storage layer unit tests |
| `race-viz/app.py` | Flask dashboard backend with SSE |
| `race-viz/templates/index.html` | Single-page dashboard UI with Plotly.js |

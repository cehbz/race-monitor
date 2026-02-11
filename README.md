# race-monitor

Torrent racing analytics using **eBPF uprobes**. Hooks libtorrent functions inside qBittorrent to track piece completion and peer progress with negligible overhead.

## Features

- **eBPF uprobe architecture** — hooks `torrent::we_have()` and `peer_connection::incoming_have()` directly
- **Zero struct offset reads** — only captures function arguments from CPU registers (survives recompiles)
- **Negligible overhead** — ~1-2% CPU at peak vs pcap's inability to keep up at wire speed
- **No NVMe contention** — unlike packet capture, does not interfere with the download being measured
- **Hybrid metadata** — eBPF for lightweight events, qBittorrent API for torrent metadata (hash, name, size)
- **Two event types**:
  - `piece_received` — we completed and verified a piece (`torrent::we_have`)
  - `have` — a peer announced a piece (`peer_connection::incoming_have`)
- Normalized SQLite schema for post-hoc analysis
- Flask visualization dashboard

## Requirements

- **Linux kernel ≥ 5.8** — eBPF uprobe support
- **CAP_BPF + CAP_PERFMON** or root — required for eBPF probe attachment
- **clang** — for compiling eBPF C to bytecode (build-time only)
- **linux-headers** — kernel headers for vmlinux.h (build-time only)
- **qBittorrent with symbol table** — the binary must not be stripped (`nm` should show libtorrent symbols)

### Verify prerequisites

```bash
# Check qBittorrent has the required symbols
nm --defined-only /usr/bin/qbittorrent-nox | grep we_have
# Should show: _ZN10libtorrent7torrent7we_haveE...

# Check kernel version
uname -r  # needs >= 5.8
```

## Installation

Build from source:

```bash
git clone https://github.com/cehbz/race-monitor
cd race-monitor
make build
```

The `make build` target runs `go generate` (compiles eBPF C → bytecode) then builds the Go binary.

If you've already generated the eBPF bytecode and just want to rebuild Go:

```bash
make build-quick
```

### Grant eBPF capabilities

```bash
# Lower perf_event_paranoid (persists across reboots)
echo 'kernel.perf_event_paranoid=1' | sudo tee /etc/sysctl.d/99-perf.conf
sudo sysctl -w kernel.perf_event_paranoid=1

# Grant capabilities (CAP_SYS_ADMIN needed for uprobe PMU on Debian/Ubuntu kernel < 6.7)
sudo setcap cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_admin+ep ./race-monitor
```

Or run as root.

## Configuration

Create `~/.config/race-monitor/config.toml`:

```toml
binary = "/usr/bin/qbittorrent-nox"          # Required: path to qBittorrent binary
webui_url = "http://127.0.0.1:8080"          # Optional: qBittorrent Web UI URL
race_db = "~/.local/share/race-monitor/races.db"  # Optional
dashboard_url = "http://localhost:8888"       # Optional: enables real-time dashboard updates
```

**Required fields:**
- `binary`: Full path to the qBittorrent binary (must have symbol table)

**Optional fields:**
- `webui_url`: qBittorrent Web UI URL for fetching torrent metadata (default: `http://localhost:8080`)
- `race_db`: Database path (default: `~/.local/share/race-monitor/races.db`)
- `dashboard_url`: Dashboard URL for race notifications (default: disabled)

## Usage

### Start the daemon

```bash
race-monitor daemon --detach --log-file ~/race-monitor.log
```

The daemon attaches eBPF uprobes to the qBittorrent binary and waits for events. It can be started before or after qBittorrent — uprobes attach to the binary file, not a running process, and fire whenever any process executes those functions.

### List recent races

```bash
race-monitor list
race-monitor list -days 30
```

### Command-line options

```
race-monitor daemon [options]
  --binary string     Path to qBittorrent binary (overrides config)
  --webui-url string  qBittorrent Web UI URL (overrides config)
  --log-level string  Log level: trace, debug, info, warn, error (default: info)
  --log-file string   Log file path (default: stderr)
  --detach            Run in background
```

## How It Works

### Architecture

race-monitor uses **eBPF uprobes** to hook two libtorrent C++ member functions:

**`torrent::we_have(piece_index_t)`** — fires once per completed+verified piece (~1000 per race). The first event triggers race creation: the daemon queries the qBittorrent API (`TorrentsInfo` with filter="downloading") to find the active torrent and fetch metadata.

**`peer_connection::incoming_have(piece_index_t)`** — fires when a peer announces a piece (~3K/sec peak with 100 peers). The `this` pointer (peer_connection*) is used as an opaque peer identifier.

**Zero-offset approach:** The eBPF probes only read function arguments from CPU registers (RDI = `this`, RSI = `piece_index` on x86_64 System V ABI). No struct field reads, no hardcoded offsets — this survives libtorrent recompiles and version changes.

**Components:**
- **eBPF probes** (`internal/bpf/probe.c`): Two uprobe handlers, perf event output
- **capture layer** (`internal/capture/ebpf.go`): Symbol resolution, probe attachment, perf reader
- **coordinator** (`internal/race/coordinator.go`): Race lifecycle, qBittorrent API integration
- **tracker** (`internal/race/tracker.go`): Per-race event processing, boot time conversion, SQLite batching
- **SQLite storage**: Same normalized schema as before (torrents, races, peers, packet_events)

### Race Lifecycle

1. **First `we_have` event** → query qBittorrent API for downloading torrent → create race record → start tracker goroutine
2. **Event processing** → convert eBPF ktime_ns to wall clock, batch insert to SQLite
3. **Race end** → 10s idle timeout or 30min max duration → finalize race

### Performance

At 505 MiB/s download speed with ~100 peers:

| Metric | eBPF | pcap (previous) |
|---|---|---|
| Events/sec | ~3K | ~362K |
| CPU overhead | ~1-2% | Could not keep up |
| NVMe impact | None | Would contend with download |
| Capture rate | 100% | 19-29% |

### Symbol Resolution

The daemon searches the qBittorrent ELF symbol table at startup for mangled C++ symbols matching known prefixes. Compiler-generated `.cold` split functions are skipped. This handles different compiler versions and build configurations automatically.

## Visualization Dashboard

```bash
cd race-viz
pip install flask flask-cors toml
python app.py
```

The dashboard reads the same SQLite database and provides race timelines, peer statistics, and event aggregation.

## Project Structure

```
cmd/race-monitor/       CLI entry point
internal/
  bpf/                  eBPF C program + Go code generation
    probe.c             Uprobe handlers (zero struct reads)
    gen.go              bpf2go generation directive
    headers/vmlinux.h   Kernel type definitions
  capture/              eBPF loader, symbol resolution, perf reader
  race/                 Coordinator (race lifecycle) + tracker (event processing)
  storage/              SQLite schema and operations
race-viz/               Flask visualization dashboard
```

## License

MIT

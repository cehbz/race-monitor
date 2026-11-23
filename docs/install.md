# Installing race-monitor

## Requirements

- **Linux kernel >= 5.8** with eBPF uprobe support
- **clang** + **linux-headers** (build-time only, for compiling eBPF C)
- **qBittorrent with symbol table** (binary must not be stripped)
- **Go 1.25+**
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
dashboard_url = "http://127.0.0.1:8081"   # optional: race-monitor notifies the dashboard of new races
```

Without `webui_url`, every started torrent is kept as a race (see [how it works](how-it-works.md#race-lifecycle)).

`~/.config/race-monitor/viz.toml` (dashboard):

```toml
race_db = "~/.local/share/race-monitor/races.db"
bind_host = "0.0.0.0"
bind_port = 8081   # default 8080, which qBittorrent's WebUI also defaults to
our_ip = ""        # your public IP, shown as highlighted "self" row
```

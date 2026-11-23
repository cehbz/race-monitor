# Operating race-monitor

## 1. Calibrate (once per binary)

Requires at least one active download for peer_connection discovery:

```bash
race-calibrate --pid $(pgrep -f 'qbittorrent-nox$')
```

Discovers 4 struct offsets: `info_hash`, `torrent_ptr`, `sockaddr_in`, `peer_id`. Results cached in `~/.config/race-monitor/calibration.json`, keyed by the binary's SHA256. race-monitor exits on a binary whose hash has no calibration, so a new qBittorrent binary needs `race-calibrate` rerun.

## 2. Monitor

```bash
race-monitor $(pgrep -f 'qbittorrent-nox$') --detach --log-file ~/race-monitor.log
race-monitor $(pgrep -f 'qbittorrent-nox$') --log-level debug  # foreground
```

## 3. Enrich

```bash
race-enricher                    # long-running daemon, inotify wakeup
race-enricher --backfill --once  # enrich all existing IPs and exit
race-enricher --once             # process current queue and exit
```

## 4. Dashboard

```bash
cd race-viz && python3 app.py    # binds bind_host:bind_port from viz.toml
```

## Systemd services

`make install-services` installs system template units from `systemd/`:

```bash
systemctl start race-monitor@$USER
systemctl start race-enricher@$USER
systemctl start race-viz@$USER
```

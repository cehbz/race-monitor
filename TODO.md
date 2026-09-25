# TODO

- Cross-race peer contamination: race `05341ae1ea4e209b54188a2b56e8253e6b89063b` recorded peer `51.178.128.174:54041` with more pieces than the torrent has. Recorded before identity-based BPF dedup and `race_errors`; check whether it still happens (a `race_errors` row of the contamination type would show it).
- Unify the binary path in the systemd units: `race-monitor@.service` runs `~/.local/bin`, `race-enricher@.service` runs `~/bin`.

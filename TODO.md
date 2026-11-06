# TODO

- Cross-race peer contamination: race `05341ae1ea4e209b54188a2b56e8253e6b89063b` recorded peer `51.178.128.174:54041` with more pieces than the torrent has. Recorded before identity-based BPF dedup and `race_errors`; check whether it still happens (a `race_errors` row of the contamination type would show it).
- Unify the binary path in the systemd units: `race-monitor@.service` runs `~/.local/bin`, `race-enricher@.service` runs `~/bin`.
- `race-enricher`'s ipapi.is lookups mostly fail: 350 this boot and 4,077 the last. Most are refused connections, with some 429s from the 30-a-day free limit. 60 are a parse error, since `company` can arrive as a string where `ipAPIResponse` expects an object.
- `torrent::start` can produce an all-zero info hash (races 716 and 794). A race like that can't be classified, so it is kept, and race 716 holds 173,112 unidentified events.
- Check how a race-viz detail page renders for a viewer already on a race that gets dropped as restored; its endpoints now return errors.

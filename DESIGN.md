# race-monitor: design

## Model
- **Torrent:** identified by its info hash; has a name, a size and a piece count. Has races. Its probe events carry its address in qBittorrent's memory, bound to it by its start until its race ends or it is restored. A torrent starting at an address takes it over from whatever held it, an unidentified start included, and the peers seen at that address are forgotten, so a peer the earlier torrent had is seen again.
- **Race:** one download of a torrent added while being watched, from its start to its finalization; records its peers' and our own piece acquisition. It exists only once its start is kept, and holds every piece event since the torrent's start, including those held while it was pending. A restored torrent never becomes a race and leaves no records, including one a qBittorrent restart interrupted. It ends a grace period after the download completes (half the download's duration, clamped to 5–60 s, never extended), at once when no peer was seen, or 30 minutes after its torrent's start; all three are measured from the torrent's start. A stop of race-monitor, requested or because its event source closed, ends every race once the events it has received are written.
- **Classification:** decides whether a pending start becomes a race. A start is kept when the torrent's addition date is within 5 s of its start, and dropped otherwise. A start that can't be classified within 60 s becomes a race and the failure is logged; with no qBittorrent API configured, every start becomes a race at once. One start's classification never delays another's.
- **Pending start:** a started torrent awaiting classification. It holds its piece events, peer routing and finish in order; it becomes a race with them when kept, and is discarded with them when restored or at shutdown.
- **Unidentified start:** a torrent start whose info hash reads as all zeros, an unknown failure. It is never classified or made a race; it is recorded with its torrent pointer, its time and its struct dump, logged as an error, and its events are counted, not stored, until another torrent starts at its address.
- **Peer:** a remote participant in one race, identified within its torrent by address and port; has a client and a peer ID. A seeder is seen from its bitfield, a leecher from its piece announcements.
- **Self:** our own client in a race, treated as a peer whose pieces are its verified completions.
- **Piece event:** a peer's announcement of a piece, or our completion of one, with its time from the kernel clock.
- **Race error:** an anomaly detected in one race. A piece index outside the torrent's piece count, seen 10 times from one source, is recorded as one, and so are events a race dropped because it fell behind, once per race with their count.
- **Calibration:** the four struct offsets for one qBittorrent binary, keyed by the binary's hash. Monitoring doesn't run without the calibration matching its binary.
- **Peer standing:** a peer's standing against Self in one race. A seeder holds 80% of the pieces before our first completion; a competitive peer is ahead for at least max(5 s, 10% of the race) with an average lead of at least 2% of the pieces.
- **Address enrichment:** per peer IP: its reverse DNS name, its BGP prefix and any provider its hostname names.
- **Network:** per BGP prefix: ASN, ISP, whether it is a datacenter, location, and its provider.
- **Provider:** the hosting brand behind a peer: a hostname pattern first, then a brand alias by ASN or domain, then the raw datacenter name.
- **Enrichment queue:** addresses awaiting lookup. Address lookups are free; network lookups are rate-limited per day.

## Tests
- Pending mark: `pending(t)`, called first in a test, defined in `pending_test.go` in each Go package with model-level tests (`internal/race`, `internal/storage`, `internal/enrichment`, `cmd/race-monitor`); Python's `@pending` in `race-viz/tests/pending.py`. `RUN_PENDING=1` runs marked tests.
- Model-level tests are the package tests that exercise the coordinator, tracker, store, enrichment service and the dashboard's analysis functions, run with `go test ./...` and `pytest race-viz/tests` (`race-viz/requirements-dev.txt`). Unit tests below an object's interface go beside the code in `*_unit_test.go` or `test_*_unit.py`.

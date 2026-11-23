# race-monitor

Records when each peer gets each piece of a BitTorrent race, from inside a running qBittorrent.

## What

race-monitor measures BitTorrent races on a qBittorrent seedbox. eBPF uprobes on libtorrent inside the running client record when each peer, and our own client, obtains each piece of a newly added torrent, with sub-millisecond timestamps at about 1–2% CPU. A dashboard replays each race and ranks the peers against us.

## Why

It provides observations for racing and for improving race performance: feedback on race tuning, and, when other peers do significantly and consistently better than us, the data to work out why.

## How

Five uprobes on libtorrent symbols feed a single-writer coordinator, which classifies each started torrent and routes piece events to a tracker per race that writes them to SQLite. Struct offsets are discovered once per qBittorrent binary by `race-calibrate`, so no struct layout is hardcoded. `race-enricher` resolves peer addresses to networks and hosting providers, and a Flask dashboard reads the same database. The domain model is in [DESIGN.md](DESIGN.md); the mechanics are in [how it works](docs/how-it-works.md).

## How it differs

Other race-monitoring tools exist; none found records every peer's progress piece by piece on a headless Linux seedbox without modifying the client. qBittorrent's own peer list shows progress snapshots with no per-piece timing. Packet capture has to reassemble TCP, frame and parse the protocol and decrypt it, and captured 19–29% of events at 505 MiB/s with about 100 peers, where the uprobes, firing after libtorrent has parsed each message, capture all of them. Racing tools such as autobrr and qbit-race act on a race, by grabbing and re-announcing, rather than measuring it.

## What it doesn't do

It doesn't influence a race. It doesn't record restored torrents, or a race that a qBittorrent restart interrupted. It needs Linux 5.8 or later and an unstripped qBittorrent binary it has been calibrated for.

## More

- [Install and configure](docs/install.md)
- [Calibrate, run and operate](docs/operation.md)
- [How it works](docs/how-it-works.md): probes, calibration, race lifecycle, enrichment, design decisions
- [Dashboard](race-viz/README.md)
- Layout: `cmd/` holds the three binaries, `internal/` the eBPF program (`bpf`), capture, race coordinator and tracker (`race`), storage and enrichment, `race-viz/` the dashboard
- Tests: `go test ./...` and `pytest race-viz/tests`
- License: MIT

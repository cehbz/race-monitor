# TODO

- Cross-race piece contamination still happens after identity-based BPF dedup: `race_errors` holds 8 `piece_index_out_of_range` rows (races 43 to 882), seven from `incoming_have` on a peer connection and one, race 882, from `we_have` on a torrent pointer (piece 636 of 627).
- The repo's `systemd/` holds system template units installed by `make install-services`, while hbd runs user units in `~/.config/systemd/user` that aren't in the repo; bring the deployed units into the repo and make `install-services` install them.
- `race-enricher`'s ipapi.is lookups mostly fail: 350 this boot and 4,077 the last. Most are refused connections, with some 429s from the 30-a-day free limit. 60 are a parse error, since `company` can arrive as a string where `ipAPIResponse` expects an object.
- `torrent::start` can produce an all-zero info hash (races 716 and 794, and again at the Nov 17 boot). A race like that can't be classified, so it is kept, and race 716 holds 173,112 unidentified events.
- Check how a race-viz detail page renders for a viewer already on a race that gets dropped as restored; its endpoints now return errors.

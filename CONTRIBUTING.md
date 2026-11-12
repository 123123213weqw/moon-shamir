# Contributing

Every rule in this file was learned by a red ladder run in this
repository's own history; the commit messages name the incidents.

## The order of operations

`scripts/host-check.sh` is the loop below as one command: push the
tracked paths, pin the expected answer of any example that lacks one
(the engine is their only writer), run the ladder on the host, pull
the verified tree back. The steps it automates:

1. Edit sources locally; sync to the build host (rsync, excluding
   `_build`, `.git`, `.github` and pushing **with `--delete`** so the
   host mirrors the git manifest - a file the repository does not
   track must not sit among the sources moon compiles).
2. On the host: `moon fmt`, then `scripts/stats.py --write`, then
   `sh scripts/verify.sh` - in that order. fmt changes line counts;
   the stats table must be written after the settling, or the next
   run is stale-red.
3. Sync back (host to local, `--delete`, same exclusions).
4. `git add -A` is safe only at this point - after the pull, on a
   tree the ladder just verified. An unfiltered add after pulling
   from a host that ever held other work shipped someone else's
   October experiment inside this library once (see the purge
   commits); if the host is not yours alone, diff against
   `git ls-files` first.
5. Commit, push. CI runs the same ladder; if it is red, the next
   commit fixes it - a red main is never left behind "for later".

## Baselines refresh deliberately

`tests/bench.baseline` and `tests/size.baseline` change only by an
explicit `--write` of their scripts, never as a side effect of a red
run, and a baseline change is a reviewable act: say in the commit why
the number moved. A new benchmark or artifact without a baseline entry
fails the ladder - add it in the same commit that adds the code.

## When you add a feature

- The oracle grows with the engine: an independent Python path for
  every new operation, fuzz beside fixtures, refusals beside behavior.
  If the engine and the oracle agree by construction, the test is
  theater - write the Python side from the specification, not from the
  MoonBit source.
- Crypto vectors are computed before they are written down (Python's
  `hmac`/`hashlib`), never transcribed by eye; RFC 4231's case 3
  caught a real long-key bug that every in-block vector had walked
  past.
- Walk the branches: a vector or fuzz case for each normalization
  shape, each refusal path, each encoding. Coverage that never
  executed a branch has not covered it.
- Refusal messages follow the style audit (ASCII, lowercase start, no
  trailing period); `scripts/messages.py` counts them into the stats
  table, so the count moves with the code.
- The public surface is frozen in `tests/api.golden`; if your change
  moves it, that is a deliberate API decision - update the golden in
  the same commit and say so in the message.
- Examples are pinned: run the CLI, save the answer under
  `examples/expected/`, index it in `examples/README.md`. An example
  that cannot quietly stop being true is documentation that tests
  itself.

## Honesty lines

Boundaries and THIRD_PARTY are part of the deliverable: a ported file
gets its provenance notice, a public-label-vs-MAC distinction gets its
sentence, a limitation gets written down in the same commit that ships
the feature. The proposal's numbers are recalibrated to the recounted
source whenever the stats move.

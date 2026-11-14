#!/bin/sh
# The whole host loop from CONTRIBUTING as one command: sync the
# sources to the build host, let the engine pin the expected answer of
# any example that lacks one (the engine is their only writer), run the
# full ladder there, and sync the verified tree back. A failing step
# stops everything; the ladder's log waits at /tmp/vf.txt on the host.
#
# The push and pull are scoped to the paths the repository tracks -
# same effect as syncing the whole tree, without asking rsync to walk
# whatever else happens to sit beside the sources on either end.
#
# Usage: scripts/host-check.sh [host-alias]
#   host-alias  ssh target from ~/.ssh/config (default WZU_V100)
# The host toolchain lives at /tmp/moon-latest-test; adjust below if
# it moves.
set -e
host="${1:-WZU_V100}"
moon_home=/tmp/moon-latest-test
root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"
echo "== push: tracked paths to $host"
rsync -a --delete --exclude 'expected' ./examples/ "$host:moon-shamir/examples/"
rsync -a --delete ./cmd/ "$host:moon-shamir/cmd/"
rsync -a --delete ./scripts/ "$host:moon-shamir/scripts/"
rsync -a --delete ./tests/ "$host:moon-shamir/tests/"
rsync -a --delete ./docs/ "$host:moon-shamir/docs/"
rsync -a ./.gitignore ./LICENSE ./README.md ./CHANGELOG.md ./CONTRIBUTING.md \
  ./VERSIONING.md ./THIRD_PARTY.md ./moon.mod ./moon.pkg ./*.mbt ./*.mbti "$host:moon-shamir/"
echo "== host: pin new example answers, then the full ladder"
ssh "$host" 'cd ~/moon-shamir && set -e
  export PATH=/tmp/moon-latest-test/bin:$PATH
  moon build --target js >/dev/null
  mkdir -p examples/expected
  for f in examples/*.json; do
    e="examples/expected/$(basename "$f" .json).expected.json"
    if [ ! -f "$e" ]; then
      node _build/js/debug/build/cmd/main/main.js "$f" > "$e"
      echo "pinned $e"
    fi
  done
  moon fmt
  MOON_HOME=/tmp/moon-latest-test python3 -B scripts/stats.py --write >/dev/null
  MOON_HOME=/tmp/moon-latest-test sh scripts/verify.sh > /tmp/vf.txt 2>&1
  tail -1 /tmp/vf.txt'
echo "== pull: verified tree back"
rsync -a "$host:moon-shamir/"*.mbt "$host:moon-shamir/"*.mbti \
  "$host:moon-shamir/PROJECT_STATS.md" "$host:moon-shamir/moon.mod" \
  "$host:moon-shamir/moon.pkg" "$host:moon-shamir/README.md" \
  "$host:moon-shamir/CHANGELOG.md" "$host:moon-shamir/CONTRIBUTING.md" ./
rsync -a "$host:moon-shamir/cmd/" ./cmd/
rsync -a "$host:moon-shamir/docs/" ./docs/
rsync -a "$host:moon-shamir/examples/" ./examples/
rsync -a "$host:moon-shamir/scripts/" ./scripts/
rsync -a "$host:moon-shamir/tests/" ./tests/
echo "== verified on the host; review and commit here"

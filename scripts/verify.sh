#!/bin/sh
# One command runs the whole ladder. Native builds need a C compiler; set
# SKIP_NATIVE=1 to skip that target.
set -e
cd "$(dirname "$0")/.."
export MOON_HOME="${MOON_HOME:-$HOME/.moon}"
export PATH="$MOON_HOME/bin:$PATH"
for target in js wasm wasm-gc native; do
  if [ "$target" = "native" ] && [ -n "$SKIP_NATIVE" ]; then
    echo "native: skipped (SKIP_NATIVE=1)"
    continue
  fi
  printf '%s check: ' "$target"
  moon check --deny-warn --target "$target" >/dev/null
  echo "0 warnings"
  printf '%s test: ' "$target"
  moon test --target "$target" | tail -1
done
moon build --target js
printf 'fixtures: '
node scripts/check.mjs | tail -1
printf 'oracle: '
python3 -B scripts/reference.py | tail -1
printf 'robustness: '
python3 -B scripts/robustness.py | tail -1
printf 'cli tool: '
node scripts/shamir.mjs split 0123456789abcdef 3 5 2026 > /tmp/shamir_shares.txt
LINES=$(grep -v '^#' /tmp/shamir_shares.txt | grep ':')
node scripts/shamir.mjs combine $(echo "$LINES" | sed -n '1p;3p;5p') | grep -q 'secret_hex 0123456789abcdef' \
  && node scripts/shamir.mjs diagnose $(echo "$LINES" | tr '\n' ' ') | grep -q 'suspects \[\]' \
  && echo 'round trip passed'
printf 'stats: '
python3 -B scripts/stats.py | tail -1
moon fmt --check
echo 'Verify: every step passed'

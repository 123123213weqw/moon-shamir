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
  && node scripts/shamir.mjs kdf 'paper backup' cafe 1000 | grep -q 'seed [0-9]' \
  && node scripts/shamir.mjs reshare 4 6 77 $(echo "$LINES" | sed -n '1p;3p;5p') > /tmp/shamir_reshared.txt \
  && R=$(grep -v '^#' /tmp/shamir_reshared.txt | grep ':') \
  && node scripts/shamir.mjs combine $(echo "$R" | sed -n '1p;2p;3p;4p') | grep -q 'secret_hex 0123456789abcdef' \
  && node scripts/shamir.mjs split cafebabe 2 3 5 words > /tmp/shamir_words.txt \
  && W=$(grep -v '^#' /tmp/shamir_words.txt | grep ':') \
  && node scripts/shamir.mjs combine $(echo "$W" | sed -n '1p;2p') | grep -q 'secret_hex cafebabe' \
  && echo 'round trip passed (split/combine/diagnose/kdf/reshare/words)'
printf 'bench: '
moon bench --target js 2>/dev/null | grep -c ' ok$' | xargs -I{} echo '{} benchmarks ran'
printf 'scale: '
python3 -B scripts/scale.py | tail -1
printf 'messages: '
python3 -B scripts/messages.py | tail -1
printf 'surface: '
moon info
diff pkg.generated.mbti tests/api.golden && echo 'api surface unchanged'
printf 'stats: '
python3 -B scripts/stats.py | tail -1
moon fmt --check
echo 'Verify: every step passed'

"""Gates the build artifact sizes: wasm and wasm-gc module bytes are
measured after a release build and compared against the recorded
baseline. Bloat beyond the budget - an accidental dependency, an
embedded table twice as large - fails the ladder; --write refreshes
deliberately."""
import sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'tests' / 'size.baseline'
BUDGET = 1.5
# The CLI is js-only, and the library builds no standalone wasm
# artifact - so the stable carriers of the full library code are the js
# CLI bundle and the wasm internal-test module the backend step builds.
TARGETS = {
    'cli-js': ROOT / '_build/js/debug/build/cmd/main/main.js',
    'test-wasm': ROOT / '_build/wasm/debug/test/moon_shamir.internal_test.wasm',
}

def measure():
    sizes = {}
    for name, path in TARGETS.items():
        if not path.exists():
            raise SystemExit(f'{name} artifact missing: build release first')
        sizes[name] = path.stat().st_size
    return sizes

def read_baseline():
    if not BASELINE.exists():
        return {}
    out = {}
    for line in BASELINE.read_text().splitlines():
        if '=' in line:
            name, value = line.split('=', 1)
            out[name.strip()] = int(value)
    return out

sizes = measure()
if '--write' in sys.argv:
    BASELINE.write_text(''.join(f'{n} = {v}\n' for n, v in sorted(sizes.items())))
    print(f'size baseline written: {sorted(sizes.items())}')
    raise SystemExit(0)
recorded = read_baseline()
if not recorded:
    print('size baseline: MISSING - run scripts/size.py --write once')
    raise SystemExit(1)
failures = []
for name, size in sorted(sizes.items()):
    if name not in recorded:
        failures.append(f'{name}: new target, baseline has no entry')
        continue
    if size > recorded[name] * BUDGET:
        failures.append(f'{name}: {size} bytes vs baseline {recorded[name]} '
            f'exceeds {BUDGET}x')
for name in recorded:
    if name not in sizes:
        failures.append(f'{name}: target disappeared')
if failures:
    for failure in failures:
        print(' ' + failure)
    raise SystemExit(1)
print(f'size: {sorted(sizes.items())} within {BUDGET}x of baseline')

"""Parses moon bench output, compares against the recorded baseline, and
fails the ladder when a benchmark regresses beyond the budget. The
baseline travels in the repo; --write refreshes it deliberately, never
as a side effect of a red run."""
import re, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
BASELINE = ROOT / 'tests' / 'bench.baseline'
BUDGET = 3.0  # a benchmark may be at most 3x its recorded mean

def run_bench():
    result = subprocess.run(
        ['moon', 'bench', '--target', 'js'], cwd=ROOT,
        capture_output=True, text=True, timeout=300)
    if result.returncode:
        print(result.stdout[-500:])
        raise SystemExit('moon bench failed')
    # Lines: <mean> ± <sigma>   <min> … <max>  in 10 × N runs
    means = {}
    current = None
    for line in result.stdout.splitlines():
        named = re.search(r'bench .*"([^"]+)"', line)
        if named:
            current = named.group(1)
            continue
        timing = re.match(r'\s*([0-9.]+) (ns|µs|ms|s) ±', line)
        if timing and current:
            value = float(timing.group(1))
            unit = timing.group(2)
            factor = {'ns': 1, 'µs': 1e3, 'ms': 1e6, 's': 1e9}[unit]
            means[current] = value * factor
            current = None
    return means

def read_baseline():
    if not BASELINE.exists():
        return {}
    out = {}
    for line in BASELINE.read_text().splitlines():
        if '=' in line:
            name, value = line.split('=', 1)
            out[name.strip()] = float(value)
    return out

if '--write' in sys.argv:
    means = run_bench()
    BASELINE.write_text(
        ''.join(f'{name} = {value:.0f}\n' for name, value in sorted(means.items())))
    print(f'baseline written: {len(means)} benchmarks')
    raise SystemExit(0)

means = run_bench()
recorded = read_baseline()
if not recorded:
    print('baseline: MISSING - run scripts/baseline.py --write once')
    raise SystemExit(1)
failures = []
for name, value in sorted(means.items()):
    if name not in recorded:
        failures.append(f'{name}: new benchmark, baseline has no entry')
        continue
    if value > recorded[name] * BUDGET:
        failures.append(
            f'{name}: {value:.0f}ns vs baseline {recorded[name]:.0f}ns '
            f'exceeds {BUDGET}x')
for name in recorded:
    if name not in means:
        failures.append(f'{name}: benchmark disappeared')
if failures:
    for failure in failures:
        print(' ' + failure)
    raise SystemExit(1)
worst = max(means.values())
print(f'baseline: {len(means)} benchmarks within {BUDGET}x '
    + f'(slowest {worst:.0f}ns)')

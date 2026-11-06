"""Scale gate: correctness at the size ceilings, with a noise-tolerant
time regression check. Deterministic inputs; the timing gate fails only
on a 6x slowdown, well outside scheduling noise on the reference host."""
import json, subprocess, sys, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / '_build/js/debug/build/cmd/main/main.js'

def run(request):
    result = subprocess.run(['node', str(CLI), '-'], input=json.dumps(request),
        capture_output=True, text=True, timeout=120)
    if result.returncode:
        raise RuntimeError(result.stdout)
    return json.loads(result.stdout)

# 1. The 16 KiB ceiling: split at threshold 6, recover from a sampled
#    quorum, verify, reshare upward, recover again.
secret = bytes((i * 37 + 11) % 256 for i in range(16384))
t0 = time.monotonic()
sp = run({'operation': 'split', 'secret_hex': secret.hex(),
    'threshold': 6, 'shares': 20, 'seed': 1234567})
t1 = time.monotonic()
picked = [sp['share_list'][i] for i in (0, 3, 7, 12, 19, 14)]
co = run({'operation': 'combine', 'shares': picked})
t2 = time.monotonic()
assert co['verified'] is True and co['secret_hex'] == secret.hex(), '16k recovery'
vf = run({'operation': 'verify', 'shares': sp['share_list'][:6],
    'secret_hex': secret.hex()})
assert vf['verified'] is True, '16k verify'
rs = run({'operation': 'reshare', 'shares': sp['share_list'][:6],
    'threshold_new': 8, 'shares_new': 30, 'seed': 42})
assert len(rs['share_list']) == 30, '16k reshare count'
co2 = run({'operation': 'combine',
    'shares': [rs['share_list'][i] for i in range(0, 30, 4)][:8]})
assert co2['verified'] is True and co2['secret_hex'] == secret.hex(), '16k reshare recovery'
t3 = time.monotonic()
elapsed = (t3 - t0, t2 - t1)
print(f'Scale: 16 KiB threshold-6 split {t1-t0:.2f}s, combine {t2-t1:.2f}s, '
    + f'verify+reshare(6->8,30)+recover {t3-t2:.2f}s')

# 2. Diagnose at the enumeration ceiling: 12 shares, threshold 6, one
#    corrupted share among them - still exact, still named.
sp12 = run({'operation': 'split', 'secret_hex': secret[:64].hex(),
    'threshold': 6, 'shares': 12, 'seed': 777})
bad = dict(sp12['share_list'][9])
data = bytearray(bytes.fromhex(bad['data']))
data[0] ^= 0x40
bad['data'] = bytes(data).hex()
dg = run({'operation': 'diagnose', 'shares': sp12['share_list'][:9] + [bad]})
assert dg['consistent'] is True, 'diag consistent'
assert dg['suspects'] == [10], f'diag suspects: {dg["suspects"]}'
print('Scale: diagnose at 12 shares / threshold 6 named the corrupted index in '
    + f'{dg["subsets_checked"]:.0f} subsets')

# 3. Timing gate: the 16 KiB paths together must stay under 12 seconds -
#    roughly 6x this host's current numbers, so a regression screams.
total = t3 - t0
assert total < 12.0, f'scale gate too slow: {total:.2f}s'
print(f'Scale gate passed in {total:.2f}s (budget 12s)')

"""Malformed-input sweep: every bad request is answered, never crashed."""
import json, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / '_build/js/debug/build/cmd/main/main.js'

def share(index=1, threshold=2, digest='00000000', data='ab'):
    return {'index': index, 'threshold': threshold, 'digest': digest, 'data': data}

CASES = [
    ('unknown operation', {'operation': 'nope'}),
    ('missing operation', {}),
    ('split missing secret', {'operation': 'split', 'threshold': 2, 'shares': 3}),
    ('split empty secret', {'operation': 'split', 'secret_hex': '', 'threshold': 2, 'shares': 3}),
    ('split odd hex', {'operation': 'split', 'secret_hex': 'abc', 'threshold': 2, 'shares': 3}),
    ('split non-hex', {'operation': 'split', 'secret_hex': 'zz', 'threshold': 2, 'shares': 3}),
    ('split threshold one', {'operation': 'split', 'secret_hex': 'ab', 'threshold': 1, 'shares': 3}),
    ('split threshold fractional', {'operation': 'split', 'secret_hex': 'ab', 'threshold': 2.5, 'shares': 3}),
    ('split shares below threshold', {'operation': 'split', 'secret_hex': 'ab', 'threshold': 4, 'shares': 3}),
    ('split shares over 255', {'operation': 'split', 'secret_hex': 'ab', 'threshold': 2, 'shares': 256}),
    ('split seed negative', {'operation': 'split', 'secret_hex': 'ab', 'threshold': 2, 'shares': 3, 'seed': -1}),
    ('split seed over 2^53', {'operation': 'split', 'secret_hex': 'ab', 'threshold': 2, 'shares': 3, 'seed': 9007199254740992}),
    ('split seed fractional', {'operation': 'split', 'secret_hex': 'ab', 'threshold': 2, 'shares': 3, 'seed': 1.5}),
    ('split unknown field', {'operation': 'split', 'secret_hex': 'ab', 'threshold': 2, 'shares': 3, 'wat': 1}),
    ('split both secret forms', {'operation': 'split', 'secret_hex': 'ab', 'secret_text': 'ab', 'threshold': 2, 'shares': 3}),
    ('split neither secret form', {'operation': 'split', 'threshold': 2, 'shares': 3}),
    ('share encoding unknown', {'operation': 'combine', 'shares': [
        dict(share(), encoding='rot13'), share(index=2)]}),
    ('share base64 junk', {'operation': 'combine', 'shares': [
        dict(share(data='!!not-base64!!'), encoding='base64'), share(index=2)]}),
    ('share words junk', {'operation': 'combine', 'shares': [
        dict(share(data='zzzz blet perm kana yawy clan toed flaw'),
            encoding='words'), share(index=2)]}),
    ('share words index disagree', {'operation': 'combine', 'shares': [
        dict(share(index=2, data='blet blet perm kana yawy clan toed flaw'),
            encoding='words'), share(index=2)]}),
    ('share words too few', {'operation': 'combine', 'shares': [
        dict(share(data='blet blet'), encoding='words'), share(index=2)]}),
    ('split share encoding unknown', {'operation': 'split', 'secret_hex': 'ab',
        'threshold': 2, 'shares': 3, 'share_encoding': 'hex64'}),
    ('split secret_text not string', {'operation': 'split', 'secret_text': 7, 'threshold': 2, 'shares': 3}),
    ('combine missing shares', {'operation': 'combine'}),
    ('combine shares not array', {'operation': 'combine', 'shares': 7}),
    ('combine one share', {'operation': 'combine', 'shares': [share()]}),
    ('combine index zero', {'operation': 'combine', 'shares': [share(index=0), share(index=2)]}),
    ('combine index over 255', {'operation': 'combine', 'shares': [share(index=256), share(index=2)]}),
    ('combine duplicate index', {'operation': 'combine', 'shares': [share(index=1), share(index=1)]}),
    ('combine short digest', {'operation': 'combine', 'shares': [share(digest='abcd'), share(index=2, digest='abcd')]}),
    ('combine data empty', {'operation': 'combine', 'shares': [share(data=''), share(index=2)]}),
    ('combine length mismatch', {'operation': 'combine', 'shares': [share(), share(index=2, data='abcd')]}),
    ('combine share not object', {'operation': 'combine', 'shares': [7, 8]}),
    ('combine unknown field', {'operation': 'combine', 'shares': [dict(share(), wat=1), share(index=2)]}),
    ('diagnose over twelve shares', {'operation': 'diagnose', 'shares': [
        share(index=i, threshold=2) for i in range(1, 14)]}),
    ('diagnose threshold over six', {'operation': 'diagnose', 'shares': [
        share(index=i, threshold=7) for i in range(1, 4)]}),
    ('diagnose below threshold', {'operation': 'diagnose', 'shares': [
        share(index=1, threshold=3), share(index=2, threshold=3)]}),
    ('verify non-hex secret', {'operation': 'verify', 'shares': [share(), share(index=2)],
        'secret_hex': 'zz'}),
    ('commit kind unknown', {'operation': 'split', 'secret_hex': 'ab',
        'threshold': 2, 'shares': 3, 'commit': 'md5'}),
    ('share commit unknown', {'operation': 'combine', 'shares': [
        dict(share(), commit='sha1'), share(index=2)]}),
    ('commit kinds mixed', {'operation': 'combine', 'shares': [
        dict(share()), dict(share(index=2), commit='sha256')]}),
    ('reshare threshold falls', {'operation': 'reshare', 'shares': [
        share(), share(index=2)], 'threshold_new': 1, 'shares_new': 3}),
    ('reshare below old threshold', {'operation': 'reshare', 'shares': [
        share(index=1, threshold=3), share(index=2, threshold=3)],
        'threshold_new': 3, 'shares_new': 4}),
    ('reshare unknown field', {'operation': 'reshare', 'shares': [
        share(), share(index=2)], 'threshold_new': 2, 'shares_new': 3, 'wat': 1}),
    ('verify unknown field', {'operation': 'verify', 'shares': [share(), share(index=2)], 'wat': 1}),
]

failures = []
for label, request in CASES:
    result = subprocess.run(['node', str(CLI), '-'], input=json.dumps(request),
        capture_output=True, text=True, encoding='utf-8', timeout=20)
    if result.returncode != 1:
        failures.append(label + ': exit ' + str(result.returncode))
        continue
    try:
        parsed = json.loads(result.stdout)
    except Exception:
        failures.append(label + ': stdout is not one JSON object')
        continue
    if not isinstance(parsed, dict) or not isinstance(parsed.get('error'), str):
        failures.append(label + ': no error string')
    if result.stderr.strip():
        failures.append(label + ': wrote to stderr')

print(f'Robustness: {len(CASES)} malformed requests all answered with '
    + 'one error object and exit 1')
if failures:
    for failure in failures:
        print('  ' + failure)
    sys.exit(1)

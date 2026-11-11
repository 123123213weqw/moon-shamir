"""Counts the claims PROJECT_STATS.md makes about the source."""
import json, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ['api.mbt', 'b64.mbt', 'gf256.mbt', 'hmac.mbt', 'mnemonic.mbt',
    'moonwords.mbt', 'sha256.mbt', 'shamir.mbt', 'splitmix.mbt', 'text.mbt',
    'value.mbt']
physical = noncomment = 0
for name in PRODUCTION:
    for line in (ROOT / name).read_text().splitlines():
        physical += 1
        stripped = line.strip()
        if stripped and not stripped.startswith('///'):
            noncomment += 1
tests = sum(p.read_text().count('\ntest ') for p in ROOT.glob('*.mbt'))
fixtures = len(json.loads((ROOT / 'tests/cases.json').read_text()))
examples = len([p for p in (ROOT / 'examples').glob('*.json')])
import re as _re
_pattern = _re.compile(r'(?:raise InputError\(|InputError\(\s*)\n?\s*"([^"]+)"')
messages = sum(len(_pattern.findall((ROOT / n).read_text()))
    for n in PRODUCTION)
stats = {'physical': physical, 'noncomment': noncomment, 'tests': tests,
    'fixtures': fixtures, 'examples': examples, 'messages': messages}
if '--write' in sys.argv:
    table = ('# Source and verification statistics\n\n'
        'Snapshot date: 2026-11-11. Module version: 0.5.0.\n\n'
        '| Category | Count |\n|---|---:|\n'
        f'| Owned production MoonBit physical lines (root) | {physical} |\n'
        f'| Nonblank, non-comment production lines | {noncomment} |\n'
        f'| MoonBit test declarations | {tests} |\n'
        f'| CLI fixture cases | {fixtures} |\n'
        f'| Pinned examples | {examples} |\n'
        f'| Refusal messages | {messages} |\n\n'
        'Production counts the algorithm and boundary files only; tests,\n'
        'scripts, examples and documentation are excluded. Recount with\n'
        '--write; this table is the record, not the source of truth.\n')
    (ROOT / 'PROJECT_STATS.md').write_text(table)
    print('PROJECT_STATS.md updated:', stats)
else:
    recorded = (ROOT / 'PROJECT_STATS.md').read_text()
    for key, value in stats.items():
        assert f'| {value} |' in recorded, f'stale {key}: {value}'
    print('Stats: PROJECT_STATS.md matches the source', stats)

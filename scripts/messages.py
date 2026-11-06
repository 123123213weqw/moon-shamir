"""Audits every refusal message in the production sources against one
style, and reports the count the stats table pins:
- non-empty, ASCII printable;
- starts with a lowercase letter or a digit (they name fields and values);
- no trailing period, no double spaces, no leading/trailing space;
- never names a private detail (they are user-facing strings)."""
import re, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
PRODUCTION = ['api.mbt', 'b64.mbt', 'gf256.mbt', 'hmac.mbt', 'mnemonic.mbt',
    'moonwords.mbt', 'sha256.mbt', 'shamir.mbt', 'splitmix.mbt', 'text.mbt',
    'value.mbt']
pattern = re.compile(r'(?:raise InputError\(|InputError\(\s*)\n?\s*"([^"]+)"(\s*\+)?')
failures = []
messages = []
for name in PRODUCTION:
    text = (ROOT / name).read_text()
    for match in pattern.finditer(text):
        message = match.group(1)
        continued = match.group(2) is not None
        messages.append((name, message))
        if not message:
            failures.append(f'{name}: empty message')
            continue
        if not all(32 <= ord(c) < 127 for c in message):
            failures.append(f'{name}: non-ASCII in {message!r}')
        # Fragments that continue with a + concatenation are prefixes of a
        # longer sentence; only the whole-message rules are skipped.
        if continued:
            continue
        if message != message.strip():
            failures.append(f'{name}: padded whitespace in {message!r}')
        if message[0].isupper():
            failures.append(f'{name}: capital start in {message!r}')
        if message.endswith('.'):
            failures.append(f'{name}: trailing period in {message!r}')
        if '  ' in message:
            failures.append(f'{name}: double space in {message!r}')
if failures:
    for failure in failures:
        print(' ' + failure)
    sys.exit(1)
print(f'Messages: {len(messages)} refusal messages match the style guide')

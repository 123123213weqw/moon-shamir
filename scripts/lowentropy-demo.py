"""A demonstration, not a gate: how a public per-share label breaks
low-entropy secrets from a single share. This documents why the library
must never be given a short recovery code directly - the census the
competition reviewers asked for, executable."""
import json, subprocess, time, zlib, hashlib
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / '_build/js/debug/build/cmd/main/main.js'

def run(request):
    r = subprocess.run(['node', str(CLI), '-'], input=json.dumps(request),
        capture_output=True, text=True, timeout=60)
    return json.loads(r.stdout)

# A six-digit recovery code, split 3-of-5 under sha256 commitment.
code = f"{704221:06d}"
sp = run({'operation': 'split', 'secret_hex': code.encode().hex(),
          'threshold': 3, 'shares': 5, 'seed': 20261111, 'commit': 'sha256'})
one_share = sp['share_list'][0]
label = one_share['digest']

# The attacker holds ONE share. The label is public. Enumerate.
t0 = time.time()
found_crc = found_sha = None
for guess in range(1000000):
    g = f"{guess:06d}".encode()
    if f"{zlib.crc32(g):08x}" == label:
        found_crc = g.decode()
    if hashlib.sha256(g).hexdigest()[:8] == label:
        found_sha = g.decode()
elapsed = time.time() - t0
print(f"label {label} from one share -> crc32 match: {found_crc}, "
      f"sha256 match: {found_sha}, enumeration of 10^6 in {elapsed:.1f}s")
assert found_sha == code, 'the demonstration must actually recover the code'
print("verdict: any low-entropy secret is recoverable from ONE share; "
      "the threshold never mattered. Stretch first - see docs/security.md.")

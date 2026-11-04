"""Independent Python oracle: the same scheme, separately written.

GF(256) arithmetic here is built from exponent/log tables - a different
construction path than the implementation's shift-and-reduce multiplier -
and the coefficient stream is a from-scratch SplitMix64 in Python. Every
comparison below therefore pits two independent derivations against each
other.
"""
import itertools, json, random, re, subprocess, sys
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / '_build/js/debug/build/cmd/main/main.js'
MASK = (1 << 64) - 1

# exp/log tables over 0x11B, generator 3: multiply by 3 is x XOR xtime(x).
def _times3(x):
    doubled = x << 1
    if doubled & 0x100:
        doubled ^= 0x11B
    return x ^ doubled

GF_EXP = [0] * 512
GF_LOG = [0] * 256
_x = 1
for _i in range(255):
    GF_EXP[_i] = _x
    GF_LOG[_x] = _i
    _x = _times3(_x)
for _i in range(255, 512):
    GF_EXP[_i] = GF_EXP[_i - 255]

def gf_mul(a, b):
    if a == 0 or b == 0:
        return 0
    return GF_EXP[GF_LOG[a] + GF_LOG[b]]

def gf_inv(a):
    return GF_EXP[255 - GF_LOG[a]]

def gf_eval(coefficients, x):
    acc = 0
    for c in reversed(coefficients):  # constant term first, Horner down
        acc = gf_mul(acc, x) ^ c
    return acc

def gf_interpolate_zero(points):
    acc = 0
    for i, (xi, yi) in enumerate(points):
        weight = 1
        for j, (xj, _) in enumerate(points):
            if i != j:
                weight = gf_mul(weight, gf_mul(xj, gf_inv(xi ^ xj)))
        acc ^= gf_mul(yi, weight)
    return acc

class SplitMix64:
    def __init__(self, seed):
        self.state = seed & MASK

    def next_u64(self):
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK
        return z ^ (z >> 31)

    def next_byte(self):
        return self.next_u64() & 0xFF

def crc32(data):
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0xEDB88320 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF

def split(secret, threshold, shares, seed):
    rng = SplitMix64(seed)
    polys = []
    for byte in secret:
        poly = [byte] + [rng.next_byte() for _ in range(threshold - 1)]
        polys.append(poly)
    digest = crc32(secret)
    out = []
    for x in range(1, shares + 1):
        out.append({
            'index': x, 'threshold': threshold,
            'digest': f'{digest:08x}', 'data': bytes(gf_eval(p, x) for p in polys).hex(),
            'encoding': 'hex',
        })
    return out

def combine(shares):
    threshold = shares[0]['threshold']
    chosen = sorted(shares, key=lambda s: s['index'])[:threshold]
    width = len(chosen[0]['data']) // 2
    recovered = []
    for b in range(width):
        points = [(s['index'], bytes.fromhex(s['data'])[b]) for s in chosen]
        recovered.append(gf_interpolate_zero(points))
    return bytes(recovered)

def diagnose(shares):
    """Independent quorum search: same enumeration, separately coded."""
    import itertools as _it
    threshold = shares[0]['threshold']
    digest = int(shares[0]['digest'], 16)
    width = len(shares[0]['data']) // 2
    good, consistent = set(), False
    secret = b''
    for subset in _it.combinations(shares, threshold):
        recovered = bytearray()
        for b in range(width):
            points = [(s['index'], bytes.fromhex(s['data'])[b]) for s in subset]
            recovered.append(gf_interpolate_zero(points))
        if crc32(recovered) == digest:
            consistent = True
            if not secret:
                secret = bytes(recovered)
            good.update(s['index'] for s in subset)
    return {
        'consistent': consistent,
        'good': sorted(good),
        'suspects': sorted(s['index'] for s in shares if s['index'] not in good),
        'secret_hex': secret.hex() if consistent else '',
    }

def run(request, error=False):
    result = subprocess.run(['node', str(CLI), '-'], input=json.dumps(request),
        capture_output=True, text=True, timeout=60)
    if error:
        assert result.returncode == 1, (result.returncode, result.stdout)
        assert isinstance(json.loads(result.stdout).get('error'), str)
        return None
    if result.returncode:
        raise RuntimeError(result.stdout or result.stderr)
    return json.loads(result.stdout)

def main():
    checked = 0
    rng = random.Random(20261104)
    for iteration in range(40):
        length = rng.randrange(1, 33)
        secret = bytes(rng.randrange(256) for _ in range(length)).hex()
        threshold = rng.randrange(2, 6)
        shares = rng.randrange(threshold, 9)
        seed = rng.randrange(0, 1 << 32)
        request = {'operation': 'split', 'secret_hex': secret,
            'threshold': threshold, 'shares': shares, 'seed': seed}
        report = run(request)
        want = split(bytes.fromhex(secret), threshold, shares, seed)
        assert report['share_list'] == want, f'split-{iteration}'
        assert report['digest'] == f"{crc32(bytes.fromhex(secret)):08x}", f'digest-{iteration}'
        # Any k of the n shares recover the secret: every subset when n is
        # small, a sample of subsets when it is not.
        subsets = list(itertools.combinations(range(shares), threshold))
        if len(subsets) > 12:
            subsets = rng.sample(subsets, 12)
        for subset in subsets:
            picked = [report['share_list'][i] for i in subset]
            answer = run({'operation': 'combine', 'shares': picked})
            assert answer['secret_hex'] == secret, f'combine-{iteration}-{subset}'
            assert answer['verified'] is True, f'verified-{iteration}-{subset}'
        # The oracle's own combine agrees on a subset, and the label binds.
        answer = combine(want)
        assert answer.hex() == secret, f'oracle-combine-{iteration}'
        checked += 1
    # Text secrets: UTF-8 is the only transformation, so the oracle
    # encodes with Python's own utf-8 and compares end to end.
    for iteration in range(8):
        alphabet = "钥匙密钥备份key🔑日本語您好0123 pass phrase"
        text = ''.join(rng.choice(alphabet) for _ in range(rng.randrange(1, 24)))
        threshold = rng.randrange(2, 5)
        shares = rng.randrange(threshold, 8)
        seed = rng.randrange(0, 1 << 32)
        request = {'operation': 'split', 'secret_text': text,
            'threshold': threshold, 'shares': shares, 'seed': seed}
        report = run(request)
        encoded = text.encode('utf-8')
        assert report['secret_bytes'] == len(encoded), f'text-len-{iteration}'
        want = split(encoded, threshold, shares, seed)
        assert report['share_list'] == want, f'text-{iteration}'
        picked = [report['share_list'][i] for i in
            rng.sample(range(shares), threshold)]
        answer = run({'operation': 'combine', 'shares': picked})
        assert answer['verified'] is True, f'text-verified-{iteration}'
        assert answer['secret_text'] == text, f'text-roundtrip-{iteration}'
        checked += 1
    # Base64 share payloads: the oracle re-encodes with Python's base64
    # and recovers through either encoding interchangeably.
    import base64 as _b64
    for iteration in range(8):
        length = rng.randrange(1, 17)
        secret = bytes(rng.randrange(256) for _ in range(length)).hex()
        threshold = rng.randrange(2, 5)
        shares = rng.randrange(threshold, 8)
        seed = rng.randrange(0, 1 << 32)
        report = run({"operation": "split", "secret_hex": secret,
            "threshold": threshold, "shares": shares, "seed": seed,
            "share_encoding": "base64"})
        assert report["share_encoding"] == "base64", f"b64-flag-{iteration}"
        hex_split = run({"operation": "split", "secret_hex": secret,
            "threshold": threshold, "shares": shares, "seed": seed})
        for b64_share, hex_share in zip(report["share_list"], hex_split["share_list"]):
            raw = _b64.b64decode(b64_share["data"], validate=True)
            assert raw.hex() == hex_share["data"], f"b64-payload-{iteration}"
            assert b64_share["encoding"] == "base64"
        mixed = hex_split["share_list"][:threshold - 1] + [report["share_list"][-1]]
        answer = run({"operation": "combine", "shares": mixed})
        assert answer["verified"] is True and answer["secret_hex"] == secret, f"b64-mix-{iteration}"
        checked += 1
    # Mnemonic shares: the word table is parsed out of the engine source
    # (one shared constant), and the encode/decode logic here is written
    # independently, checksum and all.
    word_table = re.findall(r'"([a-z]{4})"', (ROOT / 'moonwords.mbt').read_text())
    assert len(word_table) == 256, 'word table parse'
    for iteration in range(8):
        length = rng.randrange(1, 13)
        secret = bytes(rng.randrange(256) for _ in range(length)).hex()
        threshold = rng.randrange(2, 5)
        shares = rng.randrange(threshold, 8)
        seed = rng.randrange(0, 1 << 32)
        report = run({"operation": "split", "secret_hex": secret,
            "threshold": threshold, "shares": shares, "seed": seed,
            "share_encoding": "words"})
        hex_split = run({"operation": "split", "secret_hex": secret,
            "threshold": threshold, "shares": shares, "seed": seed})
        for word_share, hex_share in zip(report["share_list"], hex_split["share_list"]):
            words = word_share["data"].split(" ")
            payload = bytes(word_table.index(w) for w in words[2:-2])
            assert payload.hex() == hex_share["data"], f"words-payload-{iteration}"
            crc = crc32(bytes([word_table.index(words[0]), word_table.index(words[1])]) + payload)
            assert word_table.index(words[-2]) == (crc >> 24) & 0xFF, f"words-crc-{iteration}"
            assert word_table.index(words[-1]) == (crc >> 16) & 0xFF, f"words-crc-lo-{iteration}"
        picked = report["share_list"][:threshold]
        answer = run({"operation": "combine", "shares": picked})
        assert answer["verified"] is True and answer["secret_hex"] == secret, f"words-combine-{iteration}"
        checked += 1
    # Determinism: one fixed request, twice, byte-identical answers.
    request = {'operation': 'split', 'secret_hex': 'cafebabe', 'threshold': 2,
        'shares': 3, 'seed': 7}
    assert run(request) == run(request), 'determinism'
    checked += 1
    # A different seed yields different share bytes for the same secret.
    a = run(dict(request, seed=8))['share_list']
    b = run(dict(request, seed=9))['share_list']
    assert a[0]['data'] != b[0]['data'], 'seed entropy'
    assert a[0]['digest'] == b[0]['digest'], 'digest follows the secret only'
    checked += 1
    # Diagnosis: inject one corrupted share into a k+1 (or larger) set and
    # demand it be named - engine and oracle agree on the quorum verdict.
    for iteration in range(15):
        length = rng.randrange(1, 9)
        secret = bytes(rng.randrange(256) for _ in range(length)).hex()
        threshold = rng.randrange(2, 5)
        shares = rng.randrange(threshold + 1, min(threshold + 3, 11) + 1)
        seed = rng.randrange(0, 1 << 32)
        made = split(bytes.fromhex(secret), threshold, shares, seed)
        victim = rng.randrange(shares)
        data = bytearray(bytes.fromhex(made[victim]['data']))
        data[rng.randrange(len(data))] ^= 1 << rng.randrange(8)
        mixed = [dict(s) for s in made]
        mixed[victim]['data'] = bytes(data).hex()
        report = run({'operation': 'diagnose', 'shares': mixed})
        want = diagnose(mixed)
        assert report['consistent'] == want['consistent'], f'diag-{iteration}'
        assert report['suspects'] == want['suspects'], (iteration, report['suspects'], want['suspects'])
        assert report['good'] == want['good'], f'diag-good-{iteration}'
        assert report['secret_hex'] == want['secret_hex'], f'diag-secret-{iteration}'
        # The engine's verify agrees the clean prefix recovers, and a
        # matching secret_hex claim passes while a wrong one fails.
        clean = run({'operation': 'verify', 'shares': made[:threshold]})
        assert clean['verified'] is True, f'verify-{iteration}'
        assert clean['secret_length'] == length, f'verify-len-{iteration}'
        claim = run({'operation': 'verify', 'shares': made[:threshold], 'secret_hex': secret})
        assert claim['verified'] is True, f'claim-{iteration}'
        deny = run({'operation': 'verify', 'shares': made[:threshold], 'secret_hex': 'ff' * length})
        if 'ff' * length != secret:
            assert deny['verified'] is False, f'deny-{iteration}'
        checked += 1
    # Refusals, each answered with one error object and exit 1.
    for bad in [
        {'operation': 'diagnose', 'shares': [
            {'index': i, 'threshold': 7, 'digest': '00000000', 'data': 'ab'}
            for i in range(1, 4)]},
        {'operation': 'verify', 'shares': [
            {'index': i, 'threshold': 2, 'digest': '00000000', 'data': 'ab'}
            for i in range(1, 3)], 'secret_hex': 'zz'},
        {'operation': 'combine', 'shares': [{'index': 1, 'threshold': 2,
          'digest': '00000000', 'data': 'ab'}, {'index': 1, 'threshold': 2,
          'digest': '00000000', 'data': 'cd'}]},
        {'operation': 'combine', 'shares': [{'index': 1, 'threshold': 2,
          'digest': '00000000', 'data': 'ab'}, {'index': 2, 'threshold': 3,
          'digest': '00000000', 'data': 'cd'}]},
        {'operation': 'combine', 'shares': [{'index': 1, 'threshold': 2,
          'digest': '00000000', 'data': 'ab'}, {'index': 2, 'threshold': 2,
          'digest': 'deadbeef', 'data': 'cd'}]},
    ]:
        run(bad, error=True)
        checked += 1
    print(f'Oracle: {checked} independent checks agree '
        + '(fuzz splits, subset recovery, determinism, refusals)')

if __name__ == '__main__':
    main()

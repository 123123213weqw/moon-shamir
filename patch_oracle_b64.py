import sys
path = 'scripts/reference.py'
s = open(path).read()
anchor = """    # Determinism: one fixed request, twice, byte-identical answers."""
addition = """    # Base64 share payloads: the oracle re-encodes with Python's base64
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
        mixed = [hex_split["share_list"][0], report["share_list"][2]]
        answer = run({"operation": "combine", "shares": mixed})
        assert answer["verified"] is True and answer["secret_hex"] == secret, f"b64-mix-{iteration}"
        checked += 1
    # Determinism: one fixed request, twice, byte-identical answers."""
assert anchor in s
s = s.replace(anchor, addition)
open(path, 'w').write(s)
print('oracle patched')

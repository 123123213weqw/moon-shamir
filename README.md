# Moon Shamir

Threshold secret sharing over GF(256): split a secret into n shares of
which any k recover it, in pure MoonBit with a JSON CLI and reusable
library API.

- Repository: [https://github.com/123123213weqw/moon-shamir](https://github.com/123123213weqw/moon-shamir)
- License: Apache-2.0

## Why

A key that exists in one place is one accident away from being gone, and
one leak away from being everyone's. Shamir's scheme turns a secret into
n shares with an information-theoretic guarantee: any k shares determine
it exactly, and any k-1 leave every possible secret equally likely - not
computationally hard to distinguish, indistinguishable. Lose shares, keep
the secret; steal shares below the threshold, learn nothing.

## What it does

Each byte of the secret becomes the constant term of its own random
polynomial of degree k-1 over GF(2^8) (the AES polynomial 0x11B); share i
is the evaluation of every polynomial at x = i. Combine interpolates the
constant terms back from any k shares.

- `split`: secret as hex, threshold 2..255, shares 2..255, and a seed.
  The seed is the entropy of the split - the randomness source is
  injected by the caller, never read from the environment, and the same
  (secret, seed) pair reproduces the same shares bit for bit on every
  backend. Production callers inject a high-entropy seed; SplitMix64 is
  deterministic by design and is not a security primitive.
- `combine`: k or more shares. Below the threshold the door stays closed
  - there is no wrong-secret output to misuse. Every share carries a
  CRC-32 label of the secret, so a corrupted or foreign share is caught
  as `verified: false`; the label is an integrity check, explicitly not
  a MAC, and the secrecy rests only on the information-theoretic
  argument. With `mac_key_hex` the label upgrades to an HMAC tag that a
  key holder can produce and no one else - a replaced share set fails
  verification instead of passing; the key is the caller's to keep, and
  the tag says nothing about a holder of the key.

```json
{"operation": "split", "secret_hex": "0011223344556677", "threshold": 3,
 "shares": 5, "seed": 20261104}
```

Two audit operations sit beside them. `diagnose` takes a share set,
enumerates every k-sized subset (bounded: at most 12 shares, threshold at
most 6), and names the shares that disagree with every quorum - a
corrupted share is identified, not merely suspected. `verify` performs
the recovery and reports a verdict without returning the secret; with an
optional `secret_hex` it also proves the set belongs to that exact
secret. The CLI wraps it all:

```sh
node scripts/shamir.mjs split 0011223344556677 3 5 20261104
node scripts/shamir.mjs combine 1:3:8407759b:89ecf4f6... 3:3:...:...
node scripts/shamir.mjs diagnose <shares...>
node scripts/shamir.mjs verify <shares...> [secret-hex]
```

## Verification

The Python oracle independently rebuilds the scheme from exponent/log
tables - a different construction path than the implementation's
shift-and-reduce multiplier - including its own SplitMix64, then checks
40 random splits share-for-share, recovers the secret from every k-sized
subset of the share set (all subsets while n is small, sampled ones
beyond), pins determinism and seed sensitivity, and walks malformed
requests. The algebraic law - every C(n,k) subset of a k-of-n split
recovers the same secret - is asserted exhaustively in white-box tests
too. Four backends (js, wasm, wasm-gc, native) build with zero warnings.

```sh
moon build --target js
sh scripts/verify.sh
node _build/js/debug/build/cmd/main/main.js examples/split.json
```

## Library use

`execute(Json) -> Json raise` is the standard JSON boundary; `run(Value)
-> Value raise` is the typed one over the same requests. Every exported
function raises `InputError` with a plain message. The full public
surface is frozen in tests/api.golden and diffed on every verify run -
besides the two entry points it is exactly: the Value tree (from_json,
to_json, get, has, required, str, arr, num, record, fields_only), the
error type InputError with its equality, and the SHA-256 helpers
sha256_raw / sha256_hex that the labels build on. If a change touches
that file, the ladder says so in the same breath.

## Documentation

[Design notes](docs/design.md) - the field, the polynomials, diagnose's
quorum search, reshare's algebra, the seed story. [Usage](docs/usage.md) -
every operation, every field, every default. [Current
boundaries](docs/boundaries.md) - sizes, security honesty, semantics
pinned by tests.

## Boundaries

Secrets are hex, capped at 16384 bytes; share x coordinates are 1..255,
so n is at most 255. Seeds travel as JSON numbers and are capped at
2^53-1, the last integer a double carries exactly. The CRC-32 label
detects corruption; it does not authenticate; the optional HMAC tag
authenticates against everyone but a key holder. SplitMix64 makes splits
reproducible from the seed - treat the seed as the secret-bearing
entropy and discard nothing you would not publish about the secret
itself.

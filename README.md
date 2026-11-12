# Moon Shamir

Threshold secret sharing over GF(256): split a secret into n shares of
which any k recover it, in pure MoonBit with a JSON CLI and reusable
library API.

- Repository: [https://github.com/123123213weqw/moon-shamir](https://github.com/123123213weqw/moon-shamir)
- License: Apache-2.0

## Why - and what this is conditional on

A key that exists in one place is one accident away from being gone, and
one leak away from being everyone's. Shamir's scheme turns a secret into
n shares such that any k determine it and any k-1 leave it
indistinguishable - **when the secret is high-entropy and the
coefficient seed is uniform**. That condition is not decoration: the
public integrity label in every share is an enumeration oracle, and a
six-digit recovery code falls to **one** share in seconds (the
demonstration runs in scripts/lowentropy-demo.py; see
[the security model](docs/security.md)). Split random keys, stretch
anything a human chose, seed with full-width `seed_hex` from a real
random source - then the threshold guarantee is the real thing.

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

Around them sit the operations a share holder actually reaches for.
`diagnose` enumerates every k-sized subset (bounded: at most 12 shares,
threshold at most 6) and names the shares that disagree with every
quorum - a corrupted share is identified, not merely suspected.
`verify` reports a verdict without returning the secret; with an
optional `secret_hex` it proves the set belongs to that exact secret.
`reshare` mints a fresh split from k old shares without the secret
existing in memory, raising the threshold or growing the count, and old
shares die with the rotation. `split_many` splits up to 64 secrets in
one request, each at its own derived seed - position i answers exactly
a standalone split at seed + i. `info` describes one share in hand
(x, threshold, labels, payload size, and whether a words checksum
verifies - a bad checksum is a finding, not a refusal), and
`fingerprint` folds a share set into one 16-hex-digit id for
"did I transcribe these correctly" without recovering anything. `sort`
puts a shuffled, mixed-encoding share pile into canonical order - by
x, one uniform payload encoding - with the one-split agreement checked
but nothing interpolated, so a below-threshold set sorts as happily as
a quorum. `check` counts the set against its threshold and answers
`gap` - how many shares short - and `ready`, with the agreement checked
and nothing recovered, so "do we have enough" is a question a holder
below the quorum can ask without combine's refusal.
A password can stand in for the seed (PBKDF2-HMAC-SHA256), an HMAC key
can tag every share against substitution, and secrets may be UTF-8
text. The CLI wraps all of it:

```sh
node scripts/shamir.mjs split 0011223344556677 3 5 20261104
node scripts/shamir.mjs combine 1:3:8407759b:hex:89ecf4f6... 3:3:...:hex:...
node scripts/shamir.mjs diagnose <shares...>
node scripts/shamir.mjs verify <shares...> [secret-hex]
node scripts/shamir.mjs reshare 4 6 77 <shares...>
node scripts/shamir.mjs split cafebabe 2 3 5 words
node scripts/shamir.mjs info <share>
node scripts/shamir.mjs fingerprint <shares...>
node scripts/shamir.mjs sort [encoding] <shares...>
node scripts/shamir.mjs check <shares...>
node scripts/shamir.mjs kdf "a pass phrase" [salt-hex] [iterations]
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

## Performance

Means on the pinned toolchain (0.1.20261104, js backend, 1 KiB secret,
threshold 5), as recorded in tests/bench.baseline and gated by
scripts/baseline.py: the ladder fails beyond 3x, and the file refreshes
only by an explicit --write - a deliberate, reviewable act.

| Benchmark | Work per call | Mean |
|---|---|---:|
| split | 20 shares of a 1 KiB secret | 2.10 ms |
| combine | k = 5 of 8 shares | 0.22 ms |
| reshare | 5 shares re-minted as 5-of-8 | 2.82 ms |
| fingerprint | SHA-256 over 8 share images | 4.45 ms |

Artifact sizes are gated the same way (1.5x, tests/size.baseline): the
js CLI bundle is ~572 KiB and the wasm internal-test module ~365 KiB.

## Library use

`execute(Json) -> Json raise` is the standard JSON boundary; `run(Value)
-> Value raise` is the typed one over the same requests; and
`split_with_defaults(secret_hex, k, n)` is the one-call constructor for
the common shape - every other choice at its documented default
(seed 0, a public constant: tests and demos, never entropy). Every
exported function raises `InputError` with a plain message. The full
public surface is frozen in tests/api.golden and diffed on every verify
run - besides the three entry points it is exactly: the Value tree
(from_json, to_json, get, has, required, str, arr, num, record,
fields_only), the error type InputError with its equality, the SHA-256
helpers sha256_raw / sha256_hex that the labels build on, and the
batched interpolation pair gf_lagrange_weights / gf_interpolate_weighted
that the engines amortize with. If a change touches
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

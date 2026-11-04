# Moon Shamir

Threshold secret sharing over GF(256): split a secret into n shares of
which any k recover it, in pure MoonBit with a JSON CLI and reusable
library API.

- Repository: [https://github.com/yyqdbngt/moon-shamir](https://github.com/yyqdbngt/moon-shamir)
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
  argument.

```json
{"operation": "split", "secret_hex": "0011223344556677", "threshold": 3,
 "shares": 5, "seed": 20261104}
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
-> Value raise` is the typed one. Every exported function raises
`InputError` with a plain message.

## Boundaries

Secrets are hex, capped at 16384 bytes; share x coordinates are 1..255,
so n is at most 255. Seeds travel as JSON numbers and are capped at
2^53-1, the last integer a double carries exactly. The CRC-32 label
detects corruption; it does not authenticate. SplitMix64 makes splits
reproducible from the seed - treat the seed as the secret-bearing
entropy and discard nothing you would not publish about the secret
itself.

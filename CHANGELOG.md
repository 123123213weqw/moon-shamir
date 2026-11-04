# Changelog

## 0.2.0 — 2026-11-04

Two audit operations and a command-line tool. `diagnose` enumerates every
k-sized subset of a share set (bounded to 12 shares of a threshold at
most 6, so at most C(12,6) = 924 interpolations per byte), keeps the
subsets whose recovered bytes carry the label the shares agree on, and
names the shares that appear in no consistent subset - a corrupted share
is identified, not merely suspected, because it disagrees with every
quorum. `verify` performs combine's interpolation and reports a verdict
without returning the secret; with an optional secret_hex it additionally
requires the recovered bytes to equal it, so a holder can prove a share
set belongs to a known secret while the response carries nothing new.
The oracle grew an independently coded quorum search: 15 rounds inject a
flipped-bit share into a random split and demand the engine and the
oracle name the same suspect, agree on the good set and the recovered
secret. scripts/shamir.mjs wraps the engine as split / combine /
diagnose / verify commands with one-line print-friendly shares
(index:threshold:digest:data), wired into the verify ladder as a
round-trip check. Five new malformed-input cases (30 total), two new
fixtures, one new pinned example, two new white-box tests (12 total).

## 0.1.0 — 2026-11-04

## 0.1.0 — 2026-11-04

First release. Shamir k-of-n threshold secret sharing over GF(2^8)
(0x11B): every byte of the secret is the constant term of its own random
degree k-1 polynomial; share i evaluates them at x = i; combine
interpolates the constant terms back from any k shares, sorted to the
lowest x coordinates so the choice is deterministic. Below the threshold
combine refuses outright - no wrong-secret output exists to misuse.

The coefficient stream is SplitMix64 seeded by the caller: entropy, like
time in the rest of this family of tools, is injected, never read, and a
(seed, secret) pair reproduces its shares bit for bit on js, wasm,
wasm-gc and native. Every share carries a CRC-32 label of the secret -
an integrity check for corrupted or foreign shares, explicitly not a
MAC; the secrecy argument is information-theoretic and rests on nothing
else.

Verification: a Python oracle that rebuilds the scheme independently
from exponent/log tables with its own SplitMix64, checking 40 random
splits share-for-share and recovering the secret from every k-sized
subset; white-box tests asserting the subset law exhaustively (all ten
3-subsets of a 3-of-5 split), seed determinism, seed sensitivity,
tamper detection and refusal messages; 25 malformed-input cases; every
example pinned to its exact answer.

# Changelog

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

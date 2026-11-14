# Security model

Written after a competition review correctly held three claims against
this library. Each is stated here as an attack, with the demonstration
that proves it and the usage that avoids it.

## What the threshold guarantee actually says

Shamir's information-theoretic statement - any k-1 shares leave every
secret of the same length equally likely - holds when the polynomial
coefficients are uniform. In this library the coefficients come from
SplitMix64 seeded by the caller, so the guarantee is conditional twice:

1. **The seed must be uniform in its full range.** A guessed or reused
   seed regenerates the exact coefficient stream; with k-1 shares and
   the seed, the secret follows by interpolation. The numeric seed
   field tops out at 53 exact bits (a JSON double); use `seed_hex` for
   the full 64, and inject it from a real random source - the library
   deliberately reads no entropy of its own.
2. **The secret itself must carry the entropy you care about.** The
   scheme hides a uniformly random 128-bit key perfectly. It does not
   magnify a six-digit code into one.

## The public label is an oracle (demonstrated)

Every share carries the secret's digest - CRC-32, or the first 32 bits
of SHA-256. That label is public by design (integrity, not
authentication), and it is a verification oracle for offline
enumeration: scripts/lowentropy-demo.py splits a six-digit recovery
code 3-of-5, keeps **one** share, and recovers the code by enumerating
10^6 candidates against the label in under three seconds. The
threshold never mattered. Consequences:

- A low-entropy secret must never be split directly. Stretch first:
  derive 32 bytes with `kdf` (or any KDF), split the derived bytes,
  keep the mapping on the caller's side. What a paper backup of a
  recovery phrase wants is a high-entropy key that *encrypts* the
  phrase, with the key then shared - not the phrase itself.
- The seed is exactly as sensitive as the secret (it regenerates the
  shares' polynomial; with the seed and any share's label, weak
  secrets fall as above).

## What each protection is for

| Layer | Catches | Does not catch |
|---|---|---|
| threshold refusal | recovery below k | nothing about enumeration elsewhere |
| CRC-32 / SHA-256 label | corrupted or foreign shares | forgery (public), low-secret enumeration |
| HMAC tag | whole-set substitution, without the key | a key holder; low-entropy secrets *with* the key leaked |
| PBKDF2 seed path | cheap guessing of a password seed | entropy the password never had; GPU-speed guessing - the kdf response carries `memory_hard: false` and the substitution recipe (Argon2id outside, split its output) is in usage.md |

## Correct use, in one paragraph

Generate a 64-bit seed from a cryptographic source and pass it as
`seed_hex`. Split high-entropy material only; stretch anything a human
chose. If adversaries may replace shares, add `mac_key_hex`. Treat
every share, the seed, and the mac key as secret-bearing. Rotate by
reshare and destroy the old generation.

This file replaces the earlier unqualified wording. The proposal and
boundaries carry the same conditions; the enumeration script runs the
claim so nobody has to trust the prose.

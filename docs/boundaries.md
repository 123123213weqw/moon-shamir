# Current boundaries

What this library does and, just as deliberately, what it does not.
Every line here is enforced or stated somewhere in the code and tests.

## Scope

A pure, in-memory decision core. No file I/O, no network, no persistent
storage, no process spawning; the JSON CLI reads one request and prints
one answer. Distributing shares - printing them, storing them,
transmitting them - belongs to the caller.

## Sizes and ranges

- Secrets: hex or UTF-8 text, at most 16384 bytes.
- Share x coordinates: 1..255, so n is at most 255 per split.
- Threshold: 2..255, never above the share count.
- Seeds: whole numbers 0..2^53-1 - the last integers a JSON double
  carries exactly - or a password of at most 1024 bytes stretched by
  PBKDF2 with 1..1000000 iterations.
- Diagnose: at most 12 shares of threshold at most 6, so the
  enumeration is exact (at most 924 subsets per byte position).
- sort and check: 1..255 shares, the same range fingerprint accepts -
  a single share is a valid question for all three.
- Reshare: the new threshold may rise but never fall below the old one;
  new x coordinates avoid the old indexes, and the refusal names the
  bound when 255 x values cannot fit.

## Security honesty

- The secrecy argument is information-theoretic: any k-1 shares leave
  every secret of the same length equally likely. Nothing else carries
  security weight.
- The CRC-32 and SHA-256 labels are integrity checks against corruption
  and mix-ups, not authenticators - anyone can recompute either for any
  candidate secret. They are not MACs and are not described as them.
- SplitMix64 makes splits reproducible from the seed. It is not a
  security primitive; the caller owns the entropy. A password derives
  its seed through PBKDF2-HMAC-SHA256 (1..1000000 iterations) - a real
  stretch, but the entropy is the password's, and a weak password is a
  weak split no matter the iteration count.
- Seeds are as sensitive as the secret: they regenerate the shares, and
  knowing the seed for a public share set is knowing the secret.
- No side-channel hardening is claimed: constant-time field operations
  are not pursued, and the word-count of a words share reveals its
  length on sight.

## The newer operations, same discipline

- HMAC tags (0.4.0): they authenticate against everyone but a holder
  of the key; the key is the caller's to keep, and a key holder can
  mint tags for any secret - the tag says nothing about who split.
  Keyed and unkeyed shares never mix (refused by name), and reshare
  carries the tag without needing the key because the secret never
  exists in memory to re-tag.
- fingerprint: it describes a share set, not a split - a different
  subset of the same split has a different fingerprint, by design and
  documented in usage. It is a comparison aid, not an identity scheme;
  nothing prevents two holders of different splits of the same secret
  from comparing notes offline.
- split_many: each secret's seed is the request seed plus its
  position - the equivalence with standalone splits is the contract
  and is tested position-for-position. A batch under one password
  derives all seeds from one stretch; the password's entropy covers
  every secret in the batch.
- info: the describe mode reads fields as they stand when a words
  share fails its checksum - payload estimated from word count,
  checksum_ok false - while a non-words share that will not parse is
  refused outright, since hex and base64 carry no in-band checksum to
  dispute. info validates nothing about the secret.
- sort: it canonicalizes, it does not verify. The one-split agreement
  is checked and a words payload must decode (its checksum included -
  a bad one is a refusal here, unlike info's finding mode), but no
  interpolation runs: a corrupted hex or base64 payload that still
  parses sorts happily, and membership is claimed only as far as the
  label fields assert. The output re-encodes every payload (hex by
  default), so sorting trades payload spellings, never payload bytes.
- check: the gap counts consistent shares, not correct ones - no
  interpolation runs, so a corrupted payload that still parses counts
  toward readiness and readiness is not a recovery verdict. A single
  share is accepted (combine demands two): "how far is the quorum" is
  askable below the door, and the report carries nothing
  secret-shaped.
- split_with_defaults: the shortcut fixes every optional choice at
  its default, and seed 0 is a public constant - the constructor
  exists so the common call cannot misspell a field name, not to make
  a constant seed safe. It answers exactly what run answers; there is
  no second code path to diverge.
- size and bench baselines: both refresh only by an explicit --write,
  never as a side effect of a red run; a baseline change is a
  deliberate, reviewable act.

## Semantics pinned by tests

- Any k of n shares recover the same secret - asserted exhaustively on
  subsets and fuzzed by the oracle on random splits.
- Below the threshold, combine refuses; there is no wrong-secret output.
- A share set mixing thresholds, digests or commitment kinds is refused
  by name.
- A corrupted share is caught by the label (verified: false) and named
  by diagnose when a quorum exists without it.
- Reshared sets recover the same secret on their own quorums; old and
  new shares never alias an x coordinate.
- sort returns the canonical index order from any input order and any
  mix of payload encodings, re-encoded uniformly; duplicate and
  foreign shares are refused by the same names combine uses, and a
  set below the threshold sorts as happily as a quorum.
- check's gap is the threshold minus the shares in hand, floored at
  zero; ready lands exactly at the quorum, a single share is a valid
  question, and the report carries no secret-shaped field.
- The same (secret, seed) reproduces the same shares on js, wasm,
  wasm-gc and native, bit for bit.

## Provenance

The scheme is Shamir 1979 (with Blakley's independent formulation);
the field is the AES one; SplitMix64 is Steele's; HMAC and PBKDF2 are
RFC 2104 and 8018; the word-table idea follows SLIP-39's word encoding
with a different, deterministic table. The contribution is the MoonBit
implementation, its evidence chain, and the operations (diagnose,
verify, reshare) wrapped around the core. See THIRD_PARTY.md.
Competition admission and final review belong to the organizers;
publication is not acceptance.

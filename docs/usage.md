# Usage

> **Low-entropy secrets are breakable from a single share.** A public
> integrity label rides in every share; a six-digit code is enumerated
> against it in seconds (scripts/lowentropy-demo.py demonstrates). Split
> high-entropy material only - stretch anything a human chose first.
> Seeds must be uniform and full-width (`seed_hex`, 8 bytes from a real
> random source). [Security model](security.md).

One request object in, one report object out, over the standard JSON
boundary `execute(Json) -> Json raise` or the typed `run(Value) -> Value
raise`. Every failure raises `InputError` with a plain message; the CLI
prints it as `{"error": "..."}` and exits 1. Object key order is never
significant.

Library callers who only need the common shape can skip request
building entirely: `split_with_defaults(secret_hex, k, n)` answers
exactly what `split` answers with every optional field at its default -
seed 0, crc32 labels, hex payloads, no mac. Seed 0 is a fixed public
constant: right for tests and demos, wrong for entropy - inject a real
seed, a password derivation or a full-width `seed_hex` through `run`
for anything that must stay secret.

## The operations at a glance

| Operation | What it does | Interpolates |
|---|---|---|
| [split](#split) | One secret into n shares; any k recover it | no |
| [split_many](#split_many) | Up to 64 secrets in one request, each at seed + i | no |
| [combine](#combine) | k or more shares back into the secret | yes - returns it |
| [diagnose](#diagnose) | Names the shares no quorum agrees with | yes - returns it when a quorum exists |
| [verify](#verify) | Verdict only; can prove a known secret | yes - returns nothing |
| [reshare](#reshare) | Fresh split from k old shares | yes - the secret never exists in memory |
| [fingerprint](#fingerprint) | 16-hex-digit id for a share set | no |
| [info](#info) | Describes one share; a bad checksum is a finding | no |
| [sort](#sort) | Canonical order, one uniform payload encoding | no |
| [check](#check) | Threshold gap and readiness, counted | no |
| [kdf](#kdf) | Derives the seed a password split would use | no |

The interpolation column is the honesty column: everything the scheme
does to the secret runs through interpolation, and each operation
says whether it returns the result, keeps it out of memory, or never
runs it at all.

## split

```json
{"operation": "split", "secret_hex": "0011223344556677",
 "threshold": 3, "shares": 5, "seed": 20261104}
```

- `secret_hex` or `secret_text` - exactly one. Hex is bytes; text is
  encoded UTF-8 first. Up to 16384 bytes.
- `threshold` 2..255, `shares` 2..255 with `shares >= threshold`.
- `seed` - whole number 0..9007199254740991 - or `seed_hex` (exactly
  8 bytes, the full 64 bits a numeric field cannot carry) - **or** a `password`
  (plus optional `salt_hex`, default the library constant, and
  `iterations`, default 10000, range 1..1000000). Exactly one of
  `seed` and `password`.
- `share_encoding` - `hex` (default) | `base64` | `words`.
- `commit` - `crc32` (default) | `sha256`.
- `mac_key_hex` - optional, 1..64 bytes. When present every share
  carries a `mac`: the first 16 hex digits of HMAC-SHA256 under that
  key. Unlike the public labels, a mac cannot be forged without the
  key - a whole share set replaced by an attacker fails verification
  instead of passing. combine, verify and diagnose take the same
  `mac_key_hex`; keyed shares without the key are refused (a silent
  skip would read as success), a key with unkeyed shares is refused
  (a silent no-op would lie), and reshare carries the mac through
  without needing the key.

The report carries `secret_bytes`, `threshold`, `shares`, `seed`,
`share_encoding`, `commit`, the `digest` label of the secret, and
`share_list` - one object per share with `index` (its x, 1..255),
`threshold`, `digest`, `commit`, `data`, `encoding`. The same
`(secret, seed)` reproduces the same shares on every backend.

## split_many

```json
{"operation": "split_many", "secrets": ["aabb", "ccdd"], "threshold": 2,
 "shares": 4, "seed": 1000}
```

Split several secrets in one request - at most 64, each hex. The
threshold, share count, encodings, commitment and key apply to every
secret; each gets its own seed, the request's seed (or password
derivation) plus its position, so secret i's shares are exactly what a
standalone split with that derived seed answers - the oracle checks
this position-for-position. The response's `splits` array carries one
entry per secret with its own digest and share list.

## combine

```json
{"operation": "combine", "shares": [<share>, <share>, ...]}
```

Give it `threshold` or more shares of one split (they may mix hex and
base64 and words freely; they must agree on `threshold`, `digest` and
`commit`). The answer carries `secret_hex`, and also `secret_text`
when the recovered bytes are valid UTF-8; `verified` says whether the
recovered bytes match the label the shares carried - false means a
share was corrupted or does not belong, and the bytes are meaningless
by design. Below the threshold the operation refuses; there is no
wrong-secret output.

## diagnose

```json
{"operation": "diagnose", "shares": [<share>, ...]}
```

At most 12 shares of threshold at most 6. Enumerates every k-sized
subset, keeps those whose recovery matches the label, and reports
`consistent`, `good` (shares in at least one consistent subset),
`suspects` (shares in none - the corrupted ones, identified), and
`secret_hex` when a quorum exists.

## verify

```json
{"operation": "verify", "shares": [...], "secret_hex": "..."}
```

Performs the recovery and reports a verdict without returning the
secret. With the optional `secret_hex` the verdict additionally
requires the recovered bytes to equal it - proof that a share set
belongs to a known secret, with nothing new in the response.

## reshare

```json
{"operation": "reshare", "shares": [...], "threshold_new": 3,
 "shares_new": 5, "seed": 77}
```

From `threshold` or more old shares, mints a fresh split (a new
threshold that may rise but not fall, a new share count, a new seed or
password) without the secret existing in memory. New shares land on x
coordinates no old share occupies. Old and new sets are incompatible
by construction - destroy the old shares.

## fingerprint

```json
{"operation": "fingerprint", "shares": [...]}
```

One short id - 16 hex digits - for a share set: SHA-256 over the
canonical image of every share sorted by index. Answer the questions
"did I transcribe these correctly" (compare against a fingerprint taken
beforehand) and "is this the same batch as that one" without recovering
anything. Order-insensitive by construction; a different subset of one
split has a different fingerprint, because the set is what it describes.

## sort

```json
{"operation": "sort", "shares": [...], "share_encoding": "hex"}
```

Put a share list in canonical order - by `index`, ascending - without
recovering anything. Every share is parsed and the set must be one
split's (same `threshold`, `digest`, `commit`, mac agreement, distinct
indexes), the same rules every recovering operation holds; a set below
the threshold sorts as happily as a full quorum, because nothing is
interpolated. Payloads come back in one encoding of the caller's
choosing (`hex` default, or `base64` / `words`), so a mixed pile
becomes a uniform, canonically ordered list for storage or paper -
`did I transcribe these in order` answered before combine is attempted.

## check

```json
{"operation": "check", "shares": [...]}
```

Count a share set against its threshold without recovering anything:
`shares` in hand, the `threshold` they name, `gap` - how many more are
needed before combine's door opens - and `ready` (`gap` is zero). The
one-split agreement is demanded with the same refusals by name, so
`ready` means k consistent shares, not merely k lines; a single share
is a valid question here (combine demands two). The report also names
the `digest`, `commit`, `authenticated` and `payload_bytes` - and
carries nothing secret-shaped.

## info

```json
{"operation": "info", "share": {...}}
```

Describe one share without recovering anything: its x, threshold,
label, commitment kind, encoding, payload length, whether it carries a
mac, and - for words shares - whether the embedded checksum verifies. A
bad checksum is a finding (`checksum_ok: false`), not a refusal; info
exists to say what is in hand, including what is wrong with it.

## kdf

```json
{"operation": "kdf", "password": "...", "salt_hex": "aabb",
 "iterations": 20000}
```

Standalone derivation of the seed a password split would use:
PBKDF2-HMAC-SHA256, first 7 bytes, shifted into 53 bits. Pin the seed
before splitting, or reproduce it years later.

## Share shapes

One line on paper: `index:threshold:digest:encoding:data`, as printed by
`scripts/shamir.mjs` after `split` - and every encoding accepts the
same line back through `combine`, `diagnose`, `verify` and `reshare`.

## CLI

```sh
moon build --target js
node scripts/shamir.mjs split 0011223344556677 3 5 20261104
node scripts/shamir.mjs combine 1:3:...:... 3:3:...:... 5:3:...:...
node scripts/shamir.mjs diagnose <shares...>
node scripts/shamir.mjs verify <shares...> [secret-hex]
node scripts/shamir.mjs sort [encoding] <shares...>
node scripts/shamir.mjs check <shares...>
```

## Errors

Every malformed request - unknown fields, out-of-range numbers, odd or
non-hex strings, short mnemonics, duplicate share indexes, mixed
commitments, missing threshold - is answered with exactly one
`{"error": "<message>"}` object and exit 1. The message names the
offending field or share. 78 such cases are pinned in
scripts/robustness.py.

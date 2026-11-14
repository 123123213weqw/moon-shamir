# API reference

The machine-facing counterpart of [usage.md](usage.md): every public
symbol the module exports, every field each operation accepts and
answers, and the error contract. Behavior is frozen by the ladder -
`pkg.generated.mbti` against `tests/api.golden`, the fixtures, the
oracle, the malformed-input sweep - so this page describes what is
tested, not what is intended.

## The two boundaries

```moonbit
pub fn execute(request : @json.Json) -> @json.Json raise
pub fn run(request : Value) -> Value raise InputError
```

One request object in, one report object out. `execute` speaks JSON and
is what the CLI calls; `run` is the typed form over the same requests
and is what library callers should prefer. They differ in transport
only: every validation, default and refusal is in `run`, and
`execute` is `run(from_json(request)).to_json()`.

Failures raise `InputError`, a suberror carrying one plain message that
names the offending field or share. The CLI prints it as
`{"error": "<message>"}` and exits 1. Nothing writes to stderr.

```moonbit
pub fn split_with_defaults(secret_hex : String, threshold : Int32,
                           shares : Int32) -> Value raise InputError
```

The one-call constructor for the common shape: exactly what `run`
answers for `{"operation": "split", "secret_hex", "threshold",
"shares"}` with every optional field at its documented default - seed
0, crc32 labels, hex payloads, no mac. Seed 0 is a fixed public
constant: right for tests and demos, wrong for entropy.

## Conventions

- Object key order is never significant, on input or output.
- Hex fields are lowercase, without a `0x` prefix; an odd number of
  digits or any non-hex character is a refusal.
- Numbers must be whole where whole is required (`threshold`, `shares`,
  `seed`, `iterations`, share `index`): `2.5` is a refusal, not a
  truncation.
- Unknown fields are refused by name. A request that carries `wat` is
  answered `unknown field: wat` - a misspelled option must not read as
  a default.
- Optional string fields distinguish absent from empty: `mac_key_hex:
  ""` is a refusal (an empty key would make the mac a public constant),
  not the default.
- Seeds travel two ways: `seed`, a whole number 0..9007199254740991
  (the exact range of a JSON double), or `seed_hex`, exactly 8 bytes -
  the full 64 bits. The response always carries `seed_hex`; the numeric
  `seed` is `null` above 2^53-1 rather than approximate.

## Types

```moonbit
pub(all) enum Value {
  Null
  Bool(Bool)
  Number(Double)
  String(String)
  Array(Array[Value])
  Object(Map[String, Value])
}

pub(all) suberror InputError { InputError(String) }
```

`Value` is the module's own JSON tree, so `run` never forces a caller
into the `@json` API. The accessors it exports are the honest subset:
`get`, `has`, `required` (refuses when missing), `num`/`str`/`arr`
(refuse when the shape is wrong), `fields_only` (refuses unknown
fields), `record` (builds an object).

## The share object

Every operation that takes or returns shares speaks this shape, in
every encoding:

| Field | Type | Meaning |
|---|---|---|
| `index` | number | The x coordinate, 1..255. |
| `threshold` | number | The k this share was minted for, 2..255. |
| `digest` | string | 8 hex digits - the label of the secret (crc32 or sha256 head). |
| `commit` | string | `crc32` or `sha256` - which label kind. |
| `data` | string | The payload: hex, base64 or words. |
| `encoding` | string | `hex` (default on input when absent), `base64` or `words`. |
| `mac` | string | Optional. 16 hex digits - HMAC-SHA256 head under the split's key. |

Words shares carry index, threshold and a two-word checksum inside the
payload, and the fields must agree with the words: a `share index`
field that disagrees with mnemonic word 1 is a refusal, so two sources
of truth cannot quietly disagree. Encodings mix freely within one
request - hex, base64 and words shares of one split combine together.

## Operations

### split

Request: `operation`, `secret_hex` xor `secret_text` (hex bytes, or
UTF-8 text; at most 16384 bytes), `threshold` 2..255, `shares` 2..255
and at least the threshold, plus the optional fields:

| Field | Default | Bounds |
|---|---|---|
| `seed` | 0 | whole 0..9007199254740991, xor `seed_hex` (8 bytes), xor `password` |
| `password` | - | 1..1024 bytes; with `salt_hex` (default the library constant) and `iterations` (default 10000, 1..1000000) |
| `share_encoding` | `hex` | `hex` \| `base64` \| `words` |
| `commit` | `crc32` | `crc32` \| `sha256` |
| `mac_key_hex` | absent | 1..64 bytes |

Response: `algorithm` (`shamir-gf256`), `secret_bytes`, `threshold`,
`shares`, `share_encoding`, `commit`, `authenticated`, `digest` (the
secret's label), `seed_derivation` (`direct` or `pbkdf2-sha256`),
`seed`, `seed_hex`, `share_list`. The same `(secret, seed)` pair
reproduces the same shares on every backend.

### split_many

Request: `secrets` - 1..64 hex strings, each 1..16384 bytes - plus the
same `threshold`/`shares`/encodings/commit/mac fields and the same
seed choices as split. Secret i is split at `seed + i` (mod 2^53), so
its shares are exactly a standalone split's at that derived seed.

Response: `algorithm`, `secrets`, `threshold`, `shares`,
`share_encoding`, `commit`, `authenticated`, `seed_derivation`,
`splits` - one entry per secret with `position`, `secret_bytes`,
`digest` and its own `share_list`.

### combine

Request: `shares` - 2..255 entries of one split, threshold or more -
and `mac_key_hex` when they carry a mac. Keyed shares without a key
are refused (a silent skip would read as success); a key with unkeyed
shares is refused (a silent no-op would lie).

Response: `algorithm`, `secret_hex`, `recovered_digest`, `verified`,
and `secret_text` when the recovered bytes are valid UTF-8.
`verified: false` means a corrupted or foreign share - the bytes are
meaningless by design. Below the threshold the operation refuses:
there is no wrong-secret output.

### diagnose

Request: `shares` - 2..12 entries of threshold at most 6, at least the
threshold. The enumeration is exhaustive (at most C(12,6) = 924
interpolations per byte position), so the verdict is exact, not
heuristic.

Response: `shares`, `threshold`, `subsets_checked`,
`consistent_subsets`, `consistent`, `good` (indexes in at least one
consistent subset), `suspects` (in none - the corrupted ones,
identified), and `secret_hex` (empty string when no quorum exists).

### verify

Request: `shares` (2..255, threshold or more), optional
`secret_hex` - a claim, itself hex-checked - and `mac_key_hex`.

Response: `algorithm`, `shares`, `threshold`, `commit`,
`secret_length`, `verified` - a verdict only, nothing secret-shaped.
With the claim, verified additionally requires the recovered bytes to
equal it: proof that a share set belongs to a known secret.

### reshare

Request: `shares` - the old set, threshold or more; `threshold_new`
2..255 (may rise, never falls below the old threshold - the refusal
names that bound); `shares_new` at least `threshold_new`; the same
seed choices as split; `share_encoding`.

Response: `algorithm`, `threshold_new`, `shares_new`, `digest`,
`commit`, `share_encoding`, `seed`, `seed_hex`, `share_list`. New
shares land on x coordinates no old share occupies; old and new sets
are incompatible by construction, and the mac rides along without
needing the key.

### fingerprint

Request: `shares` - 1..255 entries of one split, a single share
included. Order does not matter.

Response: `algorithm`, `shares`, `threshold`, `fingerprint` - 16 hex
digits, SHA-256 over the canonical image of the shares sorted by
index. A different subset of one split has a different fingerprint,
because the set is what it describes.

### info

Request: `share` - one share object.

Response: `algorithm`, `index`, `threshold`, `digest`, `commit`,
`authenticated`, `payload_bytes`, `checksum_ok`, and `mac` when the
share carries one. A words share whose embedded checksum fails is
described anyway - `checksum_ok: false` is the finding, not a
refusal; info exists to say what is in hand, including what is wrong
with it. A non-words share that cannot parse at all is refused.

### sort

Request: `shares` - 1..255 entries of one split (the same one-split
agreement every recovering operation demands); `share_encoding` - the
output encoding, `hex` default.

Response: `algorithm`, `shares`, `threshold`, `digest`, `commit`,
`share_encoding`, `share_list` - canonically ordered by index,
payloads re-encoded uniformly. Nothing is interpolated; a set below
the threshold sorts as happily as a quorum.

### check

Request: `shares` - 1..255 entries of one split.

Response: `algorithm`, `shares` (count), `threshold`, `gap`
(threshold minus count, floored at zero), `ready`, `digest`,
`commit`, `authenticated`, `payload_bytes`. `ready` means k
consistent shares are in hand, not merely k lines; the report carries
nothing secret-shaped.

### kdf

Request: `password` (1..1024 bytes), optional `salt_hex` (default the
library constant) and `iterations` (default 10000, 1..1000000).

Response: `algorithm` (`pbkdf2-sha256`), `iterations`, `salt_hex`,
`seed`, `seed_hex` - the seed a password split with the same fields
would use, derivable years later.

## The field helpers

Also exported, because the boundary code is ordinary MoonBit over
`Value` and callers assembling requests may want the same pieces:

| Function | Role |
|---|---|
| `get(Value, String) -> Value` | A field or `Null`. |
| `has(Value, String) -> Bool` | Whether the field is present at all. |
| `required(Value, String) -> Value raise` | The field or `InputError("missing field: ...")`. |
| `num` / `str` / `arr` | Extract with a type check; wrong shape is a refusal. |
| `fields_only(Value, Array[String])` | Refuse any field outside the list, by name. |
| `record(Array[(String, Value)])` | Build an object. |

## The arithmetic surface

Two pieces of the field arithmetic are exported for callers doing
their own interpolation - the same functions the engine uses:

```moonbit
pub fn gf_lagrange_weights(points : Array[(Int32, Int32)], at : Int32) -> Array[Int32]
pub fn gf_interpolate_weighted(points : Array[(Int32, Int32)], weights : Array[Int32]) -> Int32
```

Weights depend only on the x coordinates and the evaluation point, so
they are computed once and reused across byte positions - the engine's
own pattern, exported so a caller does not reimplement it. The field
is GF(2^8) on the AES polynomial 0x11B.

```moonbit
pub fn sha256_hex(bytes : Array[Int32]) -> String
pub fn sha256_raw(bytes : Array[Int32]) -> Array[Int32]
```

The hash the mac and the labels are built on, exposed for callers
verifying labels without re-deriving them.

## Error contract

Every malformed request is answered with one `InputError` carrying a
plain ASCII message: lowercase start, no trailing period, the
offending field or value named. The message set is pinned twice - by
the 78 malformed cases in `scripts/robustness.py` and by the style
audit in `scripts/messages.py` - so a message cannot drift silently.
The refusal is the feature: a request that cannot be honored
honestly stops with a name, never with a default.

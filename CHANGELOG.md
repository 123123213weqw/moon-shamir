# Changelog

## 0.7.0 — 2026-11-14

Four additions to the boundary, one honest field, and the evidence to
match.

quorum_check is the planner's view beside check's count: the counted
fields ride unchanged (shares, threshold, gap, ready) beside excess,
quorums - how many distinct minimal quorums the set forms, C(count,
threshold) by an overflow-checked UInt64 multiplicative formula,
exact until the count passes the 2^53 integers a JSON double carries
and null past it (C(255, 8) is the last exact value at the share
ceiling, and the oracle walks the boundary against math.comb) - and
crosscheck_ready, whether the extras are enough for cross-validation.
combine and verify grow the crosscheck switch: the shares beyond the
interpolating quorum are evaluated against the polynomial the quorum
determines and never enter the interpolation; the response carries
crosschecked, consistent and suspects, a disagreeing extra closes the
verdict, and without the switch the behavior is byte-identical to
before. split takes an audit label the report carries verbatim -
1..256 bytes of printable UTF-8, never in the shares, covered by
neither the integrity label nor the fingerprint. fingerprint's
response and info carry each share's own 8-hex-digit id - the first 4
bytes of SHA-256 over the same canonical image the set id hashes -
for paper reconciliation without a collection ceremony. kdf answers
memory_hard: false and documents the Argon2id substitution beside the
field, because PBKDF2 trades time, not memory, and a response that
names its own weakness class cannot be quoted selectively.

Around them: two generated laws (the fingerprint's
order-insensitivity, subset-distinctness and per-share distinctness;
the rotation's recovery on fresh quorums, strided quorums and the old
generation), eighteen new malformed-input refusals (96 pinned, the
count in usage.md moving with the code), and a diagnose bench at the
enumeration ceiling - C(12, 6) = 924 subsets, one corrupted payload -
with the baseline entry written deliberately beside it. The
host-check push's exclude pattern had never matched anything: rsync
matches patterns against paths inside the transfer, so the pinned
answers traveled like every other file and one push clobbered the
engine's fresh re-pin with a local stale copy; the pattern is fixed,
and the trap joins CONTRIBUTING's rsync list. boundaries.md carries
the honesty lines for all of it. 53 test declarations, 14 fixture
cases, 14 pinned examples, 96 pinned refusals, 121 refusal messages.

## 0.6.1 — 2026-11-14

The documentation-and-discipline release; no engine code changed, so
every pin from 0.6.0 still holds.

docs/api.md is the machine-facing API reference: the two boundaries,
the types, the share object, one section per operation with the
request fields, defaults, bounds and response shape, the exported
field helpers and GF(256) interpolation surface, and the error
contract with both of its pins named. docs/threat-model.md is the
attack-side companion of security.md - the assets ranked, then seven
adversaries (the custodian below the threshold, the corruptor, the
forger, the low-entropy enumerator, the seed thief, the transcription
error, the commitment confuser), each with what stops it, what does
not, and which operation demonstrates it.

examples/threat-demo.json makes the seed-thief adversary executable:
its request is split.json's, byte for byte, seed included, and its
pinned answer is therefore split.expected.json byte for byte - the
reproducibility that makes the scheme auditable is the same fact that
makes the seed exactly as sensitive as the secret.

Around them: the README opens with the CI and license badges;
.gitignore closes the whitelist's in-tree gap (.DS_Store, *.pyc,
*.tmp inside the whitelisted directories would otherwise be
trackable); CONTRIBUTING gains the rsync traps as a list - every
line an incident, including the one where a misaimed `--delete` pull
emptied the working tree down to its ignored artifacts; VERSIONING.md
states what a version means here (observable change is surface, so
response fields and refusal texts are minor events, never patches),
the three files that move together, the gates, the tags, and the
publish-from-the-host rule; and scripts/stats.py reads the module
version from moon.mod and stamps the snapshot date at write time, so
the stats table can no longer disagree with the release it
documents. 14 pinned examples.

## 0.6.0 — 2026-11-13

Two operations for the questions around recovery, one constructor -
and a ladder that had learned to fail green.

sort puts a share list in canonical order: by x coordinate, payloads
re-encoded in one encoding of the caller's choosing (hex by default),
the one-split agreement demanded with the same refusals by name, and
nothing interpolated - a shuffled mixed-encoding pile becomes a
storage-ready list, and a set below the threshold sorts as happily as
a quorum. check counts a set against its threshold and answers the
gap - how many shares short - and ready, with the same agreement and
no recovery, so "how far is the quorum" is askable below combine's
refusal; a single share is a valid question. split_with_defaults(
secret_hex, k, n) is the one-call constructor for the common shape,
every optional field at its documented default, and its doc comment
says plainly what seed 0 is worth. The engine's three inline
copy-and-sort blocks collapsed into shares_sorted, and the new
operations' agreement checks into shares_agreeing.

The bug this release nearly shipped with: the ladder's surface and
cli-tool steps were && chains, and under set -e a failing command
inside an AND list never exits the shell - a drifted api.golden
skipped its echo and the ladder ran green. The toolchain pin to
0.1.20261104 had changed moon info's rendering, so the golden had
quietly gone a format generation stale; it is refreshed, both steps
are fatal and say why, and the fix was verified red before green (a
drifted golden stops the ladder with rc=1 naming the file).

Around them: reshare and fingerprint join the benchmark ladder (and
the size baseline moves with the code that grew it), the README gains
the performance table those numbers deserve, host-check.sh runs
CONTRIBUTING's whole host loop as one command with the engine
pinning new examples' answers itself, the reshare chain joins the
pinned examples end to end, a generated property holds split_many's
position law on random parameters, the oracle cross-examines batches
under password seeds, sha256 labels, mac tags and words payloads
together, boundaries state what the new operations prove and do not,
and usage.md opens with an operations-at-a-glance table whose honest
column is interpolation. 44 test declarations, 9 CLI fixtures, 13
pinned examples, 116 refusal messages.

## 0.5.1 — 2026-11-11

The security-clarification release, answering a competition review
that was right on all three counts.

seed_hex: full-width 64-bit seeds. The numeric seed field was capped
at 53 exact bits by its JSON double carrier; seed_hex takes 8 bytes,
the seed channel is UInt64 end to end, and the response always
carries the exact hex while the numeric form is honestly null above
2^53-1. The refactor caught the password-derivation path silently
rounding through a double on its way to the same engine.

The enumeration demonstration: scripts/lowentropy-demo.py splits a
six-digit recovery code, keeps one share, and recovers the code by
enumerating 10^6 candidates against the public integrity label in
under three seconds - the threshold never mattered, because a public
label is an offline verification oracle. The README's headline claim
is now conditional (high-entropy secret, uniform full-width seed),
usage.md opens with the warning, and docs/security.md states the
whole threat model as attacks, demonstrations and a protection
matrix. Low-entropy input must be stretched first; the library ships
the kdf operation for exactly that.

## 0.5.0
## 0.5.0 — 2026-11-11

Three new operations, one real bug fixed, and the delivery machinery
hardened - on top of 0.4.0:

fingerprint folds a share set into one 16-hex-digit id (SHA-256 over
the canonical image of every share sorted by index) - "did I
transcribe these correctly" without recovering anything, with the
set-not-split semantics documented rather than implied. split_many
splits up to 64 secrets in one request, each at its own derived seed
(position i answers exactly a standalone split at seed + i, checked
position-for-position). info describes one share in hand - x,
threshold, labels, payload size, mac presence, and whether a words
checksum verifies; a failed checksum is a finding (checksum_ok
false), not a refusal.

The bug: HMAC keys longer than the 64-byte block were hashed but not
zero-padded back, so the ipad loop read past a 32-byte array - every
key over the limit aborted. Unreachable through the API (which caps
keys at 64 bytes) but the engine functions are public; RFC 4231's
case-3 vector walked the branch and caught it, and the oracle now
fuzzes the 63/64-byte edge the API does allow. All three RFC key
shapes and the PBKDF2 4096-iteration vector are pinned.

Delivery: batched interpolation exported (gf_lagrange_weights /
gf_interpolate_weighted) with the golden surface moving in the same
commit; bench and artifact-size baselines gate regressions (3x and
1.5x); refusal messages are style-audited and counted (104); the
verify ladder checks every step's exit code after a pipe bug let red
steps print green; CONTRIBUTING records the discipline the incidents
taught; and a whitelist .gitignore makes the unfiltered-add leak that
briefly shipped private files structurally impossible. The ecosystem
gap claim is re-censused: threshold secret sharing remains the only
implementation in a registry index of 23151 entries.

34 tests plus 2 bench declarations across four backends, 157 oracle
groups, 69 malformed cases, 2590 physical lines, 16 fixture checks,
9 pinned examples.

## 0.4.0
## 0.4.0 — 2026-11-09

The authenticated release. On top of 0.3.0:

HMAC-authenticated shares: split (and reshare, which inherits the tag
verbatim) accepts mac_key_hex of 1..64 bytes, and every share then
carries a mac - the first 16 hex digits of HMAC-SHA256 under that key.
Unlike the public labels, a mac cannot be forged without the key, so a
share set replaced wholesale by an attacker fails verification instead
of passing. The semantics are pinned: keyed shares without a key are
refused, a key with unkeyed shares is refused, a wrong key yields
verified false, and mac fields that disagree are refused. The oracle
authenticates with Python's hmac module across random keyed splits.

Frozen public surface: tests/api.golden holds the generated interface
file and the ladder diffs it on every run - execute and run, the Value
tree, InputError, and the SHA-256 helpers are the whole export list.
Refusal-message style audit: 90 messages held to one style, counted in
the stats table. Generated-input laws: four core-quickcheck properties
(500 cases each) beside the exhaustive ones. Boundary pinning: the
255-share full ring at threshold 255, the 16384-byte ceiling, and the
one-past-the-end refusals for password and iteration limits.

The CLI's one-line shares carry their encoding (five fields; four-part
lines stay accepted as legacy hex) and unquoted words shares reassemble
from argv. Two pinned words examples walk the paper-share path. And a
real bug the proposal audit caught is fixed: the verify script piped
every step into tail, so a failing step could not fail the run - every
step now checks its command, and the ladder's exit code means what its
last line says.

31 test declarations (29 run as tests, 2 as bench), 134 oracle groups,
61 malformed cases, 2252 physical lines. Proposal recalibrated to the
recounted source.

## 0.3.0
## 0.3.0 — 2026-11-07

Six feature waves on top of the 0.2.0 audit operations, each landed with
the full ladder green and the oracle extended to match.

Field and speed: multiplication moved to exponent/logarithm tables over
generator 3 (one add of logs per multiply), with the shift-and-reduce
multiplier kept as a witness and all 65536 input pairs held equal;
Lagrange weights are now computed once per subset instead of once per
byte, so combine, diagnose and reshare amortize their inversions across
the whole secret - a 16 KiB threshold-6 split runs in 0.23 s and
combines in 0.09 s, gated by a scale check that fails past 12 s.

Secrets and shares: secrets may arrive as UTF-8 text (with the text
echoed back when the recovered bytes decode); share payloads may travel
as hex, base64, or words - one word per byte plus a two-word checksum
over a frozen 256-word table of four-letter dictionary words ranked by
sha256, so a share survives paper. Encodings mix freely inside one set;
every share names its own.

Commitments: SHA-256 (FIPS 180-4, vectors pinned) joins CRC-32 as a
choice of integrity label; the commitment rides in every share, and a
set that mixes kinds is refused.

Reshare: from k old shares, a complete fresh split is minted without
the secret existing in memory (g = f + h, thresholds may rise but not
fall, new x coordinates avoid the old indexes); white-box and oracle
tests drive three-generation chains and pin that stale generations are
refused when honest and caught by the label when forged.

Seeds: a split or reshare can take a password instead of a numeric
seed - PBKDF2-HMAC-SHA256 (RFC 8018, vectors pinned; HMAC by RFC 4231)
with a salt and 1..1000000 iterations, first 7 bytes shifted into 53
bits - and a standalone kdf operation pins the derivation. The response
names how its seed was made.

Verification and delivery: scripts/scale.py gates the size ceilings
(16 KiB, diagnose at 12-of-6 exact enumeration, a reshare chain) with a
12-second budget; two moon bench blocks time split and combine at
1 KiB; docs/ gained design notes, a usage reference and a boundaries
statement; the CLI grew reshare and kdf verbs; and a GitHub Actions
workflow runs the four-backend matrix plus the entire evidence ladder
on every push, pinned to the 0.1.20261023 toolchain shipped as a
release asset of this repository.

22 test declarations across four backends, 120 oracle check groups, 52
malformed-input cases, 1602 physical lines of production MoonBit.

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

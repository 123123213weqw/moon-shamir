# Threat model

The attack-side companion of [security.md](security.md). Security
states guarantees; this file states adversaries - who they are, what
they want, what stops them here, and what does not. Every "stops
them" column entry names the mechanism and, where one exists, the
operation or script that demonstrates it.

## Assets

| Asset | Sensitivity | Why |
|---|---|---|
| the secret | the point | whatever was split |
| each share | secret-bearing | k-1 of them are useless alone; k of them are the secret |
| the seed (`seed`/`seed_hex`) | equal to the secret | regenerates the exact coefficient stream; with the seed, one share's label + the seed is the secret (see [security.md](security.md)) |
| the mac key | authenticator | mints valid tags for any secret; anyone holding it can rewrite a share set convincingly |
| the password | entropy source | its derived seed regenerates the split; a weak password is a weak split at any iteration count |

Anything in the top row plus one item below it in an attacker's hands
is game over for that asset - the model below is about preventing the
combinations short of that.

## Adversaries

### 1. The custodian who kept too few shares

Wants the secret with k-1 shares (or fewer).

- **Stops them:** the information-theoretic argument - every secret of
  the same length is equally likely, provided the coefficients were
  uniform (seed uniform in its full range; use `seed_hex` from a real
  random source).
- **Does not stop them:** anything about a low-entropy secret; see
  adversary 4.
- **Interface:** `combine` refuses below the threshold - there is no
  wrong-secret output to misuse. `check` answers "how far am I" for
  the honest holder without interpolating anything.

### 2. The corruptor

Flips bytes in stored or transcribed shares - bit rot, a typo, a
malicious clerk.

- **Stops them:** the integrity label riding in every share. Combine
  answers `verified: false` and the bytes are meaningless by design;
  `diagnose` names the suspects exactly, by exhaustive enumeration;
  `fingerprint` catches a mistyped batch before combine is attempted.
- **Does not stop them:** the label is public - the corruptor cannot
  forge a *consistent* set without the secret, but they can deny
  service (corrupted shares are detected, not repaired; reshare from
  a clean quorum is the recovery).
- **Interface:** `diagnose` for forensics, `sort`/`check`/`fingerprint`
  for the pre-flight, `reshare` to rotate after the incident.

### 3. The forger

Replaces the whole share set with one minted for a secret they chose,
hoping the swap goes unnoticed until the quorum meets.

- **Stops them:** the HMAC tag under `mac_key_hex` (0.4.0). A forged
  set carries no valid tag; `combine`/`verify` refuse it. Keyed and
  unkeyed sets never mix - both directions are refused by name, so a
  forged unkeyed share cannot hide in a keyed combine.
- **Does not stop them:** a holder of the mac key - the tag
  authenticates the set against everyone *but* a key holder, who can
  mint tags for any secret. The tag says nothing about who split.
- **Does not apply:** unkeyed splits. There the crc32/sha256 label is
  integrity only, and adversary 3 wins against it by construction -
  which is the documented reason to add a mac when share replacement
  is in the model.

### 4. The enumerator

Takes one share and guesses the secret offline against the public
label.

- **Stops them:** nothing, if the secret is low-entropy - this is a
  demonstrated break, not a hypothetical: `scripts/lowentropy-demo.py`
  splits a six-digit code 3-of-5, keeps one share, and recovers it in
  under three seconds. The threshold never mattered.
- **What actually stops them:** entropy. Stretch human-chosen material
  first (a KDF's 32 output bytes), split the derived bytes, keep the
  mapping on the caller's side. The seed is the same exposure: with a
  guessed seed and one share, the same enumeration works.
- **Interface:** `kdf` for the stretch; the demo to see the failure
  honestly.

### 5. The seed thief

Reads the seed but not the secret - a backup note, a shell history
line, a config dump.

- **Stops them:** nothing. The seed is exactly as sensitive as the
  secret: the same (secret, seed) pair reproduces the same shares
  bit for bit on every backend, so the thief who also has any one
  share (or the published example output) regenerates everything.
- **Demonstrated:** `examples/threat-demo.json` replays a split from
  its published seed and answers byte-identically - the reproducibility
  that makes the scheme auditable is the same fact that makes the
  seed a secret.
- **Mitigation:** treat the seed as a share of equal rank; store it
  with the same discipline; after any seed leak, reshare and destroy
  the old generation.

### 6. The transcription error

Not an adversary, but the model's most likely event: a paper share,
typed back in.

- **Stops them:** the label (`verified: false` instead of a silent
  wrong secret), the words encoding's embedded checksum
  (`checksum_ok: false` in `info`), `fingerprint` for the whole
  batch, `sort` for mixed encodings and order.
- **Residual:** any of these catches the error; none repairs it. The
  honest answer is re-transcription, checked the same way.

### 7. The commitment confuser

Mixes shares of two splits that share a secret - a crc32-labeled set
with a sha256-labeled one, a threshold-2 set with a threshold-3 one,
generation 1 with generation 2 after a reshare.

- **Stops them:** the one-split agreement every multi-share operation
  demands, refused by name: different thresholds, different splits,
  different commitments, different macs, duplicate x coordinates.
  Cross-generation mixing after a reshare interpolates garbage that
  fails the label (and with the true threshold, is refused outright).
- **Interface:** `fingerprint`/`check` answer "is this all one split"
  without interpolating.

## What is out of scope, said plainly

- No side-channel hardening is claimed: constant-time field operations
  are not pursued, and a words share's word count reveals its payload
  length on sight.
- Distribution is the caller's problem: who receives which share,
  over what channel, is outside the library's reach; the library's
  guarantee begins after the shares exist.
- Availability is nobody's goal here: the threshold exists to require
  people, and this model is entirely about stopping the wrong ones.
  Fewer than k consistent shares is a locked door by design.

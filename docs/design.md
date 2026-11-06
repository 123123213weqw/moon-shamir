# Design notes

These notes record how the pieces fit and why the shapes are what they
are. Every claim here is enforced somewhere in the ladder; where a note
describes a boundary, boundaries.md says it again in the shorter voice.

## 1. One field, two constructions

All arithmetic lives in GF(2^8) with the AES reduction polynomial 0x11B.
Bytes ride as Int32 in 0..255; subtraction is addition is XOR, which is
the whole reason the Lagrange weights lose their minus signs: the weight
of point i toward target a is the product of (a XOR x_j) times the
inverse of (x_i XOR x_j) over every j other than i.

The field is built twice on purpose. The production multiplier is a pair
of exponent/logarithm tables over generator 3 (order 255), built in an
init block - a multiply is one integer add plus a table read. The
witness multiplier is the classic shift-and-reduce loop. A white-box
test holds the two equal on all 65536 input pairs and checks the
generator's order; the oracle is a third construction (tables built by
yet another code path in Python). A bug would have to survive all three
agreeing.

## 2. Splitting: one polynomial per byte

Each byte of the secret is the constant term of its own random
polynomial of degree threshold-1. Share x is the list of evaluations of
every polynomial at x. That per-byte independence is what keeps the
code small - split, combine, diagnose and reshare are the same three
loops with different interpolation targets - and what makes the batched
weights profitable: the weights depend only on the x coordinates, so
one weight set serves every byte of the secret.

The coefficient stream is SplitMix64 seeded by the caller. Entropy is
injected, never read - the same discipline as time in the limiter
family this project belongs to - and it is what makes every oracle
check possible at all: the oracle redraws the exact same coefficients
from its own independent SplitMix64 and compares share for share.

## 3. Recovery, refusal and the closed door

Combine sorts the share set by x and interpolates from the lowest
threshold coordinates - a deterministic choice, so the same input set
answers the same output every backend. Below the threshold the operation
refuses outright. This is deliberate: an implementation that returns
"the best guess" below threshold hands the caller garbage that looks
like a secret. Here there is no such output to misuse; the refusal names
the missing count.

## 4. The integrity label and its honest limits

Every share carries an 8-hex-digit label of the secret: the first 32
bits of CRC-32 (default) or of SHA-256 (when the split asked for the
stronger name). The label catches corrupted shares and foreign shares -
and diagnose uses it as a quorum oracle to name precisely which shares
disagree with every consistent subset. It is not a MAC and says so
everywhere it appears: anyone can recompute either label for any
candidate secret. The secrecy argument is information-theoretic and
rests on nothing else.

Commitments are part of a share's identity. A set that mixes crc32
labeled with sha256 labeled shares is refused even when both label the
same secret - two label kinds are two splits for recovery purposes,
and a refusal is cheaper than a wrong verdict.

## 5. Diagnose: quorum search as an oracle problem

Diagnose enumerates every k-sized subset of at most 12 shares of
threshold at most 6 (C(12,6) = 924 interpolations, each now amortized
across the secret by the batched weights), keeps the subsets whose
recovered bytes carry the label, and reports:
- consistent - at least one subset verifies;
- good - the shares that appear in at least one consistent subset;
- suspects - the shares that appear in none.
A corrupted share disagrees with every quorum, so it is identified, not
merely suspected. The bounds keep the enumeration exact rather than
heuristic; larger sets are refused by name.

## 6. Reshare: the secret never exists

Lagrange interpolation is generalized from recovery at zero to
evaluation at any point; zero is just the at=0 case, which is why
combine's arithmetic is untouched by the generalization. Reshare draws
a fresh random polynomial h per byte with h(0)=0 from the caller's new
seed and defines g = f + h, where f is the old polynomial implied by
the input shares. Each new share is g evaluated at a fresh x:
- g(0) = f(0) = the secret byte - the split protects the same secret;
- any threshold old shares determine f, hence g, at every new x;
- no threshold of old shares plus new shares reveals anything extra.
The threshold may rise (the degree grows) but never fall, or g would
silently stay at the old degree. New x coordinates are the smallest
values no input share occupies, so a reshare can mint more shares than
it started from without aliasing an old x. Old and new shares sit on
different polynomials; mixing them is refused (thresholds disagree) or
fails the label (same threshold) - which is the proactive-security
point: after a reshare, destroy the old shares and the compromise
window closes.

## 7. Seeds people can actually keep

A split's entropy is its seed. The raw form is a whole number up to
2^53-1 (the last integer a JSON double carries exactly). The humane
form is a password: PBKDF2-HMAC-SHA256 with a salt (default: the
library's own 8-byte constant) and 10000 iterations (1..1000000),
taking the first 7 bytes of the 32-byte output and shifting down 3
bits into the 53-bit range. HMAC and PBKDF2 are pinned by their RFC
vectors; the oracle derives with Python's hashlib and demands the
password split equal the same-seed split share for share. The stretch
is a real cost barrier; the entropy still comes from the password, and
the README says so in the same breath.

## 8. Encodings are appearances

A share's bytes may appear as hex (default), base64, or words - one
word per byte plus a two-word checksum over a frozen 256-word table of
four-letter dictionary words ranked by sha256. The layout is
positional: word 1 the index, word 2 the threshold, payload, then the
two checksum words; decoding refuses by position and cross-checks the
index and threshold fields the share object also carries. Hex and
base64 shares mix freely in one set; the encoder never guesses, every
share names its own encoding.

## 9. What the oracle checks

scripts/reference.py rebuilds the scheme from different construction
paths - GF(256) tables by a third code path, SplitMix64 in Python,
hashlib for the KDF and the sha256 label, base64 and UTF-8 from the
standard library - and then demands share-for-share agreement on random
splits, all k-subsets (sampled when numerous), injected-corruption
diagnoses, reshares minted independently, password derivations, seed
sensitivity, and the refusal paths. If the engine and the oracle agree,
the disagreement would have to be in code that both got wrong the same
way; the constructions are different enough that this is the honest
cross-check available to a single author.

# Third-party notices and attribution

## Dependencies

This package depends on moonbitlang/core only (the standard library):
its `@json`, `@debug`, `@bench`, `@quickcheck`, `@encoding.utf8` and
`@encoding.base64` packages. No other registry module is imported.

## Code ported from the author's own repository

sha256.mbt - the SHA-256 compression function over whole blocks with a
reusable schedule - is ported from the author's moon-snapvault
(https://github.com/yyqdbngt/moon-snapvault), where it was originally
written for that project and cross-checked against the published
gmlewis/sha256 package plus the FIPS 180-4 vectors. The port adapts the
byte representation to this library's Array[Int32] shape and pins the
FIPS vectors again here; see the commit that introduced it for the
exact provenance. The author is the same person; the notice exists so
the file's history is findable from both repositories.

## Standards and algorithms implemented from public specifications

- Shamir threshold secret sharing (Shamir 1979; Blakley 1979
  independently) over GF(2^8) with the AES reduction polynomial
  0x11B (FIPS 197).
- HMAC (RFC 2104) and PBKDF2 with HMAC-SHA256 (RFC 8018), implemented
  from the RFC texts; test vectors from RFC 4231 and the standard
  PBKDF2-SHA256 vectors.
- CRC-32, the reflected 0xEDB88320 form.
- SplitMix64 (Steele, 2014) as the seeded, non-cryptographic
  coefficient stream.
- The word-table idea of paper-friendly share encodings follows
  SLIP-39's approach; the 256-word table here is this project's own -
  four-letter words from the system dictionary ranked by sha256(word)
  ascending, first 256 taken, frozen in moonwords.mbt. No SLIP-39
  wordlist or code is included.

## AI assistance

Parts of the code, tests, documentation and commit messages were
written with AI programming assistance (the full session history is in
the repository's commit record). All algorithms follow the published
specifications above; the AI tooling did not introduce any third-party
code.

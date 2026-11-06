# Examples

Every example is executed by `scripts/check.mjs` on every verify run and
compared against its pinned answer in `expected/` - an example cannot
quietly stop being true.

| File | Shows |
|---|---|
| split.json | A 16-byte secret split 3-of-5 with a fixed seed; the share list, digest label and seed in the report. |
| combine.json | Shares 1, 3 and 5 of that split recovering the exact hex secret, verified. |
| diagnose.json | Five shares with one corrupted payload; the quorum search names the suspect and still recovers the secret. |
| words-split.json | The same machinery with `share_encoding: "words"` - shares printed as word sequences that survive paper. |
| words-combine.json | Words shares 1 and 3 recovering the secret through the positional decode and its checksum. |

Reproduce any of them by hand:

```sh
moon build --target js
node _build/js/debug/build/cmd/main/main.js examples/split.json
```

or with the friendlier CLI:

```sh
node scripts/shamir.mjs split a1b2c3d4e5f60718 2 3 20261107 words
```

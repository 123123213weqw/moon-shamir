# Versioning and release policy

How this module earns a version number, what moves when, and what a
release mechanically is. The rules exist because every one of them was
once missed; the ladder and CI now catch the misses.

## What a version means

The module follows semver with a 0.x maturity rule: while the major is
0, the minor carries both features and honest breakage, and the patch
is reserved for fixes that make no new claims.

- **MAJOR (unused while 0.x):** removal or remeaning of public surface
  in `pkg.generated.mbti`.
- **MINOR:** anything observable added or changed. New operations, new
  request fields, new response fields, a refusal that previously
  passed now refusing (or naming itself differently) - a caller can
  observe all of these, so none of them is a patch. The api golden in
  `tests/api.golden` moving is a MINOR event by definition.
- **PATCH:** a fix to something the project itself declared wrong -
  a wrong answer, a crash, a ladder that could run green past a
  failure. Where the fix changes observable output, the changelog
  says so in one sentence; the pinning tests are updated in the same
  commit.

The reasoning: this library's contract is its request/response shapes
and its refusal messages, pinned twice (fixtures and the message
audit). Anything a caller can diff is API surface, whatever the type
system sees.

## The three files that move together

A release is one commit that touches all of:

1. `moon.mod` - `version` is the published identity, on mooncakes and
   in every downstream `moon add`.
2. `CHANGELOG.md` - a section at the top named for the version, prose
   not bullet fragments, saying what changed and why.
3. `PROJECT_STATS.md` - written by `scripts/stats.py --write` on the
   verification host after `moon fmt`; the script reads the version
   from `moon.mod`, so the table cannot disagree with the release.

`moon fmt` before the stats write, the stats write before the ladder -
the order CONTRIBUTING pins, because fmt moves the line counts the
table records.

## The gates

A release commit is pushed only after `scripts/verify.sh` runs green
on the verification host, and CI runs the same ladder on every push.
The ladder includes the fixtures, the pinned examples, the oracle
cross-examination, the malformed-input sweep, both baselines (bench
and size, each moved only by an explicit `--write` with its reason in
the commit message), the message style audit, the api-golden surface
check and `moon fmt --check`. A red main is never left behind.

## Tags and artifacts

Every release version gets a git tag named for it (`v0.7.0`) and a
GitHub release whose notes are the changelog section. The toolchain is
its own pinned asset (`toolchain-0.1.20261104`), referenced by CI and
the docs; bumping it is its own commit with its own ladder run, never
folded into a release.

## Publishing to mooncakes

The publish runs from the verification host, where the ladder just
went green: `moon publish` ships the tree whose `moon.mod` names the
version. The host is the publishing machine because it is the only
place the full ladder runs against the exact tree being shipped - the
rule "release what you verified" applied mechanically. A failed
publish is fixed and re-run from a green ladder, never by hand-editing
the published tree.

## Emergency moves

A red main after a release commit: the next commit fixes it forward.
A published version that must not be used: publish a patch above it
and mark the bad version in the changelog - mooncakes has no unpublish,
so the correction is always a new version, and the changelog is where
the warning lives.

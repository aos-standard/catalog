# Addendum — vectors 29 and 30 (`accuracy`), corpus `2d8fac7`: v13 unchanged, 30/30; a cold reading on the two new vectors

**Date:** 2026-10-20 (JST morning). **Why:** after `ADDENDUM-profile13.md` (v13 at `270e9fe`, 28/28), Trilatic added vectors 29 and
30 at `2d8fac7` — the first whose RFC 3161 tokens state an `accuracy` — and reported (tsc#4, 2026-10-19T15:05Z) that
`war_cold_verifier_v13.py` at catalog `e691785` agrees on all 30. This addendum is our own run of the same thing.

| | |
|---|---|
| Verifier | `war_cold_verifier_v13.py` sha256 `c1e302620e50a906f411f5344b6e71d12bf2accaf9376aa6b067f248b87b5b91` — unchanged since `FROZEN_V13.txt` (2026-10-19 00:5x UTC), which predates `2d8fac7` |
| Corpus | tarball of `maximusrufus/work-acceptance-record@2d8fac7`, `vectors/` 30 files; 01–28 byte-identical to `270e9fe` (checked with `cmp`) |
| Result | **30/30** (`run_v13_2d8fac7.json`). 29 `criteria-token-accuracy-flips-commitment`: criteria token 30 s before the check with a stated accuracy of 60 s → `criteria_committed_before_check: no`, `CRITERIA_COMMITTED_AFTER_CHECK`. 30 `…-millis-still-before`: same timing at 500 ms → `yes`, no code |

On 29 and 30 this is a **cold reading**: v13's `accuracy` handling (criteria token at genTime + accuracy, record token at
genTime − accuracy, `ordering` ignored) was written from the 1.3 text on 2026-10-19 and recorded in `ADDENDUM-profile13.md`
as "implemented, unexercised" before any vector carried an `accuracy`. The two vectors now exercise it, and the reading
held without a change. The other two clean-room verifiers reported 29/30 → 30/30 after a fix (babyblueviper1) and 30/30
unchanged (robertolocatelli81-dev); 28–30 came from the latter's questions, so agreement on them is not independent
evidence of the rule, only of the three readings.

Files: `run_v13_2d8fac7.json` (sha256 in `FROZEN_2D8FAC7.txt`). Nothing else changed.

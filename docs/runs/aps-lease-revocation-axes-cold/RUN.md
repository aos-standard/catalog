# APS `lease-revocation-axes` revision 2 — clean-room model, Mode B run against PR #180

**Date:** 2026-10-24 (JST morning). **Target:** `fixtures/lease-revocation-axes/` of
Agent-Authority-Conformance/aps-conformance-suite PR #180, head `b745d252191e89fe123e33411f124a1b67542c2a`.
`revision-2/vectors.json` sha256 `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8`,
`revision-2/oracle-checkpoints.json` `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea`,
`README.md` `247c9fd06148f076d38bb1380b9cacc96bbbc30a869a3792a94ab8472d55967a`,
`ORACLE.md` `45359c00c0e1c466468760fc7d90ecb3ef4b24647f63ea32c85c5c7c613ab948`.

| | |
|---|---|
| Written from | the family `README.md`, `ORACLE.md`, and the **input shape** of `revision-2/vectors.json`. Each call's `expected` block was on screen while the input shape was read, before the model was written: this is **answer-exposed**, not a blind read |
| Not opened | `harness.ts`, `verify.ts`, `generate.py`, `sdk-bridge.mjs`, `mutation.test.mjs`, the family's records, and the runner Aicent-com published |
| Language / deps | Python 3.10.12, standard library only, Linux 6.8 |
| Frozen before the first scored run | `FROZEN_FIRST_RUN.txt`: `lra_cold_model.py` `f9569cbc…efced0a1`, `run_lra.py` `61697716…e947cf79` |
| Run mode / authorship | Mode B. **author-produced** under `CONTRIBUTING.md`: this catalog wrote the alternate implementation that supplies the recomputation. It wrote none of the vectors, claim inputs, or the family's implementation |

## 1. Baseline — 176/176

`first_run_b745d25.json` (`0044c9c3…2c952`). Every call in every case, in all four profiles
(`cached_lease` / `live_standing_read` × `exclusive` / `inclusive`), on all nine scored fields: **176/176 call-profiles
match, 1584/1584 field comparisons**. The model's ledger truth equals each call's `truth` input on all 44 calls (an
input-consistency check, not a score). Per call: `PER_VECTOR.txt`.

The model's ten readings are in its docstring (R1–R10), fixed before the run. The two that the text leaves most open:
R4, a cached lease yields the original active observation (`as_of = issued_at`) while the evidence is fresh and bound;
and R5, the live mode makes one read at T only for a fresh, bound call, and no diagnostic read otherwise.

## 2. Oracle checkpoints — 11/11 non-diagnostic, 1 outside the model

`check_checkpoints.py` → `checkpoints_b745d25.json` (`66d594f7…64dc`). The twelve hand-reasoned checkpoints of
`ORACLE.md`: the eleven with `diagnostic: false` all agree. Index 5 (`LRA-04-r1`, live, exclusive, `diagnostic: true`)
expects a diagnostic status read after rejection (`revoked` at 121000). This model fixed the default path, which makes no
such read, so that checkpoint is outside what it implements; index 4, the same call without the diagnostic, agrees.

## 3. Declared defective variants — 6 of the 10 value-observable ones on the first reading, 10 of 10 on a second

Each of the twelve declared variants was written into this model from its name and the README's one-line list
("ignored or sliding expiry, fail-open status, sticky outage, retrieval as renewal, deny after dispatch, blanket denial and
first-read-only behavior", plus the four new variants), run in its declared profile, and the failed cases compared with
`expected_failed_cases`.

`lra_mutants.py` (`FROZEN_MUTANTS.txt`, frozen before its run) → `mutants_b745d25.json` (`4b9a38f1…ab23`):

| variant | result |
|---|---|
| lease-ignores-expiry, live-fail-open, deny-but-dispatch, deny-everything, second-worker-stale, ignore-evidence-binding | declared set reproduced exactly (second-worker-stale fails only LRA-08, on w2) |
| sliding-lease | declared also has LRA-04 |
| retrieval-renews-evidence | declared also has LRA-04 |
| sticky-unavailable | declared also has LRA-03, LRA-07 |
| live-first-read-only | declared also has LRA-11 |
| fabricated-live-read, selective-not-supported | fail nothing here: the README says the read audit catches them, and this model has no read audit. Not counted either way |

Nowhere did this model fail a case the declaration omits.

`lra_mutants_alt.py` (`FROZEN_ALT_POSTHOC.txt`) → `mutants_alt_b745d25.json` (`1b465d61…8b`). **Post-hoc**: written
after the table above, one alternative reading per differing variant. All four then reproduce the declared sets:

| variant | first reading | reading that matches the declaration |
|---|---|---|
| sliding-lease | a use while fresh extends the lease | the use renews the lease **before** freshness is judged, so an expired call is revived |
| retrieval-renews-evidence | a read on a fresh call extends the lease | a bound call reads whenever the source is up, the read renews, **then** freshness is judged |
| sticky-unavailable | after an outage the source stays unreachable (no observation) | after an outage the worker never re-reads and **keeps its last observation** |
| live-first-read-only | the first successful read per worker and grant is reused | the first **attempt**, even a failed one, is the only read |

So the declared sets are consistent with these vectors. Four of the one-line descriptions admit a second reading, though,
and under it a faithful implementation of the variant fails fewer cases. A third party re-deriving the variants from the
text alone cannot tell which reading the declaration fixes. One sentence per variant stating the defect's rule (as in the
right-hand column) would close that.

## 4. Not covered

- The read audit (source-read counts and timing), so `fabricated-live-read` and `selective-not-supported` are not tested here.
- Diagnostic reads (checkpoint 5 and the twenty positive diagnostic profile runs the README mentions).
- `not_supported` answers, unclaimed axes, unsupported policies, the six corpus-mutation tests, report byte stability.
- No vector is suspected defective.

## Files

`lra_cold_model.py`, `run_lra.py`, `lra_mutants.py`, `lra_mutants_alt.py`, `check_checkpoints.py`, the four result JSON
files, `PER_VECTOR.txt`, `VERBATIM.txt` (the commands and their uncut output), the three `FROZEN_*.txt`, `SHA256SUMS`.
Each script takes the upstream files as arguments and reads nothing else; run with `python3 -I`. The upstream files are not
copied here. CC0.

# Addendum, 2026-10-24 — the variant rules added at bccef3e, read cold

**This file is added beside `RUN.md` and changes nothing in it.** The files listed in `SHA256SUMS` are as at `3e882bc`.

At `bccef3e` (PR #180), the family README (sha256 `5d799f914fcd5043f64adb6b8b588675a781dcbf526f47d89db8b2be14cb1ad8`)
gives each defective variant one sentence stating the rule `harness.ts` applies. `lra_mutants_v3.py` writes each variant
from its sentence alone, without opening `harness.ts`. It was frozen before its first run (`FROZEN_V3.txt`, `750a316d…936a`)
and run against the same `revision-2/vectors.json` (`a0a07ea5…1ed8`). Output: `mutants_v3_output.txt`,
`mutants_v3_bccef3e.json`.

| variant | from the bccef3e sentence |
|---|---|
| lease-ignores-expiry, sliding-lease, live-fail-open, retrieval-renews-evidence, deny-but-dispatch, deny-everything, live-first-read-only, second-worker-stale, selective-not-supported, ignore-evidence-binding | declared set reproduced exactly |
| sticky-unavailable | fails LRA-11 only; the declaration also has LRA-03 and LRA-07 |
| fabricated-live-read | not written: the sentence says the answers are hardcoded from the call id, grant and time, without giving them |

**sticky-unavailable.** The sentence says that after a source read gets no answer, the worker "gives no observation for
every later fresh, matched call". In LRA-03 and LRA-07 the source stays down after r1, so the correct answer at every
later call is already no observation (`not_established`, deny). A variant that also gives no observation matches it
there, and cannot fail those cases. The declared set is reproduced by the post-hoc reading of `lra_mutants_alt.py`, in
which the worker keeps its last observation (r1's `active` at 0). So either the sentence or the declared set does not
describe `harness.ts`, and this run cannot tell which.

**Correction to RUN.md §3 and §4.** RUN.md counted `selective-not-supported` with `fabricated-live-read` as needing the
read audit. That was wrong, and a misreading of ours: the README at `b745d25` says this of `fabricated-live-read`
only. By its rule ("every deny becomes `not_supported`") it changes `action_decision`, and the
vectors catch it. The bccef3e sentence reproduces its declared set. Only `fabricated-live-read` is outside this model.

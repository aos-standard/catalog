# Correction, 2026-10-24 — sticky-unavailable: the mismatch in ADDENDUM-bccef3e was ours

**This file is added beside `RUN.md` and `ADDENDUM-bccef3e.md` and changes nothing in them.**

`CLARIFICATION-86e5e7a.md` (published earlier, at `84a99da`) gives the same diagnosis but still models answers only, so
it calls `sticky-unavailable` and `fabricated-live-read` only partly testable here. The rerun below adds the read count,
so that statement no longer holds. `CLARIFICATION-86e5e7a.md` stays as published.

**What was wrong.** `ADDENDUM-bccef3e.md` says of `sticky-unavailable`: "either the sentence or the declared set does not
describe `harness.ts`". That is wrong. Both describe it. Our model compared the answer fields only. Revision 2 also checks
that each live call with fresh, matched evidence makes exactly one source read (`source_read_contract` in `verify.ts`),
and our model never checked that. In LRA-03 and LRA-07 the source stays down, so `sticky-unavailable` gives the expected
answers there and fails only by skipping the read. The family's author pointed this out in #186, and `86e5e7a` (PR #180)
adds it to the README.

**Rerun.** `lra_mutants_v4.py` is `lra_mutants_v3.py` with one addition: it counts the source reads at each call, and a
case fails if a live call with fresh, matched evidence makes a number of reads other than one. That rule is taken from the
`86e5e7a` README sentences, not from `verify.ts`, which we have not opened. `fabricated-live-read` is now included: per
its sentence, its answers match the expected ones and it never reads, so it is modelled as the correct answers with zero
reads. Same `revision-2/vectors.json` (`a0a07ea5…1ed8`). Output: `mutants_v4_86e5e7a.json`.

| variant | declared set reproduced | cases failed by the read count alone |
|---|---|---|
| sticky-unavailable | yes | LRA-03, LRA-07 |
| fabricated-live-read | yes | all 11 of its declared cases |
| the other 10 | yes | none |

**What this does not establish.** This reading was written after the author told us the answer, so it is post hoc. The
read-count rule is our reading of one README sentence. A run that opens `verify.ts`, or an independent one, can check it.

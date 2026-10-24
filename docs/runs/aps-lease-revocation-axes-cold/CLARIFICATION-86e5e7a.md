# Clarification, 2026-10-24 — sticky-unavailable: ADDENDUM-bccef3e.md drew the wrong conclusion

**This file is added beside the run and changes nothing in it.** The files in `SHA256SUMS` (at `3e882bc`) and in
`SHA256SUMS-bccef3e` (at `bbf68c7`) are unchanged.

`ADDENDUM-bccef3e.md` found that `sticky-unavailable`, written from its bccef3e sentence, fails LRA-11 only, while the
declared set also has LRA-03 and LRA-07. From that it concluded that "either the sentence or the declared set does not
describe `harness.ts`". **That conclusion was wrong.** The maintainer answered in #186
(https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/186#issuecomment-6378098356). Both
the sentence and the declared set match `harness.ts`. In LRA-03 and LRA-07 the variant's answers equal the expected
ones, and it fails there only on `source_read_contract` in `verify.ts`, because each of those live calls with fresh
evidence must make one source read and the variant skips it. This model compares answers only and has no read check, so
it can catch the variant in LRA-11 alone, which is the result it gave. `86e5e7a` on #180 adds this to the README
sentences for `sticky-unavailable` and `fabricated-live-read`.

Corrected reading of `ADDENDUM-bccef3e.md`: ten of the eleven variants written from the bccef3e sentences reproduce
their declared sets. `sticky-unavailable` reproduces the part of its declared set that answers can show (LRA-11). The
rest (LRA-03, LRA-07) needs the read check, which this model does not have. That makes `sticky-unavailable` a
second variant, after `fabricated-live-read`, that this run cannot fully test. The post-hoc reading in
`lra_mutants_alt.py` (the worker keeps its last observation) reached the declared set by a different defect, not the one
`harness.ts` implements.

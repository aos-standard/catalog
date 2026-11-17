# The frozen verifier on x402 PR #4298 at `d9027a5`: 25/25

PR #4298 takes the seven proposed negative vectors of this record (`../proposed/`, sha256 `e376c64b…`) into
`specs/extensions/delivery-receipt.vectors.json`. It also changes the Appendix A.7 rule: a run is compared on the levels
it lists, which run up to and including the first level that did not pass. This is a rerun, on 2026-11-17 (UTC),
that its author asked for in x402#3758.

- `dr_cold_verifier.py` is the verifier frozen on 2026-10-18 (sha256 `006eda9f…`, `../FROZEN_V2.txt`), copied here
  unchanged.
- `run_vectors_a7.py` is `../run_vectors.py` with one change for the new A.7 rule: it compares only the levels a run
  lists (`for lv in ev["levels"]`, where it used to say `for lv in V.LEVELS`).

| | Runs | Same `path`, listed levels, `valid`, `longTermEvidence`, `reason.level` and compared codes |
| --- | ---: | ---: |
| The 14 earlier runs | 14 | 14 |
| The 11 runs of the seven contributed fixtures | 11 | 11 |
| **Total** | **25** | **25** |

The Appendix A checks (A.1–A.6) are all true, as before.

## The author's statement, checked

`check_edits.py` compares the file at `d9027a5` with the file at `e82f684` (#3783) and with `../proposed/`
(`check_edits.json`):

- Every member of the earlier file, including the 14 earlier runs, is unchanged. The only new top-level member is
  `negative`.
- The seven fixtures equal the proposed ones, apart from the `$ref` paths that now start with `/negative/fixtures/`.
- In each of the 11 runs, the only edit is that the levels after the first non-passing level are dropped. The kept
  levels and every other member are unchanged.

Appendix B of `delivery-receipt.md` at `d9027a5` credits the fixtures to Tetsuroh Hori (@Tetsurohhori).

Files: `dr_cold_verifier.py`, `run_vectors_a7.py`, `run_d9027a5.json`, `check_edits.py`, `check_edits.json`,
`upstream_pins_d9027a5.txt`, `SHA256SUMS`. MIT, as the rest of this record.

# Addendum, 2026-11-13: profile 1.4.12, vectors 01 to 130 at `b56d959`: v142.1 unchanged 114/130, v1412p 130/130

**This file sits beside the earlier addenda and changes nothing in them.** It records two runs on the vectors of
`maximusrufus/work-acceptance-record` at `b56d959` (master, 2026-11-12; the vectors last changed at `c5f49b5`):
the reader frozen for profile 1.4.2, unchanged, and a new reader moved to profile 1.4.12.

| | |
|---|---|
| Subject | vectors 01 to 130 at `b56d959`, sha256 of each in `upstream_pins_b56d959.txt` |
| Read | `README.md` at `b56d959` (the profile text, including its vector table) and the vector inputs |
| Not opened | `verifier/war_verify.py`, `verifier/check_payment.py`, `composition/`, `interop/`, `x402_capture/` |
| Environment | Ubuntu 22.04, CPython 3.10.12, `cryptography` 46.0.3 |

## Run 1: v142.1, unchanged since 2026-10-27: 114/130

`war_cold_verifier_v1421.py` with `run_vectors_v1421.py` and `tsa_check_141.py`, as frozen in `FROZEN_V1421.txt`, run
once (`run_v1421_b56d959.json`; its `readme_pin` field is a constant of the frozen runner, not the commit scored). The
16 disagreements are 95, 105, 107, 110, 112, 114 and 115 (the seven of the `v1.4.7` run, `ADDENDUM-v147-unchanged.md`)
and 116 to 118, 121 to 124, 126 and 130, which profiles 1.4.8 to 1.4.12 added. Every vector that existed at 1.4.2
still agrees.

## Run 2: v1412p, frozen before its one run: 130/130

`war_cold_verifier_v1412p.py` is v142.1 with six edits, each from the profile text, marked P1 to P6 in the file:

| Edit | Profile text | Vectors |
| --- | --- | --- |
| P1 a stated-time fraction of one to three digits | step 11, *Times* | 95 |
| P2 ASCII digits only in stated times and `genTime` | step 11, *Form of `genTime`* | (none fails without it here) |
| P3 the signature's R must be a canonical point of prime order | step 2 (1.4.8) | 116 |
| P4 `relying_party_keys`, and the point rule for the producer's key | step 12 (1.4.5, 1.4.7) | 110 to 115, 119, 120 |
| P5 a `genTime` not usable for step 5 makes the authority check `failed` | step 11, *Form of `genTime`* | 105, 107 |
| P6 step 4's closed list of unreadable criteria files | step 4 (1.4.8 to 1.4.12) | 117, 118, 121 to 130 |

Frozen at 2026-11-12T23:55:59Z (`FROZEN_V1412P.txt`), run once at 2026-11-12T23:56:06Z: **130/130**
(`run_v1412p_b56d959.json`, `.stdout`). An earlier freeze line, taken one minute before after an edit of the file's
header had failed, is kept in `FROZEN_V1412P_superseded.txt`; nothing was run under it.

Controls: two copies of vector 01 with a wrong expectation (`signature_valid` flipped; an extra `VERDICT_MISMATCH`)
both disagree, 0/2 (`controls-v1412p/`).

## Answer exposure

This run is answer-exposed, and says how:

- The README's vector table, which states each vector's outcome in words, was read before the six edits were written.
- Run 1 was scored first, so the 16 vectors v142.1 misses were known before the edits.
- The `expected` objects were not opened while editing; the runner compares them.

So 130/130 shows that the six edits, written from the profile text, reproduce the published outcomes. It does not show
that a reader written without the vector table would reach them. Run 1 is the result without exposure to vectors 91
to 130: v142.1 was frozen before any of them existed.

## Files added

`war_cold_verifier_v1412p.py`, `run_vectors_v1412p.py`, `FROZEN_V1412P.txt`, `FROZEN_V1412P_superseded.txt`,
`run_v1421_b56d959.json`, `run_v1412p_b56d959.json`, `run_v1412p_b56d959.stdout`, `controls-v1412p/`,
`upstream_pins_b56d959.txt`, `SHA256SUMS-b56d959`.
`tsa_check_141.py` is the file already in this directory. CC0.

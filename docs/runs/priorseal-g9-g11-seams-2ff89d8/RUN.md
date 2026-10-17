# G9–G11 candidate seams — a reproduction with a reader written from the 1.0.0 text

Requested in [probityai/agent-evidence-atlas#49](https://github.com/probityai/agent-evidence-atlas/issues/49#issuecomment-6231394593):
the three one-field seams stay candidates "pending a separately recorded reproduction".
This is one, with a different reader from the two already reported.

| | |
|---|---|
| Subject | `imokokok/PriorSeal@2ff89d86611257b4440232e5c2793926b3d52043` (contract 1.0.1), `examples/open-evidence-lab-exact-call-matrix-v1/` |
| Run date | 2026-10-17 (UTC 07:45–08:00) |
| Environment | Ubuntu 22.04, CPython 3.10.12 (stdlib; `cryptography` for Ed25519 only) |
| Reader | `oel_exact_call_reader.py`, sha256 `a7aa5099…33fbf8` — **unchanged since 2026-10-11**, published at [`1c261be` `docs/runs/priorseal-exact-call-matrix-v1/`](https://github.com/aos-standard/catalog/tree/1c261be/docs/runs/priorseal-exact-call-matrix-v1). Written from `INPUT-CONTRACT.md` at `d840553` (contract 1.0.0) before `reader.mjs`, `verify.mjs`, `expected.json` or `report.json` were opened; not updated to 1.0.1 |
| Variants | `run_variants.py`: copy the example directory to a scratch dir, change one field of case-00, run the reader as a subprocess. Same three changes as @piiiico's table and @ogasurfproject-jpg's run |
| Output | `variants_2ff89d8.json` (sha256 in `FROZEN.txt`) |

## Baseline at `2ff89d8`

`bound` agrees with `expected.json` on 6 / 6. Reason-code sets agree on 5 / 6: case-05 gets
`OUTSIDE_TIME_WINDOW` only, because the 1.0.0 text had no `OUTSIDE_AUTHORIZATION_WINDOW` row and
this reader was not updated. EIP-712 digest and recovered signer unchanged from the 10-11 run.

## The three variants

| Change to case-00 | this reader | for comparison: `reader.mjs` / profile (piiiico) | priorseal-reader-v0 (ogasurfproject) | piiiico's reader |
|---|---|---|---|---|
| no `executedAt`, no `observedAt` | `bound: true`, no window code | `bound: true` / `NON_COMPLIANT` | `bound: true` | (not stated) |
| `executedAt: "late"` | **no verdict**: `TypeError: '>' not supported between 'str' and 'int'` (exit 1) | `bound: true` / `COMPLIANT` | no verdict (`ValueError`) | `bound: true` |
| `chainId` as a JSON string of the same number | **`CHAIN_MISMATCH`** | `CHAIN_MISMATCH` / `CHAIN_MISMATCH` | `bound: true` | `bound: true` |

**G9 (missing time) reproduces.** A third independent reader skips both windows when there is no
time and reports bound, as `reader.mjs` does; the profile fails closed. Three readers, one answer
each way, and the text does not choose.

**G10 (non-numeric time) reproduces, in the worse form.** Like priorseal-reader-v0 before
`1bdbebc5`, this reader does not answer at all. Of four readers that have now been fed
`"late"`, two say `bound` and two crash; none refuses. That is the producer-side check the
seam asks for.

**G11 (chainId) splits the readers by contract version, not by author.** This reader returns
`CHAIN_MISMATCH`, agreeing with both shipped paths and disagreeing with the two 1.0.1 readers.
It was written from the 1.0.0 text, whose field-map row said only "strict equality". The two
readers that report bound followed the 1.0.1 paragraph "Comparison semantics (made explicit in
1.0.1)", which says a JSON integer participates through its canonical decimal string.
So the seam was introduced by that paragraph: under the 1.0.0 text a cold reader reached the
shipped answer; under 1.0.1, two did not.

This variant was also already on record before 1.0.1. The 10-11 run's probe table (row 7,
`chainId` as a JSON string) has all three paths — this reader, `reader.mjs` and the profile —
returning `CHAIN_MISMATCH`, at `1c261be`. Rows 2–3 of the same table (`nonce` and `nativeValue`
as JSON numbers, where the shipped paths compare after `String()`) are what the 1.0.1 paragraph
was written to state. The paragraph generalised from those two fields to all of them; the chainId
comparison in the shipped code is not after `String()`.

## What this does and does not show

- It is a reproduction of three probes with a reader of an older text, not a new reader of
  1.0.1. It does not implement `OUTSIDE_AUTHORIZATION_WINDOW`.
- It does not open `reader.mjs` or the profile for this run; the two shipped-path columns above
  are quoted from @piiiico's table, not re-run here.
- It cannot say which chainId rule is right; it says which text produced which answer.
- The reader was answer-exposed for case-04 and case-05 by 10-11 (both were posted in the thread
  before it was written).

## Files

`run_variants.py`, `variants_2ff89d8.json`, `FROZEN.txt` (sha256 of both and of the reader).

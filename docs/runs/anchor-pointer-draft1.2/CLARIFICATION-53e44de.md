# Clarification, 2026-10-29 — on which results `proof_heights` is returned

**Added beside draft 1.2 (`53e44de`); nothing there is changed.** The README lists `proof_heights` under
`anchored` only, and AP-29 expects it on `root_mismatch`. @aeoess asked which results carry it
(aeoess/agent-governance-vocabulary#217, comment 6475609825) after running their updated reader
([`ots-anchor-reader` at `2ae5fa4`](https://github.com/aeoess/ots-anchor-reader/commit/2ae5fa4b57c366dce05089a85756fe3a00b87862))
on the 31 vectors: 31/31, and still 28/28 on draft 1.1.

**Rule.** For the `opentimestamps` mechanism, `proof_heights` (every Bitcoin height the proof names, sorted, each once)
is returned on every result from step 11 on: `height_not_in_proof`, `header_unavailable`, `root_mismatch` and
`anchored`. It is not returned on `pending` (the proof names no Bitcoin height) or on any earlier result. That is what
the draft 1.2 reader does on all 31 vectors (`run.json`), and what the second reader does.

**Vectors.** Only AP-29 pins it outside `anchored`. AP-11 (`height_not_in_proof`), AP-12 (`header_unavailable`),
AP-13, AP-14 and AP-26 (`root_mismatch`) carry it in the reader's output but their `expected` names the result only;
a later draft would pin it there. A reader may assert it on those vectors as its own reading, as the second reader's
`supplemental.json` does.

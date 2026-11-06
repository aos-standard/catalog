# ACP dispute_resolution, PR #316 at `94a71e9`: the ddc2871 cases laid out for the extension's own repository

The [`ddc2871/`](../ddc2871/) record scored 35/35. This directory lays 33 of those cases out as files the ACP
repository could hold, and checks them with the repository's own validation approach. No reader was changed or run here.

## What changed upstream since ddc2871

PR #316 moved to `94a71e9` (2026-11-03). That commit adds only Section 7.4a requirement 6 (delivery receipts), with a
checklist line and a changelog line. The schema and the examples file are byte-identical to `ddc2871`. The cases use
Sections 4.4, 4.4a, 4.5, 7.2 to 7.5 and 7.7, which did not change. So the 35/35 at `ddc2871` carries over by
construction, not by a new run.

## What is here

| Path | What |
| --- | --- |
| `for-acp/examples/unreleased/dispute_resolution/conformance_cases.json` | 33 cases: each `input` (a `DisputeRecord`, and a `DisputeDetermination` for the determination checks) and `expect` |
| `for-acp/examples/unreleased/dispute_resolution/README.md` | the fields, the readings and the source, for that repository's readers |
| `for-acp/scripts/validate_conformance_fn.js` | a function for `scripts/validate-consistency.js`: every record must validate as `DisputeRecord`, every determination as `DisputeDetermination` unless the case expects it rejected |
| `tools/make_conformance_cases.py` | builds the cases file from `../ddc2871/` (rebuilding gives the same bytes) |
| `tools/schema_check.py`, `runs/schema_check_94a71e9.json` | all 35 inputs checked with Python jsonschema 4.25.1 |
| `tools/harness.js`, `runs/validator_94a71e9.txt` | the function above, run alone with ajv 8.20.0 and ajv-formats 3.0.1 configured as `validate-consistency.js` configures them |
| `upstream_pins_94a71e9.txt` | what was fetched and read |

## Selection and changes

- **Left out:** U1 and U2. They are the example pairs as published at `db04871` and `089d8f9`, and the example was
  later fixed. What they test is covered by E4 (`line_amount_missing`) and E6 (`opened_at`). U3, the example as
  published at `ddc2871`, is kept.
- **Inputs and expectations** are copied as they are. Parenthetical comparisons with older readers or older text are
  removed from notes. The case-set field `spec_open` is dropped.
- **`readings_stated`:** the eight cases that `ddc2871/` marked as depending on a reading (D4d, D8, D8b, D8c, D8d, E1,
  E2, E7) are each stated in the text at `94a71e9`. Approval binding is in Section 4.4a, the intent finding in
  Section 7.4 rule 4, and allocation and the unfulfilled share in Section 7.4 rules 1 and 3. The adjustment types for
  rule 3 are in Section 7.4 rule 3. That is this author's reading of the text, for the RFC author to confirm.

## Results

- Python jsonschema: all 35 `DisputeRecord` inputs are valid. Of the determinations, E5, E6 and T3 are invalid on
  purpose: their cases expect the determination rejected. U1 is invalid too, and it is left out.
- The validator function on the 33 cases: 0 errors. On a copy with one record missing `claim`, T0's determination
  missing `seal` and a duplicated id, it reports all three. That check was run in the working directory and is not
  stored here.

## Limits

The schema check shows the inputs have the right shape. It does not check any decision. The expectations are this
author's, written from the text and scored by this author's reader (`ddc2871/`). Contributing to the ACP repository
requires its CLA, so these files are offered as CC0 for the RFC author to copy if wanted. CC0.

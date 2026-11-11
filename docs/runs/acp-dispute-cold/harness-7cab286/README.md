# A harness for the dispute_resolution conformance cases (ACP PR #316 at `7cab286`)

`scripts/run_dispute_conformance.js` runs `examples/unreleased/dispute_resolution/conformance_cases.json` against any
implementation. It holds no reference implementation and decides nothing itself.

- The implementation is a command named in `DISPUTE_PROVIDER_CMD`. For each case the harness writes the case's `input`
  to the command's stdin as one JSON object and reads one JSON object from its stdout.
- Only the keys that the case's `expect` names are compared, by deep equality (object key order ignored). Other keys
  in the output are ignored, so a provider may print more than the cases ask for.
- It prints one line per disagreeing case and `N of 33 cases agree`, and exits 0 only when all agree. `--json` gives the
  rows as JSON.
- Node standard library only, so it can sit beside `validate-consistency.js` without a new dependency.

```
DISPUTE_PROVIDER_CMD="python3 my_provider.py" node scripts/run_dispute_conformance.js [path/to/conformance_cases.json]
```

## Two runs, to show what it separates

`runs/conformance_cases_7cab286.json` is the file in the SEP branch at `7cab286`, byte for byte
(sha256 `284db2ec…`). The provider in both runs is `adapter/cold_reader_provider.py`, which wraps one of the two
readers from the cold read in `../` and prints `eligible`, `not_eligible`, `approval_bound`, `per_line`, and
`det_ok` / `det_problems` when the input has a determination.

| Reader | Written against | Result | Disagrees on |
| --- | --- | --- | --- |
| `readers/acp_dispute_check_089d8f9.py` (sha256 `b519d178…`, frozen, unchanged) | the RFC at `089d8f9` | **33 of 33** | none |
| `readers/acp_dispute_check_db04871.py` (sha256 `2a5f878e…`, frozen, unchanged) | the RFC at `db04871` | **27 of 33** | E1, E2, E4, E5, E6, E7 |

The six are the cases written for the text added at `089d8f9`: which adjustment types count under Section 7.4 rule 3
(E1, E2, E7), `line_amount_missing` (E4), all five factors (E5) and `opened_at` on the determination (E6). An
implementation that follows the older text fails exactly the cases tied to the sentences that changed, and passes the
rest. Run files: `runs/run_reader_089d8f9.json`, `runs/run_reader_db04871.json`.

Negative controls, run once and not kept as files: a provider that prints the same fixed decision for every case gets
0 of 33; a command that exits non-zero gets 0 of 33, each row reporting the exit code; one that prints text that is not
JSON gets 0 of 33.

## What these runs do not show

The case expectations and both readers have the same author. 33 of 33 shows that the harness reproduces the
cold-read result through a process boundary, not that the expectations are right. Whether they are right needs an
implementation written by someone else.

## Files

| File | What |
| --- | --- |
| `scripts/run_dispute_conformance.js` | the harness (CC0) |
| `adapter/cold_reader_provider.py` | the provider used here: reader file as the first argument |
| `readers/` | copies of the two frozen readers from `../db04871` (top level) and `../089d8f9/` |
| `runs/` | the case file at `7cab286` and the two run files |

To rerun:
`DISPUTE_PROVIDER_CMD="python3 -I -B adapter/cold_reader_provider.py readers/acp_dispute_check_089d8f9.py" node scripts/run_dispute_conformance.js runs/conformance_cases_7cab286.json`

CC0.

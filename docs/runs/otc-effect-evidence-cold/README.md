# autonomous-ot-control, federation fixtures `v2` — a cold reader for the `effect_evidence` boundary: 12/12, 10/10; and a 21-mutant battery with 11 survivors

**Date:** 2026-10-28. CC0 for the files here. Asked for in aeoess/agent-governance-vocabulary#177
(comment 6452081809: "you asked for fixtures to run cold"). Answer-exposed, see below.

## Inputs, pinned

darklordVirtual/autonomous-ot-control at `3b7b7e8` (`upstream_pins.txt`). The reader was written from
`docs/federation/README.md` (the six claims, the two digest rules, "The fixtures"),
`contracts/federation-case-v1.schema.json`, `contracts/edge-result-v1.schema.json` and the 22 case files.
`federation/edges/_template/adapter.py` (the reference verifier) and `runner/` (the scorer) were not
fetched; the checkout was sparse and did not include them. Before scoring, the reader recomputes every
per-file SHA-256 and the package digest of the set and stops if either differs.

**Answer-exposed.** The manifest's `expected_verdict` per case, and a field-by-field diff of every negative
against its positive, were read before the reader was written. So 12/12 and 10/10 show that a reader can be
written from the text to agree with the manifest, not that a stranger's reader would.

The fixture files are not copied here (their licence is not yet decided, README / SDD D-01); the pins above
and `result_*.json` (case ids, verdicts, reasons, `fixtures_sha256`) are what is published.

## Runs

| file | what | result |
|---|---|---|
| `result_v2_3b7b7e8.json`, `run_v2_3b7b7e8.txt` | the reader on `v2` (22 cases), compared with the manifest by `compare_to_manifest.py` | 12/12 established, 10/10 negatives caught; `claim_id` equals the manifest's claim on 10/10 |
| `result_v1_3b7b7e8.json`, `run_v1_3b7b7e8.txt` | the same reader, unchanged, on `v1` (18 cases) | 12/12, 6/6; `claim_id` 6/6 |
| `lax_battery_v2.txt`, `lax_battery_v1.txt` | 21 mutants of the frozen reader, each dropping or bending one check, over `v2` and `v1` | `v2`: 10 caught, 11 survivors. `v1`: 6 caught, 15 survivors |

`FROZEN.txt`: the reader (`90031452020ad9ae1c4a6b0f6c7ec7b7fd8471f6201bb1039f95d1350afc0cd6`) was frozen before its first run and is unchanged.
The comparison is this catalog's own (`compare_to_manifest.py`); the testbed's scorer was not run, so there
is no `run-record.json` and no derived independence level here. The battery script went through four
versions before one ran correctly (two crashed on a non-unique anchor; the third let two mutants raise
instead of assuming a value); each is kept and hashed in `FROZEN.txt`, and the reader did not change.

## Readings fixed where the text leaves room

1. `decision_correspondence`: when `execution.executed` is true, `decision.approved` must be true and the
   decision must be `accept`, or `verify`/`escalate` with `reviewer.approved` true; and the envelope's
   `request.request_id` and the evidence's `proposal.proposal_id`, where present, must be the claim's
   `proposal_id` ("bound to the proposal"). When `executed` is false and the twin recorded `APPLIED` or an
   observation exists, the trail disagrees with itself: CONTRADICTED under this claim (the schema's own
   words on `execution`; the manifest files `denied_but_applied` under this claim).
2. A case verdict is CONTRADICTED if any claim is, else NOT_ESTABLISHED if any claim is, else ESTABLISHED;
   `claim_id` names the first such claim in the README's order.
3. `observation_after_dispatch`: observed equal to dispatched is "at or after" and establishes (all twelve
   positives have the two equal).
4. A case not of the schema's shape is NOT_ESTABLISHED with reason `malformed`, never ESTABLISHED, and the
   reader does not raise on it.

## What the sealed set does not exercise (the 11 survivors on `v2`)

A survivor is a reader missing one check that still agrees with the manifest on every case. The README's
`corpus_adequacy` boundary asks for mutations of the *reference* verifier; this is the same question put to
a second implementation, so it says what a seeded fault would have to look like, not what the reference does.

| mutant | what the set would need to catch it |
|---|---|
| M02 ignore `reviewer.approved` on verify/escalate | a negative with `decision.approved` true and `reviewer.approved` false (`executed_without_approval` flips only `decision.approved`) |
| M03, M03b ignore the envelope's `request_id` / the evidence's `proposal_id` | a negative whose envelope or evidence names another proposal (`proposal_swapped` swaps only the twin record) |
| M08 ignore twin `status` | a negative whose twin record is not `APPLIED` while `executed` is true |
| M09 ignore twin `zone_id` | a negative whose twin record names another zone |
| M10 check only the observation, M11 check only the twin | `effect_value_not_reached` changes the *claim's* value, so twin and observation both disagree at once; a negative where the twin applied the claimed value but the observation shows another (or the reverse) would separate the two checks |
| M12 null observation counts as observed | a negative with `observation: null` (the schema says NOT_ESTABLISHED) |
| M17 digest with `ensure_ascii=True`, M18 digest without `sort_keys` | no `remora_evidence` in the 22 files contains a non-ASCII character, and every one is already key-sorted on disk, so two of the three parts of the digest rule are not tested; one case with a non-ASCII string and unsorted keys would test both |
| M20 malformed case answered ESTABLISHED | a case that is not of the schema's shape |

Caught on `v2` and not on `v1` (the four v2 faults doing their work): M04 (`denied_but_applied`), M05
(`execution_count_missing`), M13 (`dispatch_time_missing`), M14 (`observation_time_missing`).
Two mutants are stricter than the text and refuse positives: M15 (strict "after") and M19 (default JSON
separators), 12 false refusals each.

## Not covered

The testbed's runner and scorer were not run (no run record, no level); submitting a record there is a pull
request and a consent record under its rules, and is not done by this directory. Nothing live: no REMORA
server, no plant, no network. The seventh claim (`evidence_existence_witness`, testbed issue 26) is outside
these fixtures. The reference verifier was not opened, so nothing here says what it does or does not check.

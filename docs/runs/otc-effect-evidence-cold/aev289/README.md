# The 21 mutants over agent-evidence-vectors' 42 building-control cases (PR #289, `38ed52b`)

A reply to the question in aeoess/agent-governance-vocabulary#177: which of the 21 mutants of the frozen reader
in [`../`](../) still survive on the 42 cases of `agent-evidence-vectors` `ot_federation/corpus/cases.json`
(the corpus `agent-evidence-vectors==0.29.3` ships; same bytes, see `upstream_pins_38ed52b.txt`).

The reader (`otc_effect_evidence_cold.py`, sha256 `90031452…`) and the mutation list (`lax_battery.py` v4,
sha256 `f4193f42…`) are the frozen ones from the record above, unchanged. Only the loader is new
(`battery_on_aev289.py`): the corpus is one JSON file with each trail under `case` and its frozen answer under
`expected` (verdict and six claims), not an `ot-federation-fixtures/v1` directory. The package was not
installed and its reader and runner were not opened.

## Result

| What | Result | File |
| --- | --- | --- |
| Frozen reader over the 42 cases, verdict | agrees on 39/42 | `run_38ed52b.txt`, `run_38ed52b.json` |
| Frozen reader, the six claims (38 cases give them) | agrees on 33/38 | same |
| 21 mutants, judged on the case verdict against the corpus, on the 39 cases where the frozen reader agrees | 20 caught; 1 survivor (M12); M14 raises on one case | same |
| The same, judged on the six claims | 21 caught (M12 by `observation_null`) | same |

### The three cases where the frozen reader itself disagrees with the corpus

The battery compares each mutant with the corpus's frozen answer, so on a case where the frozen reader already
disagrees, every mutant "disagrees" too and that case says nothing about the mutant. The table above excludes
those three (`reviewer_absent`, `twin_requested_other_value`, `twin_value_missing`); `run_38ed52b.txt` lists them
unfiltered.

| Case | Corpus | This reader | Where the difference comes from |
| --- | --- | --- | --- |
| `twin_value_missing` (`new_setpoint_c` absent from the twin record) | NOT_ESTABLISHED | CONTRADICTED ("twin applied None, claim says 21.5") | A defect in this reader. The schema says an absent optional member is evidence, not a default, and the claim that needs it is NOT_ESTABLISHED; the reader compared the absent value as if it were a different one. The corpus is right. |
| `twin_requested_other_value` (`requested_setpoint_c` 23.0, `new_setpoint_c` 21.5 = claim) | CONTRADICTED under `call_binding` | ESTABLISHED | A check this reader does not have. Upstream's table defines `call_binding` as "the twin's own operation record belongs to this proposal"; the corpus README adds "and for the claimed value" and reads `requested_setpoint_c`. The reader follows upstream's words and never looks at that field; the 21-mutant list has no mutant for it either, so this is a check the sealed sets do not exercise that the earlier record did not list. |
| `reviewer_absent` (executed VERIFY, `reviewer` null) | NOT_ESTABLISHED | CONTRADICTED ("executed on verify without an approving reviewer") | A reading. The schema's rule for a missing member points the corpus's way (the review is not shown, so the claim is not established); the reader treated executing a VERIFY with no review on record as the trail disagreeing with itself. Negative either way. |

Two more cases differ only on a claim, not on the verdict: `denied_but_applied` and `not_executed_but_observed`
(`executed` false, `executions` 1). The corpus has `single_dispatch` NOT_ESTABLISHED there; this reader has it
ESTABLISHED because the recorded count is one. Both have the verdict CONTRADICTED under `decision_correspondence`.

### The mutants

- **M12** (a null observation counts as observed) is the one survivor on the verdict: on `observation_null` the
  mutant moves `declared_effect_observed` to ESTABLISHED, but `observation_after_dispatch` is NOT_ESTABLISHED
  on the same case (no observation time), so the case verdict stays NOT_ESTABLISHED and matches. On the six
  claims the same case catches it. Whether that is a survivor depends on what a verifier is held to: this
  battery scored verdicts, and the corpus's frozen answers carry the claims as well, so both are reported.
- **M14** (assume the observation time equals the dispatch time when absent) is caught by
  `observation_time_missing`, and raises on `observation_null`: the mutant removed the reader's `obs is None`
  guard, which no earlier case exercised. The raise is the mutant's, not the corpus's; the frozen reader does
  not raise on that case.
- The other 19 are each caught by the case the corpus README names for them. `M19` (default JSON separators) is
  caught by 16 cases on the verdict because every digest changes.

The eleven checks the earlier record listed as unexercised by the sealed `v2` set (M02, M03, M03b, M08, M09,
M10, M12, M17, M18, M20 and M05) each have a case here that catches the mutant, on the verdict for all but M12.

## Files

| File | sha256 |
| --- | --- |
| `battery_on_aev289.py` | in `SHA256SUMS` |
| `run_38ed52b.txt`, `run_38ed52b.json` | in `SHA256SUMS` |
| `upstream_pins_38ed52b.txt` | what was fetched, opened, not opened and not run |

Readings and the reader's defects are stated above; the reader is kept as frozen so the two records can be
compared. CC0.

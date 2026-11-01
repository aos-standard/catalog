# AEP conformance corpus at `0039ad6`: an independent semantic verifier from the public text, blind run 32/32

`WasmAgent/wasmagent-protocol` ships an AEP conformance corpus and an implementer guide
(`conformance/aep/IMPLEMENTER.md`) with rules for claiming an *independent* semantic verifier: do not import or call
any WasmAgent evaluator, implement from the public spec, the canonical JSON Schema and the manifest verdicts, keep
the first blind run before any mismatch-specific fix, and pin the corpus. This record follows those rules.

The project's own external-evidence registry (`external-evidence/aps-conformance-suite-pr-94.json`) records
`independent_semantic_verification: NOT_YET_ESTABLISHED`. This is offered as one such run, not as a certification.

## Result of the first blind run (reader v1, frozen before scoring; no fixes made)

| Layer | Scored where the manifest gives a record outcome | Agreement |
| --- | --- | --- |
| structural (canonical schema) | 32 fixtures | **32/32** |
| semantic (attribution floor / vocabulary / count) | 32 fixtures | **32/32** |
| authenticity (`unsigned` / `dsse-valid` / `invalid`) | 16 fixtures | **16/16** |
| chain (`not-present` / `intact` / `partial` / `orphaned` / `broken`) | 7 fixtures | **7/7** |

Fixtures with full agreement on every scored layer: **32/32**, no exceptions raised. `not-checked` is an evaluation
state (verifier-result-contract.md §1), so the 16 `authenticity: not-checked` entries and the `chain: not-checked`
entries are reported in `runs/run_0039ad6_v1.json` with what the reader computes, and not scored.

Mismatch list of the blind run: empty. There was no second version.

## Readings the public text left open (made from valid fixtures only, before the freeze)

The text names the signing profile precisely (Ed25519 over DSSE PAE of the decoded in-toto Statement bytes, exactly one
signature) but four things a verifier needs are not stated in any document or in the canonical schema. They were read
from the bytes of five *valid* fixtures with `probe/hyp.py`, which tried candidate inputs and kept the one every valid
fixture agreed on; no negative fixture was opened before the freeze.

| | Reading | Where it is not stated |
| --- | --- | --- |
| R1 | the signed predicate is the record without `signature` and `dsse_envelope`; the subject digest is sha256 over its canonical JSON (sorted keys, no whitespace, UTF-8). Code-point and UTF-16 key order give the same bytes on this corpus | "canonical JSON" is not defined (RFC 8785 is not named); the subject digest input is not stated |
| R2 | `subject[0].name` is `urn:wasmagent:run:` + `run_id` | the name form appears only in fixtures |
| R3 | `prev_record_hash` is the hex sha256 of the previous record under R1 | `prev_record_hash` is not in `aep-record.schema.json` and is not described in any document |
| R4 | an `observed` list with no floor is a semantic violation, including an empty list | the schema says the pair is reported "together, never instead of" |
| R5 | `authorization_evidence_count` lower than the number of distinct observed grades is a violation | own reading; no fixture tests it |
| R6 | a record carrying only the retired inline `signature` is `invalid` | the vocabulary has no legacy outcome (the contract's `unsupported-legacy` is not in the manifest vocabulary) |
| R7 | the inline record must equal the signed predicate | "payload bound to the record" |
| R8 | exactly one subject | not stated |
| R9 | when both are present, the legacy `signature` field must carry the envelope's `signatures[0]` (`sig`, `key_id`) | schema: "the legacy signature field is derived from the envelope's signatures[0]" |
| R10–R11 | chain: a non-null `prev_record_hash` on record i ≥ 1 must equal R3 of record i−1 (else `broken`); a non-null link on the first record is `orphaned`; all links of a multi-record sequence absent is `not-present`; some absent is `partial`; one record with no predecessor is `not-present` | the state names and one-line notes only |
| R12 | a sequence is `dsse-valid` / `unsigned` only if every record is | not stated |

The schema validator is the reader's own, for the keywords the canonical schema uses (no `jsonschema` package).

## What the corpus does not pin: one check removed at a time

`reader/mutants.py` removes one check from the frozen reader by an exact source edit and reruns the corpus
(`runs/mutants_0039ad6_v1.json`). 15 of 32 mutants keep 32/32. Most survive only because a negative fixture is
rejected by two checks at once; reading the reasons per fixture (`detail` in the run file) separates those from the
rules no fixture reaches:

1. **No fixture fails on the signature itself.** Every authenticity negative is either an inline mutation of a signed
   record (`tampered-run-id`, `tampered-created-at`: the signature over the payload stays valid, the binding fails) or
   validly re-signed (`*-resigned`, `multiple-signatures`). A reader with Ed25519 verification removed (A3) agrees on all
   32. The project's adequacy fault L2-1 removes the whole envelope verification, which also removes the binding and
   subject checks, so it is detected; the signature step alone is not isolated. A payload byte or a signature byte
   flipped after signing would pin it.
2. **No fixture names a key the manifest does not list.** A reader that falls back to any known key for an unknown
   `keyid` (A5) agrees on all 32. Adequacy fault L2-2 (always the default key) is a different fault and is detected by
   the Rust fixture.
3. **The binding checks are never separated.** Both tampered fixtures fail R7 (predicate ≠ record) and R1 (subject
   digest) together, and `tampered-run-id` also fails R2. A reader missing any one of these agrees on all 32 (A8, A11,
   A12). A fixture whose predicate equals the record but whose subject digest is wrong, and the reverse, would pin each.
4. **Every `*-resigned` fixture keeps the legacy `signature` field from the original signing.** The schema says that
   field is derived from `signatures[0]`; in all five re-signed fixtures it is not (in the valid fixtures it is). A reader
   that compares the field (R9) rejects all five for that reason alone, whatever the intended defect, and a reader that
   checks only that field rejects them without checking `payloadType`, `_type`, `predicateType` or the subject name
   (A1, A6, A7, A10 survive here). Either regenerating the field or stating that verifiers ignore it would separate them.
5. Not reached by any fixture: two subjects (A9), a wrong JSON type for a typed member (S5), and the interplay of
   `authorization_evidence_count` with the floor (R5, M8). The schema says that, when the count is present, the floor
   must equal the weakest grade across the declared set; no fixture carries a count together with a floor.

Small: `manifest.json#historical` names `historical/rust-struct-order-sha256-ed25519.json`; the file in the tree is
`historical/rust-sha256-ed25519.json`.

## Files

| File | What |
| --- | --- |
| `reader/aep_check_v1.py` | the reader, frozen before any scored run (`FROZEN.txt`) |
| `reader/run_corpus.py` | scores a reader on `manifest.json#conformance_target` |
| `reader/mutants.py` | the one-check-removed battery |
| `probe/hyp.py` | the valid-fixture probe used for R1–R3 |
| `runs/run_0039ad6_v1.json` | the blind run, with per-fixture reasons |
| `runs/mutants_0039ad6_v1.json` | the battery |
| `upstream_pins_0039ad6.txt` | what was fetched, opened, not opened |

## Exposure and limits

The manifest was read in full before the reader was written, including every expected verdict and note, as
IMPLEMENTER.md allows; the reader was written to the vocabulary and layer split it states. So 32/32 shows that the
public text plus the manifest are enough to reproduce the verdicts, not that the verdicts were predicted unseen.
The battery shows what this corpus leaves open for *this* reader; it says nothing about the project's own verifiers,
which were not opened or run. CC0.

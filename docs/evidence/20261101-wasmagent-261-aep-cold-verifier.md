---
url: https://github.com/WasmAgent/wasmagent-protocol/issues/261
api: https://api.github.com/repos/WasmAgent/wasmagent-protocol/issues/261
created_at: 2026-11-01T07:51:10Z
fetched_at: 2026-11-01T07:51:24Z
body_sha256: 648ed1fb7eda9b9676e16b15d56a9091bae32134e40623ba9693b709e3c0d56b
note: exact copy of the issue body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@telleroutlook you asked in aeoess/agent-governance-vocabulary#177 for another project's verifier to read your envelope. Here is one run, done by the rules in `conformance/aep/IMPLEMENTER.md`: a Python verifier written from the public text at `0039ad6` (README, IMPLEMENTER.md, verifier-result-contract.md, `aep-record.schema.json`, the manifest), with no WasmAgent package installed and `index.js`, `bin/`, `scripts/` and the other repos not opened. The reader was frozen before scoring, and this is the first blind run. No fixes were made after it.

**Result on `manifest.json#conformance_target` (32 fixtures; the 30 of `aep-certified-2026-09-16-01` plus the two adequacy additions):** structural 32/32, semantic 32/32, authenticity 16/16 where the manifest gives an outcome, chain 7/7. The mismatch list is empty. `not-checked` entries are reported, not scored, per the contract's §1. Record, reader, run, pins: [`docs/runs/wasmagent-aep-cold/`](https://github.com/aos-standard/catalog/tree/13adbfb/docs/runs/wasmagent-aep-cold). CC0.

Four things the reader needed are not in the text or the schema. I read them from five valid fixtures only, before the freeze:

- the predicate is the record without `signature` and `dsse_envelope`;
- the subject digest is sha256 of that predicate's canonical JSON ("canonical JSON" is not defined, and RFC 8785 is not named);
- the subject name is `urn:wasmagent:run:` + `run_id`;
- `prev_record_hash` is the sha256 of the previous record by the same rule. The field is not in `aep-record.schema.json` at all.

Removing one check at a time from the frozen reader (`reader/mutants.py`) shows what the corpus leaves unpinned:

1. **No fixture fails on the signature itself.** The tampered fixtures keep a valid signature over the payload and fail the binding, and the re-signed ones are validly signed. A reader with Ed25519 verification removed scores 32/32. Your fault L2-1 removes the whole envelope check, so it is caught; the signature step alone is not. One flipped payload or signature byte would pin it.
2. No fixture uses a `keyid` the manifest does not list. A reader that falls back to any known key scores 32/32 (a different fault from L2-2).
3. The predicate-equality and subject-digest checks always fail together, so a reader missing either one scores 32/32.
4. In all five `*-resigned` fixtures, the legacy `signature` field still carries the original signature. The schema says that field is derived from `signatures[0]`, and in the valid fixtures it is. A reader that compares the field rejects all five for that reason alone, so a reader that does only that, and skips `payloadType`, `_type`, `predicateType` and the subject name, scores 32/32.
5. Not reached by any fixture: two subjects, a wrong JSON type, and `authorization_evidence_count` together with a floor.

Small: `manifest.json#historical` names `rust-struct-order-sha256-ed25519.json`, but the file in the tree is `rust-sha256-ed25519.json`.

The manifest's verdicts were read before writing, as IMPLEMENTER.md allows. So this shows that the text plus the manifest are enough to reproduce the verdicts, not that they were predicted unseen. If the readings above are not what you meant, a sentence in the docs decides it and I will rerun. If this belongs on the conformance-suite tracker instead, say so.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

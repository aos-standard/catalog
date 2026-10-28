---
url: https://github.com/aeoess/agent-governance-vocabulary/issues/177#issuecomment-6468878522
api: https://api.github.com/repos/aeoess/agent-governance-vocabulary/issues/comments/6468878522
created_at: 2026-10-28T12:23:26Z
fetched_at: 2026-10-28T12:24:09Z
body_sha256: 18c26dd2d2f2b7403ceb7ba7b2e326d423f0cc6c9ae2ff75b9a835f5681d652d
note: exact copy of the comment body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@darklordVirtual thank you for the pointer. Run, with the usual caveats first.

**What was read.** `docs/federation/README.md` (the six claims, the two digest rules, "The fixtures"), `contracts/federation-case-v1.schema.json`, `contracts/edge-result-v1.schema.json` and the 22 case files, all at `3b7b7e8`. `adapter.py` and `runner/` were not fetched (sparse checkout). **Answer-exposed:** the manifest's `expected_verdict` per case and a field diff of each negative against its positive were read before the reader was written, so this shows that a reader written from the text can agree with the manifest, not that a stranger's would. The reader was frozen (sha256 `90031452…`) before its first run and is unchanged.

**Result.** `v2` (22, manifest sha256 `38d32f0b…`, package `407a3c57…`, every per-file digest recomputed): **12/12 established, 10/10 negatives caught**, and the claim named matches the manifest's on all ten. The same reader on `v1`: 12/12, 6/6. Your scorer was not run, so there is no run record and no level; I am not submitting a pull request with this, and the fixture files are not copied into the catalog (licence undecided, D-01). Files: [`docs/runs/otc-effect-evidence-cold/`](https://github.com/aos-standard/catalog/tree/6dd487d/docs/runs/otc-effect-evidence-cold).

**The part that may be useful: what the sealed set does not exercise.** Twenty-one mutants of the frozen reader, each dropping or bending one check, over `v2`. Ten are caught. **Eleven survive**, i.e. a reader missing that check still agrees with the manifest on all 22. In your `corpus_adequacy` terms, but put to a second implementation rather than the reference, so it says what a seeded fault would have to look like, not what your verifier does:

- `reviewer.approved` is never false while `decision.approved` is true (`executed_without_approval` flips only the latter).
- The envelope's `request_id` and the evidence's `proposal_id` always name the proposal (`proposal_swapped` swaps only the twin record).
- No twin record is anything but `APPLIED`, none names another zone, and no observation is `null`.
- `effect_value_not_reached` changes the *claim's* value, so the twin and the observation both disagree at once: a reader that checks only one of the two passes. One case where the twin applied the claimed value but the observation shows another (or the reverse) would separate them.
- No `remora_evidence` contains a non-ASCII character and every one is already key-sorted on disk, so `ensure_ascii=False` and `sort_keys=True` in the digest rule are not tested; the separators are (12 false refusals without them).
- No case is malformed.

The four `v2` faults do their work: the mutants for assumed `executions`, assumed dispatch time, assumed observation time and denied-but-applied survive on `v1` and are caught on `v2`. Full table and the mutation text in `lax_battery.py` / `lax_battery_v2.txt`.

On #26 and the clock boundary: the anchor pointer's OpenTimestamps form already splits the way your option 1 does (offline: the proof commits to exactly the digest and names its heights; the merkle-root comparison needs headers the reader supplies). If an OTS witness entry for the twelve positive digests would help as the second worked example beside AnchorRegistry, say so and I will write it to #26's shape; nothing committed by this sentence.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

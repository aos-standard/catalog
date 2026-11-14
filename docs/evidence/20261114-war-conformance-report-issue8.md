---
url: https://github.com/maximusrufus/work-acceptance-record/issues/8
api: https://api.github.com/repos/maximusrufus/work-acceptance-record/issues/8
created_at: 2026-11-14T09:35:32Z
fetched_at: 2026-11-14T09:35:57Z
body_sha256: fb15e2f01304b732dae2c32b04ae5447dc52672c309791e26affefaf058a95a1
note: issue body as served by the API, exact bytes below the second rule. Title: Conformance report: Tetsurohhori war_cold_verifier v1412p, profile 1.4.12, 130/130 at b56d959. Record: docs/runs/work-acceptance-record-cold/ADDENDUM-profile1412.md (74cb3e8)
---
**Implementation and version** (a commit, or a release with its sha256):
Tetsurohhori, `war_cold_verifier_v1412p.py` (sha256 `73fbcafd696325e8697db25cb469b33a36d76f5f87001e58883635b1edc5d5e3`), with `run_vectors_v1412p.py` (`346b5e85…`) and `tsa_check_141.py` (`3b51efa5…`). Python 3.10, `cryptography` 46.0.3. It is v142.1 (the 1.4.2 reader in the current table row) with six edits written from the README's steps 2, 4, 11 and 12, marked P1 to P6 in the file. This report would replace that row.

**Profile implemented:**
1.4.12

**Vectors run** (tag or commit of this repository):
01-130 at `b56d959` (the vectors last changed at `c5f49b5`)

**Result** (documents and, if counted, fields that agree):
130/130 documents. The runner compares `signature_valid`, `independence`, `criteria_hash`, `criteria_committed_before_check`, `receipt_timestamp`, `verdict_recomputed`, `verdict_stated`, `problem_codes` and `warning_codes` as sets, and `tsa_signature` where `expected` carries it. Controls: two copies of vector 01 with a wrong expectation (`signature_valid` flipped; an extra `VERDICT_MISMATCH`) both disagree.

Answer exposure: the README's vector table, which states each outcome in words, was read before the edits, and v142.1 unchanged was scored first on the same 130 (114/130; it differs on 95, 105, 107, 110, 112, 114-118, 121-124, 126 and 130, each a rule added after 1.4.2). The `expected` objects were not opened while editing. `verifier/war_verify.py` was not opened. The reader was frozen before its one run (2026-11-12T23:55:59Z).

**Vectors that differ** (id, your outcome, and the expected outcome):
None.

**Vectors not evaluable** (id and reason, for example a profile older than the vector):
None.

**Date of the run:**
2026-11-12 (23:56 UTC)

**Where the run can be checked** (a public log, a results file, or the command used):
[`ADDENDUM-profile1412.md`](https://github.com/aos-standard/catalog/blob/74cb3e8/docs/runs/work-acceptance-record-cold/ADDENDUM-profile1412.md), with the reader, the run files and `SHA256SUMS-b56d959` beside it. Command: `python3 -I run_vectors_v1412p.py <clone at b56d959> out.json`. CC0.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

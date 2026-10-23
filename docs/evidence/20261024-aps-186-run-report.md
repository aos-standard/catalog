---
url: https://github.com/Agent-Authority-Conformance/aps-conformance-suite/issues/186
api: https://api.github.com/repos/Agent-Authority-Conformance/aps-conformance-suite/issues/186
created_at: 2026-10-23T23:12:20Z
fetched_at: 2026-10-23T23:18:15Z
body_sha256: 447eb62e5db7601f1eee846fa109c00cfc6d86355cd8f88726bf8e153b266126
note: exact copy of the issue body as served by the GitHub API at fetched_at; the row in CONDUCT.jsonl hashes this whole file
---
### Who ran it

the account posting this issue, for aos-standard/catalog

### Date

2026-10-24

### Run mode

B: alternate recomputation using another implementation or primitive

### Implementation name

clean-room Python model of lease-revocation-axes revision 2 (`lra_cold_model.py`), written from the family README, ORACLE.md and the input shape of the vectors

### Implementation repo and commit or version

https://github.com/aos-standard/catalog/tree/3e882bc/docs/runs/aps-lease-revocation-axes-cold (aos-standard/catalog `3e882bc`; `lra_cold_model.py` sha256 `f9569cbcfe39800587923cbfcac7c18032ea3fda08e97ee6814c5aa3efced0a1`, frozen before the first scored run)

### Corpus reference

PR #180 head `b745d252191e89fe123e33411f124a1b67542c2a`; `revision-2/vectors.json` sha256 `a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8`, `revision-2/oracle-checkpoints.json` `1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea`

### Environment

Python 3.10.12, standard library only, Linux 6.8 (Ubuntu)

### Per-vector results

```text
call         cached/excl  cached/incl  live/excl  live/incl
LRA-01-r1    match        match        match        match
LRA-01-r2    match        match        match        match
LRA-01-r3    match        match        match        match
LRA-01-r4    match        match        match        match
LRA-02-r1    match        match        match        match
LRA-02-r2    match        match        match        match
LRA-02-r3    match        match        match        match
LRA-02-r4    match        match        match        match
LRA-03-r1    match        match        match        match
LRA-03-r2    match        match        match        match
LRA-03-r3    match        match        match        match
LRA-03-r4    match        match        match        match
LRA-04-r1    match        match        match        match
LRA-04-r2    match        match        match        match
LRA-05-r1    match        match        match        match
LRA-05-r2    match        match        match        match
LRA-05-r3    match        match        match        match
LRA-06-r1    match        match        match        match
LRA-06-r2    match        match        match        match
LRA-06-r3    match        match        match        match
LRA-07-r1    match        match        match        match
LRA-07-r2    match        match        match        match
LRA-07-r3    match        match        match        match
LRA-07-r4    match        match        match        match
LRA-08-r1    match        match        match        match
LRA-08-r2    match        match        match        match
LRA-08-r3    match        match        match        match
LRA-08-r4    match        match        match        match
LRA-08-r5    match        match        match        match
LRA-09-r1    match        match        match        match
LRA-09-r2    match        match        match        match
LRA-10-r1    match        match        match        match
LRA-10-r2    match        match        match        match
LRA-10-r3    match        match        match        match
LRA-10-r4    match        match        match        match
LRA-10-r5    match        match        match        match
LRA-10-r6    match        match        match        match
LRA-11-r1    match        match        match        match
LRA-11-r2    match        match        match        match
LRA-11-r3    match        match        match        match
LRA-11-r4    match        match        match        match
LRA-12-r1    match        match        match        match
LRA-12-r2    match        match        match        match
LRA-12-r3    match        match        match        match
44 calls x 4 profiles = 176; 176 match, 0 diverge; field comparisons 1584/1584
```

### Verbatim command and output

```text
$ (in fixtures/lease-revocation-axes/revision-2) sha256sum vectors.json oracle-checkpoints.json
a0a07ea58bcacfd056cbd648e03de4ff14778aa151e8b5d2574e43e31a111ed8  vectors.json
1a0ed8a70bc7e7583c02855953485230261a8aeb5c0adc105292ab4b6e0916ea  oracle-checkpoints.json
$ python3 -I run_lra.py vectors.json first_run_b745d25.json
176/176 call-profiles agree; fields 1584/1584; truth input mismatches 0
(exit 0)
$ python3 -I lra_mutants.py vectors.json mutants_b745d25.json
match      lease-ignores-expiry         declared=5 here=5 only_declared=[] only_here=[]
differ     sliding-lease                declared=5 here=4 only_declared=['LRA-04'] only_here=[]
match      live-fail-open               declared=3 here=3 only_declared=[] only_here=[]
differ     sticky-unavailable           declared=3 here=1 only_declared=['LRA-03', 'LRA-07'] only_here=[]
differ     retrieval-renews-evidence    declared=4 here=3 only_declared=['LRA-04'] only_here=[]
match      deny-but-dispatch            declared=11 here=11 only_declared=[] only_here=[]
match      deny-everything              declared=10 here=10 only_declared=[] only_here=[]
differ     live-first-read-only         declared=9 here=8 only_declared=['LRA-11'] only_here=[]
match      second-worker-stale          declared=1 here=1 only_declared=[] only_here=[]
audit_only fabricated-live-read         declared=11 here=0 only_declared=['LRA-01', 'LRA-02', 'LRA-03', 'LRA-05', 'LRA-06', 'LRA-07', 'LRA-08', 'LRA-09', 'LRA-10', 'LRA-11', 'LRA-12'] only_here=[]
audit_only selective-not-supported      declared=11 here=0 only_declared=['LRA-02', 'LRA-03', 'LRA-04', 'LRA-05', 'LRA-06', 'LRA-07', 'LRA-08', 'LRA-09', 'LRA-10', 'LRA-11', 'LRA-12'] only_here=[]
match      ignore-evidence-binding      declared=1 here=1 only_declared=[] only_here=[]
(exit 0)
$ python3 -I lra_mutants_alt.py vectors.json mutants_alt_b745d25.json
match  sliding-lease                declared=['LRA-04', 'LRA-05', 'LRA-07', 'LRA-08', 'LRA-10'] here=['LRA-04', 'LRA-05', 'LRA-07', 'LRA-08', 'LRA-10']
match  retrieval-renews-evidence    declared=['LRA-04', 'LRA-05', 'LRA-08', 'LRA-10'] here=['LRA-04', 'LRA-05', 'LRA-08', 'LRA-10']
match  sticky-unavailable           declared=['LRA-03', 'LRA-07', 'LRA-11'] here=['LRA-03', 'LRA-07', 'LRA-11']
match  live-first-read-only         declared=['LRA-01', 'LRA-02', 'LRA-03', 'LRA-06', 'LRA-07', 'LRA-08', 'LRA-09', 'LRA-10', 'LRA-11'] here=['LRA-01', 'LRA-02', 'LRA-03', 'LRA-06', 'LRA-07', 'LRA-08', 'LRA-09', 'LRA-10', 'LRA-11']
(exit 0)
$ python3 -I check_checkpoints.py vectors.json oracle-checkpoints.json checkpoints_b745d25.json
0 LRA-01-r1 cached_lease exclusive agree 
1 LRA-02-r4 cached_lease exclusive agree 
2 LRA-02-r2 live_standing_read exclusive agree 
3 LRA-03-r2 live_standing_read exclusive agree 
4 LRA-04-r1 live_standing_read exclusive agree 
5 LRA-04-r1 live_standing_read exclusive outside_model {"observation": {"checkpoint": {"status": "revoked", "as_of_ms": 121000, "retrieved_at_ms": 121000}, "model": null}, "authority_answer": {"checkpoint": "revoked", "model": "not_established"}, "current_validity": {"checkpoint": "revoked", "model": "not_established"}}
6 LRA-05-r2 live_standing_read inclusive agree 
7 LRA-05-r2 live_standing_read exclusive agree 
8 LRA-09-r1 live_standing_read exclusive agree 
9 LRA-12-r2 live_standing_read exclusive agree 
10 LRA-06-r3 live_standing_read exclusive agree 
11 LRA-07-r2 live_standing_read exclusive agree 
11/11 non-diagnostic checkpoints agree; 1 diagnostic outside the model
(exit 0)
```

### Author-produced or independent

author-produced

### Suspected defective vectors

None. Notes for the record:

- Author-produced because this catalog wrote the alternate implementation that supplies the recomputation; it wrote none of the vectors, claim inputs, or the family's implementation. Answer-exposed: each call's `expected` block was on screen while the input shape was read. `harness.ts`, `verify.ts`, `generate.py`, `sdk-bridge.mjs`, `mutation.test.mjs` and the Aicent-com runner were not opened.
- Checkpoint 5 (`LRA-04-r1`, live, exclusive, `diagnostic: true`) is outside this model, which fixes the default path with no diagnostic read. Index 4, the same call without the diagnostic, agrees.
- The twelve declared variants were re-derived in this model from their names and the README's one-line list, not from `mutation.test.mjs`. On that first reading six of the ten value-observable variants reproduce the declared sets exactly. Four (`sliding-lease`, `retrieval-renews-evidence`, `sticky-unavailable`, `live-first-read-only`) fail a subset of the declared cases, and none fails a case the declaration omits. A second reading per variant, written after seeing that, reproduces all four. The second readings are: the use or read renews the lease before freshness is judged; after an outage the worker keeps its last observation and never re-reads; and a failed first attempt counts as the only read. So the declared sets fit the vectors, but someone re-deriving a variant from the text cannot tell which reading is meant. One sentence per variant stating its rule would settle it. `fabricated-live-read` and `selective-not-supported` need the read audit, which this model does not have.

Files, hashes and the post-hoc label: [`docs/runs/aps-lease-revocation-axes-cold/RUN.md`](https://github.com/aos-standard/catalog/blob/3e882bc/docs/runs/aps-lease-revocation-axes-cold/RUN.md). CC0.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.


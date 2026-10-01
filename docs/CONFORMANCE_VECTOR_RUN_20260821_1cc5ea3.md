## Conformance vector run — anchors_verify adapter

- **Run (JST):** 2026-08-21T07:38:36+09:00
- **Vector source:** `tersignhq/evidence-record-conformance` @ commit `1cc5ea32b3da4f195b55782c8a3573d8564673a7`
- **Vector bundle SHA256 (ordered file digests):** `370b3428c7dd6af86eb4b43fcd9d9134d38b1b995dcd1a01055f980fa1456e7e`
- **Verifier:** `anchors_verify.py` (**unchanged** — adapter-only run)
- **Adapter:** `scripts/conformance_vector_run.py` (**written by us**; not third-party harness)
- **Third-party harness:** **not executed** (`tools/differential.py`, `keccak.py`, etc.) — supply-chain trust boundary; JSON vectors only.
- **AI assistance:** drafted with AI assistance (Cursor); runs executed locally.

### Exclusion policy

The 2026-08-10 run excluded `p19-` / `n27-` / `n28-` because those vectors were **not present at `46ad663`**. At `2f80fb29` they exist; exclusions were cleared so the published reason and implementation stay aligned.

### boundary_binding vectors (all at this layer)

**5 vectors** at the layer `anchors_verify` operates at (was 3 at `46ad663`). Each row records **expected · observed · rejection_class · stop reason**.

- `n25-boundary-prefix-only-no-position`: expected `reject` · observed `reject` · verdict **match** · rejection_class `unattested` · reason: no position_binding_introduced attestation (attested_prefix_lines=0); digest and boundary checks alone are insufficient — offline snapshots cannot be distinguished from verified streams
- `n26-coverage-claimed-over-empty-attestation`: expected `reject` · observed `reject` · verdict **match** · rejection_class `unattested` · reason: no position_binding_introduced attestation (attested_prefix_lines=0); digest and boundary checks alone are insufficient — offline snapshots cannot be distinguished from verified streams
- `n29-suite-transition-redigests-prefix`: expected `reject` · observed `reject` · verdict **match** · rejection_class `suite_transition_redigest` · reason: digest_suite_transition at line 4: prefix was redigested under successor digest suite 'sha3-256-jcs' (binding must use 'keccak256-jcs' digest for history written before the transition)
- `p18-boundary-binds-prefix-and-position`: expected `valid` · observed `valid` · verdict **match** · rejection_class `ok` · reason: attested_prefix_lines=3
- `p20-suite-transition-preserves-prefix`: expected `valid` · observed `valid` · verdict **match** · rejection_class `ok` · reason: attested_prefix_lines=3

**Layer summary:** 5 of 5 match at this verifier layer.

### Verdict counts

- match: 5
- mismatch: 0
- not_applicable: 49
- skipped (excluded prefixes): 0

### not_applicable reasons (by kind)

- `anchor_relation`: 2 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `canonical_bytes`: 4 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `chain_link`: 2 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `chain_set`: 3 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `decision_evidence_binding`: 3 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `digest_recompute`: 7 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `independence_claim`: 23 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `offer_binding`: 2 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `phase_claim`: 3 — AUEC evidence-record layer; no ANCHORS.jsonl adapter

### Structurally out of scope for anchors_verify

- Signed equivocation / counter-signature recovery (secp256k1) — **no signature suite verification**
- keccak256 content addressing / RFC8785 JCS canonicalization — **different digest domain**
- Chain link arithmetic, offer binding, independence scope — **not ANCHORS stream semantics**
- Stream tip after last `position_binding_introduced` remains unattested until next attestation
- Force-push on witness repo breaks history-dependent checks

### n26 note

`n26` encodes our own 2026-08-09 downgrade finding (`VERIFY OK` beside `attested_prefix_lines=0`). This run tests **our** verifier, not AUEC or a third-party adapter.

### Prior runner

`mohammedmessaoudene-cmd` reported results on the same commit using **his AUEC implementation**. Those numbers are **not** ours and are not reproduced here.


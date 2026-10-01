**Note (2026-08-20):** A later commit `2f80fb29` changed the suite target set from 44 to 52, and `boundary_binding` at this layer from 3 to 5. The body below is left as the facts at `46ad663`.

## Conformance vector run — anchors_verify adapter

- **Run (JST):** 2026-08-10T07:30:15+09:00
- **Vector source:** `tersignhq/evidence-record-conformance` @ commit `46ad663b90805a2e526ef3cd28c3f70762883125`
- **Vector bundle SHA256 (ordered file digests):** `ae31a62a86dffef0c917d58b004fcc579d4044af5df65aa60f91b00045906222`
- **Verifier:** `anchors_verify.py` (**unchanged** — adapter-only run; zero-line diff)
- **Adapter:** `scripts/conformance_vector_run.py` (**written by us**; not the suite's harness)
- **Third-party harness:** **not executed** (`tools/differential.py`, `keccak.py`, etc.) — supply-chain trust boundary; JSON vectors only.
- **AI assistance:** implementation, adapter, execution, and drafting were assisted by AI (Claude, Cursor). I reviewed the executed evidence and remain responsible for this report.

### Required boundary_binding vectors

`boundary_binding` is the only vector kind `anchors_verify` operates at. The suite contains
**exactly three** such vectors, and **all three were run**.

- `n25-boundary-prefix-only-no-position`: expected `reject` · observed `reject` · verdict **match** · rejection_class `unattested`
- `n26-coverage-claimed-over-empty-attestation`: expected `reject` · observed `reject` · verdict **match** · rejection_class `unattested`
- `p18-boundary-binds-prefix-and-position`: expected `valid` · observed `valid` · verdict **match** · rejection_class `ok`

**Why `unattested` and not `fork`/`truncation`:** both negatives fail on the absence of a
position-bound attestation, which is the property each vector isolates. `n25` names its prefix
truthfully but binds no position; `n26` claims coverage through position 3 over an attestation
reaching an empty prefix. Before the 2026-08-09 fix, `n26`'s shape printed `VERIFY OK`.

**This is not a blanket `unattested` default.** `p18` differs from `n25` only in that its boundary
event binds its own position, and `p18` is **accepted**. The rejection therefore tracks the property
under test rather than a default-deny path.

### Verdict counts

- match: 3
- mismatch: 0
- not_applicable: 41
- skipped (p19/n27/n28 excluded — not present at `46ad663`): 0

**Read both numbers.** 3 of 44 vectors in the suite; 3 of 3 at the layer this verifier operates at.
The remaining 41 are not failures and are not passes — `anchors_verify` has no adapter path for them.

### not_applicable reasons (by kind)

- `anchor_relation`: 2 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `canonical_bytes`: 4 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `chain_link`: 2 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `chain_set`: 3 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `digest_recompute`: 7 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
- `independence_claim`: 18 — AUEC evidence-record layer; no ANCHORS.jsonl adapter
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


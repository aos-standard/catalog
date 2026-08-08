# ANCHORS stream verifier

Standalone checker for [`ANCHORS.jsonl`](ANCHORS.jsonl) and [`ANCHORS.jsonl.digests.json`](ANCHORS.jsonl.digests.json). **Standard library only.** Takes **public HTTPS URLs** as input — no local checkout required.

**Run (copy-paste):**

```bash
python3 anchors_verify.py --anchors-url https://raw.githubusercontent.com/aos-standard/catalog/main/ANCHORS.jsonl --digests-url https://raw.githubusercontent.com/aos-standard/catalog/main/ANCHORS.jsonl.digests.json
```

**Self-test (adversarial vectors, no network):**

```bash
python3 anchors_verify.py --self-test
```

## What it checks

- Each JSONL line SHA-256 matches the sidecar entry for that line index. Hashes cover the **full stored line including the trailing newline byte**.
- Boundary rules for `witness_ref_introduced` and `signature_suite_introduced` (field presence before/after each event).
- **Truncation vector 1:** fewer anchor lines than digest entries → fail closed.
- **Truncation vector 2:** anchor lines and sidecar both shortened but internally consistent → fail closed **when compared to witness platform snapshots** (commit pinned in `witness_ref_introduced`, and `main` on the same repository).

## Limits (read before citing results)

- **Signature verification is not implemented.** The stream may declare `signature_suite`; this tool does not validate signatures or keys.
- **Equivocation** (conflicting signed claims) is out of scope without a signature suite.
- **Truncation vector 2 depends on witness platform history not being rewritten.** If the witness repository history is force-pushed, detection can be broken. Do **not** claim unconditional truncation detection — only: *while witness history has not been rewritten, truncation is detected.*

Detection strength inherits the availability and honesty of the witness platform whose history you compare against.

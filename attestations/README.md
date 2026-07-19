# Audit Badge Attestations

Signed, opt-in attestations for MCP servers scanned with [mcp-blast-radius](https://github.com/aos-standard/mcp-blast-radius).

**Properties:** free · maintainer-initiated · no phone-home · 90-day expiry · Ed25519 signed

---

## Files

| Path | Purpose |
|------|---------|
| `{owner}__{repo}.json` | Full attestation (governance-aligned schema + scan metadata + signature) |
| `endpoints/{owner}__{repo}.json` | [shields.io endpoint](https://shields.io/badges/endpoint-badge) payload for README badges |
| `public_key.pem` | Ed25519 public key for independent signature verification |

---

## Verify an attestation

### 1. Check expiry

Open `{owner}__{repo}.json` and confirm `expires_at` is in the future (ISO 8601 UTC).

### 2. Verify Ed25519 signature

**Option A — mcp-blast-radius scripts (recommended):**

Requires `pip install cryptography` (Ed25519 verification only; no maintainer signing keys).

```bash
git clone --depth 1 https://github.com/aos-standard/mcp-blast-radius.git
cd mcp-blast-radius/packaging/scripts
pip install cryptography
python3 verify_attestation.py \
  https://raw.githubusercontent.com/aos-standard/catalog/main/attestations/OWNER__REPO.json \
  --public-key https://raw.githubusercontent.com/aos-standard/catalog/main/attestations/public_key.pem
```

Local files also work (e.g. after `curl -sO`):

```bash
python3 verify_attestation.py OWNER__REPO.json --public-key public_key.pem
```

**Option B — manual hash + IRA-SIG:**

1. Remove `signature`, `evidence_hash`, and `snippet` from the JSON.
2. Canonicalize: `json.dumps(body, sort_keys=True, separators=(",", ":"))`.
3. SHA-256 hex → `evidence_hash`.
4. Verify `signature` field (`IRA-SIG-{timestamp}-{ed25519_hex}`) against `evidence_hash` using `public_key.pem` (timestamp prepended to hash before verify).

Expected output: `PASS: Ed25519 signature valid`

### 3. Confirm scan metadata

- `tool_url` matches the repo displaying the badge
- `scanned_version` is a published mcp-blast-radius release
- `result_summary` reflects the maintainer's pasted scan (we do not re-scan on badge display)

---

## Issue flow (maintainers)

1. Run `mcp-blast-radius-gate --gate-mode advisory --target-dir <your-package>` locally.
2. Open [badge application](https://github.com/aos-standard/mcp-blast-radius/issues/new?template=badge-application.yml).
3. After human review, attestation appears here and `snippet` field provides README markdown.

We never actively scan your repository without an application.

---

## Schema (summary)

Attestations extend the [governance.json](../governance.json) top-level shape:

- `schema_version`, `generated_at`, `publisher`, `spec`
- `structure_audit`, `immune_loop`, `manifest_discipline`, `knowledge_base`
- Plus: `attestation_type`, `tool_url`, `tool_repo`, `scanned_version`, `scan_date`, `scan_command`, `scanned_path`, `result_summary`, `corpus_patterns_base`, `expires_at`, `evidence_hash`, `signature`, `snippet`

Review uses **73 calibration pattern classes** (aggregate methodology; corpus body not published).

---

## Public key permanence

The verifying public key lives at:

`https://raw.githubusercontent.com/aos-standard/catalog/main/attestations/public_key.pem`

Key rotation (if ever needed) will be announced in catalog commits with overlap period for old signatures.

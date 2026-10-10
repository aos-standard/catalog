# Case: unterminated final line (1-byte pair)

Pinned verifier: **`anchors-verify-v0.12`**.

## Rule (from ANCHORS_VERIFY.md)

- Each JSONL line SHA-256 matches the sidecar entry for that line index. Hashes cover the **full stored line including the trailing newline byte**, computed on **raw bytes** (not Unicode-normalized line strings).
- A final line with no trailing newline byte is hashed as stored; a digest computed over the same line with a newline byte does not match it.

**Unterminated final line (v0.11):** A stream whose final line has no trailing newline byte was hashed as if it had one through v0.10; under v0.11 it is hashed as stored, so such a stream that was VERIFY PARTIAL can become VERIFY FAILED (digest mismatch at the final line). Through v0.10, `unterminated.jsonl` against this sidecar was VERIFY PARTIAL.

## Files

| file | size_bytes | sha256 |
|------|------------|--------|
| `terminated.jsonl` | 19237 | `7817d72fe446dacc3659ddaca29ce79877aca5ccf497cfc3e0b2c406467f9723` |
| `unterminated.jsonl` | 19236 | `433d51d6f76086fa4d420fb94725851763a8c6b4da9d13db1149f2fdf730f82b` |
| `sidecar.json` | 5304 | `7c6a3023efe4271a91aecf0bbfffddadddab2688ea27e26d407c8d480ccaa165` |

`terminated.jsonl` is a freeze of `ANCHORS.jsonl` (73 lines, final byte `0a`).
`unterminated.jsonl` is the same bytes without that final `0a`.
Invariant: `terminated == unterminated + b"\n"`.

Regenerate `unterminated.jsonl` and print digests:

```bash
python3 make_case.py
```

After regeneration, sha256 values must match the table.

## Commands (file://, twice)

```bash
VERIFY=../../../anchors_verify.py   # or curl pin anchors-verify-v0.12
python3 "$VERIFY" \
  --anchors-url file://$(pwd)/terminated.jsonl \
  --digests-url file://$(pwd)/sidecar.json \
  --expect-witness-repo aos-standard/catalog
python3 "$VERIFY" \
  --anchors-url file://$(pwd)/unterminated.jsonl \
  --digests-url file://$(pwd)/sidecar.json \
  --expect-witness-repo aos-standard/catalog
```

## Expected (measured 2026-10-10)

### terminated.jsonl

- Outcome: **VERIFY PARTIAL**
- Exit: **3**
- Measured stderr (verbatim):

```
VERIFY PARTIAL: lines=73 digests=73 witness_repo=aos-standard/catalog witness_commit=0eb69bf9f26f03b8d4fbce3b3b64ac46e10e1582 attested_prefix_lines=18
```

### unterminated.jsonl

- Outcome: **VERIFY FAILED**
- Exit: **1**
- Reason includes: `digest mismatch at line 73`
- Rejection class: `digest_mismatch`
- Measured stderr (verbatim):

```
VERIFY FAILED: digest mismatch at line 73
```

Note: The verifier reads the witness repository over the unauthenticated GitHub API; a rate-limited client sees HTTP 403 and VERIFY FAILED.

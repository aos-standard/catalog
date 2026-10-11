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

## Run it in CI (GitHub Actions)

Weekly plus manual. Fetches the four files from tag `anchors-verify-v0.12`, runs the pair, and fails if either exit code or the first stderr line differs from the measured values (3 / `VERIFY PARTIAL`, 1 / `digest mismatch at line 73`). An unauthenticated GitHub API `HTTP 403` is printed as `rate-limited, not a case failure` and fails the job — it is not treated as a pass.

```yaml
name: unterminated-final-line
on:
  schedule:
    - cron: "17 8 * * 1"
  workflow_dispatch:

jobs:
  case:
    runs-on: ubuntu-latest
    steps:
      - name: Fetch pinned files and compare the pair
        run: |
          set -euo pipefail
          T=https://raw.githubusercontent.com/aos-standard/catalog/anchors-verify-v0.12
          curl -fsSLO "$T/anchors_verify.py"
          for f in terminated.jsonl unterminated.jsonl sidecar.json; do
            curl -fsSLO "$T/docs/cases/unterminated-final-line/$f"
          done

          run_case() {
            local stream="$1"
            local expect_exit="$2"
            local expect_needle="$3"
            set +e
            python3 anchors_verify.py \
              --anchors-url "file://$(pwd)/${stream}.jsonl" \
              --digests-url "file://$(pwd)/sidecar.json" \
              --expect-witness-repo aos-standard/catalog \
              >"${stream}.stdout" 2>"${stream}.stderr"
            local rc=$?
            set -e
            local first
            first=$(head -n 1 "${stream}.stderr")
            if grep -q "HTTP 403" "${stream}.stderr"; then
              echo "rate-limited, not a case failure" >&2
              exit 1
            fi
            if [ "$rc" -ne "$expect_exit" ]; then
              echo "exit mismatch: got $rc want $expect_exit" >&2
              cat "${stream}.stderr" >&2
              exit 1
            fi
            case "$first" in
              *"$expect_needle"*) ;;
              *)
                echo "stderr mismatch: first line lacked ${expect_needle}" >&2
                echo "$first" >&2
                exit 1
                ;;
            esac
            echo "ok ${stream} exit=${rc} first=${first}"
          }

          run_case terminated 3 "VERIFY PARTIAL"
          run_case unterminated 1 "digest mismatch at line 73"
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

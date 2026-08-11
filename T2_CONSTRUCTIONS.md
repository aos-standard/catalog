# T2 constructions (ten mutations plus baseline)

Fixed, byte-reproducible attack constructions against the attested-prefix fork
target (T2) for [`anchors_verify.py`](anchors_verify.py).

**Distribution:** single file [`t2_constructions.py`](t2_constructions.py) —
standard library only, same discipline as the verifier. **Not on PyPI.**

**Input:** the tag-bundled [`ANCHORS.jsonl`](ANCHORS.jsonl). No network.

```bash
python3 t2_constructions.py
# -> t2_constructions/{baseline,A2,A3,B,C,D2,D3,E,F,G,H}.jsonl
#    + matching *.jsonl.digests.json
#    + MANIFEST.json (sha256 + expected exit/verdict per id)
```

Pin with tag **`anchors-verify-v0.6`** (same commit that carries this doc).
Older tags `anchors-verify-v0.1` … `v0.5` are left in place and are not
re-pointed.

## Count correction (do not hide)

A public comment on [`aos-standard/catalog#1`](https://github.com/aos-standard/catalog/issues/1)
said **"nine constructions"**.

**That count was wrong.** What was actually run is **ten mutations plus
baseline** (eleven artifacts). The miscount is ours. This release publishes
the full set under the corrected name.

| id | construction |
|----|--------------|
| `baseline` | unmodified stream |
| `A2` | duplicate a genuine record into the attested prefix |
| `A3` | insert an altered genuine record into the attested prefix |
| `B` | delete one record inside the attested prefix |
| `C` | flip one byte inside the attested prefix |
| `D2` | duplicate a genuine record into the unattested tip |
| `D3` | alter one record in the unattested tip |
| `E` | remove the binding row (line count shrinks) |
| `F` | truncate the stream to 10 lines |
| `G` | append a binding claiming `line_count: 24` |
| `H` | replace the binding row with a record row (line count preserved) |

Expected disposition against `anchors-verify-v0.5` / `v0.6` verifier logic:

- attested-prefix mutations **A2, A3, B, C** → `fork or insertion detected`, exit 1
- unattested-tip mutations **D2, D3** (and **baseline**) → `VERIFY PARTIAL`, exit 3
- **E, F** → `truncation vector 2`, exit 1
- **G** → witness commit has fewer than the claimed line count, exit 1
- **H** → `missing witness after introduction`, exit 1

Exact expected exit codes and rejection substrings are recorded in
[`t2_constructions/MANIFEST.json`](t2_constructions/MANIFEST.json).

## Threat models (both; which is stricter)

Two different attack assumptions appear in the public record. **Both are
stated here. Do not conflate them.**

### 1. This construction set — sidecar regenerated

Each forgery **regenerates** the digest sidecar (`*.jsonl.digests.json`) so
that per-line digests match the forged stream. The attacker is assumed to
control **both** the presented `ANCHORS.jsonl` **and** the sidecar. The only
thing not under attacker control is the **witness repository history**.

This is the threat model used in the 2026-08-11 T2 self-attack and in every
artifact this script emits (`sidecar_regenerated: true` in the manifest).

### 2. External separator-receipt attacks — sidecar unmodified

The external receipt work that inserted Unicode / C0 separators inside an
attested prefix kept the **original sidecar bytes unchanged**. Digest entries
still described the honest stream; only the raw anchors bytes were mutated.
That is a **stricter** attacker constraint: the adversary does **not** get to
rewrite the sidecar to hide the mutation.

### Which is stricter?

**Sidecar-unmodified (external separator receipts) is the stricter threat
model.** The attacker has fewer degrees of freedom. A break under that model
is a stronger result than a break under the sidecar-regenerated model used
here.

This T2 set does **not** claim to match separator-receipt byte layouts, and
it does **not** reprint external receipt bodies (reference and digests only).

## Verify a construction

After generation (or from the committed `t2_constructions/` tree):

```bash
python3 anchors_verify.py \
  --anchors-url file://$(pwd)/t2_constructions/A2.jsonl \
  --digests-url file://$(pwd)/t2_constructions/A2.jsonl.digests.json \
  --expect-witness-repo aos-standard/catalog
```

Witness-platform checks require network access to the named repository.
**Generation itself does not.**

## Reproducibility

Running `t2_constructions.py` twice against the same `ANCHORS.jsonl` must
yield identical `sha256_anchors` / `sha256_digests` values in `MANIFEST.json`.

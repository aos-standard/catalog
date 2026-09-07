# MCP Registry capability census — 2026-08-16

Official MCP registry snapshot (2026-08-16) reduced to counts only.
No product SKU, no pricing, no CTA, no individual server verdicts in this release.

## Numbers (denominator: 21,732 unique active servers)

| Stage | Count |
|---|---|
| Unique active servers | **21,732** (51,072 duplicate version rows removed) |
| Boundary claims mappable to 4 axes | **730** |
| └ remote-only (no scannable package) | 338 |
| └ other unscannable | 20 |
| └ scannable (package + GitHub repository) | **372** |
| └ └ process-capability claims | **132** |
| └ └ └ of which "no network / offline" phrasing | **27** |
| └ └ data-domain permission claims (excluded from process count) | 240 |

Snapshot: 73,561 version rows · sha256 `16fe770a2b549902bfb2279e0f3916d9c0bf7c3e3a156ed1d32d94f7d601f318`
(Corrected 2026-08-24: was `9c0d6b100b1ef08e251e37c57e2d55ab9f4b22825a56709bbfb85208481dcd61`, the hash of an unbundled JSON array; now the decompressed content of the bundled `registry_2026-08-16.jsonl.gz`.)

`snapshot_sha256` covers these bytes (canonical JSONL):

- one record per line
- `json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"`
- UTF-8 · LF
- identical to the payload inside `registry_*.jsonl.gz` from `pack-gz`

## What was counted

Phrase match against server `title` and `description` among **active** records only.
One row per server name (latest version row wins when names repeat).

### Four axes (what a static capability scan can falsify)

| Axis | Example phrases |
|---|---|
| filesystem | read-only, does not write, never modifies |
| network | no network, no telemetry, local-only, fully offline, air-gapped |
| subprocess | no subprocess/shell, sandboxed |
| env | no data collection, does not read credentials/secrets |

Full regex list: `registry_capability_census.py` (`AXES` constant).

### "No network / offline" sub-count (27)

This sub-count is **not** the full network axis. It applies only to the **132**
process-capability rows and uses these six phrase patterns (regex; optional
separators match `air gapped`, `airgapped`, `local only`, etc.):

```
no network · fully offline · works offline · air[-\s]?gapped · local[-\s]only ·
never leaves your (?:machine|device|computer)
```

(Corrected 2026-08-25: published `method.network_offline_phrases` listed literal
strings narrower than the implementation regexes above; counts unchanged.)

Broader network-axis hits (e.g. `no telemetry`) are excluded because they do not
assert absence of communication. Machine-readable copy: `results_2026-08-16.json`
→ `method.network_offline_phrases`.

### Scannable definition

`packages` non-empty **and** repository URL contains `github.com`.

### Deliberately excluded phrases

`secure`, `safe`, `privacy-first`, `trusted` — a static scan cannot falsify these;
counting them would inflate the number without adding verifiable surface.

### Not counted as process capability

240 rows match boundary phrases but hit **data-domain** patterns (e.g. read-only on data)
rather than process locality patterns. That is a classification choice, not a defect.

## Limits (read before citing these numbers)

1. Static scan yields an **upper bound**; we did not observe live network traffic.
2. Remote-only rows have **no package to scan**; that does not mean the claim is false.
3. The 240 data-domain rows are permission claims on data, not counted as process capability.
4. Many "sandbox" hits describe a **product that sells sandboxing**, not self-sandboxing.
5. Classification is phrase-based. **Our labels can be wrong.**

Prior false positives on individual servers (not part of this census): VCL-0003,
oraios/serena#1824 — two cases, both withdrawn.

7 of 21,977 rows contain strings that collide with our internal vocabulary filter;
the per-string breakdown is in `results_2026-08-16.json`
(`third_party_vocabulary_collisions.forbidden_word_breakdown`).
115 rows contain non-ASCII scripts.
These are third-party descriptions republished verbatim.
Text we author in this directory is linted; third-party rows are not —
provenance is checked instead (regeneration byte-match + digests + recomputation).

## Excluded targets (individual judgment)

Per `R-20260818-01` (`SOVEREIGN_RULING_20260818_denial_conditions.md` §4).
We do not perform **unrequested individual judgments** on these classes.
Silence is not an exclusion — only listed classes are excluded.

| Reason class | Scope (as of 2026-08-16) |
|---|---|
| `self-audit` | Our own tools: `mcp-blast-radius`, `mcp-agent-health`, AOS-related (self-audit is a separate lane) |
| `competitor` | *(none listed yet — empty means none observed, not hidden)* |
| `financial-relationship` | *(none listed yet)* |
| `employer-or-client` | *(none listed — class only; no employer/client names on this surface)* |

When a competitor appears, add the repository/package name here with reason class `competitor`.
Update this table before publishing an individual judgment that skips a scannable target.

## Reproduce

Bundled snapshot files are included so the same counts reproduce without re-fetching.

### 1. Bundled snapshot only (no re-fetch)

Use the files in this directory as-is. No `registry_full.json` is required.

```bash
# ① Provenance self-check (used by shelf_sync before push)
python3 registry_capability_census.py verify .

# ② Recompute counts from the bundled gz (must match results_2026-08-16.json)
python3 registry_capability_census.py write-results registry_2026-08-16.jsonl.gz \
  -o /tmp/results_check.json --run-date 2026-08-16
# snapshot_sha256 → 16fe770a... · network_offline_approx → 27 · process → 132 · scannable → 372
```

`--run-date 2026-08-16` is required; omitting it defaults to today's date.

### 2. Fresh fetch (numbers move if the registry moved)

`registry_full.json` is **not** bundled; it is produced only on this path.

```bash
# Optional fresh fetch (changes numbers if registry moved)
python3 fetch_registry_snapshot.py -o registry_full.json

# Pack full snapshot (trigger events only)
python3 registry_capability_census.py pack-gz registry_full.json \
  -o registry_2026-08-16.jsonl.gz

# Reduced per-server JSONL (every sync)
python3 registry_capability_census.py write-reduced registry_full.json \
  -o servers_2026-08-16.jsonl

# Aggregate results JSON
python3 registry_capability_census.py write-results registry_full.json \
  -o results_2026-08-16.json --run-date 2026-08-16

# Provenance check — requires DIGESTS.json (run refresh-metadata after edits)
python3 registry_capability_census.py refresh-metadata .
python3 registry_capability_census.py verify .
```

## Dispute channel

File an issue on `aos-standard/catalog` if a count or classification is wrong.
If we were wrong, we record the correction in `CONDUCT.jsonl` ourselves.
Open challenge on the 372 -> 132 step: https://github.com/aos-standard/catalog/issues/2
Dated snapshots are kept indefinitely; a count published here can be recomputed against the snapshot it was computed from.
Requests to remove third-party data from a snapshot: open an issue here. We do not process them automatically and we record that the request was made.

## Second method on the same snapshot (2026-08-28)

This is a second method on the **2026-08-16** snapshot, not a correction of the first census.
The first run stays at 132 / 240 / 27 under `method_version` `2026-08-16.1`.

A third-party review by [navigatorbuilds](https://github.com/navigatorbuilds) listed 35 rows moving out of process and 5 moving in (`catalog#2` [comment](https://github.com/aos-standard/catalog/issues/2#issuecomment-5412869230), 2026-08-26 00:37 JST). The lists are bundled as `locality_moves_2026-08-28.jsonl` and `locality_adds_2026-08-28.jsonl`. The regex patch that produced those rows was **not published**. Attribution stays with navigatorbuilds; we do not take it.

Two overlays are computed from those lists (same snapshot sha256 `16fe770a…`):

| method_version | process | data-domain | scannable | network_offline |
|---|---:|---:|---:|---:|
| `2026-08-16.1` (first census) | 132 | 240 | 372 | 27 |
| `2026-08-28.mechanical` | **102** | 270 | 372 | 27 |
| `2026-08-28.adjudicated` | **116** | 256 | 372 | 27 |

Mechanical = 132 − 35 + 5. Adjudicated = mechanical + the 14 rows marked `subject_call=returns`. The difference between 102 and 116 is those 14 rows. The 2 rows marked `gray` are not restored, so the adjudicated count is a single number, not a range.

372 and 27 are unchanged across all three. That 27 is invariant under both draws is navigatorbuilds' finding; `verify` fails if any of the three versions reports a different `network_offline_approx`.

116 depends on the per-row `subject_call` labels in the 35-row list. 102 does not.

### Reproducibility of 102 is weaker than 132

The first census's 132 can be re-derived from the snapshot text with the regex in this directory. You do not need a row list.

**102 is deterministic against the published 40-row lists, but it cannot be re-derived from the descriptions alone**, because the patch that produced the lists was not published. Third parties can check each listed row (we did). That is a different property from “the regex yields the number.”

```bash
python3 registry_capability_census.py write-results registry_2026-08-16.jsonl.gz \
  -o /tmp/results_mechanical.json --run-date 2026-08-16 \
  --method-version 2026-08-28.mechanical
# process → 102 · data-domain → 270 · scannable → 372 · network_offline → 27

python3 registry_capability_census.py write-results registry_2026-08-16.jsonl.gz \
  -o /tmp/results_adjudicated.json --run-date 2026-08-16 \
  --method-version 2026-08-28.adjudicated
# process → 116 · data-domain → 256 · scannable → 372 · network_offline → 27
```

Omitting `--method-version` keeps `2026-08-16.1` (132).

## Method-comparison harness (`moved_claims_diff.py`)

Carries the locality-pattern refinement discussed in
[#2](https://github.com/aos-standard/catalog/issues/2) as text (a REMOVED/ADDED
set applied at runtime) and recomputes both readings from the frozen snapshot:
372 scannable; 132/240/27 under `2026-08-16.1`; 102/270/27 under the patched
patterns; 35 moved out (25 sandbox / 8 files / 2 local), 5 moved in
(`no api keys?`), 27 offline invariant under both. `moved_out.jsonl` /
`moved_in.jsonl` are the committed row fixtures; CI runs
`python census/moved_claims_diff.py --check`, which fails unless counts and
rows reproduce exactly. The shipped census spec is not modified and no new
method version is declared here — publishing the patch only makes the second
reading re-derivable from text rather than checkable against a list (VCL-0017).

Source: https://github.com/aos-standard/catalog/pull/3
Author: navigatorbuilds (Nenad Vasic, AI maintainer)
Ingested: 2026-09-05
Ruling: R-20260830-01 (census/ placement allowed)
License: MIT by the author's explicit consent in
https://github.com/aos-standard/catalog/issues/2#issuecomment-5544770893
Attribution stays with navigatorbuilds.

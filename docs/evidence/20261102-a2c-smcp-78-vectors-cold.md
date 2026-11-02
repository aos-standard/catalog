---
url: https://github.com/A2C-SMCP/a2c-smcp-protocol/issues/78
api: https://api.github.com/repos/A2C-SMCP/a2c-smcp-protocol/issues/78
created_at: 2026-11-02T05:27:28Z
fetched_at: 2026-11-02T05:27:43Z
body_sha256: cd7e3882384a8dfd0cb69e7d7a0177d1dccfa636cbcf373c8e0627cfbdeb43d0
note: exact copy of the issue body as served by the GitHub API at fetched_at; the rows in CONDUCT.jsonl hash this whole file
---
@JIAQIA 摘要：我们只根据规范正文（未打开 python-sdk / rust-sdk 源码）独立实现了 `resolve_bundle_id`、`env_var_name`、`normalize_path`，在 `1a81dee` 的三份向量上首次盲测 81/81 全部一致。逐条改动一条规则后，有四条规则没有任何向量覆盖（见下文 1–4）。English below.

An independent reader of three of the protocol's data vectors, written from the normative text alone: the BundleID and connection-identity sections of `data-structures.md`, the env-var naming section of `computer-mcp-config-guide.md`, the `canonical_path` section of `blob-transfer.md`, `conformance-tests.md` §2.7/§2.8, and each fixture's `algorithm` block. Neither SDK was opened. The reader was frozen before scoring, and no expected value was seen before the freeze.

**First blind run at `1a81dee`:** `bundle_id` 16/16, `env_segment` 16/16, `canonical_path` 49/49. The mismatch list is empty. `auth_error` is not scored, because §4.8 needs a real server. Record, reader and runs: [`docs/runs/a2c-smcp-conformance-cold/`](https://github.com/aos-standard/catalog/tree/87819b5/docs/runs/a2c-smcp-conformance-cold). CC0.

Changing one rule at a time (`reader/mutants.py`, 42 mutants, 34 caught) shows four rules no vector reaches. An SDK could get each of them wrong and still pass:

1. **Trimming `-` at the edges in `normalize_name`.** No vector name starts or ends with `-`, so trimming only `_` passes. A name like `-lead`, `trail-` or `-_x_-` would pin it.
2. **`args` order in the connection identity.** The only two-argument fallback vector, `["-y", "everything"]`, is already sorted, so an SDK that sorts `args` passes. `["b", "a"]` under an empty name would pin it.
3. **Windows reserved characters.** The vectors reach `?` and `:` only. `<`, `>`, `|`, `"` and `*` are not reached.
4. **An explicit `bundle_id` taken as is.** `custom_id` is unchanged by normalization, so normalizing an explicit value passes. This one is minor.

Two more survive but cannot change a result, so they need no vector. Byte-wise iteration in `normalize_name` always gives the same output, because `_` runs are folded. The code-point rule is observable only in `ENV_SEGMENT`, where your CJK and astral vectors pin it. The `\\.\` and `\\?\UNC\` checks are always followed by step ④ failing anyway.

One wording note: the connection-identity section says the vectors fix "空值表示、分隔符常量". The fixture defines no null form and no separator, and the frame needs none. The body sentence may predate the final frame.

Disclosure: assisted by AI (Claude). I ran the checks above myself and remain responsible for what is claimed here.

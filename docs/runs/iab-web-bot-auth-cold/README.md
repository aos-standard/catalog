# IAB Web Bot Auth profile: a clean-room verifier on the conformance vectors, 91/91

An independent verifier for the Web Bot Auth (WBA) profile in
[IABTechLab/iab-agentic-primitives#4](https://github.com/IABTechLab/iab-agentic-primitives/pull/4), at head
`3bcfb96` (fork `KonstantinMirin/iab-agentic-primitives`). It was written from `WEB_BOT_AUTH.md`, the vectors
`README.md`, RFC 9421, RFC 8941, RFC 9530 and RFC 7638/8037. The module's Python code was not opened. Python standard
library, plus `cryptography` for Ed25519. Run on 2026-11-16 (UTC).

| Set | Cases | Same outcome (status and rule, or identity) |
| --- | ---: | ---: |
| Committed vectors (`positive/`, `negative/`) | 20 | 20 |
| `request_scenarios` | 43 | 43 |
| `directory_scenarios` | 11 | 11 |
| `response_scenarios` | 9 | 9 |
| `target_uris` (pass, and the computed `@target-uri` equals `wire`) | 8 | 8 |
| **Total** | **91** | **91** |

These are first-run numbers. The verifier was frozen before any expected value was compared (`FROZEN_V1.txt`), and
so was the harness that signs the scenarios (`FROZEN_HARNESS.txt`). Neither was edited afterwards.

## What else reproduces

- **Signature bases.** All 19 `expected_signature_base` values (every signed message in the committed vectors) equal
  the verifier's own base byte for byte. The one exception is `negative/005`, which carries no base because it does
  not parse.
- **Signatures.** Re-signing each base with the published seed reproduces all 19 committed `Signature` values byte for
  byte. The three seeds derive from `sha256("aamp-wba-test/<name>")` as stated, and each `kid` is the RFC 7638
  thumbprint (`runs/base_and_resign_v1.txt`).
- **Scenarios.** `scenario_harness.py` signs each scenario from the data in `scenarios.json`, following the README's
  "Scenarios" section. Each `target_uris` GET is signed over its stated `wire` value and verified from its `url`. So
  the verifier's target-URI rule is checked against the file, not against itself.

## Which checks the shared files exercise

`mutation_battery.py` turns off one check of the frozen verifier at a time, then reruns all 91 cases. 26 of the 29
mutants are caught, each by the cases its rule names (`runs/mutation_battery_v1.json`). This confirms the README's
note that `negative/001`, `003`, `006` and `007` verify once their check is removed, and that `004` verifies under
lookup by `keyid` alone.

Three mutants pass every vector and every scenario:

| Mutant | Rule it removes |
| --- | --- |
| M15: the response signer's origin is not compared with `expected_origin` | `origin-mismatch` |
| M24: a directory `kid` is not compared with the key's thumbprint | `directory-kid` |
| M28: a directory signature's `tag` is not checked | `directory-tag` |

The module's own unit tests do cover all three: `test_wba_response.py` for `ORIGIN_MISMATCH`, and
`test_wba_directory.py` lines 218 and 276. I opened them after both freezes, read them only and did not run them. So
the gap is in the language-neutral files only. Another implementation graded through the adapter cannot fail on these
three rules.

## Three proposed vectors

`proposed/` holds one negative vector per gap. Each is in the committed vectors' format and signed with the published
seeds at the same clock. `build_proposed.py` rebuilds them byte for byte.

| File | Expected | What else is valid |
| --- | --- | --- |
| `x01-response-other-origin.json` | `403 origin-mismatch` | other.example.com's key, directory and request binding |
| `x02-directory-kid-not-thumbprint.json` | `403 directory-kid` | the signature and `Content-Digest` over the edited directory |
| `x03-directory-signature-wrong-tag.json` | `403 directory-tag` | the directory signature apart from its tag |

`check_proposed.py` shows that the frozen verifier refuses each one with its rule. It also shows that the mutant that
drops exactly that rule accepts it, so no other check refuses it (`runs/check_proposed.txt`). The `tier` value
(`profile`) is my guess: I did not run Cloudflare's library.

## Exposure

Before freezing, I read the vectors README, which names every negative vector with its status and rule. The file
layout also says which vectors are positive. So the 20 committed vectors are not a blind read. The scenarios' expected
outcomes, tiers and names were stripped before the harness was written (`split_inputs.py`), so the 71 scenarios were
graded blind. Neither `conformance/PROTOCOL.md` nor the interop harness was opened.

## Reproduce

Put the PR's tree at `3bcfb96` in `upstream/`, next to `reader/`. The scripts read `keys.json` and the vectors from
there.

```
python -I split_inputs.py                                  # inputs/ and answers/
python -I run_vectors.py --score                           # 20/20
python -I scenario_harness.py > scenarios_v1.json && python -I score_scenarios.py scenarios_v1.json   # 71/71
python -I check_bases.py                                   # 19/19 bases, 19/19 signatures
python -I mutation_battery.py                              # 26/29 caught
python -I build_proposed.py && python -I check_proposed.py
```

Run the scripts from a directory that holds no other Python files. The upstream files are pinned by sha256 in
`upstream_pins_3bcfb96.txt` and are not copied here. Files: `reader/`, `runs/`, `proposed/`, `FROZEN_V1.txt`,
`FROZEN_HARNESS.txt`, `upstream_pins_3bcfb96.txt`, `SHA256SUMS`. My files are under the catalog's MIT license. The
three proposed vectors may also be taken into the upstream repository under its Apache-2.0 license.

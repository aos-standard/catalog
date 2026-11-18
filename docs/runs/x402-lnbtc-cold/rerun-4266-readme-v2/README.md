# A reader updated from the current README on PR #4266: 203/206, and what the `trusted_proxy` sentence leaves open

This is a rerun that MajorTal asked for in x402#4266: a reader written from the vectors README as it now stands, on
the fixture at `dc77b23`. `b19934b`, the head on 2026-11-18, has the same README, fixture and spec bytes
(`upstream_pins_dc77b23.txt`). Run on 2026-11-18 (UTC).

- `reader/lnbtc_binding_v2.py` is the frozen `../reader/lnbtc_binding_v1.py` plus one change, written from the
  README's Inputs sentence on `config.trusted_proxy` and nothing else. With a trusted proxy, `http_server_adapter`
  reads `X-Forwarded-Host` and `X-Forwarded-Proto` and validates every hop "as it does Host".
- I took "as it does Host" to mean what v1 does with `Host`: each hop must be well formed and name the configured
  origin (or scheme). I also kept the `Host` check. The payment reader and everything else are unchanged.
- Frozen before the run (`FROZEN_V2.txt`). Exposure: the five cases' expected outcomes were known before v2 was
  written, from the PR description and the 2026-11-14 rerun.

| Section | Cases | v1 (2026-11-14) | v2 |
| --- | ---: | ---: | ---: |
| `http_server_adapter` | 47 | 42 | 45 |
| all five sections | 206 | 200 | 203 |

In `http_server_adapter`, four cases that v1 got wrong now agree: `forwarded-proto-url`, `forwarded-proto-crlf`,
`forwarded-proto-empty-hop` and `forwarded-host-malformed-hop`. Two cases are refused where the fixture expects a
binding:

| Case | Input | v2 | The fixture's reading |
| --- | --- | --- | --- |
| `forwarded-host-hop` | `Host: internal:8080`, `X-Forwarded-Host: api.example.com, proxy:8080` | refused: `Host` is not the configured origin | `Host` is not compared with the origin when a trusted proxy is configured, and a later hop only has to be a well-formed authority |
| `forwarded-proto-hops` | `X-Forwarded-Proto: https, http` | refused: hop `http` is not the configured scheme | every hop only has to be a scheme token |

`forwarded-proto-hops` agreed under v1, which ignored the header. So the sentence admits two readings, and the fixture
decides between them: "validate every hop" means well formed, not "names the configured origin", and `Host` is no longer
the authority source.

The other three differences are unchanged from v1 and unrelated: `request-origin-not-configured` and
`invoice-nonzero-padding` differ in the reason only, and `invoice-nonzero-padding-n` is the reader's padding gap.

Files: `reader/`, `run_v2.json`, `run_v2.stdout`, `score_v2.json`, `FROZEN_V2.txt`, `upstream_pins_dc77b23.txt`,
`SHA256SUMS`. MIT. Reproduce: `python -I ../reader/split_inputs.py exact_lnbtc.json inputs.json`, then
`python -I reader/run_blind_v2.py inputs.json run_v2.json`, then `python -I ../reader/score_v2.py run_v2.json exact_lnbtc.json score_v2.json`.
The runner needs `../reader/lnbtc_binding_v1.py` and `lnbtc_payment_v1.py` next to it.

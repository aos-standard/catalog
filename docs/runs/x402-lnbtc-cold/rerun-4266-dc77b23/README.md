# The frozen readers on PR #4266 at `dc77b23`: 200/206

The two readers in `../reader/`, unchanged since their freeze on 2026-11-10 (`../FROZEN.txt`), run once on the
fixture of x402 PR #4266 (a draft stacked on #3727, which follows up this record). Same three commands as
`../README.md`, with the same `split_inputs.py`, `run_blind.py` and `score_v2.py`. Run on 2026-11-14.

| Section | Cases | Same outcome | Same outcome and reason |
| --- | ---: | ---: | ---: |
| `http_binding` | 32 | 32 | 32 |
| `http_server_adapter` | 47 | 42 | 41 |
| `mcp_binding` | 28 | 28 | 28 |
| `client` | 17 | 17 | 17 |
| `facilitator_settle` | 82 | 81 | 80 |
| **Total** | **206** | **200** | **198** |

## The seven new cases

Six agree with no change to the readers: `arguments-nan`, `arguments-infinity`, `arguments-utf16-member-order`,
`mcp-server-differs`, `invoice-duplicate-payment-hash` and `invoice-description-hash-and-inline`.

`invoice-nonzero-padding-n` does not: the reader does not check the padding bits of the `n` field, as it does not for
`p` (the earlier `invoice-nonzero-padding` finding), so it settles where the case expects
`invalid_exact_lnbtc_invoice_decode_failed`.

## The earlier disagreements

The five forwarded-header cases still differ. The fixture now states `config.trusted_proxy: true`, but the frozen
reader predates that member and does not read it. `request-origin-not-configured` and `invoice-nonzero-padding`
differ in the reason only, as before. The readers were not edited for this run, so these show what changed in the
fixture, not what a reader updated to the new text would do.

## Exposure

The PR description, which names the new cases and their outcomes, was read before the run. The readers were frozen
before the PR existed, so they could not be fitted to it. Two of the new cases (`arguments-nan`,
`arguments-utf16-member-order`) came from this record's candidates.

Files: `run.json`, `run.stdout`, `score.json`, `upstream_pins_dc77b23.txt`, `SHA256SUMS`. CC0.

# x402 `exact` on `lnbtc` shared vectors (PR #3727 at `63d5640`): an independent reader from the text, blind 194/199

Two readers written from `specs/schemes/exact/scheme_exact_lnbtc.md` and the Layout, Inputs and Expectations
sections of `specs/schemes/exact/vectors/README.md`, frozen, then scored once against `exact_lnbtc.json`
(`fixture_version` 1, 199 cases). Standard library only: JCS, BOLT11 (bech32, tagged fields, signature) and
secp256k1 recovery are written in the files here.

## Result

| Section | Cases | Same outcome | Same outcome and reason |
| --- | ---: | ---: | ---: |
| `http_binding` | 32 | 32 | 32 |
| `http_server_adapter` | 47 | 42 | 41 |
| `mcp_binding` | 25 | 25 | 25 |
| `client` | 16 | 16 | 16 |
| `facilitator_settle` | 79 | 79 | 78 |
| **Total** | **199** | **194** | **192** |

"Same outcome" means the same digest, or a rejection where a rejection is expected (for `client`, also the same
`payer_called`; for `facilitator_settle`, every step, with every listed field on success). "Reason" also compares the
error string and, for settlement, the step number. Open cases count when the result is one of the listed outcomes and
not the forbidden digest. Run: `runs/run_63d5640_v1.json`; every scored value: `runs/score_63d5640_v1.json`.

## Freeze and exposure

- The readers were frozen at 2026-11-10T23:16:45Z (`FROZEN.txt`, sha256 of each file) and run once.
- Before the freeze, the vectors were read only through `reader/split_inputs.py`, which drops `expect`, `note` and
  `open_questions`. The case ids and input values were seen. The spec's "Request Binding Test Vectors" section and the
  README's "Case groups" and "Not covered" were not read. No SDK code and no other implementation was read.
- The spec's own `PaymentRequirements` and `PaymentPayload` examples were read, since they sit in the normative text.
  They are the base documents of `client` and `facilitator_settle`.
- **The scorer was changed after the run.** `reader/score.py` assumed open outcomes are a list and that settlement
  expectations sit on the case. Both were wrong: outcomes are a named object and expectations sit on each step. It
  crashed before printing any score. `reader/score_v2.py` was written after seeing those two shapes. The run file was
  not regenerated (its sha256 is in `FROZEN.txt`). `score.py` is kept.

## The seven disagreements

**Five are one finding: the inputs do not say that X-Forwarded-* comes from a trusted proxy.**

| Case | Expected | This reader |
| --- | --- | --- |
| `forwarded-host-hop` | binds, taking the authority from `X-Forwarded-Host` | rejects: `Host` is `internal:8080` |
| `forwarded-proto-url`, `forwarded-proto-crlf`, `forwarded-proto-empty-hop` | reject a malformed `X-Forwarded-Proto` hop | binds: the header is not read |
| `forwarded-host-malformed-hop` | rejects a malformed `X-Forwarded-Host` hop | binds: the header is not read |

The text says the server "MUST validate the public origin against its configuration and reconstruct it only from
trusted proxy information when behind a proxy". The cases' `config` has `public_origin` and `bound_headers` and
nothing about proxies, so a reader cannot tell that these hops are trusted. This one took them as untrusted and did not
read them. A `trusted_proxy` (or similar) member in `config`, or a sentence under Inputs, would let a reader from the
text get these five right.

**Two differ only in the reason.**

- `request-origin-not-configured` (open, `http-adapter-origin-policy`): rejected, as the `reject` outcome lists, but
  with `invalid_exact_lnbtc_request_binding` where the outcome names `invalid_exact_lnbtc_request_mismatch`. The text
  lists binding failures under no local reason, so this reader used the binding reason for all of them.
- `invoice-nonzero-padding`: rejected at step 5, but as `invalid_exact_lnbtc_invoice_payee_mismatch`. This reader does
  not check that the padding bits of a 52-character `p` field are zero, so the altered field decodes, the recovered
  key differs and the payee check fails. The expected `invalid_exact_lnbtc_invoice_decode_failed` follows from reading
  "strictly decode" as including zero padding. The text does not list what strict decoding includes.

## What the cases pin: one rule changed at a time

`reader/mutants.py` changes one rule of the frozen readers in a copy and reruns all 199 cases
(`runs/mutants_63d5640_v1.json`). 26 of 36 mutants are caught. Two of the 26 are caught by an exception in the
reader rather than by a case's expectation: accepting control and non-ASCII header values, and accepting lone
surrogates.

**Not reached by any case:**

1. JCS member order by UTF-16 code units, rather than by code point (RFC 8785 section 3.2.3). They differ only for
   keys above U+FFFF beside keys in U+E000 to U+FFFF.
2. Rejecting duplicate member names in `params_json` ("including duplicate object member names").
3. Rejecting `NaN` and `Infinity` in `params_json`. They are not JSON, but several parsers accept them by default.
   This mutant survives partly because the JCS step refuses a non-finite number anyway; the gap itself was confirmed
   by searching the inputs: no case contains `NaN` or `Infinity`.
4. Rejecting an inline description `d` beside the description hash ("no inline description").
5. A `p`-multiplier amount whose last digit is not 0 (BOLT #11).
6. A second valid `p` field.
7. The client's check of `requestBindingParams.server` against its intended MCP server.

Three more mutants survive because, on these inputs, another check gives the same outcome: authority syntax in the
URL (the host character check rejects the same values), uppercase hex in the preimage (the hash check rejects it,
with another reason), and comparing parameters without JCS (equal objects compare equal either way).

`runs/candidates_63d5640.json` has one candidate `mcp_binding` case for each of 1 to 3, in the vectors' layout, each one
change from an existing `params_json` case. The expectations are this reader's. For 4 to 7 a case would need a
re-signed invoice or a client base for MCP, and none is offered here.

## Files

| File | What |
| --- | --- |
| `reader/lnbtc_binding_v1.py` | `http:1`, the server adapter and `mcp:1`, with JCS. Readings are marked R1 to R7 |
| `reader/lnbtc_payment_v1.py` | client validation, `/settle` and the replay store, with BOLT11 and secp256k1. Readings P1 to P11 |
| `reader/split_inputs.py` | the inputs-only copy the readers ran on (sha256 in `FROZEN.txt`) |
| `reader/run_blind.py` | runs both readers on that copy |
| `reader/score.py`, `reader/score_v2.py` | the scorer that crashed, and the one used |
| `reader/mutants.py`, `runs/mutants_63d5640_v1.json` | the one-rule battery |
| `reader/make_candidates.py`, `runs/candidates_63d5640.json` | the three candidate cases |
| `upstream_pins_63d5640.txt` | the PR head and the sha256 of the three files read |

To rerun: fetch the three files at `63d5640`, then
`python3 -I -B reader/split_inputs.py exact_lnbtc.json inputs.json`,
`python3 -I -B reader/run_blind.py inputs.json run.json` and
`python3 -I -B reader/score_v2.py run.json exact_lnbtc.json score.json`.

The expectations of the candidates and the readings are this author's and have not been agreed. CC0.

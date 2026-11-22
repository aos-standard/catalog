# Rerun on agent-did #306 (`d09ca9f`): the five gaps are closed; one small one left

Asked for in [agent-did#127](https://github.com/edisonduran/agent-did/issues/127#issuecomment-7084711440): once #306
is merged, rerun the battery, "especially the record-first and literal-URL mutants". #306 was merged at
2026-11-22T19:52:48Z as `d09ca9f`. Its `http-verification-vectors.json` has 95 vectors: the 84 earlier ones unchanged,
two `steps` sequences, and nine `-literal` URL twins.

The reader is the rc.5 one, unchanged (`../rerun-rc5-76b4f73/reader/agent_did_http_v2.py`, sha256 `01ab9074…`,
frozen 2026-11-22T14:28:30Z on the rc.5 text). Only the runner is new: it runs `steps[]` as the fixture's `usage`
defines them. `PREDICTION.txt` states the expected result and was written before scoring.

## Result: 94/95 verdicts, 92/95 reasons, as predicted

| Vectors | Verdicts | Reasons |
| --- | --- | --- |
| the 84 earlier ones | 84/84 | 82/84 (the same two as before) |
| `accept-valid-after-forged-same-nonce`, `reject-replayed-at-expires` (`steps`) | 2/2 | 2/2 |
| the nine `reject-url-*-literal` | 8/9 | 8/9 |

All three differences come from the reader, and #306 settles each one in the fixture's favour:

- `reject-url-non-canonical-ipv4-literal` (verdict) and `reject-url-non-canonical-ipv4` (reason): the reader was
  written from the rc.5 text, which let `0x5d.0xb8.0xd8.0x22` through. #306 adds to §6.5 item 4 that a host whose last
  label is a number is an IPv4 address and is normalized only as dotted-decimal.
- `reject-keyid-not-in-document` (reason): the reason table now says a `keyid` of the agent DID that its document does
  not list is `keyid_not_authorized`.

## The battery, rerun

These are the same mutant definitions as the rc.5 rerun: the rule toggles of `mutants_v2.py`, the source mutants of
`mutants_v2_src.py` (read unchanged by `reader/mutants_v3.py`), and the four code mutants that are not toggles
(`reader/extra_checks_v3.py`). The baseline difference above is left out of "caught".

**All five gaps from the rc.5 rerun are now caught:**

| Mutant | Caught by |
| --- | --- |
| `(keyid, nonce)` recorded before the signature is checked | `accept-valid-after-forged-same-nonce` |
| replay store drops the pair at `expires` | `reject-replayed-at-expires` |
| apostrophe allowed in query | `reject-url-apostrophe-in-query-literal` |
| percent-encoded dot segments allowed | `reject-url-encoded-dot-segment-literal` |
| IPv6 not required in RFC 5952 form (reader with `[…]` kept in `@authority`) | `reject-url-non-canonical-ipv6-literal` |

In total, 32 of 35 mutants are caught. Two of the three survivors only reflect how this reader is built: with
"required component" off, the order check still rejects, and with "key listed in the document" off, the
`assertionMethod` check still rejects.

**The third survivor points at a small gap, found through a defect in this reader.** The reader builds `@authority`
from the parsed host name and drops the brackets of an IPv6 literal. It gives `2001:db8:0:0::1` where the fixture signs
`[2001:db8:0:0::1]` (RFC 9421 §2.2.3 takes the authority of RFC 9110, brackets included). That is wrong, yet the
reader passes all 95 vectors. The reason is that every IPv6 vector is a rejection, and each one is rejected anyway:
either by the RFC 5952 rule or, with that rule off, on the signature. No vector accepts a request to an IPv6 host. So
a verifier that mishandles the brackets is caught only for the non-canonical form, and the fixture never shows it
accepting a correct one.

## Proposed vector (1)

`proposed/proposed_http_vectors_v3.json`, `proposed-accept-ipv6-host`: an accepted request to
`https://[2001:db8::1]/v1/verify?mode=fixture`, in RFC 5952 form, signed over `"@authority": [2001:db8::1]`. It uses
the fixture's own keys, DID, clock, `Date` and body, and Ed25519 makes it byte-reproducible. This frozen reader rejects
it (`signature_invalid`). The same reader with the brackets kept accepts it. So it separates the two.

## Reproduce

Fetch `fixtures/http-verification-vectors.json` at `d09ca9f` into `upstream/fixtures/` and check the hash in
`upstream_pins_pr306.txt`. Copy `../rerun-rc5-76b4f73/reader/agent_did_http_v2.py`, `mutants_v2.py` and
`mutants_v2_src.py` into `reader/`. Then:

```
python3 -I -B reader/split_http_v3.py upstream/fixtures/http-verification-vectors.json blind
python3 -I -B reader/run_v3.py reader/agent_did_http_v2.py blind/http_inputs.json run.json
python3 -I -B reader/score_v3.py run.json blind/http_expected_SEALED.json
python3 -I -B reader/mutants_v3.py reader blind/http_inputs.json blind/http_expected_SEALED.json m.json
python3 -I -B reader/build_proposed_v3.py upstream/fixtures/http-verification-vectors.json p.json
python3 -I -B reader/extra_checks_v3.py reader blind/http_inputs.json blind/http_expected_SEALED.json p.json x.json
```

`blind/http_inputs.json` hashes to `9a9bd68b…`. You need Python 3 and `cryptography`.

The same author wrote the reader, the runner and the proposed vector. CC0.

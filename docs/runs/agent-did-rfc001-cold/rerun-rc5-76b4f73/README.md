# Rerun on Agent-DID `v1.0.0-rc.5` (`76b4f73`): 84/84 HTTP verdicts, and what the vectors still leave open

Asked for in [agent-did#127](https://github.com/edisonduran/agent-did/issues/127#issuecomment-7064981675): rerun the
reader on the `v1.0.0-rc.5` fixtures, "especially for anything those vectors still leave open".

Two runs, kept apart:

1. **The first reader, unchanged** (`agent_did_check_v1.py`, sha256 `0308622a…`, frozen 2026-11-03) on the four files
   it read at `37a3190`.
2. **A new reader for the rc.5 HTTP profile** (`reader/agent_did_http_v2.py`), written from the rc.5 text and frozen
   before any expected value of `http-verification-vectors.json` was read. It was then run on the 84 HTTP vectors and
   on the interop vector.

## 1. The unchanged first reader: 39/42

| Fixture | At rc.5 | Agreement |
| --- | --- | --- |
| `jcs-vectors.json` | unchanged bytes | **32/32** |
| `metadata-commitment-vectors.json` | unchanged bytes | **5/5** |
| `canonical-document-reference.json` | changed (now a real base58btc key) | **1/1** |
| `interop-vectors.json` (`webvh`) | changed | `Content-Digest` 1/1; signature base, HTTP verdict and message verdict **0/3** |

The three misses are the rc.5 wire changes, not disagreements: the reader looks for the rc.4 `Signature-Agent` header
(ADR-006 D-8a), and it verifies a payload signature without the `agent-did/v1/message` prefix (RFC-001 §6.2.3).
`runs/run_rc5_v1_unchanged.json` and `runs/score_rc5_v1_unchanged.json` have the details.

## 2. The rc.5 reader: 84/84 verdicts, 82/84 reasons

Text used: RFC-001 §6.2.1, §6.2.3 and §6.5; the Anti-Replay guide ("Verifying", the reason table, the `NonceStore`
contract); ADR-006 D-8a; RFC 9421 §2; RFC 8941; RFC 9530. No SDK code and no generator script were opened.

| What | Agreement |
| --- | --- |
| `http-verification-vectors.json`, verdict (83 single, 1 two-step sequence) | **84/84** |
| the same, `reason` as named in the guide's table | **82/84** |
| signature base, where the reader built one | 19 of 24 equal. The other 5 differ on purpose: the four `reject-*-differs` vectors change the request after signing, and the non-canonical IPv4 one is signed over the normalized authority |
| `interop-vectors.json` (`webvh`): message signature, `Content-Digest`, signature base, HTTP verdict | **4/4** |

The two reason differences:

- **`reject-keyid-not-in-document`:** the fixture says `keyid_not_authorized`, the reader says `keyid_not_bound`. The
  guide's table defines `keyid_not_bound` as "`keyid` is not a key of the agent DID" and `keyid_not_authorized` as
  "`keyid` is not an `assertionMethod` key of the DID document". A `keyid` under the agent DID that the document does
  not list reads as the first. The table could say which reason applies when the key is missing from the document.
- **`reject-url-non-canonical-ipv4`** (`https://0x5d.0xb8.0xd8.0x22/…`): both reject, but the reader rejects on the
  signature, not on `url_not_normalized`. §6.5 item 4 asks for "a host that is lowercase ASCII …, a canonical
  dotted-decimal IPv4 address or a bracketed IPv6 address". `0x5d.0xb8.0xd8.0x22` is lowercase ASCII with no empty
  label, so the text as written lets it through, while a WHATWG URL parser reads it as `93.184.216.34`. The text
  could add that a host which a URL parser reads as an IPv4 address (hex or octal parts, fewer than four parts, an
  all-numeric last label) is normalized only in dotted-decimal form.

Readings the reader took where the text leaves room (marked R1–R7 in the code): field names compared
case-insensitively; one agent document built from all `keys` and registered under the agent DID only, as the fixture's
`usage` says; checks run in the order of the guide's reason table; a label with no `Agent-DID` member reported as
`signed_component_missing`; `url_not_normalized` checked after the time checks; any valid Agent-DID label accepts,
and the reason reported is that of the first label with `tag="agent-did"`; and for the interop vector, the given
verification method is taken as an `assertionMethod` key.

## 3. What the vectors do not pin yet: one rule changed at a time

`reader/mutants_v2.py` turns off one rule of the frozen reader, and `reader/mutants_v2_src.py` changes one rule in its
source. Each rerun covers all 84 vectors. **29 of 36 mutants are caught.** The battery confirms that the gaps from
the first run are closed, as #127 says. Caught: tag, alg, `created` skew both ways, `expires`, the lifetime cap and
its boundary, `keyid` binding, `Content-Digest` (also a dictionary with a second algorithm), component order, nonce
presence, nonce grammar and length, replay, and `@signature-params` re-serialization. The vectors for a missing
`Date` and for each dropped component are there and the reader agrees with them, but this reader cannot turn those
two rules off on their own (see the next paragraph).

Two survivors only show how this reader is built, not a gap in the vectors. With "required component" off, the order
check still rejects. With "key listed in the document" off, the `assertionMethod` check still rejects.

The five real survivors:

1. **A forged request consumes the nonce.** §6.5 item 6 says to record the pair "only after the signature has
   verified". A verifier that records it first passes every vector: the one sequence vector repeats a valid request.
2. **The last second of a nonce's life.** The guide's `NonceStore` contract keeps the pair "through the second
   `expires` inclusive". A store that drops it at `expires` passes every vector, because no replay is tried at
   `now == expires`.
3. **URL rules, for a verifier whose URL parser does not normalize.** 9 of the 16 `reject-url-*` vectors are signed
   over the components a normalizing parser derives: `?mode=hello%20world` for a space, `/v1/verify` for `/v1/../v1/verify`,
   `xn--bcher-kva.example` for `bücher.example`, and `[2001:db8::1]` for `[2001:db8:0:0::1]`. A verifier that reads the
   URL as written (an RFC 3986 split) and skips the rule still rejects these 9, on the signature. The mutants
   "apostrophe allowed in query", "IPv6 not required in RFC 5952 form" and "percent-encoded dot segments allowed" all
   survive. With a WHATWG parser they would be caught. So these vectors pin the rule for one family of parsers, and
   §6.5 item 4 exists so that "every URL parser derives the same" components.

## Proposed vectors (7)

`proposed/proposed_http_vectors.json` uses the fixture's own keys, DID, clock, `Date` and body. Ed25519 is
deterministic, so `reader/build_proposed.py` rebuilds the file byte for byte.

| id | Gap | Frozen reader | Reader with the rule off |
| --- | --- | --- | --- |
| `proposed-forged-does-not-consume-nonce` | 1 | `[false, true]` | `[false, false]` |
| `proposed-replay-in-last-second` | 2 | `[true, false]` | `[true, true]` |
| `proposed-url-apostrophe-in-query-literal` | 3 | reject, `url_not_normalized` | accept |
| `proposed-url-non-canonical-ipv6-literal` | 3 | reject, `url_not_normalized` | accept |
| `proposed-url-dot-segment-literal` | 3 | reject, `url_not_normalized` | accept |
| `proposed-url-encoded-dot-segment-literal` | 3 | reject, `url_not_normalized` | accept |
| `proposed-url-space-in-query-literal` | 3 | reject, `url_not_normalized` | accept |

The first one needs two different requests against one nonce store, so it uses a new field, `steps[]`. The
`*-literal` vectors are signed over the components as written, which is the counterpart of the existing ones. With
both, a verifier that skips the rule is caught whichever parser it uses. The IPv4 case is left out because the reader
itself lets that host through (see section 2). `reader/check_proposed.py` checks all seven: **7/7 isolate**.

## Reproduce

Fetch `docs/` and `fixtures/` at `76b4f73` into `upstream/` and check the hashes in `upstream_pins_rc5.txt`. Copy
`../reader/split_inputs.py`, `run_blind.py`, `score.py` and `agent_did_check_v1.py` into `v1/`. Then run from this
folder:

```
mkdir -p blind blind_v1
python3 -I -B reader/split_http.py upstream/fixtures/http-verification-vectors.json blind
python3 -I -B v1/split_inputs.py upstream/fixtures blind_v1
python3 -I -B v1/run_blind.py v1/agent_did_check_v1.py blind_v1/inputs.json run_v1.json 1704067230
python3 -I -B v1/score.py run_v1.json blind_v1/expected_SEALED.json
python3 -I -B reader/run_blind_v2.py reader blind/http_inputs.json blind_v1/inputs.json run_v2.json
python3 -I -B reader/score_v2.py run_v2.json blind/http_expected_SEALED.json blind_v1/expected_SEALED.json
python3 -I -B reader/mutants_v2.py reader blind/http_inputs.json blind/http_expected_SEALED.json blind_v1/inputs.json m1.json
python3 -I -B reader/mutants_v2_src.py reader blind/http_inputs.json blind/http_expected_SEALED.json m2.json
python3 -I -B reader/build_proposed.py upstream/fixtures/http-verification-vectors.json reader p.json
python3 -I -B reader/check_proposed.py reader p.json blind/http_inputs.json
```

The input files must hash to the values in `FREEZE.txt`. You need Python 3 and `cryptography` (tested with 3.4.8).

## Answer exposure

These were seen before the freeze:

- the top-level `description`, `usage`, `keysNote`, `clock`, the DIDs, and the key ids and relationships;
- the key structure of each vector, and how often each key and header name occurs across the vectors (for example 69
  carry `reason`, one carries `expectedSequence`, one uses lower-case header names, and one carries a
  `Signature-Agent` header);
- the rc.5 interop `signatureBase`, which `score.py` printed during the unchanged v1 run. It shows the
  `"agent-did";key="sig1"` line form.

No vector `id`, `rule`, `description`, `expected`, `reason` or HTTP `signatureBase` was read before the freeze.
`reader/smoke_selfsign.py` checked the reader against a request it signed itself, with a fresh key and no fixture.

The same author wrote the reader, the readings and the proposed vectors. Nothing here says what either SDK does
beyond the values the fixtures publish. CC0.

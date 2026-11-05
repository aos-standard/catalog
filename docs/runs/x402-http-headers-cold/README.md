# x402 HTTP header vectors (PR #4066 at `c3e23c9`): an independent decoder from the text, blind 16/16

x402 PR #4066 proposes `specs/transports-v2/vectors/http_headers.json`: 16 shared cases for decoding
`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE` and `PAYMENT-RESPONSE`, for every SDK to load. This record is a decoder
written by someone outside the project from the text alone, scored once on those cases. It then checks which
decoding rules the cases pin.

Text used: `specs/transports-v2/http.md` (each header carries a base64-encoded object), the Scope section of
`specs/transports-v2/vectors/README.md` (base64, then UTF-8, then JSON; the result must be an object; base64 is RFC
4648 section 4, with section 3.3's rejection of characters outside the alphabet), RFC 4648, RFC 3629 and RFC 8259.
The vectors README was written with the cases, so it is not independent of them. It is the only place that names the
base64 variant.

## First blind run (decoder v1, frozen before scoring)

| | Agreement |
| --- | --- |
| cases | **16/16** |
| case × header runs (a case runs once per listed header) | **30/30** |

The mismatch list is empty. Answer exposure: the case ids, the headers each case lists and the values were read
before the freeze, and no `note` or `expect` was. The ids name what most cases test (for example `json-null` and
`alphabet-space`), and the split of 10 rejecting and 6 decoding cases was seen while the layout was read.
`reader/split_inputs.py` sealed the notes and expectations, and `FROZEN.txt` has the hashes. Readings the text
leaves open are named B1–B5 in the decoder. B1 (padding required) and B5 (duplicate names) are cases the README
lists as not covered.

## What the cases pin: one rule changed at a time

`reader/mutants.py` changes one rule of the frozen decoder and reruns the cases (`runs/mutants_c3e23c9_v1.json`).
7 of 19 mutants are caught.

**Caught:**

- A decoder that drops characters outside the alphabet, as Python's default and Node's `Buffer.from(s, 'base64')`
  do. Only `alphabet-space` catches it.
- URL-safe `-` and `_` accepted (`alphabet-base64url`).
- The value percent-decoded first (`alphabet-percent-encoded-pad`).
- Latin-1 instead of UTF-8 (`utf8-text`).
- Any JSON value accepted, or arrays accepted (the six `json-*` scalar and array cases).

`alphabet-percent-encoded-pad` pins "do not percent-decode", not the alphabet: lenient decoders also reject it,
because dropping `%` leaves `3D` as data. So the strict alphabet rule of RFC 4648 section 3.3 is pinned by one case,
`alphabet-space`.

**Not reached by any case, and not on the README's "Not covered" list:**

1. `==` appended to a value that already fills its last quantum (RFC 4648 3.2).
2. `=` inside the value, as when two encodings are concatenated (3.3).
3. CR LF line breaks, as MIME (RFC 2045) writes base64 (3.1: none unless the referring spec says so).
4. Non-zero pad bits in the last character. RFC 4648 3.5 lets a decoder reject them, and the spec does not say
   whether an x402 decoder must.
5. JSON in UTF-16 with a BOM. The README decodes UTF-8, but a parser handed bytes may detect the encoding (RFC 4627
   section 3), as Python's `json.loads(bytes)` does.
6. `NaN` or `Infinity` as a member value (not JSON under RFC 8259 6, but accepted by default by several parsers).
7. Data after the JSON value.

The README's own list (missing padding, invalid UTF-8, a BOM, duplicate names) survives too, as it says. Trimming
spaces and tabs from the ends of the value also survives. `alphabet-space` puts its space inside the value, and HTTP
removes whitespace at the ends of a field value before a decoder sees it (RFC 9110 5.5).

`runs/candidates_c3e23c9.json` has one candidate case for each of 1–7, in the vectors' own layout, each one change
from an `http.md` example. For 1–3 and 5–7 the expectation is `reject`. Case 4 has none: it is a choice for the spec.
The expectations are this author's reading and have not been agreed. The frozen decoder agrees with all of them,
which shows only that the decoder and the candidates match each other.

## Files

| File | What |
| --- | --- |
| `reader/x402_header_check_v1.py` | the decoder, frozen before scoring (readings B1–B5) |
| `reader/split_inputs.py` | separates `note` and `expect` from the inputs |
| `reader/run_blind.py` | runs a decoder on the inputs, once per listed header |
| `reader/score.py` | compares as parsed JSON, as the README says; reasons are not compared |
| `reader/mutants.py` | the one-rule-changed battery (a mutant that raises is counted as rejecting) |
| `reader/make_candidates.py` | builds the candidate cases |
| `runs/run_c3e23c9_v1.json`, `runs/score_c3e23c9_v1.json` | the blind run and every scored value |
| `runs/mutants_c3e23c9_v1.json` | the battery |
| `runs/candidates_c3e23c9.json` | seven candidate cases |
| `FROZEN.txt` | hashes of the decoder and inputs at the freeze |
| `upstream_pins_c3e23c9.txt` | what was fetched, opened and not opened |

## Reproduce

Fetch `specs/transports-v2/vectors/http_headers.json` at `c3e23c9` (kychee-com/x402, the PR head) and check its
hash in `upstream_pins_c3e23c9.txt`. Then:

```
python3 -I -B reader/split_inputs.py http_headers.json blind
python3 -I -B reader/run_blind.py reader/x402_header_check_v1.py blind/inputs.json run.json
python3 -I -B reader/score.py run.json blind/expected_SEALED.json
python3 -I -B reader/mutants.py reader/x402_header_check_v1.py blind/inputs.json blind/expected_SEALED.json mutants.json
python3 -I -B reader/make_candidates.py blind/inputs.json candidates.json
```

`inputs.json` must hash to the value in `FROZEN.txt`. The decoder uses the standard library only.

The same author wrote the decoder, the readings and the candidates. No SDK code or test file was opened or run. CC0.

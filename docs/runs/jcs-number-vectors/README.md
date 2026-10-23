# JCS number vectors — RFC 8785 number serialization, 1001 doubles (CC0)

**Date:** 2026-10-23. **Why:** two independent clean-room verifiers of the same draft record format (ours and
babyblueviper1's, x402-foundation/tsc#4) carried a canonicalizer that got non-integer numbers wrong, found only when
vector 52 of `maximusrufus/work-acceptance-record` put one in a signed body. Ours refused floats; theirs wrote the
language's float form. RFC 8785 3.2.2.3 requires ECMAScript `Number::toString`. A canonical form that is wrong on
numbers agrees with other implementations only until the first amount with a decimal point.

`jcs-number-vectors.tsv` (tab-separated, `#` comment lines, then a header row) holds 1001 IEEE 754 doubles, each with:

- `bits`: the double's 64 bits (hex, little-endian order of the value as a big integer);
- `json`: a JSON number literal that parses to exactly that double;
- `expected`: its RFC 8785 serialization;
- `why`: which group it belongs to.

The groups: zero and negative zero; the switch points between decimal and exponent form (around 1e21 and 1e-7) with
their ulp neighbours; integers around ±2^53; the smallest subnormal, the largest subnormal, the smallest normal and
the largest finite; common decimals; amounts in cents written as JSON numbers; and a seeded random sample (600 bit
patterns, 300 decimals).

`expected` is Node.js v20.20.2 `String(x)`, cross-checked against an independent Python implementation (0 mismatches
of 1001). `build_vectors.py` rebuilds the inputs (seed 20261023).

## Run it

Python: `python3 check_python.py <module> <callable>` (the callable maps a Python value to `str` or `bytes`).

| implementation | result (2026-10-23) |
|---|---|
| `rfc8785` 0.1.4 (PyPI), `dumps` | 1001/1001 |
| `jcs` 0.2.1 (PyPI), `canonicalize` | 1001/1001 |
| `canonicalize` 4.0.0 and `json-canonicalize` 3.0.1 (npm) | 1001/1001 (JavaScript numbers are the reference here) |
| Python `json.dumps` | 902/1001: writes `0.0`, `-0.0`, `1000000000000000.0` and other integral doubles with a fraction |
| `canonicaljson` 2.0.0 (PyPI) | 902/1001, the same rows. It implements Matrix's canonical JSON, not RFC 8785; listed to show that the vectors separate the two rules, not as a defect |

The vectors exercise only numbers. They say nothing about string escaping, member ordering or Unicode.

Hashes: `FROZEN.txt`.

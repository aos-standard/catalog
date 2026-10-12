# Independent run — PriorSeal exact-call envelope matrix v1

A third reader, written from the published input contract alone, run over the
same bytes. Requested in
[probityai/agent-evidence-atlas#49](https://github.com/probityai/agent-evidence-atlas/issues/49#issuecomment-6087229885):
"A reader written by someone else, or a run by someone else on these same bytes,
is still the missing piece."

| | |
|---|---|
| Subject | `imokokok/PriorSeal@d84055319325e6eef5a0a275e0f2f78f5919bdb4`, `examples/open-evidence-lab-exact-call-matrix-v1/` |
| Run date | 2026-10-11 (UTC 12:40–13:05) |
| Environment | Ubuntu, CPython 3.x stdlib (+ `cryptography` for Ed25519 only), Node v20.20.2 for the shipped runner |
| Independent reader | `oel_exact_call_reader.py` — sha256 `a7aa5099515afab8000c04ad56f05ec57a4efc5f02c0f5984149276ad633fbf8` |
| Order of work | Reader written and run from `INPUT-CONTRACT.md` before `reader.mjs`, `verify.mjs`, `expected.json` or `report.json` were opened. `FROZEN_BEFORE_OPENING_THEIR_READER.txt` records the hashes at that point. |

## What was reproduced

| Check | Result |
|---|---|
| `MANIFEST.json` file digests | 17 of 17 match |
| EIP-712 digest, rebuilt from §2.1 | `0x9e404bfc63c56cda555b71c4e59237178edc7a428de7f50738804a1f092cf5b1` — equals the published value |
| Signer recovery (own keccak-256 and secp256k1) | `0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a` — equals `authorization.authorizer.address` |
| Acceptance signature, §2.2 | Ed25519 valid over sorted-key compact JSON of the acceptance without `signature` (575 bytes) |
| Reason-code sets, five cases | 5 of 5 equal to `expected.json` when the §5 code is merged into the set |
| Shipped runner, cold (`npm ci --ignore-scripts`, `node verify.mjs`) | exit 0, output byte-identical to the committed `report.json` (sha256 `f0104a0b…8c1e`) |

## One disagreement on the fixture bytes

`case-04-execution-evidence-unavailable`: `expected.json` has `bound: false`.
The independent reader returned `bound: true` with `EXECUTION_UNAVAILABLE`
reported beside it, not inside the binding reason codes.

§4 says `bound = reasonCodes is empty` and lists eight codes. §5 calls
`EXECUTION_UNAVAILABLE` "a separate class … never scored as a mismatch". The
text does not say whether the §5 code is a member of the set that decides
`bound`. Both readings fit the text; the fixture pins one of them.

## Two places where the text and the bytes differ, or the text is silent

1. §2.1 says `issuedAt`, `notBefore`, `expiresAt` and `maxUses` "are decimal
   strings in the JSON object". In `fixture/signed-authorization.json` the first
   three are JSON numbers (`1000`, `1000`, `2000`); only `maxUses` is a string.
   The digest is unaffected if the reader converts either form.
2. §2.1 lists the 15 struct fields and their Solidity types but not the JSON
   paths they are read from (`principalType` ← `authorization.principal.type`,
   `executor` ← `authorization.delegate.executor`, and so on). The mapping in
   the reader is an inference. It reproduces the digest, so it is the right one;
   it is not written down.

## Probes outside the fixture

These envelopes are **not part of the published matrix**. Each is the positive
control `case-00` with one change. `probe.py` builds them; `probe.mjs` feeds
them to the two shipped paths (`reader.mjs` and the PriorSeal profile via
`buildAuthorizedReceipt`, called the way `verify.mjs` calls it). Full output:
`probes.json`, `probes2.json`.

| Change to `case-00` | Independent reader | Lab reader (`reader.mjs`) | PriorSeal profile |
|---|---|---|---|
| `executedAt: 2001` (after `validUntil` 2000) | `OUTSIDE_TIME_WINDOW` | `OUTSIDE_TIME_WINDOW` | `OUTSIDE_AUTHORIZATION_WINDOW`, `OUTSIDE_TIME_WINDOW` |
| `nativeValue` as JSON number `1000000000000000` | `TRANSACTION_VALUE_MISMATCH` | bound | bound, `COMPLIANT` |
| `nonce` as JSON number `7` | `NONCE_MISMATCH` | bound | bound, `COMPLIANT` |
| `executedAt: null`, `observedAt: 2001` | bound | `OUTSIDE_TIME_WINDOW` | both window codes |
| `executionDataAvailable: false` and a different `target` | `CALL_TARGET_MISMATCH` + availability | both codes, one set | both codes, `NOT_ASSESSABLE` |
| `target`, `calldataHash` in upper-case hex | bound | bound | bound |
| `chainId` as a JSON string instead of a number | `CHAIN_MISMATCH` | `CHAIN_MISMATCH` | `CHAIN_MISMATCH` |
| `executedAt: 2000` (equal to `validUntil`) | bound | bound | bound |

Reading:

- **Row 1 is the two shipped paths disagreeing with each other.** The matrix
  exercises three of the eight field-map rows (`callTarget`, `calldataHash`,
  `transactionValue`). The time row is not exercised, and it is where the Lab
  reader and the profile produce different reason-code sets: in this fixture
  `intent.validUntil` equals `authorization.expiresAt`, the profile checks both,
  the field map names only the first.
- Rows 2–3: "strict string equality" in §4 is implemented by both shipped paths
  as equality after `String()` conversion. A reader that takes the phrase
  literally rejects a JSON number that the producer accepts.
- Row 4 is the independent reader's own reading of "fallback" (absent, not
  null). The shipped paths' reading is the more defensible one; it is listed
  because the text does not choose.
- Row 5: when evidence is unavailable and a field also differs, the profile
  reports `NOT_ASSESSABLE`. §5 and §7 do not state that precedence.

## What this run does not establish

- Nothing about PriorSeal beyond these files at this commit.
- Nothing about real-chain behaviour, calldata meaning, or economic outcome.
- The probes are one person's guesses at loose rules, not a conformance suite.
- The independent reader has had no review other than its own self-checks
  (keccak-256 of `""` and `"abc"`, and the address derived from the published
  test key).
- No endorsement, integration or relationship between the projects.

## Reproduce

```bash
git clone https://github.com/imokokok/PriorSeal && cd PriorSeal
git checkout d84055319325e6eef5a0a275e0f2f78f5919bdb4
python3 -I /path/to/oel_exact_call_reader.py examples/open-evidence-lab-exact-call-matrix-v1
npm ci --ignore-scripts && python3 -I /path/to/probe.py "$(pwd)"
```

Run assisted by AI (Claude). The maintainer of this repository ran the commands
and is responsible for what is claimed here.

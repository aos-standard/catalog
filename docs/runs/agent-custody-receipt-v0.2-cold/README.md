# agent-custody receipt v0.2: a verifier written from the specification page, run on the published conformance vectors

Issue svayatta/agent-custody#185 asks for independent verifiers "written from the spec, not ported from our code", and
says the format is done when "a party we don't control has verified receipts with an implementation we didn't write".
This is such a run, from outside the project: a verifier in Python (`ac_receipt_check.py`, standard library plus
`cryptography` for Ed25519) written from `site/receipt/v0.2.md` at `bd57844` only, scored on the four vector files the
page points to. The reference verifier, the browser verifier, the Python verifier in the repository, and the vector
generator were not opened (`upstream_pins_bd57844.txt`).

## Result at `bd57844`

| Vector file | What it fixes | Reader v3 |
| --- | --- | --- |
| `canonical.json` | canonical JSON and digests of 6 values, a keyid, a DSSE envelope | all agree (6 canonical forms, 6 digests, keyid, signature) |
| `merkle.json` | 7 leaf hashes, roots at 8 sizes, 7 inclusion proofs, 8 consistency cases (one must fail) | all agree |
| `audit.json` | 4 pairs of signed tree heads with a consistency proof | **4/4** on the failing-check names |
| `receipts.json` | 97 bundles with keys, options and `expected.failing` | **97/97 on the verdict** (pass or fail); **95/97 on the exact set of failing check names** |

The two cases whose failing names differ are both re-signed approval records, and in both the reference fails one or
two checks more than the page's wording gives a reason for (finding 4 below); on the verdict the two readers agree.

Three versions of the reader were scored, each frozen before its run and kept with its run (`FROZEN.txt`):

| Version | receipts exact | verdict | What changed before the next version |
| --- | --- | --- | --- |
| v1 (`e857689a…`) | 78/97 | 92/97 | eight edits: `isError` defaults to `false` in the upstream content digest; hash-only log lines are `{"hash"}` objects; the audit's extends check is skipped when the order is wrong; "signer observations" are the envelope's own signature keyids; a malformed approval payload or an envelope withheld beside clear arguments fails the signatures check only; the precommit's approval is judged on forwarded calls only; one ordering change later reverted |
| v2 (`074b3503…`) | 93/97 | 97/97 | two edits: the order check reads the two proofs' indexes whether or not the authorization's proof verifies; the precommit's approval envelope is judged by its own shape, not by the receipt's capture note |
| v3 (current) | 95/97 | 97/97 | |

Every edit came from a vector the reader got wrong and from re-reading the page, none from the reference code. Same
author for the reader and this table: the numbers say the reader reproduces the published verdicts, not that the page
is complete. Where the page is not complete is the point of the findings.

## Findings (for the spec, not defects of the implementation)

1. **16 check names the vectors expect are not on the page's list.** `vectors.md` says "the names are listed on the
   specification". `v0.2.md` §Verification names 33 checks; `receipts.json` and `audit.json` expect these 16 that it does
   not name: `authorization names this call`, `authorization log inclusion proof`, `authorization logged before
   execution`, `authorization carries this approval`, `authorization approval was valid`, `strict mode in force`,
   `strict: call precommitted before forwarding`, `delegation chain to the principal`, `tree head names the expected log`,
   `reconciliation links the original operation`, `reconciliation lookup matches authorization`, `reconciliation provider
   status`, `older tree head signature`, `newer tree head signature`, and the two concrete `withheld <path>` lines. The
   authorization, strict, log-id and reconciliation checks are described in prose on the page (the reader implements
   them from that prose and reports them under the vectors' names); delegation chains (`parent`, `agentKey`) are not on
   the page at all. A second implementation written from the page alone cannot name 14 of the 16 without the vectors.
2. **The upstream content digest when the result has no `isError`.** The page: "`contentDigest` is the digest of
   `{ content, isError }` of the result" and canonical JSON drops `undefined`. The vectors' results carry no `isError`
   and the digest is over `{ content, isError: false }` (three passing vectors turn on it). A sentence saying `isError`
   defaults to `false` would settle it.
3. **A hash-only log copy is not lines of strings.** `vectors.md`: "treat its strings as the lines of a log copy".
   The three `remote-log-*` cases carry `{"hash": "<hex>"}` objects; a reader that follows the sentence raises.
4. **Two re-signed approval vectors the page does not explain.** `resigned-approval-consumed-after-expiry` changes only
   `approval.consumedAt` (to after `expiresAt`); the reference fails `approval valid at forward time` and also
   `approval payload binding`. `resigned-approval-checked-before-issuance` changes only `approval.checkedAt` (to before
   `issuedAt`); the reference fails `approval valid at forward time` and also `approval consistent with execution` and
   `authorization approval was valid`, although the precommit's own `checkedAt` is inside the window. The page's text
   for `payload binding` (principal, agent, tool, arguments, action fields), for `consistent with execution` (an
   approved, consumed record with matching signer observations) and for `authorization approval was valid` (the
   precommit's own status, signers and check time) gives no reason for the extra names. Either the page or the
   expected names should move. Both readers reject both receipts.
5. **One description disagrees with its vector.** `resigned-note-path-proto`'s description says "both verifiers fail
   `structural parts in clear` instead"; its `expected.failing` is `withheld __proto__.x` and `log inclusion proof`.
   The reader follows the page (a path that names no structural part is allowed; a named path with no commitment fails
   its own line) and agrees with the expected names, not the description.

None of these is a receipt that verifies but should not; the two reader-versus-reference differences are the reference
being stricter on re-signed records, so this is published rather than sent to the address in `SECURITY.md`.

## Readings fixed where the page leaves room (R1–R26, marked in the code)

R1 canonical key order is UTF-16 code-unit order and non-ASCII is unescaped. R2 a "forwarded call" is one whose
`execution.status` is `executed`, `failed` or `error`; `denied` and `withheld` are refusals. R3 the approval payload's
schema: exactly the eleven named fields, `version` `0.1`, a UUID id, hex-64 `argsDigest`, times with an offset and
`expiresAt` after `issuedAt`, a safe-integer `amount`, nonempty `currency` and `beneficiary`; an unknown field is
malformed. R4 payload binding compares principal, agent, tool, the digest of the full arguments (when in clear) and the
action fields by name or by the `fields` map. R5 `checkedAt` and `consumedAt` (when present) must lie in
`[issuedAt, expiresAt)`. R6 consistency: approved, a consumption time, and `approverKeyids` equal to the keyids on the
envelope's signatures. R7 signatures: distinct trusted keyids whose signature verifies, at least `requiredApprovers`.
R8 authorization: names this call when it is issuer-signed, of the authorization predicate type, with this receipt id and
subject; its tree head and proof are checked like the receipt's; it precedes the receipt when its leaf index is smaller;
it carries this approval when envelope, threshold and field map are equal. R9 strict: `issuer.strict` is `true`, and a
forwarded call carries an authorization. R10 an enforced deny pairs only with `denied`; `enforced: false` may pair with
anything; `allow` never pairs with `denied`. R11 the upstream content digest is over `{content, isError}` with `isError`
defaulting to `false`. R12 Stripe deliveries: HMAC over `<t>.<rawBody>`, `t` within 300 s of the receipt's timestamp, the
bound value appearing in the result outside `_meta`. R13 the log id is compared only when one is expected. R14 a log
copy line is the leaf string, a hex leaf hash, or `{"hash"}`. R15 a delegation chain: each link signed by the key its
parent names in `agentKey`, the root by the attested principal key, windows nested as instants, scopes narrowing, one
principal. R16 reconciliation: the embedded original is issuer-signed, names the operation and idempotency key and
precedes this leaf; the lookup's digest equals both `lookupDigest`s; the provider record is the first content item's
JSON, its status maps through `confirmed`/`failed` to the operation's status and its identity path holds the key.
R17 a gateway receipt must carry a delegation and a non-null policy. R18 the grant window is enforced on forwarded
calls; a refusal outside the window passes with a note. R19 scope is checked on `executed` and `failed`. R20 a
commitment is `{ "$custody": "withheld", sha256 }` or the encrypted form with a 16-byte tag; anything else is data.
R21 the structural parts a note may not name are listed in `STRUCTURAL_PREFIXES`. R22 a time without an offset is not
a time. R23 the issuer keyid must equal the keyid of the verifying signature. R24 after a failed signature, payload type
or structural check nothing else is decided. R25 the policy's `errors` may be a named commitment on an allow.
R26 without a delegation the principal must be `claimed`.

## Files

| File | Purpose |
| --- | --- |
| `ac_receipt_check.py` (v3), `ac_receipt_check_v2.py`, `ac_receipt_check_v1.py` | the verifier and its earlier versions, digests in `FROZEN.txt` and `SHA256SUMS` |
| `run_vectors.py` | scores a reader on the four files; classifies each receipt case by whether its expected names are all page-named |
| `run_bd57844_v3.json`, `_v2`, `_v1` | the three scored runs, with every case's expected and produced names |
| `FROZEN.txt` | freeze times, the answer exposure, and every edit between versions |
| `upstream_pins_bd57844.txt` | what was fetched, read, and not opened |

## Not covered

No mutation battery; the Go verifier the issue plans does not exist yet to compare with; the provider-delivery path was
exercised by the Stripe vectors only; the GitHub delivery form, witness countersignatures, checkpoints and the log API
are implemented from the page but no vector covers them. CC0.

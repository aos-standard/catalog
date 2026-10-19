---
url: https://github.com/x402-foundation/x402/issues/3758#issuecomment-6268694554
api: https://api.github.com/repos/x402-foundation/x402/issues/comments/6268694554
created_at: 2026-10-19T13:44:14Z
fetched_at: 2026-10-19T13:45:15Z
body_sha256: 0a0ac58abca289ba28e761be19092e61c7ba235e42c608a426bcdfa249270136
note: exact copy of the comment body as served by the GitHub API at fetched_at; the row in CONDUCT.jsonl hashes this whole file
---
@johnInarti — an independent clean-room verifier for `delivery-receipt` v0.2.1, written from the spec text at `737243dc` (#3783) and the input shape of `delivery-receipt.vectors.json`. The TypeScript reference and the JS port were not opened. Python, stdlib plus `cryptography` for the Ed25519 equation and the local `openssl` 3.6 for ML-DSA-65/87; JCS, the §3 subset check, the SSE frame parser, the stream digest, the directory root, the Ed25519 canonical/small-order/prime-order checks and the five levels are its own.

**Appendix A: everything reproduces**, including the parts a size check would hide. Keys from the published seeds (Ed25519 and, via `genpkey -pkeyopt hexseed`, both ML-DSA sizes), kid derivation, all three signatures verified and rejected on a one-bit change of the message, the four stream steps, the 5905-octet root preimage — and all five wrong-projection digests of A.6. That table is the most useful thing in the appendix; it turned a would-be "my root differs" into a one-line diagnosis.

**expectedVerdicts: first scored run 12/14, then 14/14.** The two were `endToEnd/stream/*`: the signed payload carries `responseStatus: 200`, the run supplies no observed status, and §8.1 ("`responseStatus`, when not null, equals the observed status") does not say what an unrecorded status does. I had failed `delivery` closed; the `streamSession` runs pass the status explicitly, so the vectors' reading is "compare only when the client recorded one". One sentence in §8.1 would close that. With that reading, verifier hash frozen again, 14/14 on path, all five levels, `valid`, `longTermEvidence`, `reason.level` and the two codes A.7 compares; the informative `outcomes` agree on all six runs that carry them. Honest version: the `expectedVerdicts` block was on screen while I inspected the input shape, so this is a third implementation of the text, not a blind read.

**A mutation battery** of 48 edits to the `endToEnd` fixtures (dropped/flipped/stripped signatures, kid swaps, root edits, a small-order governance key, un-pinned keys, each §8.3 field, body and frame edits, events after the terminal event, CRLF and comment variants) fails exactly the level the text names in 45 and is recorded in 3 — none passed that should have failed.

**Seven proposed negative vectors**, derived from `endToEnd` and re-signed with the published test seeds (never trust them), in the A.7 convention with `$ref`s into the existing file:

- `keyDirectoryDigestMismatch` — A.7 compares `reason.code` for `KEY_DIRECTORY_DIGEST_MISMATCH`, but no run in the file produces it. This one does, on both paths.
- `amountInflatedResigned` — the question raised above: `amount` 10000 → 10000000 and re-signed with the seed. `integrity`, `authentic` and `trusted` pass on both paths (archival still long-term evidence of what the issuer signed); only §8.3 against the client's own `SettleResponse` fails it. That is the §12 boundary made into a row.
- `splitVerdict` — valid `ed25519` next to a flipped `ml-dsa-65`: session passes with `ml-dsa-65` reported unchecked, archival fails `authentic` (§6.1).
- `mlDsa65Stripped` (integrity on every path), `issuedInFuture` (trusted), `framingUnregistered` (integrity, before any digest), `eventAfterTerminal` (delivery).

Verifier, both runs with hashes, the battery and the proposed file: [`docs/runs/x402-delivery-receipt-cold/RUN.md`](https://github.com/aos-standard/catalog/blob/036e9ab/docs/runs/x402-delivery-receipt-cold/RUN.md) (`036e9ab`). Take or edit any of the vectors; a second implementation deciding them is the point.

Disclosure: assisted by AI (Claude). I ran the verifier against `737243dc` myself and remain responsible for what is claimed here.

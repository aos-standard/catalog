# WIMSE HTTP signature test vectors: a clean-room reader on the 29 judged vectors

An independent reader for the WIMSE workload-to-workload HTTP signature profile, run on the vector set in
[draft-miao-wimse-http-signature-test-vectors-00](https://datatracker.ietf.org/doc/draft-miao-wimse-http-signature-test-vectors/00/).
That set is the seed corpus proposed in [FG-TIDA/themes#66](https://github.com/FG-TIDA/themes/issues/66). The reader
was written from these texts:

- [draft-ietf-wimse-http-signature-08](https://datatracker.ietf.org/doc/draft-ietf-wimse-http-signature/08/), Section 3;
- [draft-ietf-wimse-workload-creds-02](https://datatracker.ietf.org/doc/draft-ietf-wimse-workload-creds/02/), Section 5.1;
- workload-creds-03, Section 5.1.3;
- RFC 9421, RFC 8941, RFC 9530, RFC 7515 and RFC 7519.

No implementation's code was opened. Python standard library, plus `cryptography` for Ed25519 and P-256. Run on
2026-11-21 (UTC). The vectors were taken from the Internet-Draft text, because the Zenodo record answered 403 to this
network.

| Set | Cases | Same outcome |
| --- | ---: | ---: |
| Positive vectors P-01 to P-06 (accept, and the reader's signature base equals the given base) | 6 | 6 (P-06: see "Folding") |
| Message negatives N-01 to N-15 (N-09b at T0+300 and at T0+301 counted once) and N-21 | 17 | 17 |
| Behavior cases a verifier can show (N-17: one error surface; N-20: the probe; N-22: selection by tag) | 3 | 3 |
| Behavior cases about senders or servers (N-16, N-18, N-19) | 3 | not applicable to a reader |
| **Judged set** | **29** | **26 of 26 applicable** |

The reader was frozen before any vector body or expected outcome was read (`FREEZE.txt`): sha256 `09a91bf3…`,
2026-11-21T12:15:35Z. It was not edited afterwards. Before freezing, these were on screen: the table of contents (the
vector names), Section 2 (conventions) and Section 3 (keys, WITs, trusted audiences). The negative vectors' names say
what each one tests. Before the vectors, the reader was checked only on the base specification's own examples
(Figures 2 and 4 of -08), which both verify.

## Signature bases and signatures

- All six given signature bases equal the reader's own byte for byte.
- All six literal signatures verify under the WIT's `cnf.jwk`: P-01, P-04, P-05 and P-06 with vec-a-key, P-02 with
  vec-b-key, P-03 with ES256 vec-c-key.
- The decoy `sig1` in P-06 verifies under other-key, and its base also equals the given one.
- The N-15 signature verifies under svcC's ES256 key, as the entry says. The reader rejects it, because the WIT's
  `cnf.jwk` is Ed25519.

Message negatives are built from each entry's prose (`run_negatives.py`). A regenerated signature uses the published
keys and the reader's base builder, which matched all six given bases.

## Three things in the text

**1. Folding (P-06).** In P-06, `Signature-Input` is folded between `"@query"` and `"workload-identity-token"`, and the
continuation line carries one extra leading space. Under RFC 8792's single-backslash strategy, all leading whitespace
of a continuation line is removed. So the unfolded field reads `"@query""workload-identity-token"`, which is not a
valid inner list (RFC 8941). Read that way, the reader rejects P-06 as malformed (`runs/positives_strict.txt`). With the
one space restored, P-06 verifies and both bases match (`runs/p06_fold.txt`). Breaking that line at another point, or
using RFC 8792's double-backslash strategy, would remove the ambiguity.

**2. The WIT placeholder.** Section 2 defines the placeholder as `[WIT-x, full text in the Test Key Material section]`.
It says that the placeholder "is retained verbatim in the signed material". The messages and bases print
`[WIT-A，§2 全文]` instead: a full-width comma, "§2" (the keys are in Section 3), and Japanese for "full text". This
appears 12 times. The signatures are computed over the full token. With the full token substituted, all six verify.
With the placeholder kept as printed, every positive is rejected, because the placeholder is not a JWT
(`runs/positives_literal_placeholder.txt`). Suggested wording: "Signatures and signature bases are computed over the
full token text; the placeholder is presentational only."

**3. Against -09.** draft-ietf-wimse-http-signature-09 (2026-11-20) was published after the vector draft. Four points
touch the vectors:

- O-2 can close. -09 Section 3.7 adds the note that the example nonces are illustrative (#420).
- N-20 quotes "Section 5.1.4 of [workload-creds]". workload-creds-02 has no Section 5.1.4. -09 points to Section 5.1.3
  of workload-creds-03, "Validating the WIT" (#422).
- P-04 already follows -09's clarified CONNECT `@authority` rule: lowercase host, default port omitted (#419).
- -09 newly allows a request to carry a server-generated nonce from `Accept-Signature` (#369). There is no vector for
  this yet.

## Which rules the 29 vectors exercise

`mutation_battery.py` turns off one check of the frozen reader at a time, then reruns the judged message set: P-01 to
P-06 (P-06 with the space restored), and the 17 message negatives. 14 of the 39 mutants are caught. 25 pass every
vector (`runs/mutation_battery.txt`).

| Group | Mutants that pass every vector |
| --- | --- |
| WIT validation | issuer signature, `typ`, `exp`, `cnf.jwk.alg` policy, `sub` (M01–M05) |
| Validity window | `created` in the future (M06) |
| Required parameters | `nonce`, `created`, `expires` (M09, M10, M39) |
| Request coverage | `@method`, `@path`/`@query`, `@path` alone, Authorization, Workload-Identity-Token, Content-Type, Content-Digest (M13–M19) |
| Body | Content-Digest presence (M20) |
| CONNECT | `@path` covered (M22, M34; reader-specific, see below), `@authority` required (M23) |
| Two WIMSE signatures | first one used (M27) |
| Response coverage | `@status`/`@method;req`, `@path;req`/`@query;req`, Workload-Identity-Token, Content-Type/Digest (M32, M33, M35, M36) |

Three causes stand out:

- **N-01, N-03 and N-05 carry the P-01/P-03 signature over unchanged.** A verifier without the coverage, digest or
  `expires` check still rejects them, because the signature no longer verifies (M14, M20, M39 →
  `signature_invalid`). N-06 and N-07 regenerate their signatures, and they do isolate their rule.
- **N-08 does not say which key regenerates `sig1`.** It is built here with other-key, so a verifier that takes the
  first WIMSE-tagged signature still fails on the signature (M27). With vec-a-key, only the count check would catch
  it.
- **There is no vector in which only the WIT is wrong.** N-09 has an expired WIT, but its window has also passed.

M22 and M34 pass only because this reader cannot compute `@path` for a CONNECT request. That is a property of this
reader. A reader that computes `@path` as `/` would be caught by N-02 and N-21.

## Ten proposed vectors

`proposed/proposed_vectors.json` holds one negative vector per gap. Each uses the draft's keys, WITs, clock (T0+60)
and trusted audiences. `check_proposed.py` confirms two things for each: the frozen reader rejects it, and the mutant
that removes the named rule accepts it. The result is 10 of 10 (`runs/check_proposed.json`).

| Id | What | Isolates |
| --- | --- | --- |
| X01 | N-01, signature regenerated (`@query` not covered) | request coverage |
| X02 | N-03, signature regenerated (body, no Content-Digest) | digest presence |
| X03 | N-05, signature regenerated (`expires` missing) | required parameter |
| X04 | WIT issuer signature with one bit flipped; message re-signed | WIT signature |
| X05 | WIT `typ: JWT`, validly issued | WIT `typ` |
| X06 | WIT `exp` = T0+30, verified at T0+60, signature window valid | WIT `exp` alone |
| X07 | request does not cover Workload-Identity-Token | request coverage |
| X08 | signed response does not cover Workload-Identity-Token | response coverage |
| X09 | `created` = T0+120, verified at T0+60 | window, left edge |
| X10 | N-08 with both tagged signatures by vec-a-key | the count check alone |

X04–X06 re-issue WIT-A with the published issuer key. X02 is signed with ES256 through `cryptography`, which uses a
random nonce, so its signature value is not reproducible byte for byte. Rebuilding it gives another valid signature.
The others are Ed25519 and rebuild byte for byte.

## Files

- `reader/`: the frozen reader, and the smoke test on the base specification's examples.
- `run_positives.py`, `run_negatives.py`, `run_p06_variant.py`: the runs.
- `mutation_battery.py`, `build_proposed.py`, `check_proposed.py`: the mutant battery and the proposed vectors.
- `runs/`: outputs.
- `UPSTREAM.txt`: URLs and sha256 of every text read.
- `upstream/`: the two Internet-Draft texts the scripts read, and `vectors_clean.txt` (the vector draft with page
  headers and footers removed, which is what the scripts parse). Set `WIMSE_TMP` to choose the scratch directory.

Disclosure: AI-assisted (Claude). The run and the claims are mine.

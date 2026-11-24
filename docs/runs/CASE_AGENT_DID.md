# Case: Agent-DID RFC-001, from an outside reader to a release criterion

One project, followed from a first independent run to the security sign-off of its `v1.0.0`. Each step links the
other project's own commit or comment, so the account can be checked against the source and not taken on trust.
Measured on 2026-11-25. The project is [edisonduran/agent-did](https://github.com/edisonduran/agent-did), maintained by
Edison Muñoz Durango.

| When (UTC) | What happened | Where |
| --- | --- | --- |
| 2026-11-03 | We ran a reader written from RFC-001's text alone on its four published fixture files: blind 46/46. A one-rule-at-a-time mutation battery found that **none of the twelve HTTP verification rules was pinned by any vector**, plus three text points (salt encoding, signed payload bytes, a non-decodable key). | [agent-did#127](https://github.com/edisonduran/agent-did/issues/127) · record [`agent-did-rfc001-cold/`](agent-did-rfc001-cold/) |
| 2026-11-16 | `v1.0.0-rc.5` was released with 84 HTTP verification vectors, one or more for each of the twelve gaps, and the three text points fixed. | tag [`76b4f73`](https://github.com/edisonduran/agent-did/tree/76b4f7368f4b15376163fa83411669605815a3b9) |
| 2026-11-21 | The maintainer mapped each of the twelve gaps to its new vectors, and wrote that our record "was the external reader behind this work". He asked for a rerun and closed the issue. | [comment 7064981675](https://github.com/edisonduran/agent-did/issues/127#issuecomment-7064981675) |
| 2026-11-22 | Rerun on rc.5: 84/84 verdicts. The battery found **five gaps the new vectors still left open** (a forged request consuming a nonce, replay in the last second, and URL rules for parsers that do not normalize) and two text points. Seven vectors were proposed. | [comment 7080661840](https://github.com/edisonduran/agent-did/issues/127#issuecomment-7080661840) · [`rerun-rc5-76b4f73/`](agent-did-rfc001-cold/rerun-rc5-76b4f73/) |
| 2026-11-22 | The maintainer checked all five, wrote "All five are real", and merged #306: eleven vectors, plus both text points clarified in RFC-001. | [comment 7084711440](https://github.com/edisonduran/agent-did/issues/127#issuecomment-7084711440) · [#306](https://github.com/edisonduran/agent-did/pull/306) (`d09ca9f8`) |
| 2026-11-22 | Rerun on #306: the five gaps are caught. The one difference was our reader's own defect (it dropped IPv6 brackets). That defect showed a sixth gap, because no vector accepts an IPv6 host. One vector was proposed, and our wrong proposal from the rc.5 rerun was withdrawn beside its record. | [comment 7087960331](https://github.com/edisonduran/agent-did/issues/127#issuecomment-7087960331) · [`rerun-pr306-d09ca9f/`](agent-did-rfc001-cold/rerun-pr306-d09ca9f/) · [correction](agent-did-rfc001-cold/rerun-rc5-76b4f73/CORRECTION_20261123.md) |
| 2026-11-23 | The proposed vector was merged as `accept-url-ipv6-host`. | [comment 7088469735](https://github.com/edisonduran/agent-did/issues/127#issuecomment-7088469735) · [#307](https://github.com/edisonduran/agent-did/pull/307) (`1c078e3c`) |
| 2026-11-23 | The maintainer asked us to review RFC-001 §8 as the external reviewer that the `v1.0.0` criterion C-SPEC-3 requires. Our review raised text points only, with a sign-off conditional on two of them. | [#310](https://github.com/edisonduran/agent-did/issues/310) · [review 7096220103](https://github.com/edisonduran/agent-did/issues/310#issuecomment-7096220103) |
| 2026-11-23 | #311 addressed both conditions and every recommendation. We checked the diff and confirmed the sign-off as unconditional at `70d12439`. | [#311](https://github.com/edisonduran/agent-did/pull/311) (`70d12439`) · [confirmation 7116920249](https://github.com/edisonduran/agent-did/issues/310#issuecomment-7116920249) |
| 2026-11-24 | #312 ticked C-SPEC-3 in the release criteria, citing the review and the confirmation as its evidence, and closed #310. | [#312](https://github.com/edisonduran/agent-did/pull/312) (`ccae1119`) · [`RELEASE-1.0-CRITERIA.md`](https://github.com/edisonduran/agent-did/blob/ccae11192f1d369251671b2ccf2f44a8dda4f64a/docs/RELEASE-1.0-CRITERIA.md) |

## What carried it

- **The reader was frozen before the expected values were read**, and what was seen before the freeze is written in
  each record. The maintainer named this as what made the 84/84 meaningful.
- **The mutation battery, not the agreement count, found the gaps.** Each run agreed with every vector, and each run
  still found rules no vector pinned.
- **Each proposal came as a vector that isolates its rule**: the frozen reader gives the expected result, and the reader
  with that one rule turned off does not. The maintainer could check each claim against his own SDKs before taking it.
- **A wrong result stayed on record.** Our own reader defect and our withdrawn proposal are written beside the record,
  not edited out.

## What this does not show

The SDKs were never opened or run. Agreement between two readers is not a certification, and the vectors pin only the
rules they test. The decision to take each change in was the maintainer's, made after he checked it himself.

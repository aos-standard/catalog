# Correction, 2026-11-07: `for-acp/.../README.md` names a `PROVENANCE.json` that this record does not hold

**This file sits beside the handover record and changes nothing in it.**

## What was wrong

The last paragraph of `for-acp/examples/unreleased/dispute_resolution/README.md` says: "`PROVENANCE.json` gives each
file's sha256 and the source commit." No `PROVENANCE.json` was written. `for-acp/examples/unreleased/dispute_resolution/`
holds only `README.md` and `conformance_cases.json`. The sha256 of every file is in this record's `SHA256SUMS`, and the
source commit is named in that same README paragraph and in `../README.md`.

## How it was found

The RFC author copied the cases into the SEP branch at `7cab286`
(`maximusrufus/agentic-commerce-protocol`, 2026-11-06T14:11:52Z). In that copy the sentence reads "...copied as they
are, from aos-standard/catalog at `3886bd0` (`docs/runs/acp-dispute-cold/handover-94a71e9/`)." That is the only line
that differs from this record's README. `conformance_cases.json` there has the same sha256 as here
(`284db2ec…5f3fd3cf`). Evidence: `docs/evidence/20261107-acp-316-cases-in-branch-7cab286.md`.

## What it changes

The cases and the validator function are unaffected. Nothing in this record is edited. The README stays as it was
published at `3886bd0`, so the commit the RFC author cites still matches. CC0.

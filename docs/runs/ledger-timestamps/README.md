# Ledger timestamps — what this catalog held, and when, without trusting GitHub

Once a month this catalog writes a **manifest**: the sha256 of every file under `CONDUCT.jsonl`, `ANCHORS.jsonl`,
`ANCHORS.jsonl.digests.json`, `docs/runs/` and `docs/evidence/` at one commit, plus one line for the maintainer's private
ledger. The manifest's own sha256 is stamped with [OpenTimestamps](https://opentimestamps.org): only that hash is sent to
the public calendars, and the proof (`MANIFEST.txt.ots`) commits it to a Bitcoin block. A reader can then show that
every listed file existed with exactly those bytes no later than that block — independently of GitHub, of git commit
dates (which the author sets), and of this catalog.

Each month's manifest lists the previous months' `MANIFEST.txt` and `.ots` under `docs/runs/ledger-timestamps/`, so the
snapshots chain.

## Check one month (two steps)

1. **Recompute the manifest** (stdlib Python and git; no OpenTimestamps client):

   ```
   git clone https://github.com/aos-standard/catalog && cd catalog
   python3 docs/runs/ledger-timestamps/verify_manifest.py . docs/runs/ledger-timestamps/2026-10/MANIFEST.txt
   ```

   It reads each file's bytes at the manifest's `# commit:` from git's object store and compares the sha256. Expected:
   every public line matches; the `[private]` line is reported as not recomputable (only the maintainer holds that file;
   its public subset is `CONDUCT.jsonl`, which is in the manifest).

2. **Verify the timestamp** (OpenTimestamps client, `pip install opentimestamps-client`):

   ```
   ots verify docs/runs/ledger-timestamps/2026-10/MANIFEST.txt.ots
   ```

   It checks that the `.ots` proof commits to the sha256 of `MANIFEST.txt` and, once a calendar's commitment is in a
   block, reports the block height and time. Right after stamping the proof is *pending*; a few hours later the
   maintainer runs `ots upgrade` and publishes the result **next to it** as `MANIFEST.txt.upgraded.ots` (the pending
   file is never rewritten). A pending proof already fixes the hash with the calendars; the upgraded one needs no
   calendar. Verify whichever is present; the upgraded one is the stronger.

## What this does and does not show

- It shows **existence no later than the block time** for exact bytes. It says nothing about when a file was written
  before that, and nothing about whether its contents are true.
- It does not cover files outside the listed paths (`catalog.json`, `census/`, probes and so on).
- The `[private]` line lets the maintainer prove later what the private ledger held; a reader can only check that the
  line exists in a stamped manifest.

## Months

| month | commit | manifest sha256 | stamped (UTC) | status |
|---|---|---|---|---|
| 2026-10 | `109a30d` | `f046ca25f491eae46879b4c5b57a68efe89449b0d19af5fe5c6c6f3348cec57c` | 2026-10-19T23:14Z | Bitcoin block 972227 |

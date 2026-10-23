# Checks of the October 2026 ledger timestamp (2026-10-23)

`run_checks.sh` runs, from a fresh clone, the positive and negative controls for `../2026-10/`: recomputation of the
stamped manifest, a manifest with one changed hex digit, a manifest rebuilt from a rewritten history, the stamped
manifest in a clone that holds that rewritten branch, the block's merkle root from two explorers, and the byte-prefix
check of `CONDUCT.jsonl`. `run_checks_output.txt` is its full output (exit status 0). `manifest_from_109a30d.txt` was
built separately from the real commit; its 127 public lines equal the stamped manifest's (its private line is from a
later state of the private ledger and is not the stamped one). `FROZEN.txt` lists the sha256 of every file here.

What this shows and does not show is in `../README.md`. Not answer-blind: the same maintainer built the manifest and
wrote these checks.

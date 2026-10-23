#!/usr/bin/env bash
# Positive and negative controls for the October 2026 ledger timestamp (run from a fresh clone of aos-standard/catalog).
# The private-ledger argument of build_manifest.py is given the public CONDUCT.jsonl; only the 127 public lines are compared.
# Needs: git, python3 (stdlib), opentimestamps-client 0.7.2 (`ots`), curl. Writes only under ./out-checks/.
set -u
T=docs/runs/ledger-timestamps; M=$T/2026-10/MANIFEST.txt; O=out-checks; mkdir -p "$O"
echo "positive: recompute the stamped manifest";        python3 -I $T/verify_manifest.py . $M; echo "rc=$?"
echo "negative A: one hex digit of the CONDUCT.jsonl line changed in a copy of the manifest"
python3 - "$M" "$O/manifest_tampered.txt" <<'PY'
import sys
s = open(sys.argv[1], 'rb').read(); i = s.index(b'  CONDUCT.jsonl') - 1
open(sys.argv[2], 'wb').write(s[:i] + (b'1' if s[i:i+1] == b'0' else b'0') + s[i+1:])
PY
python3 -I $T/verify_manifest.py . "$O/manifest_tampered.txt"; echo "rc=$?"
ots verify -f "$O/manifest_tampered.txt" $M.upgraded.ots; echo "rc=$?"
echo "negative B: rewrite one byte of CONDUCT.jsonl row 1 at 109a30d on a local branch, rebuild the manifest from it"
git checkout -q -b rewrite-check 109a30db666aa60a6df2614f097416aae3522498
python3 - <<'PY'
b = open('CONDUCT.jsonl', 'rb').read(); i = b.index(b'"VCL-0001"') + 8
open('CONDUCT.jsonl', 'wb').write(b[:i] + b'2' + b[i+1:])
PY
git -c user.name=check -c user.email=check@example.invalid commit -qam "rewrite one byte of row 1"
git checkout -q -
python3 -I $T/build_manifest.py . "$(git rev-parse rewrite-check)" "$PWD/CONDUCT.jsonl" "$O/manifest_from_rewritten.txt" >/dev/null
diff <(grep -v '^#' $M | grep -v '\[private\]') <(grep -v '^#' "$O/manifest_from_rewritten.txt" | grep -v '\[private\]')
ots verify -f "$O/manifest_from_rewritten.txt" $M.upgraded.ots; echo "rc=$?"
echo "control: the stamped manifest still verifies in a clone that holds the rewritten branch"
python3 -I $T/verify_manifest.py . $M; echo "rc=$?"
echo "block: compare the proof's merkle root with two explorers"
ots info $M.upgraded.ots | grep -A1 BitcoinBlockHeaderAttestation
h=$(curl -s https://blockstream.info/api/block-height/972227)
curl -s "https://blockstream.info/api/block/$h" | python3 -c "import json,sys; print('blockstream', json.load(sys.stdin)['merkle_root'])"
curl -s "https://mempool.space/api/block/$h" | python3 -c "import json,sys; print('mempool    ', json.load(sys.stdin)['merkle_root'])"
echo "append-only: the ledger as stamped is a byte prefix of the current one"
git show 109a30d:CONDUCT.jsonl > "$O/CONDUCT_at_109a30d.jsonl"; n=$(stat -c %s "$O/CONDUCT_at_109a30d.jsonl")
head -c "$n" CONDUCT.jsonl | cmp - "$O/CONDUCT_at_109a30d.jsonl" && echo "prefix ok ($n bytes)"

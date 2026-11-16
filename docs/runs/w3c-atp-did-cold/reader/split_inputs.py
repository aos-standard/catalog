#!/usr/bin/env python3
"""Split test-vectors.json into what a reader is given and the answers. Run before the reader was written.
v2 (after the v1 score): saltHex, present on one pairwise vector only, is an input. v1 had filed it with the answers."""
import json, os, sys
W = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
src = sys.argv[1] if len(sys.argv) > 1 else os.path.join(W, "upstream/specs/did-atp/test-vectors.json")
d = json.load(open(src))
GIVE = {"rootIdentifiers": ["domain"], "pathIdentifiers": ["domain", "path", "ed25519PublicKeyHex", "mlDsa65PublicKeyHex"],
        "pairwiseIdentifiers": ["domain", "masterSecretHex", "peerId", "saltHex"], "invalidIdentifiers": ["value"]}
inp, ans = {}, {}
for grp, keep in GIVE.items():
    inp[grp] = [{"i": i, **{k: v[k] for k in keep if k in v}} for i, v in enumerate(d[grp])]
    ans[grp] = [{"i": i, **{k: v[k] for k in v if k not in keep}} for i, v in enumerate(d[grp])]
inp["primitives"] = d["primitives"]
os.makedirs(os.path.join(W, "inputs"), exist_ok=True); os.makedirs(os.path.join(W, "answers"), exist_ok=True)
json.dump(inp, open(os.path.join(W, "inputs", "given.json"), "w"), indent=1)
json.dump(ans, open(os.path.join(W, "answers", "answers.json"), "w"), indent=1)

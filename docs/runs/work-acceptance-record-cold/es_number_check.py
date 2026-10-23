#!/usr/bin/env python3
"""Compare war_cold_verifier_v1412.es_number with Node's String(x) on 400,000 doubles (seed 20261023).

Usage: python3 es_number_check.py   (needs `node` on PATH; run from this directory)
"""
import math
import random
import struct
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from war_cold_verifier_v1412 import es_number  # noqa: E402

JS = (
    "const l=require('fs').readFileSync(0,'utf8').trim().split('\\n');const b=Buffer.alloc(8);"
    "process.stdout.write(l.map(h=>{b.writeBigUInt64LE(BigInt('0x'+h));return String(b.readDoubleLE(0))}).join('\\n')+'\\n')"
)


def main() -> int:
    random.seed(20261023)
    bits = []
    while len(bits) < 300000:
        b = random.getrandbits(64)
        if math.isfinite(struct.unpack("<d", struct.pack("<Q", b))[0]):
            bits.append(b)
    for _ in range(100000):
        x = round(random.uniform(-1e6, 1e6), random.randint(0, 8))
        bits.append(struct.unpack("<Q", struct.pack("<d", x))[0])
    hexes = "\n".join("%016x" % b for b in bits) + "\n"
    js = subprocess.run(["node", "-e", JS], input=hexes, capture_output=True, text=True, check=True).stdout.splitlines()
    py = [es_number(struct.unpack("<d", struct.pack("<Q", b))[0]) for b in bits]
    bad = [(i, a, b) for i, (a, b) in enumerate(zip(js, py)) if a != b]
    print(f"{len(py) - len(bad)}/{len(py)} identical")
    for i, a, b in bad[:10]:
        print(f"  {bits[i]:016x}: node {a} ours {b}")
    return 1 if bad or len(js) != len(py) else 0


if __name__ == "__main__":
    sys.exit(main())

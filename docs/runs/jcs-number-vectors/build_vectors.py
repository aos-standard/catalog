#!/usr/bin/env python3
"""Rebuild the inputs of jcs-number-vectors.json (seed 20261023); `expected` comes from Node's String(x).

Usage: python3 build_vectors.py > in.txt   then
node -e "const l=require('fs').readFileSync('in.txt','utf8').trim().split('\n');const b=Buffer.alloc(8);process.stdout.write(l.map(h=>{b.writeBigUInt64LE(BigInt('0x'+h));return String(b.readDoubleLE(0))}).join('\n')+'\n')"
"""
import math
import random
import struct


def bits(x: float) -> int:
    return struct.unpack("<Q", struct.pack("<d", x))[0]


def frombits(b: int) -> float:
    return struct.unpack("<d", struct.pack("<Q", b))[0]


def main() -> None:
    cases = [bits(0.0), bits(-0.0)]
    for e in range(15, 25):
        for m in (1.0, 1.5, 9.999999999999999):
            cases.append(bits(m * 10.0**e))
    for e in range(-10, -3):
        for m in (1.0, 1.5, 9.999999999999999):
            cases.append(bits(m * 10.0**e))
    for x in (1e21, 1e-7, 1e-6, 999999999999999900000.0, 0.000001, 0.0000001, 123456789012345680000.0, 1e21):
        cases.append(bits(x))
    for x in (1e21, 1e-7, 1e-6):
        for d in (-2, -1, 1, 2):
            cases.append(bits(x) + d)
    for k in range(-4, 5):
        cases += [bits(float(2**53 + k)), bits(float(-(2**53) + k))]
    cases += [bits(x) for x in (5e-324, 2.2250738585072009e-308, 2.2250738585072014e-308,
                                1.7976931348623157e308, -1.7976931348623157e308)]
    cases += [bits(x) for x in (0.1, 0.2, 0.30000000000000004, 1 / 3, 2 / 3, 4.35, 0.07, 1.005, 100.0, 1e2,
                                12345.678, 9007199254740.993)]
    cases += [bits(c / 100.0) for c in (1, 5, 10, 99, 100, 101, 1999, 10000001, 123456789)]
    random.seed(20261023)
    n = 0
    while n < 600:
        b = random.getrandbits(64)
        if math.isfinite(frombits(b)):
            cases.append(b)
            n += 1
    for _ in range(300):
        cases.append(bits(round(random.uniform(-1e6, 1e6), random.randint(0, 8))))
    seen = set()
    for b in cases:
        if b not in seen:
            seen.add(b)
            print("%016x" % b)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Recompute the Anchored event's topic0 with a standard-library Keccak-256 (the pre-NIST padding Ethereum uses).
Usage: python3 -I keccak_topic0.py
"""
RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
      0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
      0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
M = (1 << 64) - 1


def rot(x, n):
    return ((x << n) | (x >> (64 - n))) & M if n else x


def f(a):
    for rc in RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ rot(c[(x + 1) % 5], 1) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                b[y][(2 * x + 3 * y) % 5] = rot(a[x][y], ROT[x][y])
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(msg: bytes) -> str:
    r = 136
    m = bytearray(msg) + b"\x01"
    m += b"\x00" * ((-len(m)) % r)
    m[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for i in range(0, len(m), r):
        for j in range(r // 8):
            a[j % 5][j // 5] ^= int.from_bytes(m[i + 8 * j:i + 8 * j + 8], "little")
        a = f(a)
    return b"".join(a[j % 5][j // 5].to_bytes(8, "little") for j in range(4)).hex()


if __name__ == "__main__":
    assert keccak256(b"") == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    print("0x" + keccak256(b"Anchored(bytes32,address,uint256)"))

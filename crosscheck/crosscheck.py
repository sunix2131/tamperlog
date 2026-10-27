"""Независимая сверка C++ реализации. Python 3, только стандартная библиотека.

Здесь деревья считаются прямо по рекурсивным определениям RFC 6962, 2.1 (MTH, PATH,
PROOF/SUBPROOF), без кэша поддеревьев и без общего кода с C++. Если обе реализации
выдают одинаковые корни и доказательства бит в бит, ошибка должна была бы совпасть
в двух разных по устройству программах.

Запуск: python3 -I crosscheck/crosscheck.py build/tamperlog [N]
"""
import hashlib
import os
import random
import subprocess
import sys


def H(b):
    return hashlib.sha256(b).digest()


def k_split(n):
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(d):
    n = len(d)
    if n == 0:
        return H(b"")
    if n == 1:
        return H(b"\x00" + d[0])
    k = k_split(n)
    return H(b"\x01" + mth(d[:k]) + mth(d[k:]))


def path(m, d):
    n = len(d)
    if n == 1:
        return []
    k = k_split(n)
    if m < k:
        return path(m, d[:k]) + [mth(d[k:])]
    return path(m - k, d[k:]) + [mth(d[:k])]


def subproof(m, d, b):
    n = len(d)
    if m == n:
        return [] if b else [mth(d)]
    k = k_split(n)
    if m <= k:
        return subproof(m, d[:k], b) + [mth(d[k:])]
    return subproof(m - k, d[k:], False) + [mth(d[:k])]


def main():
    exe = sys.argv[1]
    N = int(sys.argv[2]) if len(sys.argv) > 2 else 64

    # 1. SHA-256: случайные длины вокруг границ блока 55/56/63/64/119/120 байт.
    rnd = random.Random(20261027)
    lengths = list(range(0, 130)) + [rnd.randrange(130, 5000) for _ in range(70)]
    bad_hash = 0
    for ln in lengths:
        data = bytes(rnd.randrange(256) for _ in range(ln))
        out = subprocess.run([exe, "hash", data.hex()], capture_output=True, text=True, check=True).stdout.strip()
        if out != H(data).hex():
            bad_hash += 1
            print("sha256 mismatch at length", ln)
    print(f"sha256: {len(lengths) - bad_hash}/{len(lengths)} lengths agree")

    # 2. Деревья: все корни, все доказательства включения и согласованности для n <= N.
    dump = subprocess.run([exe, "--sha256", "dump", str(N)], capture_output=True, text=True, check=True).stdout
    leaves = [f"leaf-{i}".encode() for i in range(N)]
    counts = {"R": [0, 0], "I": [0, 0], "C": [0, 0]}
    for line in dump.splitlines():
        parts = line.split()
        kind = parts[0]
        if kind == "R":
            s = int(parts[1])
            want = [mth(leaves[:s]).hex()]
            got = parts[2:]
        elif kind == "I":
            i, s = int(parts[1]), int(parts[2])
            want = [h.hex() for h in path(i, leaves[:s])]
            got = parts[3:]
        else:
            m, s = int(parts[1]), int(parts[2])
            want = [h.hex() for h in subproof(m, leaves[:s], True)]
            got = parts[3:]
        counts[kind][0] += 1
        if got == want:
            counts[kind][1] += 1
        else:
            print("mismatch:", line[:80])
    for k, name in (("R", "roots"), ("I", "inclusion proofs"), ("C", "consistency proofs")):
        print(f"{name}: {counts[k][1]}/{counts[k][0]} agree")
    ok = bad_hash == 0 and all(c[0] == c[1] for c in counts.values())
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()

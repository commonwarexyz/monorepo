"""Exact inequalities for contiguous-symbol truncated Gamma_3(47)."""

from fractions import Fraction
from math import comb, log2


def verify(q, a, b, cycles, trits):
    buckets = min(a, b)*q*q
    edges = a*b*q*q
    degree = max(a, b)
    trees = 4*(a+b-2)
    cutoff = 66*degree
    assert edges > 256*trees
    cycle8 = Fraction(cycles, 256*comb(edges, 8))
    cycle10 = Fraction(edges*(degree-1)**8, 10*1024*comb(edges, 10))
    choose = 1
    worst = Fraction(0)
    worst_k = None
    vertices = 0
    for k in range(1, cutoff):
        choose = choose*(edges-k+1)//k
        if k < 12:
            continue
        while vertices**3+8*k*vertices < 16*k*k:
            vertices += 1
        assert vertices**3+8*k*vertices >= 16*k*k
        assert (vertices-1)**3+8*k*(vertices-1) < 16*k*k
        components = k//8
        numerator = (components*comb(k-1, components-1)
                     *edges**components*trees**(k-components))
        denominator = 2**max(8*components, vertices)*choose
        probability = Fraction(numerator, denominator)
        assert probability < Fraction(1, 2**128), (q, a, b, k)
        if probability > worst:
            worst = probability
            worst_k = k
    compression = max(cycle8, cycle10, worst, Fraction(1, 2**132))
    side = max(
        Fraction(3*edges**3, 4*buckets*buckets*(edges-34*degree+4)
                 *(edges-34*degree+3)*(edges-34*degree+2)),
        Fraction(1, 2**34),
    )
    epsilon = Fraction(1, 3**trits)
    moment6 = (Fraction(15, 8*buckets**3)-Fraction(35, 16*buckets**4)
               +Fraction(21, 32*buckets**5))
    remaining = edges-49*degree+7
    falling = 1
    for offset in range(6):
        falling *= remaining-offset
    side6 = max(moment6*edges**6/falling, Fraction(1, 2**49))
    small = 2*epsilon*side+epsilon**2
    large = compression+2*epsilon*side6+epsilon**2
    overall = max(small, large)
    assert overall < Fraction(1, 2**128), (q, a, b, trits)
    print(f"q={q} a={a} b={b} M={edges} Bmin={buckets} C8={cycles} trits={trits}")
    print(f"cycle8={-log2(cycle8):.12f} cycle10={-log2(cycle10):.12f}")
    print(f"intermediate={-log2(worst):.12f} at k={worst_k}; large>=132")
    print(f"compression={-log2(compression):.12f}; side={-log2(side):.12f}; total={-log2(overall):.12f}")
    print(f"side6={-log2(side6):.12f}; small-support={-log2(small):.12f}; large-support={-log2(large):.12f}")


if __name__ == "__main__":
    verify(47, 43, 43, 1263308051793, 61)
    # Additional shapes are bound-only experiments, not Rust implementations.
    verify(47, 42, 43, 1147259175618, 61)
    verify(53, 33, 34, 163687581714, 61)

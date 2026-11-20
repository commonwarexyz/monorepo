"""Exact bounds for recursive graph compression and pair-certified inner checks."""

from fractions import Fraction
from math import comb, log2


def vertex_bound(k):
    v = 8
    while v**3 + 8*k*v < 16*k*k:
        v += 1
    return v


def compression_bound(q, degree=None, cycle_count=None):
    degree = q if degree is None else degree
    edges = q*q*degree*degree
    tree = 8*(degree-1)
    assert edges > 256*tree
    if cycle_count is None:
        cycle_count = Fraction(edges*(degree-1)**4, 8)
    cycle8 = cycle_count / (comb(edges, 8)*256)
    cycle10 = Fraction(edges*(degree-1)**8, 10*comb(edges, 10)*1024)
    worst, worst_k = Fraction(0), None
    choose = 1
    for k in range(1, 66*degree):
        choose = choose*(edges-k+1)//k
        if k < 12:
            continue
        components = k//8
        vertices = max(8*components, vertex_bound(k))
        probability = Fraction(
            components*comb(k-1, components-1)*edges**components*tree**(k-components),
            2**vertices*choose,
        )
        if probability > worst:
            worst, worst_k = probability, k
    result = max(cycle8, cycle10, worst, Fraction(1, 2**132))
    print(f"q={q}, d={degree}: intermediate {-log2(worst):.12f} bits at k={worst_k}; compression {-log2(result):.12f}")
    return result


def side_bound(q, degree=None, certified=False):
    degree = q if degree is None else degree
    buckets = q*q*degree
    edges = buckets*degree
    if certified:
        t = 34
        remaining = edges-t*degree+4
        bound = Fraction(3*edges**3, 4*buckets*buckets*remaining*(remaining-1)*(remaining-2))
    else:
        t = (2*buckets-1).bit_length()
        bound = Fraction(degree, 2*(edges-t*degree+2))
    return max(bound, Fraction(1, 2**t))


def verify():
    assert vertex_bound(12) == 11
    outer = compression_bound(47)
    inner = compression_bound(31)
    reference = Fraction(1, 3**71)
    recursive_joint = inner + Fraction(1, 3**72)
    recursive_split = inner + 2*Fraction(1, 3**63)*side_bound(31) + Fraction(1, 3**126)
    for label, error in (("recursive joint114", recursive_joint), ("recursive split99", recursive_split)):
        assert error < reference
        total = outer + 2*error*side_bound(47) + error**2
        assert total < Fraction(1, 2**128)
        print(f"{label}: inner {-log2(error):.12f} bits; total {-log2(total):.12f} bits")
    epsilon = Fraction(1, 3**61)
    certified = outer + 2*epsilon*side_bound(47, certified=True) + epsilon**2
    assert certified < Fraction(1, 2**128)
    print(f"pair-certified inner96: {-log2(certified):.12f} bits")


if __name__ == "__main__":
    verify()

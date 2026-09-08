"""Exact finite inequalities for the derivation in SUBGROUP_TWO_PASS.md.

The graph and probability arguments are proved in that report; this script
checks the remaining finite parameter ranges without rounding the bounds.
"""

from fractions import Fraction
from math import comb, log2


def verify(q):
    buckets = q**3
    edges = q**4
    degree = q
    line_degree = 2*(degree-1)
    tree_bound = 4*line_degree
    cutoff = 66*degree
    assert edges > 256*tree_bound

    cycle8 = Fraction(edges*(degree-1)**4, 8*comb(edges, 8)*256)
    cycle10 = Fraction(edges*(degree-1)**8, 10*comb(edges, 10)*1024)
    assert cycle8 < Fraction(1, 2**129)
    assert cycle10 < Fraction(1, 2**140)

    choose = 1
    worst = Fraction(0)
    worst_k = None
    for k in range(1, cutoff):
        choose = choose*(edges-k+1)//k
        if k < 12:
            continue
        components = k//8
        numerator = (
            components*comb(k-1, components-1)
            *edges**components*tree_bound**(k-components)
        )
        denominator = 256**components*choose
        # Exact integer inequality, not a floating point security assertion.
        assert numerator*2**129 < denominator, (q, k)
        if numerator*worst.denominator > worst.numerator*denominator:
            worst = Fraction(numerator, denominator)
            worst_k = k

    sign_only = Fraction(1, 2**132)
    compression = max(cycle8, cycle10, worst, sign_only)
    inner = Fraction(1, 3**82)
    overall = compression + inner
    assert overall < Fraction(1, 2**128)

    side_bits = (2*buckets-1).bit_length()
    side = max(
        Fraction(degree, 2*(edges-side_bits*degree+2)),
        Fraction(1, 2**side_bits),
    )
    split_inner = Fraction(1, 3**71)
    split_total = compression + 2*split_inner*side + split_inner**2
    assert split_total < Fraction(1, 2**128)
    print(f"q={q} B={buckets} M={edges} D={degree}")
    print(f"k=8 bound: {-log2(cycle8):.12f} bits")
    print(f"k=10 bound: {-log2(cycle10):.12f} bits")
    print(f"k=12..{cutoff-1}: worst {-log2(worst):.12f} bits at k={worst_k}")
    print(f"k>={cutoff}: >=132 bits from signs")
    print(f"compression: {-log2(compression):.12f}; with joint inner129: {-log2(overall):.12f} bits")
    print(f"separate inner111: {-log2(split_total):.12f} bits; side-zero bound={side}")


if __name__ == "__main__":
    verify(47)
    verify(53)

"""Exact three-input atom checks and pair-certified outer composition."""

from collections import Counter
from fractions import Fraction
from itertools import combinations_with_replacement, product
from math import comb, log2


def check_atoms(moduli, buckets):
    elements = list(product(*(range(m) for m in moduli)))
    index = {value: i for i, value in enumerate(elements)}
    addition = [[index[tuple((a+b) % m for a, b, m in zip(x, y, moduli))] for y in elements] for x in elements]
    negative = [index[tuple(-a % m for a, m in zip(x, moduli))] for x in elements]
    worst = 0
    tested = 0
    for values in combinations_with_replacement(range(1, len(elements)), 3):
        counts = {(0,)*buckets: 1}
        for value in values:
            next_counts = Counter()
            for state, count in counts.items():
                for bucket in range(buckets):
                    for signed in (value, negative[value]):
                        updated = list(state)
                        updated[bucket] = addition[updated[bucket]][signed]
                        next_counts[tuple(updated)] += count
            counts = next_counts
        largest = max(counts.values())
        assert largest*4*buckets**2 <= 3*(2*buckets)**3, (moduli, buckets, values)
        assert sum(counts.values()) == (2*buckets)**3
        worst = max(worst, largest)
        tested += 1
    print(f"H={moduli}, B={buckets}: {tested} multisets, max atom={Fraction(worst, (2*buckets)**3)}, bound={Fraction(3,4*buckets*buckets)}")


def verify():
    for moduli in ((3,), (5,), (9,), (3, 3)):
        for buckets in (2, 3, 4):
            check_atoms(moduli, buckets)

    q = 47
    d = q
    m = q**4
    b = q**3
    t = 34
    threshold = t*d
    remaining = m-threshold+4
    atom = Fraction(3, 4*b*b)
    side = max(atom*m**3/(remaining*(remaining-1)*(remaining-2)), Fraction(1, 2**t))
    compression = Fraction(m*(d-1)**4, 8*comb(m, 8)*256)
    trits = (96*1000+1583)//1584
    assert trits == 61
    epsilon = Fraction(1, 3**trits)
    total = compression+2*epsilon*side+epsilon**2
    assert total < Fraction(1, 2**128)
    print(f"q47 certified inner96: marginal bits={-log2(side):.12f}, total bits={-log2(total):.12f}")


if __name__ == "__main__":
    verify()

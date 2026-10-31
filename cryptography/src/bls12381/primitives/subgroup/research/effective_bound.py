"""Exact cofactor and support bounds for the effective-circuit certificate."""

from fractions import Fraction
from math import comb, gcd, log2


def verify_cofactor():
    h = int('396c8c005555e1568c00aaab0000aaab', 16)
    assert h == 3*(11*10177*859267*52437899)**2
    assert h % 3 == 0
    assert gcd(h, 2*5*7) == 1
    for minor in range(-8, 9):
        if minor % 3:
            assert gcd(minor, h) == 1


def verify(q):
    m = q**4
    l = 8*(q-1)
    c8 = Fraction(m*(q-1)**4, 8)
    cycle8 = c8/(256*comb(m, 8))
    cycle10 = Fraction(m*(q-1)**8, 10*1024*comb(m, 10))
    c12 = Fraction(m*(q-1)**10, 12)
    theta444 = Fraction(4*(q-2), 3)*c8
    support12 = (c12/4096+theta444/2048)/comb(m, 12)
    worst = Fraction(0)
    worst_k = 0
    choose = 1
    vertices = 0
    for k in range(1, 66*q):
        choose = choose*(m-k+1)//k
        if k < (13 if q == 19 else 12):
            continue
        while vertices**3+8*k*vertices < 16*k*k:
            vertices += 1
        c = k//8
        probability = Fraction(c*comb(k-1,c-1)*m**c*l**(k-c),
                               2**max(8*c, vertices)*choose)
        if probability > worst:
            worst, worst_k = probability, k
    compression = max(cycle8, cycle10, support12, worst, Fraction(1, 2**132))
    total = compression+Fraction(1, 3**63)
    assert total < Fraction(1, 3**61)
    print(f"q{q} C8={-log2(cycle8):.12f}, C10={-log2(cycle10):.12f}, support12={-log2(support12):.12f}, intermediate={-log2(worst):.12f} at k={worst_k}")
    print(f"compression={-log2(compression):.12f}, with joint63trits={-log2(total):.12f}; required={61*log2(3):.12f}")


if __name__ == "__main__":
    verify_cofactor()
    verify(23)
    verify(19)

#!/usr/bin/env python3
"""Check the exact inequalities in src/bls12381/group/subgroup.md.

The written graph and conditioning arguments establish the bounds. This
read-only checker evaluates them and checks the fixed Rust parameter set.
"""

from collections import Counter
from fractions import Fraction as F
from itertools import product
from math import comb, gcd, log2, prod
from pathlib import Path
import re


H1 = 76329603384216526031706109802092473003
H2 = int(
    "305502333931268344200999753193121504214466019254188142667664032982267604"
    "182971884026507427359259977847832272839041616661285803823378372096355777"
    "062779109"
)
R = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def source_parameters():
    source = (
        Path(__file__).resolve().parents[1] / "src/bls12381/group/subgroup.rs"
    ).read_text()
    expected = {
        "OUTER_Q": 47,
        "INNER_Q": 19,
        "INNER_ROWS": 63,
        "OUTER_EDGES": 47**4,
    }
    for name, value in expected.items():
        matches = re.findall(
            rf"^const\s+{name}:\s*(?:usize|u32)\s*=\s*([0-9_]+)\s*;",
            source,
            re.MULTILINE,
        )
        assert len(matches) == 1, f"missing or ambiguous Rust constant: {name}"
        assert int(matches[0].replace("_", "")) == value, f"changed parameter: {name}"
    rows = re.findall(
        r"let\s+rows\s*=\s*if\s+columns\.is_some\(\)\s*"
        r"\{\s*INNER_ROWS\s*\}\s*else\s*\{\s*([0-9_]+)\s*\}\s*;",
        source,
    )
    assert len(rows) == 1 and int(rows[0].replace("_", "")) == 81
    return expected


def encoded(x):
    return {"numerator": str(x.numerator), "denominator": str(x.denominator),
            "negative_log2_display_only": log2(x.denominator) - log2(x.numerator)}


def support_bounds(q, *, inner=False):
    m, degree, ell = q**4, q, 8 * (q - 1)
    assert m > 256 * ell
    c8 = F(m * (degree - 1)**4, 8)
    p8 = c8 / (2**8 * comb(m, 8))
    p10 = F(m * (degree - 1)**8, 10 * 2**10 * comb(m, 10))
    theta444 = F(4 * (degree - 2), 3) * c8
    p12_improved = (F(m * (degree - 1)**10, 12 * 2**12)
                    + theta444 / 2**11) / comb(m, 12)
    worst, worst_k = F(0), None
    choose = 1
    vertices = 0
    checked = 0
    for k in range(1, 66 * degree):
        choose = choose * (m - k + 1) // k
        if k < (13 if inner else 12):
            continue
        while vertices**3 + 8 * k * vertices < 16 * k * k:
            vertices += 1
        assert vertices**3 + 8 * k * vertices >= 16 * k * k
        assert (vertices - 1)**3 + 8 * k * (vertices - 1) < 16 * k * k
        c = k // 8
        # The ratio of successive summands is at least M/(256*ell):
        # binomial ratio (k-j)/j >= 1 for every j<c.
        assert c == 1 or k - (c - 1) >= c - 1
        p = F(c * comb(k - 1, c - 1) * m**c * ell**(k - c),
              2**max(8 * c, vertices) * choose)
        if p > worst:
            worst, worst_k = p, k
        checked += 1
    tail = F(1, 2**132)
    compression = max(p8, p10, worst, tail,
                      p12_improved if inner else F(0))
    return compression, {
        "q": q, "M": m, "B": q**3,
        "p8": encoded(p8), "p10": encoded(p10),
        "p12_improved": encoded(p12_improved),
        "intermediate_worst": encoded(worst), "intermediate_worst_k": worst_k,
        "intermediate_checked": checked, "tail_from_k": 66 * degree,
        "tail": encoded(tail), "compression": encoded(compression),
    }


def side_bounds(q):
    m, b, d = q**4, q**3, q
    k3 = F(3, 4 * b**2)
    k6 = F(15, 8*b**3) - F(35, 16*b**4) + F(21, 32*b**5)
    a3 = max(k3 * m**3 / prod(m - 34*d + 4 - j for j in range(3)), F(1, 2**34))
    a6 = max(k6 * m**6 / prod(m - 49*d + 7 - j for j in range(6)), F(1, 2**49))
    return a3, a6


def finite_group_checks():
    cofactors = {}
    for label, h in (("G1", H1), ("G2", H2)):
        assert gcd(h, R) == gcd(h, 2*5*7) == 1
        for a, b, c, d in product(range(-2, 3), repeat=4):
            determinant = a*d - b*c
            if determinant % 3:
                assert gcd(determinant, h) == 1
        cofactors[label] = {"h": str(h), "gcd_r": gcd(h, R),
                            "gcd_2_5_7": gcd(h, 70), "mod_3": h % 3}

    # A nonzero order-five pair survives a modulo-three independent matrix.
    assert (2*1 + 1*3) % 5 == (1*1 - 2*3) % 5 == 0
    assert (2*(-2) - 1*1) % 3 != 0

    # Exact single-row laws; byte modulo 3 fails the 128-bit 81-row budget.
    assert F(1, 3**81) < F(1, 2**128)
    assert F(1, 3**80) > F(1, 2**128)
    assert F(86, 256)**81 > F(1, 2**128)
    moment_cases = 0
    for b in (2, 3):
        formula = F(22*b + 220*b*(b-1) + 120*b*(b-1)*(b-2), (2*b)**6)
        for modulus in (3, 5, 7, 9, 11):
            distribution = Counter({(0,)*b: 1})
            for _ in range(6):
                following = Counter()
                for state, count in distribution.items():
                    for bucket, sign in product(range(b), (-1, 1)):
                        target = list(state)
                        target[bucket] = (target[bucket] + sign) % modulus
                        following[tuple(target)] += count
                distribution = following
            observed = F(distribution[(0,)*b], (2*b)**6)
            assert observed <= formula
            if modulus == 3:
                assert observed == formula
            moment_cases += 1

        # Check the three-input atom bound on small finite groups.
        for modulus in (3, 5, 7):
            for values in product(range(1, modulus), repeat=3):
                distribution = Counter()
                for buckets in product(range(b), repeat=3):
                    for signs in product((-1, 1), repeat=3):
                        target = [0]*b
                        for bucket, sign, value in zip(buckets, signs, values):
                            target[bucket] = (target[bucket] + sign*value) % modulus
                        distribution[tuple(target)] += 1
                assert F(max(distribution.values()), (2*b)**3) <= F(3, 4*b*b)
    return cofactors, moment_cases


def main():
    if not __debug__:
        raise SystemExit("run this checker without Python optimization (-O)")
    parameters = source_parameters()
    x = -0xD201000000010000
    assert R == x**4 - x**2 + 1
    assert 3 * H1 == (x - 1)**2
    assert 9 * H2 == x**8 - 4*x**7 + 5*x**6 - 4*x**4 + 6*x**3 - 4*x**2 - 4*x + 13
    cofactors, moment_cases = finite_group_checks()
    inner, inner_report = support_bounds(parameters["INNER_Q"], inner=True)
    epsilon = F(1, 3**61)
    assert inner + F(1, 3**parameters["INNER_ROWS"]) < epsilon
    outer, outer_report = support_bounds(parameters["OUTER_Q"])
    a3, a6 = side_bounds(parameters["OUTER_Q"])
    small = 2*epsilon*a3 + epsilon**2
    large = outer + 2*epsilon*a6 + epsilon**2
    graph = max(small, large)
    decoder = max(F(1, 3**81), graph)
    assert graph < F(1, 2**128)
    assert decoder < F(1, 2**128)
    assert parameters["OUTER_Q"]**3 <= parameters["INNER_Q"]**4
    result = {
        "cofactors": cofactors,
        "baseline_81_trits": encoded(F(1, 3**81)),
        "biased_byte_modulo_three_81_rows": encoded(F(86, 256)**81),
        "inner": inner_report,
        "inner_epsilon": encoded(epsilon),
        "outer": outer_report,
        "A3": encoded(a3),
        "A6": encoded(a6),
        "small_support_total": encoded(small),
        "large_support_total": encoded(large),
        "total": encoded(graph),
        "decoder_total": encoded(decoder),
        "sixth_moment_enumerated_cases": moment_cases,
    }
    print("Checked q19/q47 graphs, 63 inner rows, and 81 standalone rows.")
    print("Exact cofactor, support, and final error inequalities passed.")
    print("Negative base-two logarithms below are display only:")
    for label, value in (
        ("inner raw bound", inner + F(1, 3**63)),
        ("inner epsilon", epsilon),
        ("graph path", graph),
        ("all batch sizes", decoder),
    ):
        print(f"  {label}: {log2(value.denominator) - log2(value.numerator):.12f} bits")
    return result


if __name__ == "__main__":
    main()

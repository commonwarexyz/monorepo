#!/usr/bin/env python3
"""Generate the known-answer test vectors of the BLS12-381 groups and pairing.

Every vector is computed here from the definitions, with integer arithmetic only: multiples of
the generators by the affine chord-and-tangent formulas, and the pairing as the Miller function
of the curve parameter raised to the power 3 (p^12 - 1) / r, in Fp12 = Fp2[w] / (w^6 - (1 + i)).
"""

from __future__ import annotations

import argparse
import difflib
from pathlib import Path

CRATE = Path(__file__).resolve().parents[1]
OUTPUT = CRATE / "src/group/vectors.rs"

# The base field modulus, the group order, and the absolute value of the curve parameter, which
# is negative.
P = int(
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf"
    "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    16,
)
R = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001
Z = 0xD201000000010000

# The generators, from "BLS12-381 For The Rest Of Us" and draft-irtf-cfrg-pairing-friendly-curves.
G1 = (
    int(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905"
        "a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb",
        16,
    ),
    int(
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af6"
        "00db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1",
        16,
    ),
)
G2 = (
    (
        int(
            "024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02"
            "b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8",
            16,
        ),
        int(
            "13e02b6052719f607dacd3a088274f65596bd0d09920b61a"
            "b5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e",
            16,
        ),
    ),
    (
        int(
            "0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a7"
            "6d429a695160d12c923ac9cc3baca289e193548608b82801",
            16,
        ),
        int(
            "0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af"
            "267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be",
            16,
        ),
    ),
)

# The scalars of the multiples: the smallest, one of full width, and the largest.
SCALARS = (
    2,
    0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF,
    R - 1,
)


class Fp:
    """The base field."""

    ZERO = 0
    ONE = 1

    @staticmethod
    def add(a, b):
        return (a + b) % P

    @staticmethod
    def sub(a, b):
        return (a - b) % P

    @staticmethod
    def mul(a, b):
        return a * b % P

    @staticmethod
    def inv(a):
        return pow(a, -1, P)

    @staticmethod
    def small(n):
        return n % P

    @staticmethod
    def hex(a):
        return f"{a:096x}"


class Fp2:
    """The quadratic extension Fp[i] / (i^2 + 1), as pairs (c0, c1)."""

    ZERO = (0, 0)
    ONE = (1, 0)

    @staticmethod
    def add(a, b):
        return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)

    @staticmethod
    def sub(a, b):
        return ((a[0] - b[0]) % P, (a[1] - b[1]) % P)

    @staticmethod
    def mul(a, b):
        return ((a[0] * b[0] - a[1] * b[1]) % P, (a[0] * b[1] + a[1] * b[0]) % P)

    @staticmethod
    def inv(a):
        norm = pow(a[0] * a[0] + a[1] * a[1], -1, P)
        return (a[0] * norm % P, -a[1] * norm % P)

    @staticmethod
    def small(n):
        return (n % P, 0)

    @staticmethod
    def hex(a):
        # Encodings hold the imaginary component first.
        return Fp.hex(a[1]) + Fp.hex(a[0])


# The nonresidue 1 + i, and the constants b of the curve y^2 = x^3 + b and of its twist.
XI = (1, 1)
B1 = 4
B2 = Fp2.mul(Fp2.small(4), XI)


def on_curve(field, b, point):
    x, y = point
    return field.mul(y, y) == field.add(field.mul(x, field.mul(x, x)), b)


def slope(field, p, q):
    """Returns the slope of the line through p and q, or of the tangent at p when they are equal."""
    (x1, y1), (x2, y2) = p, q
    if p == q:
        return field.mul(field.mul(field.small(3), field.mul(x1, x1)), field.inv(field.add(y1, y1)))
    return field.mul(field.sub(y2, y1), field.inv(field.sub(x2, x1)))


def add(field, p, q):
    """Returns p + q for affine points, with None the identity."""
    if p is None or q is None:
        return p or q
    (x1, y1), (x2, y2) = p, q
    if x1 == x2 and field.add(y1, y2) == field.ZERO:
        return None
    s = slope(field, p, q)
    x3 = field.sub(field.sub(field.mul(s, s), x1), x2)
    return (x3, field.sub(field.mul(s, field.sub(x1, x3)), y1))


def multiply(field, point, scalar):
    """Returns scalar * point by double and add."""
    result = None
    for bit in bin(scalar)[2:]:
        result = add(field, result, result)
        if bit == "1":
            result = add(field, result, point)
    return result


def fp12_mul(a, b):
    """Multiplies polynomials in w of degree below 6 over Fp2, with w^6 = 1 + i."""
    wide = [Fp2.ZERO] * 11
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            wide[i + j] = Fp2.add(wide[i + j], Fp2.mul(x, y))
    return tuple(
        Fp2.add(wide[k], Fp2.mul(wide[k + 6], XI)) if k < 5 else wide[k] for k in range(6)
    )


FP12_ONE = (Fp2.ONE,) + (Fp2.ZERO,) * 5


def fp12_pow(a, exponent):
    result = FP12_ONE
    for bit in bin(exponent)[2:]:
        result = fp12_mul(result, result)
        if bit == "1":
            result = fp12_mul(result, a)
    return result


def line(t, q, p):
    """Evaluates at p the line through the points t and q of the twist, scaled by w^3.

    A point (x, y) of the twist is the point (x / w^2, y / w^3) of the curve over Fp12, so a line
    of slope s on the twist has slope s / w there. Scaled by w^3, which lies in a proper subfield
    and so does not change the pairing, its value at p = (xp, yp) is
    (s x - y) - s xp w^2 + yp w^3.
    """
    s = slope(Fp2, t, q)
    x, y = t
    xp, yp = p
    return (
        Fp2.sub(Fp2.mul(s, x), y),
        Fp2.ZERO,
        Fp2.mul(s, Fp2.small(-xp)),
        Fp2.small(yp),
        Fp2.ZERO,
        Fp2.ZERO,
    )


def pairing(p, q):
    """Returns the cube of the optimal ate pairing of p in G1 and q in G2.

    The addition chain of the final exponentiation in src/core/pairing.rs computes the cube, which
    is as bilinear and as far from degenerate as the pairing itself, since 3 does not divide r.
    """
    f = FP12_ONE
    t = q
    for bit in bin(Z)[3:]:
        f = fp12_mul(fp12_mul(f, f), line(t, t, p))
        t = add(Fp2, t, t)
        if bit == "1":
            f = fp12_mul(f, line(t, q, p))
            t = add(Fp2, t, q)
    assert (P**12 - 1) % R == 0
    f = fp12_pow(f, 3 * (P**12 - 1) // R)
    # The curve parameter is negative, which inverts the pairing. The inverse of an element of
    # the cyclotomic subgroup is its conjugate, which negates the odd powers of w.
    return tuple(c if k % 2 == 0 else Fp2.sub(Fp2.ZERO, c) for k, c in enumerate(f))


def fp12_hex(a):
    # An element is (c0 + c1 v + c2 v^2) + (c3 + c4 v + c5 v^2) w with v = w^2, encoded from the
    # highest coefficient of the w part down.
    order = [5, 3, 1, 4, 2, 0]
    return "".join(Fp2.hex(a[k]) for k in order)


def hex_literal(value: str, indent: str) -> str:
    """Returns a hex literal laid out as rustfmt does."""
    if len(value) < 96:
        return f'hex!("{value}")'
    lines = [value[i : i + 96] for i in range(0, len(value), 96)]
    body = "\n".join(f'{indent}    "{line}"' for line in lines)
    return f"hex!(\n{body}\n{indent})"


def emit_multiples(name: str, field, generator) -> str:
    entries = []
    for scalar in SCALARS:
        x, y = multiply(field, generator, scalar)
        entries.append(
            "    (\n"
            f"        {hex_literal(f'{scalar:064x}', '        ')},\n"
            "        [\n"
            f"            {hex_literal(field.hex(x), '            ')},\n"
            f"            {hex_literal(field.hex(y), '            ')},\n"
            "        ],\n"
            "    ),"
        )
    return "\n".join(entries)


def generate() -> str:
    assert on_curve(Fp, B1, G1) and on_curve(Fp2, B2, G2)
    assert multiply(Fp, G1, R) is None and multiply(Fp2, G2, R) is None
    e = pairing(G1, G2)
    # The pairing is bilinear and not degenerate.
    assert e != FP12_ONE and fp12_pow(e, R) == FP12_ONE
    assert pairing(multiply(Fp, G1, 5), multiply(Fp2, G2, 7)) == fp12_pow(e, 35)
    return f"""//! Known answers for the groups and the pairing.
//!
//! Generated by scripts/vectors.py; do not edit.

use crate::core::field::{{
    fp::BYTES as FP_BYTES, fp2::BYTES as FP2_BYTES, fp12::BYTES as FP12_BYTES,
}};
use commonware_formatting::hex;

/// Scalars as big-endian integers, with the affine coordinates of their multiples of the
/// generator of G1.
pub const G1_MULTIPLES: [([u8; 32], [[u8; FP_BYTES]; 2]); {len(SCALARS)}] = [
{emit_multiples("G1", Fp, G1)}
];

/// Scalars as big-endian integers, with the affine coordinates of their multiples of the
/// generator of G2.
pub const G2_MULTIPLES: [([u8; 32], [[u8; FP2_BYTES]; 2]); {len(SCALARS)}] = [
{emit_multiples("G2", Fp2, G2)}
];

/// The pairing of the generators.
pub const PAIRING: [u8; FP12_BYTES] = {hex_literal(fp12_hex(e), "")};
"""


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    expected = generate()
    if args.check:
        actual = OUTPUT.read_text() if OUTPUT.exists() else ""
        if actual != expected:
            print(
                "".join(
                    difflib.unified_diff(
                        actual.splitlines(keepends=True),
                        expected.splitlines(keepends=True),
                        fromfile=str(OUTPUT),
                        tofile=f"generated:{OUTPUT}",
                    )
                ),
                end="",
            )
            raise SystemExit(1)
        print(f"checked {OUTPUT}")
        return
    OUTPUT.write_text(expected)
    print(OUTPUT)


if __name__ == "__main__":
    main()

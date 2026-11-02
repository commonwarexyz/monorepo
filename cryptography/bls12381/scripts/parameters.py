#!/usr/bin/env python3
"""Generate and verify the residue-number-system parameters for the BLS12-381 base field.

Adapted from the parameter generator of Commonware's VROOM port, which follows the VROOM
reference implementation (commit 013169524f701ec62f95048c427ccf9065da1abe); see NOTICE.
Only the base-field tables used by src/core/field/fp/rns.rs are emitted.
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import math
from pathlib import Path
import random
import re
from typing import NamedTuple


BASE_REDUNDANCY = 40
MIN_RNS = -1932
MAX_RNS = 2377
COMBINED_MAX = (MAX_RNS - MIN_RNS) * BASE_REDUNDANCY**2
FRACTION_BITS = 64
U64_MAX = (1 << 64) - 1
WORDS = 6
LANES = 8
BITS = 50
WORD = 52

REFERENCE_HEADER_SHA256 = "27cc87f2350bb87ec75ded2ba962fff073f61a871194f6536e159928524bb14f"
REFERENCE_ARRAY_SHA256 = {
    "moduli1": "bacaf71c02bceaea1493ebe403a0383c03ab7d956fd3f5b567d4759b72332560",
    "moduli2": "fab21eba5003c344dbcd5dca19102c5aef9322f774d64caf49e21924c02bab9f",
    "r1_rns_mat": "b9a635858ab362ace479fc9e527efb1dda75014867b81d0bb5b44ca51df871f3",
    "r1_correction": "2ba77ee8a42bcb1ee1531a215d9ece552fcfe52efd4d583a85e86197950f82da",
    "r1_shifted_quotient_estimations": "ee7a76548646b4dee3c217693598f490fed82ba6bae74dabcfe7e9d80f884f5f",
    "r2_rns_mat": "8f6343f6b62913e99c61cf1a9919d7bad046725fa9be10a0ed79ef52ac97024e",
    "r2_correction": "5ce6eae3dc95edd715b79437fa80e6acd6703e8bd0c419328e2cc0d7fa7761ce",
    "r2_shifted_quotient_estimations": "b7f859324285d7fc37eb4b663d0f387a47406ee00c17a5d940da501b3c455c59",
    "convert_to_rns_mat": "0f432b3258abb62f7595841808225332d0cb00f11472f780ce96e64611a5b83b",
    "convert_to_correction": "2ba77ee8a42bcb1ee1531a215d9ece552fcfe52efd4d583a85e86197950f82da",
    "convert_to_shifted_quotient_estimations": "4ac7f16cacc8f079b9d11656885c8dd048c15700b5f2e13889bba871629330c8",
    "convert_from_rns_mat": "473453113ea6bd754f8493b21f153869c8ec97dd722cc47437fe289613bbdfbf",
    "convert_from_correction": "682b17ef3108d038e7720bb83da684fc5814b33101bfca4059c002c5a19331ce",
    "convert_from_shifted_quotient_estimations": "b7f859324285d7fc37eb4b663d0f387a47406ee00c17a5d940da501b3c455c59",
    "moduli1_padded": "bacaf71c02bceaea1493ebe403a0383c03ab7d956fd3f5b567d4759b72332560",
    "reducer1_mont_factor": "95ec09d9b94bf4c8183f5d06203c63c14921b81de4cd19526823a316528373da",
    "reducer2_mont_factor": "9df3fc5884f66aa85a3afbc855a6f13b37feb55904d7b6ba36a3c81c039fbe42",
}
CRATE = Path(__file__).resolve().parents[1]
OUTPUT = CRATE / "src/core/field/fp/rns/parameters.rs"

P = int(
    "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf"
    "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
    16,
)
MODULI_M = (
    1125899906842615,
    1125899906842609,
    1125899906842591,
    1125899906842559,
    1125899906842553,
    1125899906842549,
    1125899906842541,
    1125899906842511,
)
MODULI_N = (
    1125899906842623,
    1125899906842621,
    1125899906842619,
    1125899906842613,
    1125899906842607,
    1125899906842603,
    1125899906842597,
    1125899906842589,
)
# A square root of the lane constant that lets the Montgomery lane product absorb the CRT
# weights of the first basis, so the reduction needs no quotient correction ("no-k").
QR = int(
    "1764464526391023609719698959639504118661371030573300677125606932387184635588659624517358062862068369090674362610896848484"
)

# Bounds adopted by src/old/fp/rns.rs, in units of p: every element, every product, and the
# multiple of p added by negation. src/core/field/fp/rns.rs adopts the same element bound.
ELEMENT_BOUND = 1 << 11
PRODUCT_BOUND = 1 << 5
NEGATION_OFFSET = 1 << 9


class Conversion(NamedTuple):
    matrix: tuple[tuple[int, ...], ...]
    fraction: tuple[int, ...]
    correction: tuple[int, ...]
    correction_shift: tuple[int, ...]


class Tables(NamedTuple):
    big_m: int
    big_n: int
    rotation: int
    reduce: Conversion
    expand: Conversion
    to_rns: Conversion
    to_canonical: tuple[tuple[int, ...], ...]
    canonical_correction: tuple[int, ...]
    encoded_p: tuple[tuple[int, ...], tuple[int, ...]]


def words(value: int) -> tuple[int, ...]:
    assert 0 <= value < 1 << (64 * WORDS)
    return tuple((value >> (64 * index)) & U64_MAX for index in range(WORDS))


def integer(values: tuple[int, ...]) -> int:
    return sum(word << (64 * limb) for limb, word in enumerate(values))


def crt_weights(moduli: tuple[int, ...]) -> tuple[int, ...]:
    total = math.prod(moduli)
    return tuple(
        (total // modulus) * pow(total // modulus, -1, modulus) % total
        for modulus in moduli
    )


def crt(residues: tuple[int, ...] | list[int], moduli: tuple[int, ...]) -> int:
    return sum(r * w for r, w in zip(residues, crt_weights(moduli))) % math.prod(moduli)


def padded(values: tuple[int, ...] | list[int]) -> tuple[int, ...]:
    assert len(values) <= LANES
    return tuple(values) + (0,) * (LANES - len(values))


def conversion(
    source_moduli: tuple[int, ...],
    destination: tuple[int, ...],
    pre: int,
    post: int,
    *,
    input_digits: int = 1,
    input_bits: int = WORD,
    floor: bool,
) -> Conversion:
    source = math.prod(source_moduli)
    target = math.prod(destination)
    shifted = tuple(
        (pre * pow(1 << input_bits, digit, source) * weight) % source
        for weight in crt_weights(source_moduli)
        for digit in range(input_digits)
    )
    matrix_rows = tuple(
        tuple(((weight % target) * post) % modulus for modulus in destination)
        for weight in shifted
    )
    offset = 0 if floor else source - 1
    fraction = tuple(
        (weight * (1 << FRACTION_BITS) + offset) // source for weight in shifted
    )
    correction = tuple(((-source % target) * post) % modulus for modulus in destination)
    correction_shift = tuple(
        correction[index] * (1 << WORD) % destination[index] for index in range(LANES)
    )
    return Conversion(
        tuple(matrix_rows) + ((0,) * LANES,) * (LANES - len(matrix_rows)),
        padded(fraction),
        correction,
        correction_shift,
    )


def is_probable_prime(value: int) -> bool:
    if value < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small:
        if value % prime == 0:
            return value == prime
    odd = value - 1
    shifts = 0
    while odd & 1 == 0:
        shifts += 1
        odd >>= 1
    for base in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53):
        x = pow(base, odd, value)
        if x in (1, value - 1):
            continue
        for _ in range(shifts - 1):
            x = x * x % value
            if x == value - 1:
                break
        else:
            return False
    return True


def build() -> Tables:
    p = P
    m = MODULI_M
    n = MODULI_N
    big_m = math.prod(m)
    big_n = math.prod(n)
    radix = 1 << WORD
    inverse_m_n = pow(big_m, -1, big_n)
    inverse_radix_n = pow(radix, -1, big_n)

    m_opt = crt([big_m // modulus for modulus in m], m)
    assert all(
        QR * QR * (-p * radix * (big_m // modulus)) % modulus == 1 for modulus in m
    )
    reduce_pre = m_opt
    reduce_post = p * inverse_m_n * inverse_m_n * radix * radix
    expand_pre = big_m * inverse_radix_n
    expand_post = radix * radix * QR
    reduce = conversion(m, n, reduce_pre, reduce_post, floor=True)
    expand = conversion(n, m, expand_pre, expand_post, floor=False)

    input_digits = (p.bit_length() + BITS - 1) // BITS
    to_rns = conversion(
        (p,),
        n,
        big_m,
        inverse_m_n * radix * radix,
        input_digits=input_digits,
        input_bits=BITS,
        floor=True,
    )

    # The radix coefficients carry an extra factor of 2^(64*WORDS) that the
    # six Montgomery word steps of the canonical conversion divide out.
    canonical_post = pow(big_m, -1, p) * pow(2, 64 * WORDS, p) % p
    canonical_shifted = tuple(expand_pre * weight % big_n for weight in crt_weights(n))
    to_canonical = tuple(
        words((shifted % p) * canonical_post % p) for shifted in canonical_shifted
    )
    canonical_correction = words((-big_n % p) * canonical_post % p)
    canonical_fraction = tuple(
        (shifted * (1 << FRACTION_BITS) + big_n - 1) // big_n
        for shifted in canonical_shifted
    )
    assert canonical_fraction == expand.fraction

    modulus_product = big_m * big_n
    e_m = big_n * pow(big_n, -1, big_m)
    e_n = big_m * inverse_m_n
    rotation = radix * (QR * e_m + inverse_m_n * e_n) % modulus_product
    assert rotation % big_m == radix * QR % big_m
    assert rotation % big_n == radix * inverse_m_n % big_n

    encoded_p = (
        tuple((p * rotation) % modulus for modulus in m),
        tuple((p * rotation) % modulus for modulus in n),
    )
    assert any(encoded_p[half][lane] for half in range(2) for lane in range(LANES))
    return Tables(
        big_m,
        big_n,
        rotation,
        reduce,
        expand,
        to_rns,
        to_canonical,
        canonical_correction,
        encoded_p,
    )


def apply_conversion(
    values: tuple[int, ...] | list[int], table: Conversion, *, correction: bool
) -> tuple[list[int], int]:
    k = sum(value * fraction for value, fraction in zip(values, table.fraction)) >> FRACTION_BITS
    output = [
        sum(value * table.matrix[row][column] for row, value in enumerate(values))
        + (k * table.correction[column] if correction else 0)
        for column in range(LANES)
    ]
    return output, k


def validate_model(tables: Tables) -> None:
    p = P
    m = MODULI_M
    n = MODULI_N
    radix = 1 << WORD
    inverse_radix_m = tuple(pow(radix, -1, modulus) for modulus in m)
    inverse_radix_n = tuple(pow(radix, -1, modulus) for modulus in n)
    rng = random.Random("bls12381:fp:rns")

    inverse_m_n = pow(tables.big_m, -1, tables.big_n)
    inverse_radix_big_n = pow(radix, -1, tables.big_n)
    reduce_pre = crt([tables.big_m // modulus for modulus in m], m)
    reduce_post = p * inverse_m_n * inverse_m_n * radix * radix
    expand_pre = tables.big_m * inverse_radix_big_n
    expand_post = radix * radix * QR

    def check_conversion(values, source, destination, pre, post, table, *, correction):
        source_product = math.prod(source)
        shifted = tuple(pre * weight % source_product for weight in crt_weights(source))
        total = sum(value * weight for value, weight in zip(values, shifted))
        raw, k = apply_conversion(values, table, correction=correction)
        lift = total - (k * source_product if correction else 0)
        assert all(
            raw[lane] % destination[lane] == lift * post % destination[lane]
            for lane in range(LANES)
        )
        return lift

    def domain(maxima):
        cases = [(0,) * LANES, maxima, tuple(maximum - 1 for maximum in maxima)]
        cases.extend(
            tuple(maximum if lane == selected else 0 for lane, maximum in enumerate(maxima))
            for selected in range(LANES)
        )
        cases.extend(tuple(rng.randrange(maximum + 1) for maximum in maxima) for _ in range(100))
        return cases

    # The no-k reduction lifts the quotient by at most 2 * LANES multiples of M.
    reduce_maxima = tuple(2 * modulus for modulus in m)
    for values in domain(reduce_maxima):
        lift = check_conversion(
            values, m, n, reduce_pre, reduce_post, tables.reduce, correction=False
        )
        assert 0 <= lift <= 2 * LANES * tables.big_m

    expand_maxima = tuple(2 * modulus for modulus in n)
    for values in domain(expand_maxima):
        lift = check_conversion(
            values, n, m, expand_pre, expand_post, tables.expand, correction=True
        )
        assert 0 <= lift < tables.big_n

    def encode(value: int):
        encoded = value * tables.big_m % p
        encoded = encoded * tables.rotation % (tables.big_m * tables.big_n)
        return (
            tuple(encoded % modulus for modulus in m),
            tuple(encoded % modulus for modulus in n),
        )

    coefficients = tuple(integer(row) for row in tables.to_canonical)
    canonical_correction = integer(tables.canonical_correction)
    inverse_canonical_radix = pow(2, -64 * WORDS, p)

    def canonicalize(n_half: tuple[int, ...]) -> int:
        k = sum(n_half[i] * tables.expand.fraction[i] for i in range(LANES)) >> FRACTION_BITS
        return (
            sum(n_half[i] * coefficients[i] for i in range(LANES)) + k * canonical_correction
        ) * inverse_canonical_radix % p

    def multiply(left_mn, right_mn):
        reduced_m = tuple(
            left_mn[0][i] * right_mn[0][i] * inverse_radix_m[i] % m[i] for i in range(LANES)
        )
        reduce_raw, _ = apply_conversion(reduced_m, tables.reduce, correction=False)
        reduced_n = tuple(
            (reduce_raw[i] + left_mn[1][i] * right_mn[1][i]) * inverse_radix_n[i] % n[i]
            for i in range(LANES)
        )
        expand_raw, _ = apply_conversion(reduced_n, tables.expand, correction=True)
        expanded_m = tuple(expand_raw[i] * inverse_radix_m[i] % m[i] for i in range(LANES))
        return expanded_m, reduced_n

    cases = [(0, 0), (0, 1), (1, 1), (p - 1, 1), (p - 1, p - 1)]
    cases.extend((rng.randrange(p), rng.randrange(p)) for _ in range(100))
    for left, right in cases:
        result = multiply(encode(left), encode(right))
        assert canonicalize(result[1]) == left * right % p

    represented = encode(1)
    expected = 1
    for _ in range(100):
        factor = rng.randrange(p)
        represented = multiply(represented, encode(factor))
        expected = expected * factor % p
        assert canonicalize(represented[1]) == expected

    digits = (p.bit_length() + BITS - 1) // BITS
    for value in (0, 1, p - 1, *[rng.randrange(p) for _ in range(100)]):
        source = padded(
            tuple((value >> (BITS * index)) & ((1 << BITS) - 1) for index in range(digits))
        )
        raw, _ = apply_conversion(source, tables.to_rns, correction=True)
        expected = encode(value)[1]
        assert all(raw[i] * inverse_radix_n[i] % n[i] == expected[i] for i in range(LANES))


def montgomery_lane_bound(total: int, modulus: int) -> int:
    """Largest output of the lane Montgomery reduction of an accumulator below total."""
    return (total >> WORD) + modulus


def fold_bound(value: int, modulus: int) -> int:
    """Largest output of folding 2^BITS into its residue for an input below value."""
    assert value >> BITS < 1 << WORD
    complement = (1 << BITS) - modulus
    return (1 << BITS) - 1 + (value >> BITS) * complement


def validate_kernel(tables: Tables) -> None:
    """Checks the lane and integer bounds of the kernel in src/old/fp/rns.rs.

    Every element has lanes in [0, 2q]. A multiplication accumulates one lane product,
    and each conversion accumulates one row product per lane plus its quotient correction.
    """
    m = MODULI_M
    n = MODULI_N
    radix = 1 << WORD
    assert all(4 * modulus < radix for modulus in m + n)
    # Each multiply-add contributes below 2^52 to a low accumulator.
    assert (1 + LANES + 2) * radix <= U64_MAX

    # The first-basis reduction of a single lane product is already in [0, 2q].
    for modulus in m:
        assert montgomery_lane_bound((2 * modulus) ** 2, modulus) <= 2 * modulus

    # The second basis adds the reduction rows to its own lane product.
    for column, modulus in enumerate(n):
        total = (2 * modulus) ** 2 + sum(
            2 * m[row] * tables.reduce.matrix[row][column] for row in range(LANES)
        )
        reduced = montgomery_lane_bound(total, modulus)
        assert fold_bound(reduced, modulus) <= 2 * modulus

    # Expansion of prepared second-basis lanes; the quotient has two 52-bit digits.
    expand_k = sum(2 * n[i] * tables.expand.fraction[i] for i in range(LANES)) >> FRACTION_BITS
    assert expand_k < 1 << 64
    for column, modulus in enumerate(m):
        total = sum(2 * n[row] * tables.expand.matrix[row][column] for row in range(LANES))
        total += (radix - 1) * tables.expand.correction[column]
        total += (expand_k >> WORD) * tables.expand.correction_shift[column]
        reduced = montgomery_lane_bound(total, modulus)
        assert fold_bound(reduced, modulus) <= 2 * modulus

    # Conversion of a canonical integer from BITS-bit digits uses both quotient digits.
    digit = (1 << BITS) - 1
    to_k = sum(digit * fraction for fraction in tables.to_rns.fraction) >> FRACTION_BITS
    assert to_k < 1 << 64
    for column, modulus in enumerate(n):
        total = sum(digit * tables.to_rns.matrix[row][column] for row in range(LANES))
        total += (radix - 1) * tables.to_rns.correction[column]
        total += (to_k >> WORD) * tables.to_rns.correction_shift[column]
        reduced = montgomery_lane_bound(total, modulus)
        assert fold_bound(reduced, modulus) <= 2 * modulus

    # Products of elements stay within the validated reduction budget, the reduction output
    # stays below the product bound, and every element expands and canonicalizes exactly.
    p = P
    assert ELEMENT_BOUND**2 <= COMBINED_MAX
    reduction = ELEMENT_BOUND**2 * p * p // tables.big_m + (2 * LANES + 1) * p
    assert reduction < PRODUCT_BOUND * p
    assert 2 * ELEMENT_BOUND * p < tables.big_n
    assert NEGATION_OFFSET <= ELEMENT_BOUND


def validate_bounds(tables: Tables) -> None:
    p = P
    m = MODULI_M
    n = MODULI_N
    assert tables.big_m > BASE_REDUNDANCY * p
    assert tables.big_n > 6 * p
    assert COMBINED_MAX * p * p < tables.big_m * tables.big_n
    assert BASE_REDUNDANCY >= 2 * LANES + 4
    assert all(integer(coefficient) < p for coefficient in tables.to_canonical)
    assert integer(tables.canonical_correction) < p
    canonical_max = sum(
        (2 * n[index]) * integer(tables.to_canonical[index]) for index in range(LANES)
    )
    canonical_k = sum(
        (2 * n[index]) * tables.expand.fraction[index] for index in range(LANES)
    ) >> FRACTION_BITS
    canonical_max += canonical_k * integer(tables.canonical_correction)
    # The seven-word canonical accumulator stays below 2^64 * p.
    assert canonical_max < (1 << 55) * p
    assert 1 < p < (1 << 381) and p & 1
    # Ceil-fixed-point error is strictly below sum(inputs)/2^64 < 1/2.
    assert sum(2 * modulus for modulus in n) < 1 << 63
    for table, destination in (
        (tables.reduce, n),
        (tables.expand, m),
        (tables.to_rns, n),
    ):
        assert all(
            coefficient < destination[column]
            for row in table.matrix
            for column, coefficient in enumerate(row)
        )
        assert all(value < destination[column] for column, value in enumerate(table.correction))
        assert all(
            value < destination[column] for column, value in enumerate(table.correction_shift)
        )
        assert all(fraction <= U64_MAX for fraction in table.fraction)
    assert all(
        value < modulus
        for half, moduli in enumerate((m, n))
        for value, modulus in zip(tables.encoded_p[half], moduli)
    )


def parse_reference_array(source: str, name: str) -> list[int]:
    line = next(line for line in source.splitlines() if re.search(rf"\b{name}\s*=", line))
    return [int(value) for value in re.findall(r"\d+", line.split("=", 1)[1])]


def validate_reference(tables: Tables, reference_header: Path | None) -> None:
    mask = (1 << WORD) - 1
    # The reference stores the plain radix coefficients without the
    # 2^(64*WORDS) factor carried by the emitted tables.
    p = P
    inverse_canonical_radix = pow(2, -64 * WORDS, p)
    from_matrix = [
        (coefficient >> (WORD * digit)) & mask
        for row in tables.to_canonical
        for coefficient in (integer(row) * inverse_canonical_radix % p,)
        for digit in range(LANES)
    ]
    correction = integer(tables.canonical_correction) * inverse_canonical_radix % p
    arrays = {
        "moduli1": list(MODULI_M),
        "moduli2": list(MODULI_N),
        "moduli1_padded": list(MODULI_M),
        "convert_from_rns_mat": from_matrix,
        "convert_from_correction": [(correction >> (WORD * digit)) & mask for digit in range(LANES)],
        "convert_from_shifted_quotient_estimations": list(tables.expand.fraction),
        "reducer1_mont_factor": [pow(modulus, -1, 1 << WORD) for modulus in MODULI_M],
        "reducer2_mont_factor": [pow(modulus, -1, 1 << WORD) for modulus in MODULI_N],
    }
    for name, actual in (
        ("r1", tables.reduce),
        ("r2", tables.expand),
        ("convert_to", tables.to_rns),
    ):
        arrays[f"{name}_rns_mat"] = [value for row in actual.matrix for value in row]
        arrays[f"{name}_correction"] = list(actual.correction)
        arrays[f"{name}_shifted_quotient_estimations"] = list(actual.fraction)

    assert arrays.keys() == REFERENCE_ARRAY_SHA256.keys()
    for name, values in arrays.items():
        encoded = ",".join(map(str, values)).encode()
        assert hashlib.sha256(encoded).hexdigest() == REFERENCE_ARRAY_SHA256[name], name

    # A supplied pinned export is checked scalar by scalar in addition to the
    # self-contained hashes used by clean source trees.
    if reference_header is not None:
        assert hashlib.sha256(reference_header.read_bytes()).hexdigest() == REFERENCE_HEADER_SHA256
        source = reference_header.read_text()
        for name, values in arrays.items():
            assert values == parse_reference_array(source, name)


def fmt_array(values, indent: str) -> str:
    rendered = [f"0x{value:016x}" for value in values]
    return "[\n" + "".join(f"{indent}    {value},\n" for value in rendered) + indent + "]"


def fmt_matrix(rows, indent: str) -> str:
    return (
        "[\n"
        + "".join(f"{indent}    {fmt_array(row, indent + '    ')},\n" for row in rows)
        + indent
        + "]"
    )


def emit_basis(moduli: tuple[int, ...]) -> str:
    radix = 1 << WORD
    return (
        "Basis {\n"
        f"    moduli: {fmt_array(moduli, '    ')},\n"
        f"    complement: {fmt_array(tuple((1 << BITS) - q for q in moduli), '    ')},\n"
        f"    inverse: {fmt_array(tuple(pow(q, -1, radix) for q in moduli), '    ')},\n"
        "}"
    )


def emit_conversion(value: Conversion) -> str:
    return (
        "Conversion {\n"
        f"    matrix: {fmt_matrix(value.matrix, '    ')},\n"
        f"    fraction: {fmt_array(value.fraction, '    ')},\n"
        f"    correction: {fmt_array(value.correction, '    ')},\n"
        f"    correction_shift: {fmt_array(value.correction_shift, '    ')},\n"
        "}"
    )


def emit(tables: Tables) -> str:
    p = P
    return f"""//! Residue-number-system parameters for the base field.
//!
//! Adapted from the BLS12-381 coordinate-field tables of VROOM
//! (<https://eprint.iacr.org/2026/393>); see NOTICE.
//!
//! Generated by scripts/parameters.py; do not edit.

use super::{{Basis, Conversion, MODULI, WORDS}};

/// The modulus `p` as little-endian 64-bit words.
pub(crate) const MODULUS: [u64; WORDS] = {fmt_array(words(p), '')};

/// `-p^(-1) mod 2^64`, the word Montgomery constant of the canonical conversion.
pub(crate) const MODULUS_N0: u64 = 0x{(-pow(p, -1, 1 << 64)) % (1 << 64):016x};

/// `floor(M / p)` for the product `M` of the first basis.
pub(crate) const M_OVER_P: u64 = {tables.big_m // p};

/// `floor(N / p)` for the product `N` of the second basis.
pub(crate) const N_OVER_P: u64 = {tables.big_n // p};

/// The first basis.
pub(crate) const M: Basis = {emit_basis(MODULI_M)};

/// The second basis.
pub(crate) const N: Basis = {emit_basis(MODULI_N)};

/// Rows of the conversion of the Montgomery quotient from the first basis to the second.
pub(crate) const REDUCE: [[u64; MODULI]; MODULI] = {fmt_matrix(tables.reduce.matrix, '')};

/// The conversion from the second basis to the first.
pub(crate) const EXPAND: Conversion = {emit_conversion(tables.expand)};

/// The conversion of a canonical integer, in {BITS}-bit digits, into the second basis.
pub(crate) const TO_RNS: Conversion = {emit_conversion(tables.to_rns)};

/// Second-basis CRT weights modulo `p`, divided by `M` and scaled by `2^{64 * WORDS}`.
pub(crate) const TO_CANONICAL: [[u64; WORDS]; MODULI] = {fmt_matrix(tables.to_canonical, '')};

/// `-N mod p`, scaled like [`TO_CANONICAL`].
pub(crate) const CANONICAL_CORRECTION: [u64; WORDS] = {fmt_array(tables.canonical_correction, '')};

/// The residues of the integer `p` in each basis.
pub(crate) const ENCODED_P: [[u64; MODULI]; 2] = {fmt_matrix(tables.encoded_p, '')};
"""


def generate(reference_header: Path | None = None) -> str:
    assert is_probable_prime(P)
    assert len(MODULI_M) == LANES and len(MODULI_N) == LANES
    assert all(modulus & 1 and modulus < 1 << BITS for modulus in MODULI_M + MODULI_N)
    moduli = MODULI_M + MODULI_N
    for index, left in enumerate(moduli):
        assert all(math.gcd(left, right) == 1 for right in moduli[index + 1 :])
    tables = build()
    validate_bounds(tables)
    validate_model(tables)
    validate_kernel(tables)
    validate_reference(tables, reference_header)
    return emit(tables)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--reference-header",
        type=Path,
        help="also compare every scalar with the pinned VROOM export",
    )
    args = parser.parse_args()
    expected = generate(args.reference_header)
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
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(expected)
    print(OUTPUT)


if __name__ == "__main__":
    main()

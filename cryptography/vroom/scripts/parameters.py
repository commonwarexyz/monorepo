#!/usr/bin/env python3
"""Generate and verify the architecture-specific VROOM parameter tables."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import math
from pathlib import Path
import random
import re
from typing import NamedTuple


BASE_REDUNDANCY = 40
MAX_ADD = 800
MIN_RNS = -1932
MAX_RNS = 2377
COMBINED_MAX = (MAX_RNS - MIN_RNS) * BASE_REDUNDANCY**2
FRACTION_BITS = 64
U64_MAX = (1 << 64) - 1
WORDS = 6

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
OUTPUT = CRATE / "src/parameters"
WRAPPER = CRATE / "src/parameters.rs"
REPORT = Path(__file__).resolve().parent / "parameters-validation.json"


class Field(NamedTuple):
    name: str
    modulus: int


class Geometry(NamedTuple):
    name: str
    lanes: int
    bits: int
    word: int
    moduli_m: tuple[int, ...]
    moduli_n: tuple[int, ...]


class Conversion(NamedTuple):
    matrix: tuple[tuple[int, ...], ...]
    fraction: tuple[int, ...]
    correction: tuple[int, ...]
    correction_shift: tuple[int, ...]


class Tables(NamedTuple):
    field: Field
    geometry: Geometry
    no_k: bool
    max_expand: int
    big_m: int
    big_n: int
    rotation: int
    reduce: Conversion
    expand: Conversion
    to_rns: Conversion
    to_canonical: tuple[tuple[int, ...], ...]
    canonical_correction: tuple[int, ...]
    encoded_p: tuple[tuple[int, ...], tuple[int, ...]]
    wide_encoded_p2: tuple[tuple[int, ...], tuple[int, ...]]
    one: tuple[tuple[int, ...], tuple[int, ...]]
    radix_256: tuple[tuple[int, ...], tuple[int, ...]]
    root: tuple[tuple[int, ...], tuple[int, ...]]
    sqrt_exponent: tuple[int, ...]
    odd_exponent: tuple[int, ...]
    half_plus_one: tuple[int, ...]
    two_adicity: int


FIELDS = (
    Field(
        "bls12381",
        int(
            "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf"
            "6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab",
            16,
        ),
    ),
    Field(
        "bls_scalar",
        int("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001", 16),
    ),
    Field(
        "bander_scalar",
        int("1cfb69d4ca675f520cce760202687600ff8f87007419047174fd06b52876e7e1", 16),
    ),
    Field("curve25519", (1 << 255) - 19),
)

X86_M = (
    1125899906842615,
    1125899906842609,
    1125899906842591,
    1125899906842559,
    1125899906842553,
    1125899906842549,
    1125899906842541,
    1125899906842511,
)
X86_N = (
    1125899906842623,
    1125899906842621,
    1125899906842619,
    1125899906842613,
    1125899906842607,
    1125899906842603,
    1125899906842597,
    1125899906842589,
)
ARM_OFFSETS = (
    1,
    3,
    5,
    9,
    11,
    15,
    17,
    21,
    23,
    27,
    33,
    35,
    41,
    45,
    51,
    57,
    63,
    65,
    71,
    83,
    87,
    93,
    101,
    107,
    111,
    113,
    117,
    125,
    131,
    135,
    143,
    153,
)
ARM_M = tuple((1 << 26) - offset for offset in ARM_OFFSETS[:16])
ARM_N = tuple((1 << 26) - offset for offset in ARM_OFFSETS[16:])

GEOMETRIES = (
    Geometry("x86", 8, 50, 52, X86_M, X86_N),
    Geometry("arm", 16, 26, 32, ARM_M, ARM_N),
)

BLS_QR = int(
    "1764464526391023609719698959639504118661371030573300677125606932387184635588659624517358062862068369090674362610896848484"
)


def words(value: int) -> tuple[int, ...]:
    assert 0 <= value < 1 << (64 * WORDS)
    return tuple((value >> (64 * index)) & U64_MAX for index in range(WORDS))


def crt_weights(moduli: tuple[int, ...]) -> tuple[int, ...]:
    total = math.prod(moduli)
    return tuple(
        (total // modulus) * pow(total // modulus, -1, modulus) % total
        for modulus in moduli
    )


def crt(residues: tuple[int, ...] | list[int], moduli: tuple[int, ...]) -> int:
    return sum(r * w for r, w in zip(residues, crt_weights(moduli))) % math.prod(moduli)


def padded(values: tuple[int, ...] | list[int], lanes: int) -> tuple[int, ...]:
    assert len(values) <= lanes
    return tuple(values) + (0,) * (lanes - len(values))


def conversion(
    source_moduli: tuple[int, ...],
    destination: tuple[int, ...],
    pre: int,
    post: int,
    geometry: Geometry,
    *,
    input_digits: int = 1,
    input_bits: int | None = None,
    floor: bool,
) -> Conversion:
    source = math.prod(source_moduli)
    target = math.prod(destination)
    input_bits = geometry.word if input_bits is None else input_bits
    source_weights = crt_weights(source_moduli)
    shifted = tuple(
        (pre * pow(1 << input_bits, digit, source) * weight) % source
        for weight in source_weights
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
    radix = 1 << geometry.word
    correction_shift = tuple(
        correction[index] * radix % destination[index]
        for index in range(geometry.lanes)
    )
    return Conversion(
        tuple(matrix_rows) + ((0,) * geometry.lanes,) * (geometry.lanes - len(matrix_rows)),
        padded(fraction, geometry.lanes),
        correction,
        correction_shift,
    )


def decompose_power_of_two(value: int) -> tuple[int, int]:
    exponent = 0
    while value & 1 == 0:
        exponent += 1
        value >>= 1
    return exponent, value


def first_nonresidue(modulus: int) -> int:
    candidate = 2
    while pow(candidate, (modulus - 1) // 2, modulus) != modulus - 1:
        candidate += 1
    return candidate


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


def build(field: Field, geometry: Geometry) -> Tables:
    p = field.modulus
    m = geometry.moduli_m
    n = geometry.moduli_n
    big_m = math.prod(m)
    big_n = math.prod(n)
    radix = 1 << geometry.word
    inverse_m_n = pow(big_m, -1, big_n)
    inverse_radix_m = pow(radix, -1, big_m)
    inverse_radix_n = pow(radix, -1, big_n)
    no_k = geometry.name == "x86" and field.name == "bls12381"

    if no_k:
        m_opt = crt([big_m // modulus for modulus in m], m)
        qr = BLS_QR
        assert all(
            qr * qr * (-p * radix * (big_m // modulus)) % modulus == 1
            for modulus in m
        )
        reduce_pre = m_opt
        reduce_post = p * inverse_m_n * inverse_m_n * radix * radix
    else:
        qr = 1
        reduce_pre = pow(-p, -1, big_m) * inverse_radix_m % big_m
        reduce_post = p * inverse_m_n * inverse_m_n * radix * radix

    expand_pre = big_m * inverse_radix_n
    expand_post = radix * radix * qr
    reduce = conversion(m, n, reduce_pre, reduce_post, geometry, floor=True)
    expand = conversion(n, m, expand_pre, expand_post, geometry, floor=False)

    input_digits = (p.bit_length() + geometry.bits - 1) // geometry.bits
    to_rns = conversion(
        (p,),
        n,
        big_m,
        inverse_m_n * radix * radix,
        geometry,
        input_digits=input_digits,
        input_bits=geometry.bits,
        floor=True,
    )

    canonical_post = pow(big_m, -1, p)
    canonical_shifted = tuple(expand_pre * weight % big_n for weight in crt_weights(n))
    canonical_values = tuple(
        (shifted % p) * canonical_post % p for shifted in canonical_shifted
    )
    to_canonical = tuple(words(value) for value in canonical_values)
    canonical_correction = words((-big_n % p) * canonical_post % p)
    canonical_fraction = tuple(
        (shifted * (1 << FRACTION_BITS) + big_n - 1) // big_n
        for shifted in canonical_shifted
    )
    assert canonical_fraction == expand.fraction

    modulus_product = big_m * big_n
    e_m = big_n * pow(big_n, -1, big_m)
    e_n = big_m * inverse_m_n
    rotation = radix * (qr * e_m + inverse_m_n * e_n) % modulus_product
    assert rotation % big_m == radix * qr % big_m
    assert rotation % big_n == radix * inverse_m_n % big_n

    def encode_exact(value: int, *, wide: bool = False):
        redundancy = value // p
        encoded = value * big_m % p
        if wide:
            encoded = encoded * big_m % p
        encoded += redundancy * p
        encoded = encoded * rotation % modulus_product
        if wide:
            encoded = encoded * rotation % modulus_product
        return (
            tuple(encoded % modulus for modulus in m),
            tuple(encoded % modulus for modulus in n),
        )

    two_adicity, odd_exponent = decompose_power_of_two(p - 1)
    nonresidue = first_nonresidue(p)
    root = pow(nonresidue, odd_exponent, p)

    tables = Tables(
        field,
        geometry,
        no_k,
        min((1 << 63) - 1, big_n // (2 * BASE_REDUNDANCY * p)),
        big_m,
        big_n,
        rotation,
        reduce,
        expand,
        to_rns,
        to_canonical,
        canonical_correction,
        encode_exact(p),
        encode_exact(p * p, wide=True),
        encode_exact(1),
        encode_exact(1 << 256),
        encode_exact(root),
        words((odd_exponent + 1) // 2),
        words(odd_exponent),
        words((p + 1) // 2),
        two_adicity,
    )
    assert tables.encoded_p == (
        tuple((p * rotation) % modulus for modulus in m),
        tuple((p * rotation) % modulus for modulus in n),
    )
    assert tables.wide_encoded_p2 == (
        tuple((p * p * rotation * rotation) % modulus for modulus in m),
        tuple((p * p * rotation * rotation) % modulus for modulus in n),
    )
    assert any(tables.encoded_p[half][lane] for half in range(2) for lane in range(geometry.lanes))
    assert any(
        tables.wide_encoded_p2[half][lane]
        for half in range(2)
        for lane in range(geometry.lanes)
    )
    assert tables.max_expand >= 6
    assert tables.max_expand * 2 * BASE_REDUNDANCY * p < big_n
    assert sum(2 * modulus for modulus in n) < 1 << 63
    return tables


def apply_conversion(
    values: tuple[int, ...] | list[int], conversion_table: Conversion, *, correction: bool
) -> tuple[list[int], int]:
    k_raw = sum(value * fraction for value, fraction in zip(values, conversion_table.fraction))
    k = k_raw >> FRACTION_BITS
    output = [
        sum(value * conversion_table.matrix[row][column] for row, value in enumerate(values))
        + (k * conversion_table.correction[column] if correction else 0)
        for column in range(len(conversion_table.correction))
    ]
    return output, k


def validate_model(tables: Tables) -> dict[str, int]:
    p = tables.field.modulus
    g = tables.geometry
    m = g.moduli_m
    n = g.moduli_n
    radix = 1 << g.word
    inverse_radix_m = tuple(pow(radix, -1, modulus) for modulus in m)
    inverse_radix_n = tuple(pow(radix, -1, modulus) for modulus in n)
    rng = random.Random(f"{g.name}:{tables.field.name}:vroom")

    inverse_m_n = pow(tables.big_m, -1, tables.big_n)
    inverse_radix_big_m = pow(radix, -1, tables.big_m)
    inverse_radix_big_n = pow(radix, -1, tables.big_n)
    if tables.no_k:
        reduce_pre = crt([tables.big_m // modulus for modulus in m], m)
    else:
        reduce_pre = pow(-p, -1, tables.big_m) * inverse_radix_big_m % tables.big_m
    reduce_post = p * inverse_m_n * inverse_m_n * radix * radix
    expand_pre = tables.big_m * inverse_radix_big_n
    expand_post = radix * radix * (BLS_QR if tables.no_k else 1)

    def check_conversion(
        values: tuple[int, ...],
        source: tuple[int, ...],
        destination: tuple[int, ...],
        pre: int,
        post: int,
        table: Conversion,
        *,
        correction: bool,
        maximum_lift: int | None,
    ) -> int:
        source_product = math.prod(source)
        shifted = tuple(
            pre * weight % source_product for weight in crt_weights(source)
        )
        total = sum(value * weight for value, weight in zip(values, shifted))
        raw, k = apply_conversion(values, table, correction=correction)
        lift = total - (k * source_product if correction else 0)
        assert all(
            raw[lane] % destination[lane] == lift * post % destination[lane]
            for lane in range(g.lanes)
        )
        if maximum_lift is not None:
            assert 0 <= lift <= maximum_lift
        return lift

    ready_m = 2 if tables.no_k else (4 if g.name == "x86" else 64)
    reduce_maxima = tuple(ready_m * modulus for modulus in m)
    reduce_cases = [
        (0,) * g.lanes,
        reduce_maxima,
        tuple(maximum - 1 for maximum in reduce_maxima),
    ]
    reduce_cases.extend(
        tuple(maximum if lane == selected else 0 for lane, maximum in enumerate(reduce_maxima))
        for selected in range(g.lanes)
    )
    reduce_cases.extend(
        tuple(rng.randrange(maximum + 1) for maximum in reduce_maxima)
        for _ in range(100)
    )
    for values in reduce_cases:
        lift = check_conversion(
            values,
            m,
            n,
            reduce_pre,
            reduce_post,
            tables.reduce,
            correction=not tables.no_k,
            maximum_lift=tables.big_m if not tables.no_k else None,
        )
        if not tables.no_k and values == reduce_maxima:
            # The inclusive endpoint is the reference's redundant encoding of
            # zero: the floor estimate may retain M, which contributes p.
            assert lift == tables.big_m
            assert p * lift // tables.big_m == p

    expand_maxima = tuple(2 * modulus for modulus in n)
    expand_cases = [
        (0,) * g.lanes,
        expand_maxima,
        tuple(maximum - 1 for maximum in expand_maxima),
    ]
    expand_cases.extend(
        tuple(maximum if lane == selected else 0 for lane, maximum in enumerate(expand_maxima))
        for selected in range(g.lanes)
    )
    expand_cases.extend(
        tuple(rng.randrange(maximum + 1) for maximum in expand_maxima)
        for _ in range(100)
    )
    for values in expand_cases:
        check_conversion(
            values,
            n,
            m,
            expand_pre,
            expand_post,
            tables.expand,
            correction=True,
            maximum_lift=tables.big_n - 1,
        )

    def encode(value: int):
        encoded = value * tables.big_m % p
        encoded = encoded * tables.rotation % (tables.big_m * tables.big_n)
        return (
            tuple(encoded % modulus for modulus in m),
            tuple(encoded % modulus for modulus in n),
        )

    coefficients = tuple(
        sum(word << (64 * limb) for limb, word in enumerate(row))
        for row in tables.to_canonical
    )
    canonical_correction = sum(
        word << (64 * limb) for limb, word in enumerate(tables.canonical_correction)
    )

    def canonicalize(n_half: tuple[int, ...]) -> int:
        k = sum(
            n_half[i] * tables.expand.fraction[i] for i in range(g.lanes)
        ) >> FRACTION_BITS
        return (
            sum(n_half[i] * coefficients[i] for i in range(g.lanes))
            + k * canonical_correction
        ) % p

    def multiply(left_mn, right_mn):
        reduced_m = tuple(
            left_mn[0][i] * right_mn[0][i] * inverse_radix_m[i] % m[i]
            for i in range(g.lanes)
        )
        reduce_raw, _ = apply_conversion(
            reduced_m, tables.reduce, correction=not tables.no_k
        )
        reduced_n = tuple(
            (reduce_raw[i] + left_mn[1][i] * right_mn[1][i])
            * inverse_radix_n[i]
            % n[i]
            for i in range(g.lanes)
        )
        expand_raw, _ = apply_conversion(reduced_n, tables.expand, correction=True)
        expanded_m = tuple(
            expand_raw[i] * inverse_radix_m[i] % m[i] for i in range(g.lanes)
        )
        return expanded_m, reduced_n

    cases = [(0, 0), (0, 1), (1, 1), (p - 1, 1), (p - 1, p - 1)]
    cases.extend((rng.randrange(p), rng.randrange(p)) for _ in range(100))
    for left, right in cases:
        result = multiply(encode(left), encode(right))
        canonical = canonicalize(result[1])
        assert canonical == left * right % p

    represented = encode(1)
    expected = 1
    for _ in range(100):
        factor = rng.randrange(p)
        represented = multiply(represented, encode(factor))
        expected = expected * factor % p
        assert canonicalize(represented[1]) == expected

    digits = (p.bit_length() + g.bits - 1) // g.bits
    for value in (0, 1, p - 1, *[rng.randrange(p) for _ in range(100)]):
        source = padded(
            tuple((value >> (g.bits * index)) & ((1 << g.bits) - 1) for index in range(digits)),
            g.lanes,
        )
        raw, _ = apply_conversion(source, tables.to_rns, correction=True)
        expected = encode(value)[1]
        assert all(
            raw[i] * inverse_radix_n[i] % n[i] == expected[i]
            for i in range(g.lanes)
        )

    radix_256 = canonicalize(multiply(encode(1), tables.radix_256)[1])
    assert radix_256 == pow(2, 256, p)
    decode_lengths = (0, 1, 7, 31, 32, 33, 64, 65, 96, 129)
    for length in decode_lengths:
        octets = bytes(rng.randrange(256) for _ in range(length))
        prefix = length % 32
        reduced = int.from_bytes(octets[:prefix], "big")
        for index in range(prefix, length, 32):
            reduced = (
                reduced * radix_256
                + int.from_bytes(octets[index : index + 32], "big")
            ) % p
        assert reduced == int.from_bytes(octets, "big") % p
    return {
        "multiply_cases": len(cases),
        "multiply_chain": 100,
        "to_rns_cases": 103,
        "decode_cases": len(decode_lengths),
        "reduce_domain_cases": len(reduce_cases),
        "expand_domain_cases": len(expand_cases),
    }


def conversion_bounds(
    name: str,
    table: Conversion,
    source_maxima: tuple[int, ...],
    destination: tuple[int, ...],
    geometry: Geometry,
    *,
    use_correction: bool,
    accumulated_products: int = 0,
    matrix_bound_multiple: int | None = None,
) -> dict[str, int]:
    assert len(source_maxima) == geometry.lanes
    radix = 1 << geometry.word
    k_raw_max = sum(
        source_maxima[index] * table.fraction[index]
        for index in range(geometry.lanes)
    )
    assert k_raw_max < 1 << 128, f"{name} quotient accumulator overflows u128"
    k_max = k_raw_max >> FRACTION_BITS
    max_low = 0
    max_high = 0
    max_total = 0
    for column, modulus in enumerate(destination):
        matrix_products = [
            source_maxima[row] * table.matrix[row][column]
            for row in range(geometry.lanes)
        ]
        matrix_total = sum(matrix_products)
        if matrix_bound_multiple is not None:
            assert matrix_total <= matrix_bound_multiple * geometry.lanes * modulus * modulus
        products = list(matrix_products)
        if use_correction:
            # The low word of k is not monotone in k.  Bound it independently
            # over the complete interval instead of evaluating only k_max.
            products.append((radix - 1) * table.correction[column])
            products.append((k_max >> geometry.word) * table.correction_shift[column])
        products.extend([(2 * modulus) ** 2] * accumulated_products)
        # Every low-half multiply-add contributes at most R-1 independently.
        low = len(products) * (radix - 1)
        high = sum(product >> geometry.word for product in products)
        total = sum(products)
        assert low <= U64_MAX, f"{name} lane {column} low accumulator overflows"
        assert high <= U64_MAX, f"{name} lane {column} high accumulator overflows"
        assert total < 1 << (geometry.word + 64)
        max_low = max(max_low, low)
        max_high = max(max_high, high)
        max_total = max(max_total, total)
    return {
        "k_raw_bits": k_raw_max.bit_length(),
        "k_max": k_max,
        "low_acc_bits": max_low.bit_length(),
        "high_acc_bits": max_high.bit_length(),
        "total_acc_bits": max_total.bit_length(),
    }


def validate_bounds(tables: Tables) -> dict[str, object]:
    p = tables.field.modulus
    g = tables.geometry
    m = g.moduli_m
    n = g.moduli_n
    assert tables.big_m > BASE_REDUNDANCY * p
    assert tables.big_n > 6 * p
    assert COMBINED_MAX * p * p < tables.big_m * tables.big_n
    if tables.no_k:
        assert BASE_REDUNDANCY >= 2 * g.lanes + 4
    else:
        assert COMBINED_MAX * p + 2 * tables.big_m < BASE_REDUNDANCY * tables.big_m

    radix = 1 << g.word
    lane_low = MAX_ADD * (radix - 1)
    lane_high = max(MAX_ADD * (((2 * modulus) ** 2) >> g.word) for modulus in m + n)
    assert lane_low <= U64_MAX
    assert lane_high <= U64_MAX

    ready_m = 2 if tables.no_k else (4 if g.name == "x86" else 64)
    reduce_bounds = conversion_bounds(
        "reduce",
        tables.reduce,
        tuple(ready_m * modulus for modulus in m),
        n,
        g,
        use_correction=not tables.no_k,
        accumulated_products=MAX_ADD,
        matrix_bound_multiple=ready_m,
    )
    expand_bounds = conversion_bounds(
        "expand",
        tables.expand,
        tuple(2 * modulus for modulus in n),
        m,
        g,
        use_correction=True,
    )
    digits = (p.bit_length() + g.bits - 1) // g.bits
    digit_maxima = padded(((1 << g.bits) - 1,) * digits, g.lanes)
    to_bounds = conversion_bounds(
        "to_rns", tables.to_rns, digit_maxima, n, g, use_correction=True
    )
    canonical_max = sum(
        (2 * n[index])
        * sum(word << (64 * limb) for limb, word in enumerate(tables.to_canonical[index]))
        for index in range(g.lanes)
    )
    canonical_k_raw = sum(
        (2 * n[index]) * tables.expand.fraction[index]
        for index in range(g.lanes)
    )
    canonical_k = canonical_k_raw >> FRACTION_BITS
    canonical_max += canonical_k * sum(
        word << (64 * limb) for limb, word in enumerate(tables.canonical_correction)
    )
    assert all(
        sum(word << (64 * limb) for limb, word in enumerate(coefficient)) < p
        for coefficient in tables.to_canonical
    )
    assert sum(
        word << (64 * limb) for limb, word in enumerate(tables.canonical_correction)
    ) < p
    canonical_limit_bits = 55 if g.name == "x86" else 32
    assert canonical_max < (1 << canonical_limit_bits) * p
    assert 1 < p < (1 << 381) and p & 1
    # Ceil-fixed-point error is strictly below sum(inputs)/2^64 < 1/2.
    assert sum(2 * modulus for modulus in n) < 1 << 63
    return {
        "M_over_p": tables.big_m // p,
        "N_over_p": tables.big_n // p,
        "MN_over_combined_p2": tables.big_m * tables.big_n // (COMBINED_MAX * p * p),
        "max_expand": tables.max_expand,
        "ready_m_multiple": ready_m,
        "lane_product_low_acc_bits": lane_low.bit_length(),
        "lane_product_high_acc_bits": lane_high.bit_length(),
        "reduce": reduce_bounds,
        "expand": expand_bounds,
        "to_rns": to_bounds,
        "canonical_acc_bits": canonical_max.bit_length(),
        "canonical_acc_over_p_bits": (canonical_max // p).bit_length(),
    }


def validate_widths(tables: Tables) -> None:
    g = tables.geometry
    for conversion_table, destination in (
        (tables.reduce, g.moduli_n),
        (tables.expand, g.moduli_m),
        (tables.to_rns, g.moduli_n),
    ):
        assert all(
            coefficient < destination[column]
            for row in conversion_table.matrix
            for column, coefficient in enumerate(row)
        )
        assert all(
            correction < destination[column]
            for column, correction in enumerate(conversion_table.correction)
        )
        assert all(
            correction < destination[column]
            for column, correction in enumerate(conversion_table.correction_shift)
        )
        assert all(fraction <= U64_MAX for fraction in conversion_table.fraction)
    for encoded in (
        tables.encoded_p,
        tables.wide_encoded_p2,
        tables.one,
        tables.radix_256,
        tables.root,
    ):
        assert all(
            value < modulus
            for half, moduli in enumerate((g.moduli_m, g.moduli_n))
            for value, modulus in zip(encoded[half], moduli)
        )


def parse_reference_array(source: str, name: str) -> list[int]:
    line = next(line for line in source.splitlines() if re.search(rf"\b{name}\s*=", line))
    return [int(value) for value in re.findall(r"\d+", line.split("=", 1)[1])]


def validate_bls_reference(tables: Tables, reference_header: Path | None) -> None:
    assert tables.field.name == "bls12381" and tables.geometry.name == "x86"
    mask = (1 << tables.geometry.word) - 1
    from_matrix = [
        (coefficient >> (tables.geometry.word * digit)) & mask
        for row in tables.to_canonical
        for coefficient in (sum(word << (64 * limb) for limb, word in enumerate(row)),)
        for digit in range(tables.geometry.lanes)
    ]
    correction = sum(
        word << (64 * limb)
        for limb, word in enumerate(tables.canonical_correction)
    )
    arrays = {
        "moduli1": list(tables.geometry.moduli_m),
        "moduli2": list(tables.geometry.moduli_n),
        "moduli1_padded": list(tables.geometry.moduli_m),
        "convert_from_rns_mat": from_matrix,
        "convert_from_correction": [
            (correction >> (tables.geometry.word * digit)) & mask
            for digit in range(tables.geometry.lanes)
        ],
        "convert_from_shifted_quotient_estimations": list(tables.expand.fraction),
        "reducer1_mont_factor": [
            pow(modulus, -1, 1 << tables.geometry.word)
            for modulus in tables.geometry.moduli_m
        ],
        "reducer2_mont_factor": [
            pow(modulus, -1, 1 << tables.geometry.word)
            for modulus in tables.geometry.moduli_n
        ],
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
        assert hashlib.sha256(encoded).hexdigest() == REFERENCE_ARRAY_SHA256[name]

    # A supplied pinned export is checked scalar by scalar in addition to the
    # self-contained hashes used by clean source trees.
    if reference_header is not None:
        assert hashlib.sha256(reference_header.read_bytes()).hexdigest() == REFERENCE_HEADER_SHA256
        source = reference_header.read_text()
        for name, values in arrays.items():
            assert values == parse_reference_array(source, name)


def fmt_array(values, indent: str = "    ") -> str:
    values = list(values)
    if not values:
        return "[]"
    rendered = [f"0x{value:016x}" for value in values]
    return "[\n" + "\n".join(indent + value + "," for value in rendered) + "\n" + indent[:-4] + "]"


def fmt_matrix(rows, indent: str = "        ") -> str:
    return "[\n" + "\n".join(
        indent + fmt_array(row, indent + "    ") + "," for row in rows
    ) + "\n" + indent[:-4] + "]"


def emit_conversion(value: Conversion, indent: str = "    ") -> str:
    return (
        "Conversion {\n"
        f"{indent}    matrix: {fmt_matrix(value.matrix, indent + '        ')},\n"
        f"{indent}    fraction: {fmt_array(value.fraction, indent + '        ')},\n"
        f"{indent}    correction: {fmt_array(value.correction, indent + '        ')},\n"
        f"{indent}    correction_shift: {fmt_array(value.correction_shift, indent + '        ')},\n"
        f"{indent}}}"
    )


def emit_lanes(geometry: Geometry, values: tuple[int, ...], indent: str = "    ") -> str:
    radix = 1 << geometry.word
    return (
        "LaneParameters {\n"
        f"{indent}    moduli: {fmt_array(values, indent + '        ')},\n"
        f"{indent}    complement: {fmt_array(tuple((1 << geometry.bits) - q for q in values), indent + '        ')},\n"
        f"{indent}    inverse: {fmt_array(tuple(pow(q, -1, radix) for q in values), indent + '        ')},\n"
        f"{indent}}}"
    )


def emit(tables: Tables) -> str:
    p = tables.field.modulus
    g = tables.geometry
    return f"""// Generated by parameters.py; do not edit.
use crate::rns::parameters::{{Conversion, LaneParameters, Parameters}};

pub(crate) const PARAMETERS: Parameters = Parameters {{
    bits: {p.bit_length()},
    modulus: {fmt_array(words(p), '        ')},
    no_k: {str(tables.no_k).lower()},
    max_expand: {tables.max_expand},
    m: {emit_lanes(g, g.moduli_m)},
    n: {emit_lanes(g, g.moduli_n)},
    reduce: {emit_conversion(tables.reduce)},
    expand: {emit_conversion(tables.expand)},
    to_rns: {emit_conversion(tables.to_rns)},
    to_canonical: {fmt_matrix(tables.to_canonical)},
    canonical_correction: {fmt_array(tables.canonical_correction, '        ')},
    canonical_n0: 0x{(-pow(p, -1, 1 << 64)) % (1 << 64):016x},
    canonical_rr: {fmt_array(words(pow(2, 768, p)), '        ')},
    encoded_p: {fmt_matrix(tables.encoded_p)},
    wide_encoded_p2: {fmt_matrix(tables.wide_encoded_p2)},
    one: {fmt_matrix(tables.one)},
    radix_256: {fmt_matrix(tables.radix_256)},
    root: {fmt_matrix(tables.root)},
    sqrt_exponent: {fmt_array(tables.sqrt_exponent, '        ')},
    odd_exponent: {fmt_array(tables.odd_exponent, '        ')},
    half_plus_one: {fmt_array(tables.half_plus_one, '        ')},
    two_adicity: {tables.two_adicity},
}};
"""


def emit_wrapper() -> str:
    module_blocks = []
    for field in sorted(FIELDS, key=lambda value: value.name):
        arm_attribute = (
            f'#[cfg_attr(not(target_arch = "x86_64"), '
            f'path = "parameters/arm/{field.name}.rs")]'
        )
        if len(arm_attribute) > 82:
            arm_attribute = (
                '#[cfg_attr(\n'
                '    not(target_arch = "x86_64"),\n'
                f'    path = "parameters/arm/{field.name}.rs"\n'
                ')]'
            )
        x86_attribute = (
            f'#[cfg_attr(target_arch = "x86_64", '
            f'path = "parameters/x86/{field.name}.rs")]'
        )
        if len(x86_attribute) > 82:
            x86_attribute = (
                '#[cfg_attr(\n'
                '    target_arch = "x86_64",\n'
                f'    path = "parameters/x86/{field.name}.rs"\n'
                ')]'
            )
        module_blocks.append(
            f'''{arm_attribute}
{x86_attribute}
mod {field.name};'''
        )
    modules = "\n".join(module_blocks)
    invocations = "\n".join(
        (
            f'''modulus!(
    {rust_name},
    {field.name},
    {48 if field.name == "bls12381" else 32},
    "{description}"
);'''
        )
        for field, rust_name, description in (
            (FIELDS[0], "Bls12381", "The 381-bit coordinate field of BLS12-381."),
            (
                FIELDS[1],
                "BlsScalar",
                "The 255-bit BLS12-381 scalar field, also the Bandersnatch coordinate field.",
            ),
            (
                FIELDS[2],
                "BanderScalar",
                "The 253-bit prime subgroup order of Bandersnatch and Banderwagon.",
            ),
            (FIELDS[3], "Curve25519", "The Curve25519 coordinate field with modulus 2^255 - 19."),
        )
    )
    return f'''//! Sealed parameter sets for the supported cryptographic fields.

use crate::{{
    field::{{Modulus, sealed}},
    rns,
}};

{modules}

macro_rules! modulus {{
    ($name:ident, $module:ident, $bytes:literal, $description:literal) => {{
        #[doc = $description]
        #[derive(Clone, Copy, Debug)]
        pub struct $name;

        impl sealed::Sealed for $name {{}}

        impl Modulus for $name {{
            type Encoding = [u8; $bytes];
            const ZERO_ENCODING: Self::Encoding = [0; $bytes];
            const PARAMETERS: &'static rns::Parameters = &$module::PARAMETERS;
        }}
    }};
}}

{invocations}
'''


def generate(reference_header: Path | None = None) -> tuple[dict[Path, str], str]:
    outputs: dict[Path, str] = {}
    validation: dict[str, object] = {
        "reference_commit": "013169524f701ec62f95048c427ccf9065da1abe",
        "reference_header_sha256": REFERENCE_HEADER_SHA256,
        "base_redundancy": BASE_REDUNDANCY,
        "max_add": MAX_ADD,
        "combined_max": COMBINED_MAX,
        "fields": {},
    }
    for geometry in GEOMETRIES:
        assert len(geometry.moduli_m) == geometry.lanes
        assert len(geometry.moduli_n) == geometry.lanes
        assert all(modulus & 1 and modulus < 1 << geometry.bits for modulus in geometry.moduli_m + geometry.moduli_n)
        for index, left in enumerate(geometry.moduli_m + geometry.moduli_n):
            assert all(math.gcd(left, right) == 1 for right in (geometry.moduli_m + geometry.moduli_n)[index + 1 :])
        for field in FIELDS:
            assert is_probable_prime(field.modulus)
            tables = build(field, geometry)
            validate_widths(tables)
            model = validate_model(tables)
            if geometry.name == "x86" and field.name == "bls12381":
                validate_bls_reference(tables, reference_header)
            key = f"{geometry.name}/{field.name}"
            validation["fields"][key] = {
                "no_k": tables.no_k,
                "lanes": geometry.lanes,
                "bits": geometry.bits,
                "word": geometry.word,
                "canonical_digits": (field.modulus.bit_length() + geometry.bits - 1) // geometry.bits,
                "model": model,
                "bounds": validate_bounds(tables),
            }
            outputs[OUTPUT / geometry.name / f"{field.name}.rs"] = emit(tables)
    outputs[WRAPPER] = emit_wrapper()
    return outputs, json.dumps(validation, indent=2, sort_keys=True) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument(
        "--reference-header",
        type=Path,
        help="also compare every BLS x86 scalar with the pinned VROOM export",
    )
    args = parser.parse_args()
    outputs, report = generate(args.reference_header)
    outputs[REPORT] = report
    if args.check:
        failed = False
        for path, expected in outputs.items():
            actual = path.read_text() if path.exists() else ""
            if actual != expected:
                failed = True
                print(
                    "".join(
                        difflib.unified_diff(
                            actual.splitlines(keepends=True),
                            expected.splitlines(keepends=True),
                            fromfile=str(path),
                            tofile=f"generated:{path}",
                        )
                    ),
                    end="",
                )
        if failed:
            raise SystemExit(1)
        print(f"checked {len(outputs) - 1} modules and {REPORT}")
        return
    for path, content in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        print(path)


if __name__ == "__main__":
    main()

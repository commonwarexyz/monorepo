//! Test-only joint G1 encoding. No production codec uses this format.
//!
//! See `cryptography/DECOMPRESSION_RESEARCH.md` for the format and tradeoffs.

use super::*;
use blst::{blst_bendian_from_fp, blst_fp_from_bendian};
use commonware_codec::Encode;
use std::hint::black_box;

#[path = "decompression/batch.rs"]
mod batch;

#[path = "decompression/receive.rs"]
mod receive;

#[path = "decompression/triple.rs"]
mod triple;

// A primitive ninth root of unity, 2^((p - 1) / 9), in Montgomery form.
const ROOT_NINE: blst_fp = blst_fp {
    l: [
        0xbcf6_6ccb_86ec_2c28,
        0x800e_f566_45cc_4f88,
        0x3d6e_77fc_1256_ec94,
        0x6776_2f3b_e7e1_cf43,
        0x95ce_ece8_f666_32bc,
        0x04a6_849b_a72b_11fb,
    ],
};

// Sliding-window schedule for e = (p + 17) / 108: (squarings, odd power).
const SIXTH_ROOT: &[(u8, u8)] = &[
    (4, 15),
    (5, 13),
    (8, 29),
    (2, 3),
    (8, 21),
    (5, 31),
    (2, 3),
    (8, 9),
    (6, 29),
    (5, 27),
    (5, 31),
    (7, 19),
    (5, 25),
    (6, 9),
    (6, 17),
    (5, 23),
    (1, 1),
    (9, 23),
    (4, 15),
    (7, 21),
    (6, 9),
    (11, 27),
    (5, 23),
    (7, 23),
    (8, 15),
    (8, 19),
    (6, 21),
    (7, 13),
    (8, 21),
    (1, 1),
    (9, 7),
    (7, 11),
    (6, 25),
    (8, 29),
    (5, 13),
    (6, 27),
    (5, 9),
    (4, 7),
    (11, 29),
    (11, 29),
    (8, 29),
    (11, 25),
    (5, 15),
    (5, 13),
    (9, 17),
    (5, 13),
    (7, 29),
    (5, 29),
    (3, 5),
    (8, 9),
    (6, 29),
    (1, 1),
    (8, 9),
    (4, 7),
    (6, 7),
    (6, 7),
    (6, 7),
    (6, 7),
    (6, 7),
    (9, 31),
    (3, 5),
];

fn cube(a: &blst_fp) -> blst_fp {
    fp_mul(&fp_sqr(a), a)
}

fn sixth_root(a: &blst_fp) -> Option<blst_fp> {
    if fp_is_zero(a) {
        return None;
    }
    let square = fp_sqr(a);
    let mut powers = [*a; 16];
    for index in 1..powers.len() {
        powers[index] = fp_mul(&powers[index - 1], &square);
    }
    let mut root = powers[(SIXTH_ROOT[0].1 / 2) as usize];
    for &(squares, power) in &SIXTH_ROOT[1..] {
        for _ in 0..squares {
            root = fp_sqr(&root);
        }
        root = fp_mul(&root, &powers[(power / 2) as usize]);
    }
    // p - 1 = 18m, m = 5 (mod 6), and 6e = m + 1. For a sixth power,
    // root^6 / a is a cube root of unity. Multiplying by a ninth root fixes it.
    for _ in 0..3 {
        if fp_eq(&cube(&fp_sqr(&root)), a) {
            return Some(root);
        }
        root = fp_mul(&root, &ROOT_NINE);
    }
    None
}

fn field_bytes(value: &blst_fp) -> [u8; 48] {
    let mut bytes = [0; 48];
    // SAFETY: value is a valid field element and bytes has the required 48 bytes.
    unsafe { blst_bendian_from_fp(bytes.as_mut_ptr(), value) };
    bytes
}

fn read_field(bytes: &[u8; 48]) -> Option<blst_fp> {
    let mut value = blst_fp::default();
    // SAFETY: bytes has the required 48 bytes and value is writable.
    unsafe { blst_fp_from_bendian(&mut value, bytes.as_ptr()) };
    // Conversion reduces modulo p, so explicitly reject noncanonical inputs.
    (field_bytes(&value) == *bytes).then_some(value)
}

fn roots(x: blst_fp) -> [blst_fp; 3] {
    let omega = cube(&ROOT_NINE);
    let second = fp_mul(&x, &omega);
    [x, second, fp_mul(&second, &omega)]
}

fn four() -> blst_fp {
    let two = fp_add(&MONTGOMERY_ONE, &MONTGOMERY_ONE);
    fp_add(&two, &two)
}

fn valid_affine(point: &blst_p1_affine) -> bool {
    !fp_is_zero(&point.x)
        && !fp_is_zero(&point.y)
        && fp_eq(&fp_sqr(&point.y), &fp_add(&cube(&point.x), &four()))
}

fn encode_pairs(points: &[G1]) -> Vec<u8> {
    let affine = to_affine(points);
    assert!(affine.iter().all(valid_affine));
    let mut inverses: Vec<_> = affine
        .chunks_exact(2)
        .flat_map(|pair| [pair[1].x, pair[1].y])
        .collect();
    batch_invert(&mut inverses, &mut Vec::new());
    let mut bytes = Vec::with_capacity(48 * points.len());
    for (pair, inverses) in affine.chunks_exact(2).zip(inverses.chunks_exact(2)) {
        let x = fp_mul(&pair[0].x, &inverses[0]);
        let y = fp_mul(&pair[0].y, &inverses[1]);
        let orbit = fp_eq(&cube(&x), &fp_sqr(&y));
        let (x, y, selector) = if orbit {
            let index = roots(pair[0].x)
                .iter()
                .position(|x| fp_eq(x, &pair[1].x))
                .unwrap();
            let negative = !fp_eq(&pair[0].y, &pair[1].y);
            (pair[0].x, pair[0].y, 2 * index + usize::from(negative))
        } else {
            let mut candidates = roots(pair[1].x).map(|x| field_bytes(&x));
            candidates.sort_unstable();
            let index = candidates
                .iter()
                .position(|x| *x == field_bytes(&pair[1].x))
                .unwrap();
            let negative = field_bytes(&pair[1].y) > field_bytes(&fp_neg(&pair[1].y));
            (x, y, 2 * index + usize::from(negative))
        };
        let mut x = field_bytes(&x);
        let mut y = field_bytes(&y);
        x[0] |= (selector as u8) << 5;
        y[0] |= u8::from(orbit) << 5;
        bytes.extend(x);
        bytes.extend(y);
    }
    if !points.len().is_multiple_of(2) {
        bytes.extend(points.last().unwrap().encode());
    }
    bytes
}

/// Check the entire encoding and both curve equations, but not G1 membership.
fn decode_pairs(bytes: &[u8]) -> Option<Vec<G1>> {
    decode_pairs_with::<false>(bytes)
}

fn decode_pairs_with<const BATCH: bool>(bytes: &[u8]) -> Option<Vec<G1>> {
    if !bytes.len().is_multiple_of(48) {
        return None;
    }
    let mut records = Vec::with_capacity(bytes.len() / 96);
    let mut inverses = Vec::with_capacity(records.capacity());
    for pair in bytes.chunks_exact(96) {
        let mut x: [u8; 48] = pair[..48].try_into().unwrap();
        let mut y: [u8; 48] = pair[48..].try_into().unwrap();
        let selector = x[0] >> 5;
        let orbit = y[0] >> 5;
        if selector >= 6 || orbit >= 2 {
            return None;
        }
        x[0] &= 0x1f;
        y[0] &= 0x1f;
        let (x, y) = (read_field(&x)?, read_field(&y)?);
        let denominator = if orbit == 1 {
            if !valid_affine(&blst_p1_affine { x, y }) {
                return None;
            }
            MONTGOMERY_ONE
        } else {
            let denominator = fp_sub(&fp_sqr(&y), &cube(&x));
            if fp_is_zero(&denominator) {
                return None;
            }
            denominator
        };
        records.push((x, y, selector, orbit));
        inverses.push(denominator);
    }
    batch_invert(&mut inverses, &mut Vec::new());
    let mut bases = Vec::with_capacity(records.len());
    let mut pending = Vec::new();
    for (&(x, y, _, orbit), inverse) in records.iter().zip(&inverses) {
        let point = if orbit == 1 {
            blst_p1 {
                x,
                y,
                z: MONTGOMERY_ONE,
            }
        } else {
            let u = fp_mul(
                &fp_mul(&four(), &fp_sub(&MONTGOMERY_ONE, &fp_sqr(&y))),
                inverse,
            );
            let v = fp_add(&u, &four());
            let radicand = fp_mul(&fp_sqr(&u), &cube(&v));
            let z = if BATCH {
                pending.push((bases.len(), radicand));
                MONTGOMERY_ONE
            } else {
                sixth_root(&radicand)?
            };
            let uv = fp_mul(&u, &v);
            // Jacobian (uv, uv^2, z) recovers (uv/z^2, z^3/(uv)).
            blst_p1 {
                x: uv,
                y: fp_mul(&uv, &v),
                z,
            }
        };
        bases.push(point);
    }
    if BATCH {
        batch::fill_roots(&mut bases, &pending)?;
    }
    // All radicands have passed their individual root checks before these
    // coordinates become curve points used by the group operations.
    let bases: Vec<_> = bases.into_iter().map(G1::from_blst_p1).collect();
    let mut decoded = Vec::with_capacity(bytes.len() / 48);
    for (mut base, &(x, y, selector, orbit)) in to_affine(&bases).into_iter().zip(&records) {
        let index = usize::from(selector / 2);
        let negative = selector & 1 != 0;
        let (first, second) = if orbit == 1 {
            (
                base,
                blst_p1_affine {
                    x: roots(base.x)[index],
                    y: if negative { fp_neg(&base.y) } else { base.y },
                },
            )
        } else {
            let mut candidates = roots(base.x);
            candidates.sort_unstable_by_key(field_bytes);
            base.x = candidates[index];
            if (field_bytes(&base.y) > field_bytes(&fp_neg(&base.y))) != negative {
                base.y = fp_neg(&base.y);
            }
            (
                blst_p1_affine {
                    x: fp_mul(&x, &base.x),
                    y: fp_mul(&y, &base.y),
                },
                base,
            )
        };
        for point in [first, second] {
            if !valid_affine(&point) {
                return None;
            }
            decoded.push(G1::from_blst_p1(blst_p1 {
                x: point.x,
                y: point.y,
                z: MONTGOMERY_ONE,
            }));
        }
    }
    let mut tail = bytes.chunks_exact(96).remainder();
    if !tail.is_empty() {
        decoded.push(G1::read_unchecked(&mut tail).ok()?);
    }
    Some(decoded)
}

#[test]
fn exponent_matches_modulus() {
    let mut exponent = [0u64; 6];
    for &(shift, power) in SIXTH_ROOT {
        let mut carry = u128::from(power);
        for word in &mut exponent {
            carry += u128::from(*word) << shift;
            *word = carry as u64;
            carry >>= 64;
        }
        assert_eq!(carry, 0);
    }
    let mut carry = 0u128;
    for word in &mut exponent {
        carry += u128::from(*word) * 108;
        *word = carry as u64;
        carry >>= 64;
    }
    assert_eq!(carry, 0);
    let mut expected = MODULUS;
    expected[0] += 17;
    assert_eq!(exponent, expected);
}

#[test]
fn sixth_roots_match_field_equation() {
    assert!(fp_is_one(&cube(&cube(&ROOT_NINE))));
    assert!(!fp_is_one(&cube(&ROOT_NINE)));
    for point in to_affine(&benchmark_points(64)) {
        let sixth = cube(&fp_sqr(&point.x));
        let root = sixth_root(&sixth).expect("sixth power");
        assert!(fp_eq(&cube(&fp_sqr(&root)), &sixth));
        assert!(sixth_root(&fp_neg(&sixth)).is_none());
        assert!(sixth_root(&fp_mul(&sixth, &ROOT_NINE)).is_none());
    }
    assert!(sixth_root(&blst_fp::default()).is_none());
}

#[test]
fn pair_roundtrip_and_orbits() {
    let mut points = benchmark_points(33);
    let mut rng = test_rng();
    for point in &mut points {
        if rng.next_u32() & 1 != 0 {
            *point = -*point;
        }
    }
    for len in 0..=points.len() {
        let bytes = encode_pairs(&points[..len]);
        assert_eq!(bytes.len(), 48 * len);
        assert_eq!(decode_pairs(&bytes).unwrap(), points[..len]);
    }
    let base = to_affine(&points[..1])[0];
    for x in roots(base.x) {
        for y in [base.y, fp_neg(&base.y)] {
            let second = G1::from_blst_p1(blst_p1 {
                x,
                y,
                z: MONTGOMERY_ONE,
            });
            let pair = [points[0], second];
            let bytes = encode_pairs(&pair);
            assert_eq!(bytes[48] >> 5, 1);
            assert_eq!(decode_pairs(&bytes).unwrap(), pair);
        }
    }
}

#[test]
fn malformed_pairs_and_nonmembers_are_rejected() {
    let points = benchmark_points(2);
    let bytes = encode_pairs(&points);
    for len in (1..96).filter(|len| len % 48 != 0) {
        assert!(decode_pairs(&bytes[..len]).is_none());
    }
    for (offset, flags) in [(0, 0xc0), (0, 0xe0), (48, 0x40), (48, 0x80)] {
        let mut bad = bytes.clone();
        bad[offset] = (bad[offset] & 0x1f) | flags;
        assert!(decode_pairs(&bad).is_none());
    }
    for offset in [0, 48] {
        let mut bad = bytes.clone();
        for (word, output) in MODULUS
            .iter()
            .rev()
            .zip(bad[offset..offset + 48].chunks_exact_mut(8))
        {
            output.copy_from_slice(&word.to_be_bytes());
        }
        assert!(decode_pairs(&bad).is_none());
    }
    assert!(decode_pairs(&[0; 96]).is_none());
    let mut bad_orbit = vec![0; 96];
    bad_orbit[48] = 0x20;
    assert!(decode_pairs(&bad_orbit).is_none());
    let one = field_bytes(&MONTGOMERY_ONE);
    let mut degenerate = Vec::from(one);
    degenerate.extend(one);
    assert!(decode_pairs(&degenerate).is_none());
    let mut infinity_tail = bytes;
    infinity_tail.extend([0; 48]);
    infinity_tail[96] = 0xc0;
    assert!(decode_pairs(&infinity_tail).is_none());

    let mut false_orbit = encode_pairs(&[points[0], points[0]]);
    false_orbit[95] ^= 1;
    assert!(decode_pairs(&false_orbit).is_none());

    let bad = order_eleven();
    for points in [[points[0], bad], [bad, -bad]] {
        let decoded = decode_pairs(&encode_pairs(&points)).unwrap();
        assert_eq!(decoded, points);
        assert!(!batch_in_g1(&decoded, 128, &Sequential, &mut test_rng()));
    }
    let mut large = benchmark_points(1000);
    assert!(batch_in_g1(
        &decode_pairs(&encode_pairs(&large)).unwrap(),
        128,
        &Sequential,
        &mut test_rng(),
    ));
    large[501] += &bad;
    let decoded = decode_pairs(&encode_pairs(&large)).unwrap();
    assert_eq!(decoded, large);
    assert!(!batch_in_g1(&decoded, 128, &Sequential, &mut test_rng()));
}

#[test]
fn mutated_encodings_are_canonical_on_curve_or_rejected() {
    let bytes = encode_pairs(&benchmark_points(3));
    let mut rng = test_rng();
    for _ in 0..256 {
        let mut mutated = bytes.clone();
        let offset = rng.next_u32() as usize % mutated.len();
        mutated[offset] ^= 1 << (rng.next_u32() % 8);
        if let Some(points) = decode_pairs(&mutated) {
            assert!(to_affine(&points).iter().all(valid_affine));
            assert_eq!(encode_pairs(&points), mutated);
        }
    }
}

#[test]
#[ignore = "manual end-to-end timing"]
fn measure_joint_decoding() {
    for n in [1000, 6000, 100_000] {
        let points = benchmark_points(n);
        let standard: Vec<_> = points.iter().flat_map(Encode::encode).collect();
        let paired = encode_pairs(&points);
        assert_eq!(decode_pairs(&paired).unwrap(), points);
        assert_eq!(decode_pairs_with::<true>(&paired).unwrap(), points);
        let mut timings: [Vec<Duration>; 6] = core::array::from_fn(|_| Vec::new());
        for repetition in 0..5 {
            for offset in 0..6 {
                let method = (offset + repetition) % 6;
                let start = Instant::now();
                let decoded = match method % 3 {
                    0 => standard
                        .chunks_exact(48)
                        .map(|mut bytes| G1::read_unchecked(&mut bytes).unwrap())
                        .collect::<Vec<_>>(),
                    1 => decode_pairs(&paired).unwrap(),
                    2 => decode_pairs_with::<true>(&paired).unwrap(),
                    _ => unreachable!(),
                };
                if method >= 3 {
                    assert!(batch_in_g1(&decoded, 128, &Sequential, &mut test_rng()));
                }
                black_box(decoded);
                timings[method].push(start.elapsed());
            }
        }
        for (method, times) in timings.iter_mut().enumerate() {
            times.sort_unstable();
            eprintln!(
                "n={n} method={} median_ms={:.3}",
                [
                    "standard_decode",
                    "joint_decode",
                    "joint_batched_decode",
                    "standard_checked",
                    "joint_checked",
                    "joint_batched_checked",
                ][method],
                times[2].as_secs_f64() * 1000.0
            );
        }
    }
}

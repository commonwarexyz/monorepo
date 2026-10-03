//! Three points per sixth root, using https://eprint.iacr.org/2021/1446.
//!
//! This is a test-only format, with the same 48 bytes per point.

use super::*;

fn double(a: &blst_fp) -> blst_fp {
    fp_add(a, a)
}

// Return the numerators of z0 and z1, and their common denominator.
fn parameters(pair: &[blst_p1_affine]) -> (blst_fp, blst_fp, blst_fp) {
    let [a, b] = pair else { unreachable!() };
    let xy = fp_mul(&a.x, &b.x);
    let cross = fp_sub(&fp_mul(&a.x, &b.y), &fp_mul(&a.y, &b.x));
    let z0 = fp_mul(
        &b.x,
        &fp_sub(
            &double(&fp_sub(
                &fp_mul(&fp_sqr(&a.x), &b.y),
                &fp_mul(&a.y, &fp_sqr(&b.x)),
            )),
            &fp_mul(&xy, &fp_sub(&a.y, &b.y)),
        ),
    );
    let z1 = fp_add(
        &fp_sub(&fp_mul(&cube(&a.x), &b.y), &fp_mul(&a.y, &cube(&b.x))),
        &double(&fp_mul(&xy, &cross)),
    );
    (z0, z1, fp_sub(&fp_sqr(&a.y), &fp_sqr(&b.y)))
}

fn exceptional(pair: &[blst_p1_affine]) -> bool {
    let (z0, _, denominator) = parameters(pair);
    fp_is_zero(&z0) || fp_is_zero(&denominator)
}

pub(super) fn encode(points: &[G1]) -> Vec<u8> {
    let affine = to_affine(points);
    assert!(affine.iter().all(valid_affine));
    let records: Vec<_> = affine
        .chunks_exact(3)
        .map(|triple| parameters(&triple[..2]))
        .collect();
    let mut inverses: Vec<_> = records
        .iter()
        .map(|(_, _, denominator)| {
            if fp_is_zero(denominator) {
                MONTGOMERY_ONE
            } else {
                *denominator
            }
        })
        .collect();
    batch_invert(&mut inverses, &mut Vec::new());
    let mut bytes = Vec::with_capacity(48 * points.len());
    for (index, ((&(z0, z1, denominator), inverse), triple)) in records
        .iter()
        .zip(&inverses)
        .zip(affine.chunks_exact(3))
        .enumerate()
    {
        if fp_is_zero(&z0) || fp_is_zero(&denominator) {
            // The pair format covers the exceptional fibers. Its second
            // field has two unused high bits; bit 7 marks this fallback.
            let mut fallback = encode_pairs(&points[3 * index..3 * index + 2]);
            fallback[48] |= 0x80;
            bytes.extend(fallback);
            bytes.extend(points[3 * index + 2].encode());
            continue;
        }
        bytes.extend(field_bytes(&fp_mul(&z0, inverse)));
        bytes.extend(field_bytes(&fp_mul(&z1, inverse)));
        let mut candidates = roots(triple[1].x).map(|x| field_bytes(&x));
        candidates.sort_unstable();
        let rank = candidates
            .iter()
            .position(|x| *x == field_bytes(&triple[1].x))
            .unwrap();
        let negative = field_bytes(&triple[2].y) > field_bytes(&fp_neg(&triple[2].y));
        let mut x = field_bytes(&triple[2].x);
        x[0] |= ((2 * rank + usize::from(negative)) as u8) << 5;
        bytes.extend(x);
    }
    bytes.extend(encode_pairs(&points[points.len() / 3 * 3..]));
    bytes
}

pub(super) fn decode(bytes: &[u8]) -> Option<Vec<G1>> {
    if !bytes.len().is_multiple_of(48) {
        return None;
    }
    let mut records = Vec::with_capacity(bytes.len() / 144);
    let mut inverses = Vec::with_capacity(records.capacity());
    let mut decoded = vec![G1::zero(); bytes.len() / 48];
    for (index, triple) in bytes.chunks_exact(144).enumerate() {
        if triple[48] & 0x80 != 0 {
            let mut pair = triple[..96].to_vec();
            pair[48] &= !0x80;
            let pair = decode_pairs_with::<true>(&pair)?;
            if !exceptional(&to_affine(&pair)) {
                return None;
            }
            decoded[index * 3..index * 3 + 2].copy_from_slice(&pair);
            decoded[index * 3 + 2] = G1::read_unchecked(&mut &triple[96..]).ok()?;
            continue;
        }
        let z0 = read_field(triple[..48].try_into().unwrap())?;
        let z1 = read_field(triple[48..96].try_into().unwrap())?;
        let mut x: [u8; 48] = triple[96..].try_into().unwrap();
        let selector = x[0] >> 5;
        if selector >= 6 {
            return None;
        }
        x[0] &= 0x1f;
        let x = read_field(&x)?;
        let c = fp_sub(&fp_sqr(&z1), &four());
        let denominator = fp_mul(&fp_sqr(&z0), &c);
        if fp_is_zero(&denominator) || fp_is_zero(&x) {
            return None;
        }
        records.push((index, z0, z1, x, c, selector));
        inverses.push(denominator);
    }
    let mut scratch = Vec::new();
    batch_invert(&mut inverses, &mut scratch);
    let mut coordinates = Vec::with_capacity(records.len());
    let mut radicands = Vec::with_capacity(records.len());
    for (&(_, z0, z1, x, c, _), inverse) in records.iter().zip(&inverses) {
        // t = x0/x1 = (z1^2 - 4)/z0^2. One inverse gives both t and 1/t.
        let t = fp_mul(&fp_sqr(&c), inverse);
        let inverse_t = fp_mul(&fp_sqr(&fp_sqr(&z0)), inverse);
        let y0 = fp_sub(
            &z1,
            &fp_mul(&fp_add(&double(&fp_sub(&z0, &z1)), &fp_mul(&z0, &t)), &t),
        );
        let y1 = fp_add(
            &fp_sub(&z1, &double(&z0)),
            &fp_mul(&fp_sub(&double(&z1), &z0), &inverse_t),
        );
        let a = fp_add(&cube(&x), &four());
        let y1_squared = fp_sqr(&y1);
        // Same-orbit pairs have a unique encoding in the fallback format.
        if fp_eq(&fp_sqr(&y0), &y1_squared) {
            return None;
        }
        let b = fp_sub(&y1_squared, &four());
        let ab = fp_mul(&a, &b);
        if fp_is_zero(&ab) {
            return None;
        }
        coordinates.push((t, y0, y1, ab));
        radicands.push(fp_mul(&cube(&a), &fp_sqr(&b)));
    }
    let extracted = batch::run::<4>(&radicands)?;
    inverses.clear();
    inverses.extend(
        coordinates
            .iter()
            .zip(&extracted)
            .map(|(&(_, _, _, ab), root)| fp_mul(&fp_sqr(root), &ab)),
    );
    batch_invert(&mut inverses, &mut scratch);
    for (((&(index, _, _, x2, _, selector), &(t, y0, y1, ab)), root), inverse) in records
        .iter()
        .zip(&coordinates)
        .zip(&extracted)
        .zip(&inverses)
    {
        // root^6 = a^3 b^2, x1 = ab/root^2, y2 = root^3/ab.
        let mut x1 = roots(fp_mul(&fp_sqr(&ab), inverse));
        x1.sort_unstable_by_key(field_bytes);
        let x1 = x1[usize::from(selector / 2)];
        let mut y2 = fp_mul(&fp_mul(&fp_sqr(&fp_sqr(root)), root), inverse);
        if (field_bytes(&y2) > field_bytes(&fp_neg(&y2))) != (selector & 1 != 0) {
            y2 = fp_neg(&y2);
        }
        for (offset, point) in [
            blst_p1_affine {
                x: fp_mul(&t, &x1),
                y: y0,
            },
            blst_p1_affine { x: x1, y: y1 },
            blst_p1_affine { x: x2, y: y2 },
        ]
        .into_iter()
        .enumerate()
        {
            if !valid_affine(&point) {
                return None;
            }
            decoded[3 * index + offset] = G1::from_blst_p1(blst_p1 {
                x: point.x,
                y: point.y,
                z: MONTGOMERY_ONE,
            });
        }
    }
    let tail = decode_pairs_with::<true>(bytes.chunks_exact(144).remainder())?;
    decoded[bytes.len() / 144 * 3..].copy_from_slice(&tail);
    Some(decoded)
}

#[test]
fn triple_roundtrip_and_exceptional_fibers() {
    let mut points = benchmark_points(41);
    let mut rng = test_rng();
    for point in &mut points {
        if rng.next_u32() & 1 != 0 {
            *point = -*point;
        }
    }
    for len in 0..=points.len() {
        let bytes = encode(&points[..len]);
        assert_eq!(bytes.len(), 48 * len);
        assert_eq!(decode(&bytes).unwrap(), points[..len]);
    }
    let base = to_affine(&points[..1])[0];
    for x in roots(base.x) {
        for y in [base.y, fp_neg(&base.y)] {
            let second = G1::from_blst_p1(blst_p1 {
                x,
                y,
                z: MONTGOMERY_ONE,
            });
            let triple = [points[0], second, points[2]];
            let bytes = encode(&triple);
            assert_eq!(bytes[48] & 0x80, 0x80);
            assert_eq!(decode(&bytes).unwrap(), triple);
        }
    }

    // The other exceptional fiber has t = 5, y0 = 22, y1 = 14/5.
    let t = fp_add(&four(), &MONTGOMERY_ONE);
    let mut inverse = [t];
    batch_invert(&mut inverse, &mut Vec::new());
    let two = double(&MONTGOMERY_ONE);
    let y0 = double(&fp_add(&double(&t), &MONTGOMERY_ONE));
    let y1 = fp_mul(&double(&fp_add(&t, &two)), &inverse[0]);
    let b = fp_sub(&fp_sqr(&y1), &four());
    let mut x1 = sixth_root(&fp_sqr(&b)).unwrap();
    if !fp_eq(&cube(&x1), &b) {
        x1 = fp_neg(&x1);
    }
    for negative in [false, true] {
        let pair = [
            blst_p1_affine {
                x: fp_mul(&t, &x1),
                y: if negative { fp_neg(&y0) } else { y0 },
            },
            blst_p1_affine {
                x: x1,
                y: if negative { fp_neg(&y1) } else { y1 },
            },
        ];
        assert!(pair.iter().all(valid_affine));
        let (z0, _, denominator) = parameters(&pair);
        assert!(fp_is_zero(&z0));
        assert!(!fp_is_zero(&denominator));
        let mut triple: Vec<_> = pair
            .iter()
            .map(|point| {
                G1::from_blst_p1(blst_p1 {
                    x: point.x,
                    y: point.y,
                    z: MONTGOMERY_ONE,
                })
            })
            .collect();
        triple.push(points[2]);
        let bytes = encode(&triple);
        assert_eq!(bytes[48] & 0x80, 0x80);
        assert_eq!(decode(&bytes).unwrap(), triple);
    }
}

#[test]
fn generic_triples_cannot_alias_exceptional_fibers() {
    let point = to_affine(&benchmark_points(1))[0];
    let six = fp_add(&four(), &double(&MONTGOMERY_ONE));
    let mut inverses = [point.y, six];
    batch_invert(&mut inverses, &mut Vec::new());
    let a = fp_mul(&six, &inverses[0]);
    let b = fp_mul(&point.y, &inverses[1]);
    // z1^2 - z0^2 = 4 makes t = 1 and recovers two identical points.
    let mut bytes = Vec::from(field_bytes(&fp_sub(&a, &b)));
    bytes.extend(field_bytes(&fp_add(&a, &b)));
    bytes.extend(field_bytes(&point.x));
    assert!(decode(&bytes).is_none());
}

#[test]
fn malformed_triples_and_nonmembers_are_rejected() {
    let points = benchmark_points(1000);
    let bytes = encode(&points[..3]);
    for len in (1..144).filter(|len| len % 48 != 0) {
        assert!(decode(&bytes[..len]).is_none());
    }
    for (offset, flags) in [(0, 0x20), (48, 0x20), (48, 0x40), (96, 0xc0), (96, 0xe0)] {
        let mut bad = bytes.clone();
        bad[offset] = (bad[offset] & 0x1f) | flags;
        assert!(decode(&bad).is_none());
    }
    for offset in [0, 48, 96] {
        let mut bad = bytes.clone();
        for (word, output) in MODULUS
            .iter()
            .rev()
            .zip(bad[offset..offset + 48].chunks_exact_mut(8))
        {
            output.copy_from_slice(&word.to_be_bytes());
        }
        assert!(decode(&bad).is_none());
        bad[offset..offset + 48].fill(0);
        if offset != 48 {
            assert!(decode(&bad).is_none());
        }
    }
    assert!(decode(&[0; 144]).is_none());
    let mut false_fallback = encode_pairs(&points[..2]);
    false_fallback[48] |= 0x80;
    false_fallback.extend(points[2].encode());
    assert!(decode(&false_fallback).is_none());
    let mut infinity = encode(&[points[0], points[0], points[2]]);
    infinity[96..].fill(0);
    infinity[96] = 0xc0;
    assert!(decode(&infinity).is_none());
    let good = decode(&encode(&points)).unwrap();
    assert!(batch_in_g1(&good, 128, &Sequential, &mut test_rng()));
    for index in [0, 1, 2, 500, 999] {
        let mut bad = points.clone();
        bad[index] += &order_eleven();
        let decoded = decode(&encode(&bad)).unwrap();
        assert_eq!(decoded, bad);
        assert!(!batch_in_g1(&decoded, 128, &Sequential, &mut test_rng()));
    }
}

#[test]
fn mutated_triples_are_canonical_on_curve_or_rejected() {
    let points = benchmark_points(6);
    let inputs = [
        encode(&points),
        encode(&[points[0], points[0], points[2], points[3], points[4]]),
    ];
    let mut rng = test_rng();
    for bytes in inputs {
        for _ in 0..512 {
            let mut mutated = bytes.clone();
            let offset = rng.next_u32() as usize % mutated.len();
            mutated[offset] ^= 1 << (rng.next_u32() % 8);
            if let Some(points) = decode(&mutated) {
                assert!(to_affine(&points).iter().all(valid_affine));
                assert_eq!(encode(&points), mutated);
            }
        }
    }
}

#[test]
#[ignore = "manual serial triple decoding timing"]
fn measure_triple_decoding() {
    for n in [1000, 6000, 100_000] {
        let points = benchmark_points(n);
        let standard: Vec<_> = points.iter().flat_map(Encode::encode).collect();
        let paired = encode_pairs(&points);
        let tripled = encode(&points);
        assert_eq!(decode(&tripled).unwrap(), points);
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
                    1 => decode_pairs_with::<true>(&paired).unwrap(),
                    2 => decode(&tripled).unwrap(),
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
                    "pair_decode",
                    "triple_decode",
                    "standard_checked",
                    "pair_checked",
                    "triple_checked",
                ][method],
                times[2].as_secs_f64() * 1000.0
            );
        }
    }
}

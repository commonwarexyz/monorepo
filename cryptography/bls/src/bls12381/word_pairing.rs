// Portions adapted from blst 0.3.16, blst/src/pairing.c.
// Copyright Supranational LLC
// SPDX-License-Identifier: Apache-2.0
//
// Homogeneous Miller formulas adapted from VROOM/src/miller.hpp.
// Copyright 2026 Simon Langowski, licensed under MIT.
// See LICENSE-VROOM for the permission notice.

//! Fixed-word optimal Ate pairing implementation.

use crate::bls12381::{
    extension,
    group::{G1, G2},
    word::{self, Fp, Fp2, Fp12},
};
use commonware_cryptography_vroom::word::{mul_by_3_fp2, mul_by_8_fp2};

const FP2_ZERO: Fp2 = [Fp::ZERO; 2];

#[derive(Clone, Copy)]
struct State {
    x: Fp2,
    y: Fp2,
    z: Fp2,
    qx: Fp2,
    qy: Fp2,
    px: Fp,
    py: Fp,
    three_px: Fp,
    minus_two_py: Fp,
}

impl State {
    fn new(px: Fp, py: Fp, qx: Fp2, qy: Fp2) -> Self {
        Self {
            x: qx,
            y: qy,
            z: [Fp::one(), Fp::ZERO],
            qx,
            qy,
            px,
            py,
            three_px: px.double().add(&px),
            minus_two_py: py.double().neg(),
        }
    }

    fn double<const FIRST: bool>(&mut self, f: &mut Fp12) {
        let xx = word::fp2_square(&self.x);
        let yy = word::fp2_square(&self.y);
        let zz = word::fp2_square(&self.z);
        let xy = word::fp2_mul(&self.x, &self.y);
        let yz = word::fp2_mul(&self.y, &self.z);

        let eight_yy = fp2_scale_eight(&yy);
        let b3_zz = fp2_mul_3b(&zz);
        let line_c = word::fp2_sub(&b3_zz, &yy);
        let yy_plus_b3_zz = word::fp2_add(&yy, &b3_zz);
        let yy_minus_b9_zz = word::fp2_sub(&yy, &fp2_scale_three(&b3_zz));
        let two_xy = word::fp2_double(&xy);

        let y3 = word::fp2_add(
            &word::fp2_mul(&yy_minus_b9_zz, &yy_plus_b3_zz),
            &word::fp2_mul(&eight_yy, &b3_zz),
        );
        let line_x = word::fp2_mul_by_fp(&xx, &self.three_px);
        let line_y = word::fp2_mul_by_fp(&yz, &self.minus_two_py);
        let x3 = word::fp2_mul(&yy_minus_b9_zz, &two_xy);
        let z3 = word::fp2_mul(&eight_yy, &yz);

        if FIRST {
            *f = [[line_c, line_x, FP2_ZERO], [FP2_ZERO, line_y, FP2_ZERO]];
        } else {
            *f = word::mul_by_014(f, &line_c, &line_x, &line_y);
        }
        self.x = x3;
        self.y = y3;
        self.z = z3;
    }

    fn add(&mut self, f: &mut Fp12) {
        let x2x1 = word::fp2_mul(&self.qx, &self.x);
        let x2y1 = word::fp2_mul(&self.qx, &self.y);
        let x2z1 = word::fp2_mul(&self.qx, &self.z);
        let y2x1 = word::fp2_mul(&self.qy, &self.x);
        let y2y1 = word::fp2_mul(&self.qy, &self.y);
        let y2z1 = word::fp2_mul(&self.qy, &self.z);

        let line_c = word::fp2_sub(&x2y1, &y2x1);
        let xq_coefficient = word::fp2_sub(&y2z1, &self.y);
        let yq_coefficient = word::fp2_sub(&self.x, &x2z1);
        let x2y1_plus_y2x1 = word::fp2_add(&x2y1, &y2x1);
        let y2z1_plus_y1 = word::fp2_add(&y2z1, &self.y);
        let three_x2x1 = fp2_scale_three(&x2x1);
        let b3z1 = fp2_mul_3b(&self.z);
        let y2y1_plus_b3z1 = word::fp2_add(&y2y1, &b3z1);
        let y2y1_minus_b3z1 = word::fp2_sub(&y2y1, &b3z1);
        let b3_x2z1_plus_x1 = fp2_mul_3b(&word::fp2_add(&x2z1, &self.x));

        let x3 = word::fp2_sub(
            &word::fp2_mul(&x2y1_plus_y2x1, &y2y1_minus_b3z1),
            &word::fp2_mul(&b3_x2z1_plus_x1, &y2z1_plus_y1),
        );
        let y3 = word::fp2_add(
            &word::fp2_mul(&b3_x2z1_plus_x1, &three_x2x1),
            &word::fp2_mul(&y2y1_plus_b3z1, &y2y1_minus_b3z1),
        );
        let z3 = word::fp2_add(
            &word::fp2_mul(&y2y1_plus_b3z1, &y2z1_plus_y1),
            &word::fp2_mul(&x2y1_plus_y2x1, &three_x2x1),
        );
        let line_x = word::fp2_mul_by_fp(&xq_coefficient, &self.px);
        let line_y = word::fp2_mul_by_fp(&yq_coefficient, &self.py);

        *f = word::mul_by_014(f, &line_c, &line_x, &line_y);
        self.x = x3;
        self.y = y3;
        self.z = z3;
    }
}

fn fp2_scale_three(value: &Fp2) -> Fp2 {
    mul_by_3_fp2(value)
}

fn fp2_scale_eight(value: &Fp2) -> Fp2 {
    mul_by_8_fp2(value)
}

fn fp2_scale_twelve(value: &Fp2) -> Fp2 {
    let four = word::fp2_double(&word::fp2_double(value));
    word::fp2_add(&four, &word::fp2_double(&four))
}

fn fp2_mul_3b(value: &Fp2) -> Fp2 {
    fp2_scale_twelve(&word::fp2_mul_by_u_plus_one(value))
}

fn fp2_conjugate(value: &Fp2) -> Fp2 {
    [value[0], value[1].neg()]
}

#[cfg(test)]
fn import_fp2(value: extension::Fp2) -> Fp2 {
    [Fp::from_element(value.c0), Fp::from_element(value.c1)]
}

fn export_fp12(value: &Fp12) -> extension::Fp12 {
    extension::Fp12(core::array::from_fn(|w| {
        extension::Fp6(core::array::from_fn(|v| extension::Fp2 {
            c0: value[w][v][0].to_element(),
            c1: value[w][v][1].to_element(),
        }))
    }))
}

fn prepare(pairs: &[(G1, G2)], states: &mut [State; 16]) -> usize {
    assert!(pairs.len() <= states.len());
    let mut denominators = [Fp::one(); 32];
    let mut count = 0;
    for (p, q) in pairs {
        let (p, q) = (p.0, q.0);
        let pz = p.z;
        let qz = q.z;
        if pz == Fp::ZERO || qz == FP2_ZERO {
            continue;
        }
        denominators[2 * count] = pz;
        denominators[2 * count + 1] = qz[0].square().add(&qz[1].square());
        count += 1;
    }
    if count == 0 {
        return 0;
    }

    let len = 2 * count;
    let mut prefixes = [Fp::one(); 32];
    let mut product = denominators[0];
    for i in 1..len {
        prefixes[i] = product;
        product = product.mul(&denominators[i]);
    }
    let mut inverse = if product == Fp::one() {
        product
    } else {
        product.invert().expect("nonzero affine denominators")
    };
    for i in (1..len).rev() {
        let denominator = denominators[i];
        denominators[i] = inverse.mul(&prefixes[i]);
        inverse = inverse.mul(&denominator);
    }
    denominators[0] = inverse;

    let mut index = 0;
    for (p, q) in pairs {
        let (p, q) = (p.0, q.0);
        let pz = p.z;
        let qz = q.z;
        if pz == Fp::ZERO || qz == FP2_ZERO {
            continue;
        }
        let pz = denominators[2 * index];
        let px = p.x.mul(&pz);
        let py = p.y.mul(&pz);
        let qz = word::fp2_mul_by_fp(&fp2_conjugate(&qz), &denominators[2 * index + 1]);
        let qx = word::fp2_mul(&q.x, &qz);
        let qy = word::fp2_mul(&q.y, &qz);
        states[index] = State::new(px, py, qx, qy);
        index += 1;
    }
    count
}

fn miller_loop(states: &mut [State]) -> Fp12 {
    let mut result = word::one();
    if let Some((first, rest)) = states.split_first_mut() {
        first.double::<true>(&mut result);
        for state in rest {
            state.double::<false>(&mut result);
        }
    }
    for squarings in [2, 3, 9, 32, 16] {
        for state in states.iter_mut() {
            state.add(&mut result);
        }
        for _ in 0..squarings {
            result = word::square(&result);
            for state in states.iter_mut() {
                state.double::<false>(&mut result);
            }
        }
    }
    word::conjugate(&result)
}

fn raise_to_z_over_two(value: &Fp12) -> Fp12 {
    let mut result = word::cyclotomic_square(value);
    for squarings in [2, 3, 9, 32, 15] {
        result = word::mul(&result, value);
        for _ in 0..squarings {
            result = word::cyclotomic_square(&result);
        }
    }
    word::conjugate(&result)
}

fn raise_to_z(value: &Fp12) -> Fp12 {
    word::cyclotomic_square(&raise_to_z_over_two(value))
}

fn final_exponentiation(value: &Fp12) -> Option<Fp12> {
    let inverse = word::invert(value)?;
    let easy = word::mul(&word::conjugate(value), &inverse);
    let easy = word::mul(&word::frobenius2(&easy), &easy);
    let y0 = word::cyclotomic_square(&easy);
    let y1 = raise_to_z(&y0);
    let y2 = raise_to_z_over_two(&y1);
    let y1 = word::mul(&y1, &word::conjugate(&easy));
    let y1 = word::mul(&word::conjugate(&y1), &y2);
    let y2 = raise_to_z(&y1);
    let y3 = word::mul(&raise_to_z(&y2), &word::conjugate(&y1));
    let y1 = word::frobenius3(&y1);
    let y2 = word::frobenius2(&y2);
    let y1 = word::mul(&y1, &y2);
    let y2 = word::mul(&raise_to_z(&y3), &y0);
    let y2 = word::mul(&y2, &easy);
    let result = word::mul(&y1, &y2);
    Some(word::mul(&result, &word::frobenius1(&y3)))
}

pub(super) fn compute(pairs: &[(G1, G2)]) -> extension::Fp12 {
    let mut product = word::one();
    for chunk in pairs.chunks(16) {
        let empty = State::new(Fp::ZERO, Fp::one(), FP2_ZERO, [Fp::one(), Fp::ZERO]);
        let mut states = [empty; 16];
        let count = prepare(chunk, &mut states);
        if count != 0 {
            product = word::mul(&product, &miller_loop(&mut states[..count]));
        }
    }
    if product == word::one() {
        return extension::Fp12::ONE;
    }

    // Nonidentity Miller states follow nonzero subgroup points throughout the
    // fixed loop, so their complete product is invertible.
    export_fp12(&final_exponentiation(&product).expect("Miller products are nonzero"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{Fp as RnsFp, extension::Fp2 as RnsFp2, pairing, scalar::Scalar};
    use blst::{blst_fp12, blst_p1_affine, blst_p2_affine};

    fn assert_matches_rns(pairs: &[(G1, G2)]) -> [u8; 576] {
        let actual = compute(pairs).to_bytes();
        assert_eq!(actual, pairing::rns_multi_pairing(pairs).to_bytes());
        actual
    }

    fn oracle_pairing(p: &G1, q: &G2) -> [u8; 576] {
        assert!(!p.is_identity() && !q.is_identity());
        let p: blst_p1_affine = blst::min_pk::PublicKey::from_bytes(&p.to_bytes())
            .unwrap()
            .into();
        let q: blst_p2_affine = blst::min_sig::PublicKey::from_bytes(&q.to_bytes())
            .unwrap()
            .into();
        blst_fp12::miller_loop_n(&[q], &[p])
            .final_exp()
            .to_bendian()
    }

    fn projective_pair() -> (G1, G2) {
        let p = G1::generator();
        let q = G2::generator();
        let pz = RnsFp::from_u64(7);
        let qz = RnsFp2 {
            c0: RnsFp::from_u64(11),
            c1: RnsFp::ONE,
        };
        (
            {
                let (x, y, _) = p.jacobian_coordinates();
                G1::from_jacobian_coordinates(x.mul(pz.square()), y.mul(pz.square().mul(pz)), pz)
            },
            {
                let (x, y, _) = q.jacobian_coordinates();
                G2::from_jacobian_coordinates(x.mul(qz.square()), y.mul(qz.square().mul(qz)), qz)
            },
        )
    }

    #[test]
    fn word_pairing_matches_rns_for_identity_and_projective_inputs() {
        let p = G1::generator();
        let q = G2::generator();
        let projective = projective_pair();
        assert_matches_rns(&[]);
        assert_matches_rns(&[(G1::IDENTITY, G2::IDENTITY)]);
        assert_matches_rns(&[(G1::IDENTITY, q), projective, (p, G2::IDENTITY)]);
        assert_matches_rns(&[
            (projective.0, projective.1),
            (projective.0.neg(), projective.1),
        ]);
        let pure_imaginary = reproject(
            (p, q),
            RnsFp::from_u64(7),
            RnsFp2 {
                c0: RnsFp::ZERO,
                c1: RnsFp::from_u64(7),
            },
        );
        assert_eq!(
            assert_matches_rns(&[pure_imaginary]),
            oracle_pairing(&p, &q)
        );
    }

    #[test]
    fn word_pairing_matches_rns_across_chunk_boundaries() {
        let p = G1::generator();
        let q = G2::generator();
        let projective = projective_pair();
        for count in [15, 16, 17] {
            let pairs: alloc::vec::Vec<_> = (0..count)
                .map(|i| match i % 4 {
                    0 => (p, q),
                    1 => (p.neg(), q),
                    2 => projective,
                    _ => (G1::IDENTITY, q),
                })
                .collect();
            assert_matches_rns(&pairs);
        }
    }

    #[test]
    fn first_line_matches_sparse_product_and_packing() {
        let mut empty: [State; 0] = [];
        assert_eq!(miller_loop(&mut empty), word::one());
        let generator = G2::generator();
        for p in [G1::generator(), G1::generator().neg()] {
            let (px, py) = p.to_affine().unwrap();
            for q in [generator, generator.neg(), generator.double()] {
                let (qx, qy) = q.to_affine().unwrap();
                let mut state = State::new(
                    Fp::from_element(px),
                    Fp::from_element(py),
                    import_fp2(qx),
                    import_fp2(qy),
                );
                let mut reference = state;
                let mut line = word::one();
                let mut sparse = word::one();
                state.double::<true>(&mut line);
                reference.double::<false>(&mut sparse);
                assert_eq!(line, sparse);
                assert_eq!(state.x, reference.x);
                assert_eq!(state.y, reference.y);
                assert_eq!(state.z, reference.z);

                let c = RnsFp2 {
                    c0: RnsFp::from_u64(12),
                    c1: RnsFp::from_u64(12),
                }
                .sub(qy.square());
                let x = qx.square().mul(RnsFp2 {
                    c0: px.mul(RnsFp::from_u64(3)),
                    c1: RnsFp::ZERO,
                });
                let y = qy.mul(RnsFp2 {
                    c0: py.mul(RnsFp::from_u64(2)).neg(),
                    c1: RnsFp::ZERO,
                });
                assert_eq!(
                    line,
                    [
                        [import_fp2(c), import_fp2(x), FP2_ZERO],
                        [FP2_ZERO, import_fp2(y), FP2_ZERO],
                    ]
                );
            }
        }
    }

    #[test]
    fn first_line_full_gt_across_live_chunks() {
        let p = G1::generator();
        let q = G2::generator();
        for count in [1, 2, 16, 17] {
            let expected = oracle_pairing(&p.mul(&Scalar::from_u64(count as u64)), &q);
            for leading in [0, 1, 16] {
                let mut pairs = alloc::vec![(G1::IDENTITY, q); leading];
                pairs.extend(core::iter::repeat_n((p, q), count));
                assert_eq!(assert_matches_rns(&pairs), expected);
            }
        }
    }

    fn reproject(pair: (G1, G2), pz: RnsFp, qz: RnsFp2) -> (G1, G2) {
        let (px, py) = pair.0.to_affine().unwrap();
        let (qx, qy) = pair.1.to_affine().unwrap();
        let (mut p, mut q) = pair;
        p.0.x = Fp::from_element(px.mul(pz));
        p.0.y = Fp::from_element(py.mul(pz));
        p.0.z = Fp::from_element(pz);
        q.0.x = import_fp2(qx.mul(qz));
        q.0.y = import_fp2(qy.mul(qz));
        q.0.z = import_fp2(qz);
        let result = (p, q);
        assert_eq!(result.0, pair.0);
        assert_eq!(result.1, pair.1);
        result
    }

    fn assert_preparation(pairs: &[(G1, G2)], products: &[RnsFp], expected_gt: [u8; 576]) {
        assert_eq!(pairs.chunks(16).len(), products.len());
        for (chunk, expected_product) in pairs.chunks(16).zip(products) {
            let live: alloc::vec::Vec<_> = chunk
                .iter()
                .filter(|(p, q)| !p.is_identity() && !q.is_identity())
                .collect();
            let product = live.iter().fold(RnsFp::ONE, |product, (p, q)| {
                product
                    .mul(p.0.z.to_element())
                    .mul(q.0.z[0].square().add(&q.0.z[1].square()).to_element())
            });
            assert_eq!(product, *expected_product);
            let empty = State::new(Fp::ZERO, Fp::one(), FP2_ZERO, [Fp::one(), Fp::ZERO]);
            let mut states = [empty; 16];
            assert_eq!(prepare(chunk, &mut states), live.len());
            for (actual, (p, q)) in states.iter().zip(live) {
                let (px, py) = p.to_affine().unwrap();
                let (qx, qy) = q.to_affine().unwrap();
                let expected = State::new(
                    Fp::from_element(px),
                    Fp::from_element(py),
                    import_fp2(qx),
                    import_fp2(qy),
                );
                assert_eq!(
                    [actual.x, actual.y, actual.z, actual.qx, actual.qy],
                    [expected.x, expected.y, expected.z, expected.qx, expected.qy],
                );
                assert_eq!(
                    [actual.px, actual.py, actual.three_px, actual.minus_two_py],
                    [
                        expected.px,
                        expected.py,
                        expected.three_px,
                        expected.minus_two_py
                    ],
                );
            }
        }
        assert_eq!(assert_matches_rns(pairs), expected_gt);
    }

    #[test]
    fn product_one_preparation_matches_nonunit_and_miss_inputs() {
        let pair = (G1::generator(), G2::generator());
        let half = RnsFp::from_u64(2).invert().unwrap();
        let three = RnsFp::from_u64(3);
        let qz = RnsFp2 {
            c0: RnsFp::ONE,
            c1: RnsFp::ONE,
        };
        let hit = reproject(pair, half, qz);
        let miss = reproject(pair, half.mul(three), qz);
        assert_ne!(hit.0.0.z, Fp::ONE);
        assert_ne!(hit.1.0.z, [Fp::ONE, Fp::ZERO]);
        for count in [1usize, 2, 16, 17] {
            let expected = oracle_pairing(&pair.0.mul(&Scalar::from_u64(count as u64)), &pair.1);
            let products = alloc::vec![RnsFp::ONE; count.div_ceil(16)];
            assert_preparation(&alloc::vec![pair; count], &products, expected);
            assert_preparation(&alloc::vec![hit; count], &products, expected);
        }
        for (count, index) in [(1, 0), (16, 0), (16, 15)] {
            let mut pairs = alloc::vec![pair; count];
            pairs[index] = miss;
            let expected = oracle_pairing(&pair.0.mul(&Scalar::from_u64(count as u64)), &pair.1);
            assert_preparation(&pairs, &[three], expected);
        }
        let two = RnsFp::from_u64(2);
        let one_repr = alloc::format!("{:?}", RnsFp::ONE);
        let redundant_one = [
            RnsFp::ONE.add(RnsFp::ZERO),
            RnsFp::ONE.mul(RnsFp::ONE),
            RnsFp::ONE.neg().neg(),
            RnsFp::ONE.add(RnsFp::ZERO.neg()),
        ]
        .into_iter()
        .find(|value| alloc::format!("{value:?}") != one_repr)
        .expect("field arithmetic supplies a redundant unit representative");
        assert_eq!(redundant_one, RnsFp::ONE);
        let redundant = reproject(
            pair,
            redundant_one,
            RnsFp2 {
                c0: redundant_one,
                c1: RnsFp::ZERO.neg(),
            },
        );
        assert_preparation(
            &[redundant],
            &[RnsFp::ONE],
            oracle_pairing(&pair.0, &pair.1),
        );
        let reciprocal_pairs = [
            reproject(pair, two, RnsFp2::ONE),
            reproject(pair, half, RnsFp2::ONE),
        ];
        assert_preparation(
            &reciprocal_pairs,
            &[RnsFp::ONE],
            oracle_pairing(&pair.0.double(), &pair.1),
        );
    }

    #[test]
    fn product_one_preparation_preserves_identity_and_chunk_boundaries() {
        let pair = (G1::generator(), G2::generator());
        let half = RnsFp::from_u64(2).invert().unwrap();
        let hit = reproject(
            pair,
            half,
            RnsFp2 {
                c0: RnsFp::ONE,
                c1: RnsFp::ONE,
            },
        );
        let identity = pairing::Gt::IDENTITY.to_bytes();
        assert_preparation(&[], &[], identity);
        assert_preparation(&[(G1::IDENTITY, pair.1); 17], &[RnsFp::ONE; 2], identity);
        let mut leading = alloc::vec![(G1::IDENTITY, pair.1); 16];
        leading.push(hit);
        assert_preparation(&leading, &[RnsFp::ONE; 2], oracle_pairing(&pair.0, &pair.1));
        for count in [16usize, 17] {
            let mut holes = alloc::vec![hit; count];
            holes[0] = (pair.0, G2::IDENTITY);
            holes[count - 1] = (G1::IDENTITY, pair.1);
            let expected =
                oracle_pairing(&pair.0.mul(&Scalar::from_u64((count - 2) as u64)), &pair.1);
            assert_preparation(
                &holes,
                &alloc::vec![RnsFp::ONE; count.div_ceil(16)],
                expected,
            );
        }
        assert_preparation(&[hit, (hit.0.neg(), hit.1)], &[RnsFp::ONE], identity);
        let mut cross_chunk = alloc::vec![pair; 17];
        let two = RnsFp::from_u64(2);
        cross_chunk[0] = reproject(pair, two, RnsFp2::ONE);
        cross_chunk[16] = reproject(pair, half, RnsFp2::ONE);
        assert_eq!(two.mul(half), RnsFp::ONE);
        assert_preparation(
            &cross_chunk,
            &[two, half],
            oracle_pairing(&pair.0.mul(&Scalar::from_u64(17)), &pair.1),
        );
    }
}

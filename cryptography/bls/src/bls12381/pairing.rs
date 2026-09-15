// Portions adapted from blst 0.3.16, blst/src/pairing.c.
// Copyright Supranational LLC
// SPDX-License-Identifier: Apache-2.0

//! Optimal Ate pairings on BLS12-381.

use crate::bls12381::{
    extension::Fp12,
    group::{G1, G2},
};

#[cfg(any(
    test,
    not(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_pointer_width = "64",
        not(miri)
    ))
))]
mod miller;

/// An element of the prime-order multiplicative target group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Gt(Fp12);

impl Gt {
    /// The multiplicative identity.
    pub const IDENTITY: Self = Self(Fp12::ONE);

    /// Returns whether this is the multiplicative identity.
    pub fn is_identity(&self) -> bool {
        self.0 == Fp12::ONE
    }

    /// Multiplies two target-group elements.
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(self.0.mul(rhs.0))
    }

    /// Returns the multiplicative inverse.
    pub fn invert(&self) -> Self {
        Self(self.0.conjugate())
    }

    /// Returns canonical big-endian coefficients in the blst target-group order.
    ///
    /// For the tower u^2 = -1, v^3 = u + 1, w^2 = v, the twelve 48-byte
    /// coefficients are ordered by powers of v, then w, then u.
    pub fn to_bytes(self) -> [u8; 576] {
        self.0.to_bytes()
    }
}

/// Computes the pairing of two public prime-order points.
///
/// Pairing either group's identity produces [Gt::IDENTITY].
///
/// Timing may depend on the points and their projective representations.
pub fn pairing(p: &G1, q: &G2) -> Gt {
    multi_pairing(&[(*p, *q)])
}

/// Computes a product of pairings of public points with shared Miller loops and one
/// final exponentiation.
///
/// An empty slice, or a slice containing only identity pairs, produces [Gt::IDENTITY].
///
/// Timing may depend on the points and their projective representations.
pub fn multi_pairing(pairs: &[(G1, G2)]) -> Gt {
    #[cfg(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_pointer_width = "64",
        not(miri)
    ))]
    {
        Gt(crate::bls12381::word_pairing::compute(pairs))
    }
    #[cfg(not(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_pointer_width = "64",
        not(miri)
    )))]
    {
        rns::compute(pairs)
    }
}

#[cfg(all(
    test,
    all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_pointer_width = "64",
        not(miri)
    )
))]
pub(super) fn rns_multi_pairing(pairs: &[(G1, G2)]) -> Gt {
    rns::compute(pairs)
}

#[cfg(any(
    test,
    not(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_pointer_width = "64",
        not(miri)
    ))
))]
mod rns {
    use super::*;
    use crate::bls12381::extension::{Fp2, bounded::Fp2Ring, fp12};
    use commonware_cryptography_vroom::{
        Backend, Bls12381, WithBackend,
        rns::{Ring, Standard, bounds::Range},
        with_backend,
    };

    pub(super) fn compute(pairs: &[(G1, G2)]) -> Gt {
        with_backend(Pairings(pairs))
    }

    struct Pairings<'a>(&'a [(G1, G2)]);

    impl WithBackend for Pairings<'_> {
        type Output = Gt;

        #[inline(always)]
        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let ring = Ring::<Bls12381, B>::new(backend);
            let mut product = fp12::one();
            for chunk in self.0.chunks(16) {
                let empty = miller::State::new(
                    Standard::ZERO,
                    Standard::ONE,
                    Fp2::ZERO.into(),
                    Fp2::ONE.into(),
                    &ring,
                );
                let mut states = [empty; 16];
                let count = prepare(chunk, &mut states, &ring);
                if count != 0 {
                    product = fp12::mul(
                        &product,
                        &miller::miller_loop(&mut states[..count], &ring),
                        &ring,
                    );
                }
            }
            if Fp12::from_bounded(product) == Fp12::ONE {
                return Gt::IDENTITY;
            }

            // Each nonidentity state is kQ with 1 <= k <= |z| < r. At doubling,
            // Y and Z are nonzero; at addition, kQ is neither Q nor -Q. Thus the
            // v*w line coefficient is nonzero and the Miller product is invertible.
            Gt(Fp12::from_bounded(
                final_exponentiation_inner(&product, &ring).expect("Miller products are nonzero"),
            ))
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn prepare<B: Backend>(
        pairs: &[(G1, G2)],
        states: &mut [miller::State<B>; 16],
        ring: &Ring<Bls12381, B>,
    ) -> usize {
        assert!(pairs.len() <= states.len());
        let fp2 = Fp2Ring::new(ring);
        let mut denominators = [Standard::ONE; 32];
        let mut count = 0;
        for (p, q) in pairs {
            #[cfg(all(
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_pointer_width = "64",
                not(miri)
            ))]
            let (pz, qz) = (p.jacobian_coordinates().2, q.jacobian_coordinates().2);
            #[cfg(not(all(
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_pointer_width = "64",
                not(miri)
            )))]
            let (pz, qz) = (p.z, q.z);
            if bool::from(ring.is_zero(pz.into()) | fp2.is_zero(qz.into())) {
                continue;
            }
            let z = crate::bls12381::extension::bounded::Fp2Standard::from(qz);
            denominators[2 * count] = pz.into();
            let norm = ring.prep_left(z.c0) * z.c0 + ring.prep_left(z.c1) * z.c1;
            denominators[2 * count + 1] = ring.batch_reduce_expand(&[ring.ready::<800>(norm)])[0];
            count += 1;
        }
        if count == 0 {
            return 0;
        }

        // Nonidentity Jacobian points have nonzero z. The Fp2 norm is nonzero
        // as well, so all G1 and G2 denominators share one base-field inverse.
        let len = 2 * count;
        let mut prefixes = [Standard::ONE; 32];
        let mut product = denominators[0];
        for i in 1..len {
            prefixes[i] = product;
            product = ring.mul(product, denominators[i]);
        }
        let mut inverse = ring.invert(product).expect("nonzero affine denominators");
        for i in (1..len).rev() {
            let denominator = denominators[i];
            denominators[i] = ring.mul(inverse, prefixes[i]);
            inverse = ring.mul(inverse, denominator);
        }
        denominators[0] = inverse;

        let mut index = 0;
        for (p, q) in pairs {
            #[cfg(all(
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_pointer_width = "64",
                not(miri)
            ))]
            let ((px, py, pz), (qx, qy, qz)) = (p.jacobian_coordinates(), q.jacobian_coordinates());
            #[cfg(not(all(
                target_arch = "aarch64",
                target_os = "linux",
                target_endian = "little",
                target_pointer_width = "64",
                not(miri)
            )))]
            let ((px, py, pz), (qx, qy, qz)) = ((p.x, p.y, p.z), (q.x, q.y, q.z));
            if bool::from(ring.is_zero(pz.into()) | fp2.is_zero(qz.into())) {
                continue;
            }
            let pz = denominators[2 * index];
            let pz2 = ring.mul(pz, pz);
            let px = ring.mul(px.into(), pz2);
            let py = ring.mul(py.into(), ring.mul(pz2, pz));
            let [qz] = fp2.batch_reduce_expand(&[fp2.ready::<800>(
                fp2.mul_by_fp(fp2.conjugate(qz.into()), denominators[2 * index + 1]),
            )]);
            let qz2 = fp2.square(qz);
            let qx = fp2.mul(qx.into(), qz2);
            let qy = fp2.mul(qy.into(), fp2.mul(qz2, qz));
            states[index] = miller::State::new(px, py, qx, qy, ring);
            index += 1;
        }
        count
    }

    #[inline(always)]
    fn raise_to_z_over_two<const N: i64, B: Backend>(
        value: &fp12::Fp12<N>,
        ring: &Ring<Bls12381, B>,
    ) -> fp12::Fp12<6> {
        let mut result = fp12::cyclotomic_square(value, ring);
        for squarings in [2, 3, 9, 32, 15] {
            let product = fp12::mul(&result, value, ring);
            result = core::array::from_fn(|i| product[i].recast_rns::<Range<0, 6>>());
            for _ in 0..squarings {
                result = fp12::cyclotomic_square(&result, ring);
            }
        }
        fp12::conjugate(&result, ring)
    }

    #[inline(always)]
    fn raise_to_z<const N: i64, B: Backend>(
        value: &fp12::Fp12<N>,
        ring: &Ring<Bls12381, B>,
    ) -> fp12::Fp12<6> {
        fp12::cyclotomic_square(&raise_to_z_over_two(value, ring), ring)
    }

    // The easy part establishes the cyclotomic invariant. Common bound 6 survives
    // consecutive cyclotomic operations; multiplication resets it to standard.
    #[inline(always)]
    fn final_exponentiation_inner<B: Backend>(
        value: &fp12::Standard,
        ring: &Ring<Bls12381, B>,
    ) -> Option<fp12::Standard> {
        let inverse = fp12::invert(value, ring)?;
        let easy = fp12::mul(&fp12::conjugate(value, ring), &inverse, ring);
        let easy = fp12::mul(&fp12::frobenius2(&easy, ring), &easy, ring);
        let y0 = fp12::cyclotomic_square(&easy, ring);
        let y1 = raise_to_z(&y0, ring);
        let y2 = raise_to_z_over_two(&y1, ring);
        let y1 = fp12::mul(&y1, &fp12::conjugate(&easy, ring), ring);
        let y1 = fp12::mul(&fp12::conjugate(&y1, ring), &y2, ring);
        let y2 = raise_to_z(&y1, ring);
        let y3 = fp12::mul(&raise_to_z(&y2, ring), &fp12::conjugate(&y1, ring), ring);
        let y1 = fp12::frobenius3(&y1, ring);
        let y2 = fp12::frobenius2(&y2, ring);
        let y1 = fp12::mul(&y1, &y2, ring);
        let y2 = fp12::mul(&raise_to_z(&y3, ring), &y0, ring);
        let y2 = fp12::mul(&y2, &easy, ring);
        let result = fp12::mul(&y1, &y2, ring);
        Some(fp12::mul(&result, &fp12::frobenius1(&y3, ring), ring))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[cfg(not(miri))]
        use crate::bls12381::extension::tests::{oracle_bytes, oracle_fp12};
        use crate::bls12381::{
            Fp,
            extension::{
                Fp6,
                tests::{pow_big, random_fp12},
            },
            scalar::Scalar,
        };
        #[cfg(not(miri))]
        use blst::{
            BLST_ERROR, blst_final_exp, blst_fp12, blst_fp12_in_group, blst_miller_loop,
            blst_p1_affine, blst_p1_uncompress, blst_p2_affine, blst_p2_uncompress,
        };
        use commonware_utils::test_rng;
        use num_bigint::BigUint;
        use rand_core::Rng;

        struct FinalExponent(Fp12);

        impl WithBackend for FinalExponent {
            type Output = Option<Fp12>;

            fn call<B: Backend>(self, backend: B) -> Self::Output {
                final_exponentiation_inner(&self.0.to_bounded(), &Ring::new(backend))
                    .map(Fp12::from_bounded)
            }
        }

        fn final_exponentiation(value: Fp12) -> Option<Fp12> {
            with_backend(FinalExponent(value))
        }

        #[cfg(not(miri))]
        fn oracle_pairing(p: &G1, q: &G2) -> [u8; 576] {
            let mut pp = blst_p1_affine::default();
            let mut qq = blst_p2_affine::default();
            let mut miller = blst_fp12::default();
            let mut target = blst_fp12::default();
            // SAFETY: Encodings have the required 48/96 bytes and outputs are initialized.
            unsafe {
                assert_eq!(
                    blst_p1_uncompress(&mut pp, p.to_bytes().as_ptr()),
                    BLST_ERROR::BLST_SUCCESS
                );
                assert_eq!(
                    blst_p2_uncompress(&mut qq, q.to_bytes().as_ptr()),
                    BLST_ERROR::BLST_SUCCESS
                );
                blst_miller_loop(&mut miller, &qq, &pp);
                blst_final_exp(&mut target, &miller);
            }
            oracle_bytes(&target)
        }

        #[test]
        fn affine_batch_matches_individual_normalization() {
            struct Check;
            impl WithBackend for Check {
                type Output = ();
                fn call<B: Backend>(self, backend: B) {
                    check_affine_batch(&Ring::new(backend));
                }
            }
            with_backend(Check);
        }

        fn check_affine_batch<B: Backend>(ring: &Ring<Bls12381, B>) {
            let p = G1::generator();
            let q = G2::generator();
            let mut pairs = [(G1::IDENTITY, G2::IDENTITY); 16];
            for (i, pair) in pairs.iter_mut().enumerate() {
                let pz = Fp::from_u64((i + 2) as u64);
                let qz = Fp2 {
                    c0: pz,
                    c1: Fp::ONE,
                };
                *pair = (
                    {
                        let (x, y, _) = p.jacobian_coordinates();
                        G1::from_jacobian_coordinates(
                            x.mul(pz.square()),
                            y.mul(pz.square().mul(pz)),
                            pz,
                        )
                    },
                    {
                        let (x, y, _) = q.jacobian_coordinates();
                        G2::from_jacobian_coordinates(
                            x.mul(qz.square()),
                            y.mul(qz.square().mul(qz)),
                            qz,
                        )
                    },
                );
            }
            for identities in [false, true] {
                if identities {
                    pairs[0].0 = G1::IDENTITY;
                    pairs[7].1 = G2::IDENTITY;
                    pairs[15] = (G1::IDENTITY, G2::IDENTITY);
                }
                for len in 0..=pairs.len() {
                    let empty = miller::State::new(
                        Standard::ZERO,
                        Standard::ONE,
                        Fp2::ZERO.into(),
                        Fp2::ONE.into(),
                        ring,
                    );
                    let mut states = [empty; 16];
                    let count = prepare(&pairs[..len], &mut states, ring);
                    let mut actual = states[..count].iter();
                    for (p, q) in &pairs[..len] {
                        let (Some((px, py)), Some((qx, qy))) = (p.to_affine(), q.to_affine())
                        else {
                            continue;
                        };
                        let state = actual.next().unwrap();
                        assert_eq!(Fp::from(state.px), px);
                        assert_eq!(Fp::from(state.py), py);
                        assert_eq!(Fp2::from(state.x), qx);
                        assert_eq!(Fp2::from(state.y), qy);
                        assert_eq!(Fp2::from(state.z), Fp2::ONE);
                    }
                    assert!(actual.next().is_none());
                }
            }
        }

        #[test]
        fn homogeneous_miller_states_match_jacobian_arithmetic() {
            struct Check;
            impl WithBackend for Check {
                type Output = ();

                fn call<B: Backend>(self, backend: B) {
                    let ring = Ring::new(backend);
                    let (px, py) = G1::generator().to_affine().unwrap();
                    let mut rng = test_rng();
                    for _ in 0..4 {
                        let mut bytes = [0; 64];
                        rng.fill_bytes(&mut bytes);
                        let q = G2::generator().mul(&Scalar::from_wide_bytes(&bytes));
                        let (qx, qy) = q.to_affine().unwrap();
                        let mut state =
                            miller::State::new(px.into(), py.into(), qx.into(), qy.into(), &ring);
                        let mut expected = q;
                        let mut product = fp12::one();
                        state.double(&mut product, &ring);
                        expected = expected.double();
                        assert_miller_point(&state, &expected);
                        for squarings in [2, 3, 9, 32, 16] {
                            state.add(&mut product, &ring);
                            expected = expected.add(&q);
                            assert_miller_point(&state, &expected);
                            for _ in 0..squarings {
                                product = fp12::square(&product, &ring);
                                state.double(&mut product, &ring);
                                expected = expected.double();
                                assert_miller_point(&state, &expected);
                            }
                        }
                    }
                }
            }
            with_backend(Check);
        }

        fn assert_miller_point<B: Backend>(state: &miller::State<B>, expected: &G2) {
            let x = Fp2::from(state.x);
            let y = Fp2::from(state.y);
            let z = Fp2::from(state.z);
            let actual = G2::from_jacobian_coordinates(x.mul(z), y.mul(z.square()), z);
            assert!(!actual.is_identity());
            assert_eq!(&actual, expected);
        }

        #[test]
        fn pairing_bytes_match_blst() {
            let generator1 = G1::generator();
            let generator2 = G2::generator();
            #[cfg(not(miri))]
            assert_eq!(
                pairing(&generator1, &generator2).to_bytes(),
                oracle_pairing(&generator1, &generator2)
            );
            let mut rng = test_rng();
            for _ in 0..4 {
                let mut bytes = [0; 64];
                rng.fill_bytes(&mut bytes);
                let a = Scalar::from_wide_bytes(&bytes);
                rng.fill_bytes(&mut bytes);
                let b = Scalar::from_wide_bytes(&bytes);
                let p = generator1.mul(&a);
                let q = generator2.mul(&b);
                let actual = pairing(&p, &q);
                #[cfg(not(miri))]
                assert_eq!(actual.to_bytes(), oracle_pairing(&p, &q));
                assert_eq!(actual, pairing(&generator1.mul(&a.mul(&b)), &generator2));
                assert!(!actual.is_identity());
                assert_eq!(actual.mul(&actual.invert()), Gt::IDENTITY);
            }
        }

        #[test]
        fn identity_pairs_contribute_one() {
            let p = G1::generator();
            let q = G2::generator();
            assert_eq!(multi_pairing(&[]), Gt::IDENTITY);
            for (p, q) in [
                (G1::IDENTITY, q),
                (p, G2::IDENTITY),
                (G1::IDENTITY, G2::IDENTITY),
            ] {
                assert_eq!(pairing(&p, &q), Gt::IDENTITY);
                #[cfg(not(miri))]
                assert_eq!(pairing(&p, &q).to_bytes(), oracle_pairing(&p, &q));
            }
            assert_eq!(
                multi_pairing(&[(G1::IDENTITY, q), (p, q), (p, G2::IDENTITY)]),
                pairing(&p, &q)
            );
        }

        #[test]
        fn multi_pairing_products_and_chunk_boundaries() {
            let p = G1::generator();
            let q = G2::generator();
            let base = pairing(&p, &q);
            let pair = [(p, q), (p.neg(), q)];
            assert_eq!(multi_pairing(&pair), Gt::IDENTITY);
            assert_eq!(multi_pairing(&[(p, q), (p, q.neg())]), Gt::IDENTITY);
            for count in [15, 16, 17] {
                let pairs: alloc::vec::Vec<_> = (0..count).map(|i| pair[i % 2]).collect();
                let expected = if count % 2 == 0 { Gt::IDENTITY } else { base };
                assert_eq!(multi_pairing(&pairs), expected);
            }
            let other = pairing(&p.double(), &q.double());
            assert_eq!(
                multi_pairing(&[(p, q), (p.double(), q.double())]),
                base.mul(&other)
            );
        }

        #[test]
        fn final_exponent_matches_blst_and_target_order() {
            let mut rng = test_rng();
            for _ in 0..4 {
                let value = random_fp12(&mut rng);
                let actual = final_exponentiation(value).unwrap();
                assert!(actual.invert().is_some());
                #[cfg(not(miri))]
                {
                    let oracle = oracle_fp12(value);
                    let mut expected = blst_fp12::default();
                    // SAFETY: The input is nonzero and both Fp12 objects are initialized.
                    unsafe { blst_final_exp(&mut expected, &oracle) };
                    assert_eq!(actual.to_bytes(), oracle_bytes(&expected));
                    // SAFETY: The pointer references a valid initialized Fp12 value.
                    assert!(unsafe { blst_fp12_in_group(&oracle_fp12(actual)) });
                }
            }
            assert_eq!(final_exponentiation(Fp12::ONE), Some(Fp12::ONE));
            assert!(final_exponentiation(Fp12([Fp6::ZERO; 2])).is_none());
        }

        #[test]
        fn hard_exponent_matches_integer_exponentiation() {
            let value = random_fp12(&mut test_rng());
            let p = BigUint::from_bytes_be(&Fp::ONE.neg().to_bytes()) + 1u8;
            let order = BigUint::from_bytes_be(&Scalar::ONE.neg().to_bytes()) + 1u8;
            let easy = value.conjugate().mul(value.invert().unwrap());
            let easy = easy.mul(easy.frobenius().frobenius());
            // blst's normalized pairing uses three times the usual hard exponent.
            let exponent = ((p.pow(4) - p.pow(2) + 1u8) / order) * 3u8;
            assert_eq!(
                final_exponentiation(value).unwrap(),
                pow_big(easy, &exponent)
            );
        }
    }
}

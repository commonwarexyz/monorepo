// Portions adapted from blst 0.3.16, blst/src/fp12_tower.c.
// Copyright Supranational LLC
// SPDX-License-Identifier: Apache-2.0
//
// Extension-field operations adapted from VROOM/src/fp12.hpp.
// Copyright 2026 Simon Langowski, licensed under MIT.
// See LICENSE-VROOM for the permission notice.

//! The tower `Fp2 = Fp[u]/(u^2 + 1)`, `Fp6 = Fp2[v]/(v^3 - u - 1)`,
//! and `Fp12 = Fp6[w]/(w^2 - v)`.

use crate::bls12381::Fp;
use commonware_cryptography_vroom::{Backend, Bls12381, WithBackend, rns::Ring, with_backend};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

pub(crate) mod bounded;
pub(crate) mod fp12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fp2 {
    pub(crate) c0: Fp,
    pub(crate) c1: Fp,
}

impl Fp2 {
    pub(crate) const ZERO: Self = Self {
        c0: Fp::ZERO,
        c1: Fp::ZERO,
    };
    pub(crate) const ONE: Self = Self {
        c0: Fp::ONE,
        c1: Fp::ZERO,
    };

    #[cfg(test)]
    pub(crate) const fn from_u64(value: u64) -> Self {
        Self {
            c0: Fp::from_u64(value),
            c1: Fp::ZERO,
        }
    }

    pub(crate) fn is_zero(self) -> bool {
        self.c0.is_zero() & self.c1.is_zero()
    }

    pub(crate) fn add(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.add(rhs.c0),
            c1: self.c1.add(rhs.c1),
        }
    }

    pub(crate) fn sub(self, rhs: Self) -> Self {
        Self {
            c0: self.c0.sub(rhs.c0),
            c1: self.c1.sub(rhs.c1),
        }
    }

    pub(crate) fn neg(self) -> Self {
        Self {
            c0: self.c0.neg(),
            c1: self.c1.neg(),
        }
    }

    pub(crate) fn mul(self, rhs: Self) -> Self {
        Self {
            c0: Fp::sum_of_products(&[self.c0, self.c1.neg()], &[rhs.c0, rhs.c1]),
            c1: Fp::sum_of_products(&[self.c0, self.c1], &[rhs.c1, rhs.c0]),
        }
    }

    pub(crate) fn square(self) -> Self {
        let product = self.c0.mul(self.c1);
        Self {
            c0: self.c0.add(self.c1).mul(self.c0.sub(self.c1)),
            c1: product.add(product),
        }
    }

    pub(crate) fn invert(self) -> Option<Self> {
        let coefficients = [self.c0, self.c1];
        let norm = Fp::sum_of_products(&coefficients, &coefficients).invert()?;
        Some(Self {
            c0: self.c0.mul(norm),
            c1: self.c1.neg().mul(norm),
        })
    }

    pub(crate) fn sqrt(self) -> Option<Self> {
        if self.c1.is_zero() {
            return if let Some(root) = self.c0.sqrt() {
                Some(Self {
                    c0: root,
                    c1: Fp::ZERO,
                })
            } else {
                Some(Self {
                    c0: Fp::ZERO,
                    c1: self.c0.neg().sqrt()?,
                })
            };
        }
        let coefficients = [self.c0, self.c1];
        let norm = Fp::sum_of_products(&coefficients, &coefficients).sqrt()?;
        let half = Fp::from_bytes(&[
            0x0d, 0x00, 0x88, 0xf5, 0x1c, 0xbf, 0xf3, 0x4d, 0x25, 0x8d, 0xd3, 0xdb, 0x21, 0xa5,
            0xd6, 0x6b, 0xb2, 0x3b, 0xa5, 0xc2, 0x79, 0xc2, 0x89, 0x5f, 0xb3, 0x98, 0x69, 0x50,
            0x7b, 0x58, 0x7b, 0x12, 0x0f, 0x55, 0xff, 0xff, 0x58, 0xa9, 0xff, 0xff, 0xdc, 0xff,
            0x7f, 0xff, 0xff, 0xff, 0xd5, 0x56,
        ])
        .expect("canonical inverse of two");
        let root = self
            .c0
            .add(norm)
            .mul(half)
            .sqrt()
            .or_else(|| self.c0.sub(norm).mul(half).sqrt())?;
        let result = Self {
            c0: root,
            c1: self.c1.mul(root.add(root).invert()?),
        };
        (result.square() == self).then_some(result)
    }

    /// Whether this value is greater than its negation, with c1 most significant.
    pub(crate) fn lexicographically_largest(self) -> bool {
        if self.c1.is_zero() {
            bool::from(self.c0.lexicographically_largest())
        } else {
            bool::from(self.c1.lexicographically_largest())
        }
    }

    #[cfg(test)]
    pub(crate) fn conjugate(self) -> Self {
        Self {
            c0: self.c0,
            c1: self.c1.neg(),
        }
    }

    #[cfg(test)]
    pub(crate) fn mul_by_nonresidue(self) -> Self {
        Self {
            c0: self.c0.sub(self.c1),
            c1: self.c0.add(self.c1),
        }
    }

    #[cfg(test)]
    pub(crate) fn mul_by_fp(self, rhs: Fp) -> Self {
        Self {
            c0: self.c0.mul(rhs),
            c1: self.c1.mul(rhs),
        }
    }
}

impl ConditionallySelectable for Fp2 {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            c0: Fp::conditional_select(&a.c0, &b.c0, choice),
            c1: Fp::conditional_select(&a.c1, &b.c1, choice),
        }
    }
}

impl ConstantTimeEq for Fp2 {
    fn ct_eq(&self, rhs: &Self) -> Choice {
        self.c0.ct_eq(&rhs.c0) & self.c1.ct_eq(&rhs.c1)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fp6(pub(crate) [Fp2; 3]);

impl Fp6 {
    pub(crate) const ZERO: Self = Self([Fp2::ZERO; 3]);
    pub(crate) const ONE: Self = Self([Fp2::ONE, Fp2::ZERO, Fp2::ZERO]);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fp12(pub(crate) [Fp6; 2]);

struct Multiply(Fp12, Fp12);

impl WithBackend for Multiply {
    type Output = Fp12;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        let ring = Ring::<Bls12381, B>::new(backend);
        Fp12::from_bounded(fp12::mul(&self.0.to_bounded(), &self.1.to_bounded(), &ring))
    }
}

struct Conjugate(Fp12);

impl WithBackend for Conjugate {
    type Output = Fp12;

    #[inline]
    fn call<B: Backend>(self, backend: B) -> Self::Output {
        Fp12::from_bounded(fp12::conjugate(&self.0.to_bounded(), &Ring::new(backend)))
    }
}

impl Fp12 {
    pub(crate) const ONE: Self = Self([Fp6::ONE, Fp6::ZERO]);

    #[inline]
    pub(crate) fn to_bounded(self) -> fp12::Standard {
        let [a, b] = self.0;
        [
            a.0[0].c0.into(),
            a.0[0].c1.into(),
            a.0[1].c0.into(),
            a.0[1].c1.into(),
            a.0[2].c0.into(),
            a.0[2].c1.into(),
            b.0[0].c0.into(),
            b.0[0].c1.into(),
            b.0[1].c0.into(),
            b.0[1].c1.into(),
            b.0[2].c0.into(),
            b.0[2].c1.into(),
        ]
    }

    #[inline]
    pub(crate) fn from_bounded(value: fp12::Standard) -> Self {
        let [a0, a1, a2, a3, a4, a5, b0, b1, b2, b3, b4, b5] = value;
        Self([
            Fp6([
                Fp2 {
                    c0: a0.into(),
                    c1: a1.into(),
                },
                Fp2 {
                    c0: a2.into(),
                    c1: a3.into(),
                },
                Fp2 {
                    c0: a4.into(),
                    c1: a5.into(),
                },
            ]),
            Fp6([
                Fp2 {
                    c0: b0.into(),
                    c1: b1.into(),
                },
                Fp2 {
                    c0: b2.into(),
                    c1: b3.into(),
                },
                Fp2 {
                    c0: b4.into(),
                    c1: b5.into(),
                },
            ]),
        ])
    }

    pub(crate) fn mul(self, rhs: Self) -> Self {
        with_backend(Multiply(self, rhs))
    }

    pub(crate) fn conjugate(self) -> Self {
        with_backend(Conjugate(self))
    }

    /// Canonical big-endian coefficients, ordered by v, then w, then u.
    pub(crate) fn to_bytes(self) -> [u8; 576] {
        let mut bytes = [0; 576];
        for (i, chunk) in bytes.as_chunks_mut::<192>().0.iter_mut().enumerate() {
            for (j, half) in chunk.as_chunks_mut::<96>().0.iter_mut().enumerate() {
                let coefficient = self.0[j].0[i];
                half[..48].copy_from_slice(&coefficient.c0.to_bytes());
                half[48..].copy_from_slice(&coefficient.c1.to_bytes());
            }
        }
        bytes
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    #[cfg(not(miri))]
    use blst::{
        blst_bendian_from_fp12, blst_fp, blst_fp_from_bendian, blst_fp2, blst_fp2_sqrt, blst_fp6,
        blst_fp12, blst_fp12_cyclotomic_sqr, blst_fp12_frobenius_map, blst_fp12_inverse,
        blst_fp12_mul, blst_fp12_sqr,
    };
    use commonware_utils::test_rng;
    use num_bigint::BigUint;
    use rand_core::Rng;

    fn random_fp(rng: &mut impl Rng) -> Fp {
        loop {
            let mut bytes = [0; 48];
            rng.fill_bytes(&mut bytes);
            bytes[0] &= 0x1f;
            if let Some(value) = Fp::from_bytes(&bytes) {
                return value;
            }
        }
    }

    pub(crate) fn random_fp12(rng: &mut impl Rng) -> Fp12 {
        Fp12(core::array::from_fn(|_| {
            Fp6(core::array::from_fn(|_| Fp2 {
                c0: random_fp(rng),
                c1: random_fp(rng),
            }))
        }))
    }

    enum Operation<'a> {
        Square,
        Invert,
        Frobenius,
        CyclotomicSquare,
        Sparse(&'a [Fp2; 3]),
    }

    struct Unary<'a>(Fp12, Operation<'a>);

    impl WithBackend for Unary<'_> {
        type Output = Option<Fp12>;

        fn call<B: Backend>(self, backend: B) -> Self::Output {
            let ring = Ring::<Bls12381, B>::new(backend);
            let input = self.0.to_bounded();
            let output = match self.1 {
                Operation::Square => fp12::square(&input, &ring),
                Operation::Invert => fp12::invert(&input, &ring)?,
                Operation::Frobenius => fp12::frobenius1(&input, &ring),
                Operation::CyclotomicSquare => {
                    let output = fp12::cyclotomic_square(&input, &ring);
                    fp12::mul(&output, &fp12::one(), &ring)
                }
                Operation::Sparse(&[c0, c1, c4]) => {
                    fp12::mul_by_014(&input, c0.into(), c1.into(), c4.into(), &ring)
                }
            };
            Some(Fp12::from_bounded(output))
        }
    }

    impl Fp12 {
        pub(crate) fn square(self) -> Self {
            with_backend(Unary(self, Operation::Square)).unwrap()
        }

        pub(crate) fn invert(self) -> Option<Self> {
            with_backend(Unary(self, Operation::Invert))
        }

        pub(crate) fn frobenius(self) -> Self {
            with_backend(Unary(self, Operation::Frobenius)).unwrap()
        }

        pub(crate) fn cyclotomic_square(self) -> Self {
            with_backend(Unary(self, Operation::CyclotomicSquare)).unwrap()
        }

        fn mul_by_014(self, c0: Fp2, c1: Fp2, c4: Fp2) -> Self {
            with_backend(Unary(self, Operation::Sparse(&[c0, c1, c4]))).unwrap()
        }
    }

    #[cfg(not(miri))]
    fn oracle_fp2(value: Fp2) -> blst_fp2 {
        let fp = [value.c0, value.c1].map(|coefficient| {
            let mut result = blst_fp::default();
            // SAFETY: The canonical input and initialized output each have 48 bytes.
            unsafe { blst_fp_from_bendian(&mut result, coefficient.to_bytes().as_ptr()) };
            result
        });
        blst_fp2 { fp }
    }

    #[cfg(not(miri))]
    pub(crate) fn oracle_fp12(value: Fp12) -> blst_fp12 {
        blst_fp12 {
            fp6: value.0.map(|half| blst_fp6 {
                fp2: half.0.map(oracle_fp2),
            }),
        }
    }

    #[cfg(not(miri))]
    pub(crate) fn oracle_bytes(value: &blst_fp12) -> [u8; 576] {
        let mut result = [0; 576];
        // SAFETY: The output has the required 576 bytes and the field value is initialized.
        unsafe { blst_bendian_from_fp12(result.as_mut_ptr(), value) };
        result
    }

    pub(crate) fn pow_big(value: Fp12, exponent: &BigUint) -> Fp12 {
        let mut result = Fp12::ONE;
        for byte in exponent.to_bytes_be() {
            for bit in (0..8).rev() {
                result = result.square();
                if byte & (1 << bit) != 0 {
                    result = result.mul(value);
                }
            }
        }
        result
    }

    #[test]
    fn quadratic_roots_and_inverses() {
        let mut rng = test_rng();
        let boundaries = [
            Fp2::ZERO,
            Fp2::ONE,
            Fp2::ONE.neg(),
            Fp2 {
                c0: Fp::ZERO,
                c1: Fp::ONE,
            },
        ];
        for value in boundaries.into_iter().chain((0..12).map(|_| Fp2 {
            c0: random_fp(&mut rng),
            c1: random_fp(&mut rng),
        })) {
            assert_eq!(value.square(), value.mul(value));
            assert_eq!(value.is_zero(), value.invert().is_none());
            if let Some(inverse) = value.invert() {
                assert_eq!(value.mul(inverse), Fp2::ONE);
            }
            let root = value.sqrt();
            #[cfg(not(miri))]
            {
                let oracle = oracle_fp2(value);
                let mut expected = blst_fp2::default();
                // SAFETY: Both pointers reference initialized Fp2 values of the required size.
                let exists = unsafe { blst_fp2_sqrt(&mut expected, &oracle) };
                assert_eq!(root.is_some(), exists);
            }
            if let Some(root) = root {
                assert_eq!(root.square(), value);
            }
            assert_eq!(value.square().sqrt().unwrap().square(), value.square());
            if !value.is_zero() {
                assert_ne!(
                    value.lexicographically_largest(),
                    value.neg().lexicographically_largest()
                );
            }
        }
    }

    #[test]
    fn cyclotomic_coefficients_match_tower_formula() {
        fn square_fp4(a: Fp2, b: Fp2) -> [Fp2; 2] {
            [
                a.square().add(b.square().mul_by_nonresidue()),
                a.mul(b).add(a.mul(b)),
            ]
        }
        let mut rng = test_rng();
        for value in [Fp12([Fp6::ZERO; 2]), Fp12::ONE]
            .into_iter()
            .chain((0..12).map(|_| random_fp12(&mut rng)))
        {
            let [a, b] = value.0;
            let t0 = square_fp4(a.0[0], b.0[1]);
            let t1 = square_fp4(b.0[0], a.0[2]);
            let t2 = square_fp4(a.0[1], b.0[2]);
            let minus = |x: Fp2, y: Fp2| x.add(x).add(x).sub(y.add(y));
            let plus = |x: Fp2, y: Fp2| x.add(x).add(x).add(y.add(y));
            let expected = Fp12([
                Fp6([
                    minus(t0[0], a.0[0]),
                    minus(t1[0], a.0[1]),
                    minus(t2[0], a.0[2]),
                ]),
                Fp6([
                    plus(t2[1].mul_by_nonresidue(), b.0[0]),
                    plus(t0[1], b.0[1]),
                    plus(t1[1], b.0[2]),
                ]),
            ]);
            assert_eq!(value.cyclotomic_square(), expected);
        }
    }

    #[test]
    fn tower_arithmetic_matches_blst() {
        let mut rng = test_rng();
        for _ in 0..8 {
            let a = random_fp12(&mut rng);
            let b = random_fp12(&mut rng);
            #[cfg(not(miri))]
            {
                let aa = oracle_fp12(a);
                let bb = oracle_fp12(b);
                let mut expected = blst_fp12::default();
                assert_eq!(a.to_bytes(), oracle_bytes(&aa));
                // SAFETY: All pointers reference initialized, non-overlapping Fp12 values.
                unsafe { blst_fp12_mul(&mut expected, &aa, &bb) };
                assert_eq!(a.mul(b).to_bytes(), oracle_bytes(&expected));
                // SAFETY: Input and output are initialized Fp12 values.
                unsafe { blst_fp12_sqr(&mut expected, &aa) };
                assert_eq!(a.square().to_bytes(), oracle_bytes(&expected));
                // SAFETY: The random input is nonzero and both values are initialized.
                unsafe { blst_fp12_inverse(&mut expected, &aa) };
                assert_eq!(a.invert().unwrap().to_bytes(), oracle_bytes(&expected));
                // SAFETY: The Frobenius power is in blst's supported range 1..=3.
                unsafe { blst_fp12_frobenius_map(&mut expected, &aa, 1) };
                assert_eq!(a.frobenius().to_bytes(), oracle_bytes(&expected));
            }
            assert_eq!(a.square(), a.mul(a));
            assert_eq!(a.mul(a.invert().unwrap()), Fp12::ONE);

            let [c0, c1, c4] = b.0[0].0;
            let sparse = Fp12([Fp6([c0, c1, Fp2::ZERO]), Fp6([Fp2::ZERO, c4, Fp2::ZERO])]);
            assert_eq!(a.mul_by_014(c0, c1, c4), a.mul(sparse));
            let easy = a.conjugate().mul(a.invert().unwrap());
            let easy = easy.mul(easy.frobenius().frobenius());
            #[cfg(not(miri))]
            {
                let oracle = oracle_fp12(easy);
                let mut expected = blst_fp12::default();
                // SAFETY: The easy exponent places this initialized value in the cyclotomic subgroup.
                unsafe { blst_fp12_cyclotomic_sqr(&mut expected, &oracle) };
                assert_eq!(easy.cyclotomic_square().to_bytes(), oracle_bytes(&expected));
            }
            assert_eq!(easy.cyclotomic_square(), easy.square());
        }
        assert!(Fp12([Fp6::ZERO; 2]).invert().is_none());
    }

    #[test]
    fn frobenius_matches_prime_exponent_and_has_order_twelve() {
        let a = random_fp12(&mut test_rng());
        let p = BigUint::from_bytes_be(&Fp::ONE.neg().to_bytes()) + 1u8;
        assert_eq!(a.frobenius(), pow_big(a, &p));
        let mut conjugated = a;
        for _ in 0..6 {
            conjugated = conjugated.frobenius();
        }
        assert_eq!(conjugated, a.conjugate());
        for _ in 0..6 {
            conjugated = conjugated.frobenius();
        }
        assert_eq!(conjugated, a);
    }
}

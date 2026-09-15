// Adapted from VROOM src/ec.hpp.
// Copyright 2026 Simon Langowski
// SPDX-License-Identifier: MIT

//! Fixed-word homogeneous points for group multiplication.
//!
//! Complete point arithmetic is shared by constant-time scalar multiplication
//! and public variable-time MSM. Timing-specific behavior belongs at entry and
//! table selection, outside the shared formulas.

use super::{BETA_SQUARED, PSI_X, PSI_Y, PSI2_X, Scalar, msm::Point, multiply_gls, multiply_glv};
#[cfg(test)]
use super::{G1, G2};
use crate::bls12381::{
    extension::Fp2 as RnsFp2,
    word::{self, Fp, Fp2},
};
use commonware_cryptography_vroom::word::{mul_by_3_fp2, mul_by_8_fp2};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[inline(always)]
fn fp_scale_three(value: &Fp) -> Fp {
    value.double().add(value)
}

#[inline(always)]
fn fp_scale_eight(value: &Fp) -> Fp {
    value.double().double().double()
}

#[inline(always)]
fn fp_mul_3b(value: &Fp) -> Fp {
    let four = value.double().double();
    four.add(&four.double())
}

#[inline(always)]
fn import_fp2(value: RnsFp2) -> Fp2 {
    [Fp::from_element(value.c0), Fp::from_element(value.c1)]
}

#[inline(always)]
fn export_fp2(value: &Fp2) -> RnsFp2 {
    RnsFp2 {
        c0: value[0].to_element(),
        c1: value[1].to_element(),
    }
}

#[inline(always)]
fn fp2_mul_3b(value: &Fp2) -> Fp2 {
    let value = word::fp2_mul_by_u_plus_one(value);
    let four = word::fp2_double(&word::fp2_double(&value));
    word::fp2_add(&four, &word::fp2_double(&four))
}

macro_rules! point {
    ($name:ident, $rns_field:ty, $field:ty, $zero:expr, $one:expr,
     $import:path, $export:path, $invert:path,
     $add:path, $sub:path, $mul:path, $square:path, $neg:path,
     $scale_three:path, $scale_eight:path, $mul_3b:path) => {
        #[derive(Clone, Copy, Debug)]
        pub(in crate::bls12381) struct $name {
            pub(in crate::bls12381) x: $field,
            pub(in crate::bls12381) y: $field,
            pub(in crate::bls12381) z: $field,
        }

        impl $name {
            pub(super) const IDENTITY: Self = Self {
                x: $zero,
                y: $one,
                z: $zero,
            };

            #[inline(always)]
            pub(super) const fn identity() -> Self {
                Self::IDENTITY
            }

            pub(super) fn is_identity(&self) -> bool {
                bool::from(self.z.ct_eq(&$zero))
            }

            pub(super) fn from_affine(x: $rns_field, y: $rns_field) -> Self {
                Self {
                    x: ($import)(x),
                    y: ($import)(y),
                    z: $one,
                }
            }

            pub(super) fn from_rns(point: super::homogeneous::$name) -> Self {
                Self {
                    x: ($import)(point.x.into()),
                    y: ($import)(point.y.into()),
                    z: ($import)(point.z.into()),
                }
            }

            pub(super) fn to_affine(self) -> Option<($rns_field, $rns_field)> {
                let inverse = ($invert)(&self.z)?;
                Some((
                    ($export)(&($mul)(&self.x, &inverse)),
                    ($export)(&($mul)(&self.y, &inverse)),
                ))
            }

            #[cfg(test)]
            pub(super) fn to_rns(self) -> super::homogeneous::$name {
                super::homogeneous::$name {
                    x: ($export)(&self.x).into(),
                    y: ($export)(&self.y).into(),
                    z: ($export)(&self.z).into(),
                }
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                let a_zero = self.z.ct_eq(&$zero);
                let b_zero = other.z.ct_eq(&$zero);
                let x_equal = ($mul)(&self.x, &other.z).ct_eq(&($mul)(&other.x, &self.z));
                let y_equal = ($mul)(&self.y, &other.z).ct_eq(&($mul)(&other.y, &self.z));
                (a_zero & b_zero) | (!a_zero & !b_zero & x_equal & y_equal)
            }
        }

        impl Point<()> for $name {
            // VROOM PointAdd, ec.hpp:176-225 (RCB Algorithm 7).
            #[inline(always)]
            fn add(&self, other: &Self, _context: &()) -> Self {
                let t3_4 = ($add)(&self.x, &self.y);
                let t3_14 = ($add)(&self.x, &self.z);
                let t4_9 = ($add)(&self.y, &self.z);
                let t4_5 = ($add)(&other.x, &other.y);
                let x3_10 = ($add)(&other.y, &other.z);
                let y3_15 = ($add)(&other.x, &other.z);

                let t0_1 = ($mul)(&self.x, &other.x);
                let t1_2 = ($mul)(&self.y, &other.y);
                let t2_3 = ($mul)(&self.z, &other.z);
                let t3_6 = ($mul)(&t3_4, &t4_5);
                let t5_11 = ($mul)(&t4_9, &x3_10);
                let x3_16 = ($mul)(&t3_14, &y3_15);

                let t4_7 = ($add)(&t0_1, &t1_2);
                let x3_12 = ($add)(&t1_2, &t2_3);
                let y3_17 = ($add)(&t0_1, &t2_3);
                let y3_18 = ($sub)(&x3_16, &y3_17);
                let x3_19 = ($add)(&t0_1, &t0_1);
                let t2_21 = ($mul_3b)(&t2_3);

                let t3_8 = ($sub)(&t3_6, &t4_7);
                let y3_24 = ($mul_3b)(&y3_18);
                let z3_22 = ($add)(&t1_2, &t2_21);
                let t1_23 = ($sub)(&t1_2, &t2_21);
                let t4_13 = ($sub)(&t5_11, &x3_12);
                let t0_20 = ($add)(&t0_1, &x3_19);

                let x3_25 = ($mul)(&t4_13, &($neg)(&y3_24));
                let t2_26 = ($mul)(&t1_23, &t3_8);
                let y3_28 = ($mul)(&t0_20, &y3_24);
                let t1_29 = ($mul)(&t1_23, &z3_22);
                let t0_31 = ($mul)(&t0_20, &t3_8);
                let z3_32 = ($mul)(&t4_13, &z3_22);
                Self {
                    x: ($add)(&t2_26, &x3_25),
                    y: ($add)(&t1_29, &y3_28),
                    z: ($add)(&z3_32, &t0_31),
                }
            }

            // VROOM PointDouble, ec.hpp:272-303 (RCB Algorithm 9).
            #[inline(always)]
            fn double(&self, _context: &()) -> Self {
                let yy = ($square)(&self.y);
                let zz = ($square)(&self.z);
                let xy = ($mul)(&self.y, &self.x);
                let yz = ($mul)(&self.y, &self.z);

                let eight_yy = ($scale_eight)(&yy);
                let b3_zz = ($mul_3b)(&zz);
                let yy_plus_b3_zz = ($add)(&yy, &b3_zz);
                let b9_zz = ($scale_three)(&b3_zz);
                let yy_minus_b9_zz = ($sub)(&yy, &b9_zz);
                let two_xy = ($add)(&xy, &xy);

                let y3_14 = ($mul)(&yy_minus_b9_zz, &yy_plus_b3_zz);
                let x = ($mul)(&yy_minus_b9_zz, &two_xy);
                let z = ($mul)(&eight_yy, &yz);
                let y = ($add)(&y3_14, &($mul)(&eight_yy, &b3_zz));
                Self { x, y, z }
            }

            #[inline(always)]
            fn neg(&self, _context: &()) -> Self {
                Self {
                    x: self.x,
                    y: ($neg)(&self.y),
                    z: self.z,
                }
            }
        }
    };
}

point!(
    G1Point,
    crate::bls12381::Fp,
    Fp,
    Fp::ZERO,
    Fp::ONE,
    Fp::from_element,
    Fp::to_element,
    Fp::invert,
    Fp::add,
    Fp::sub,
    Fp::mul,
    Fp::square,
    Fp::neg,
    fp_scale_three,
    fp_scale_eight,
    fp_mul_3b
);
point!(
    G2Point,
    RnsFp2,
    Fp2,
    [Fp::ZERO; 2],
    [Fp::ONE, Fp::ZERO],
    import_fp2,
    export_fp2,
    word::invert_fp2,
    word::fp2_add,
    word::fp2_sub,
    word::fp2_mul,
    word::fp2_square,
    word::fp2_neg,
    mul_by_3_fp2,
    mul_by_8_fp2,
    fp2_mul_3b
);

impl ConditionallySelectable for G1Point {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: Fp::conditional_select(&a.x, &b.x, choice),
            y: Fp::conditional_select(&a.y, &b.y, choice),
            z: Fp::conditional_select(&a.z, &b.z, choice),
        }
    }
}

impl G1Point {
    #[inline(always)]
    fn gather_window(table: &[Self; 16], digit: i8, identity: &Self) -> Self {
        let mask = (digit as i16) >> 7;
        let magnitude = ((digit as i16 ^ mask).wrapping_sub(mask)) as u8;
        let mut result = *identity;
        for (i, point) in table.iter().enumerate() {
            result = Self::conditional_select(&result, point, magnitude.ct_eq(&((i + 1) as u8)));
        }
        result.y = Fp::conditional_select(&result.y, &result.y.neg(), Choice::from(mask as u8 & 1));
        result
    }
}

pub(super) fn mul_g1(point: &G1Point, scalar: &Scalar) -> G1Point {
    let identity = G1Point::identity();
    let beta_squared = Fp::from_element(BETA_SQUARED);
    multiply_glv(
        #[inline(always)]
        || *point,
        scalar,
        &(),
        identity,
        #[inline(always)]
        |point| G1Point {
            x: point.x.mul(&beta_squared),
            y: point.y.neg(),
            z: point.z,
        },
        #[inline(always)]
        |table, digit| G1Point::gather_window(table, digit, &identity),
    )
}

impl ConditionallySelectable for G2Point {
    #[inline(always)]
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        let select = |a: &Fp2, b: &Fp2| {
            core::array::from_fn(|i| Fp::conditional_select(&a[i], &b[i], choice))
        };
        Self {
            x: select(&a.x, &b.x),
            y: select(&a.y, &b.y),
            z: select(&a.z, &b.z),
        }
    }
}

impl G2Point {
    #[inline(always)]
    fn gather_window(table: &[Self; 16], digit: i8, identity: &Self) -> Self {
        let mask = (digit as i16) >> 7;
        let magnitude = ((digit as i16 ^ mask).wrapping_sub(mask)) as u8;
        let mut result = *identity;
        for (i, point) in table.iter().enumerate() {
            result = Self::conditional_select(&result, point, magnitude.ct_eq(&((i + 1) as u8)));
        }
        let negative = word::fp2_neg(&result.y);
        for (value, negative) in result.y.iter_mut().zip(negative.iter()) {
            *value = Fp::conditional_select(value, negative, Choice::from(mask as u8 & 1));
        }
        result
    }

    #[inline(always)]
    fn psi(&self, coefficient_x: &Fp, coefficient_y: &Fp2) -> Self {
        Self {
            x: [self.x[1].mul(coefficient_x), self.x[0].mul(coefficient_x)],
            y: word::fp2_mul(&[self.y[0], self.y[1].neg()], coefficient_y),
            z: [self.z[0], self.z[1].neg()],
        }
    }

    #[inline(always)]
    fn psi2(&self, coefficient: &Fp) -> Self {
        Self {
            x: [self.x[0].mul(coefficient), self.x[1].mul(coefficient)],
            y: word::fp2_neg(&self.y),
            z: self.z,
        }
    }
}

pub(super) fn mul_g2(point: &G2Point, scalar: &Scalar) -> G2Point {
    let identity = G2Point::identity();
    let psi_x = Fp::from_element(PSI_X);
    let psi_y = import_fp2(PSI_Y);
    let psi2_x = Fp::from_element(PSI2_X);
    multiply_gls(
        #[inline(always)]
        || *point,
        scalar,
        &(),
        identity,
        #[inline(always)]
        |table, i, digit| {
            let point = G2Point::gather_window(table, digit, &identity);
            match i {
                0 => point,
                1 => point.psi(&psi_x, &psi_y).neg(&()),
                2 => point.psi2(&psi2_x),
                3 => point.psi2(&psi2_x).psi(&psi_x, &psi_y).neg(&()),
                _ => unreachable!(),
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::{
        Fp as RnsFp,
        extension::Fp2 as RnsFp2,
        group::msm::{self, Point},
    };
    use blst::{
        BLST_ERROR, blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_compress,
        blst_p1_from_affine, blst_p1_uncompress, blst_p2, blst_p2_add_or_double, blst_p2_affine,
        blst_p2_compress, blst_p2_from_affine, blst_p2_mult, blst_p2_uncompress,
    };
    use commonware_cryptography_vroom::{Backend, Bls12381, WithBackend, rns::Ring, with_backend};
    use subtle::{Choice, ConditionallySelectable};

    fn homogeneous_g1(point: G1, scale: RnsFp) -> G1 {
        let scale = Fp::from_element(scale);
        G1(G1Point {
            x: point.0.x.mul(&scale),
            y: point.0.y.mul(&scale),
            z: point.0.z.mul(&scale),
        })
    }

    fn homogeneous_g2(point: G2, scale: RnsFp2) -> G2 {
        let scale = import_fp2(scale);
        G2(G2Point {
            x: word::fp2_mul(&point.0.x, &scale),
            y: word::fp2_mul(&point.0.y, &scale),
            z: word::fp2_mul(&point.0.z, &scale),
        })
    }

    fn g1_from_homogeneous(x: RnsFp, y: RnsFp, z: RnsFp) -> G1 {
        G1(G1Point {
            x: Fp::from_element(x),
            y: Fp::from_element(y),
            z: Fp::from_element(z),
        })
    }

    fn g2_from_homogeneous(x: RnsFp2, y: RnsFp2, z: RnsFp2) -> G2 {
        G2(G2Point {
            x: import_fp2(x),
            y: import_fp2(y),
            z: import_fp2(z),
        })
    }

    macro_rules! rns_operations {
        ($function:ident, $point:ident) => {
            fn $function(left: &$point, right: &$point) -> ($point, $point, $point) {
                struct Check<'a>(&'a $point, &'a $point);
                impl WithBackend for Check<'_> {
                    type Output = ($point, $point, $point);

                    fn call<B: Backend>(self, backend: B) -> Self::Output {
                        let ring = Ring::<Bls12381, B>::new(backend);
                        let left = self.0.to_rns();
                        let right = self.1.to_rns();
                        (
                            $point::from_rns(Point::add(&left, &right, &ring)),
                            $point::from_rns(Point::double(&left, &ring)),
                            $point::from_rns(Point::neg(&left, &ring)),
                        )
                    }
                }
                with_backend(Check(left, right))
            }
        };
    }

    rns_operations!(g1_rns_operations, G1Point);
    rns_operations!(g2_rns_operations, G2Point);

    fn assert_g1_native(point: &G1Point) {
        assert!(
            point.x != Fp::ZERO || point.y != Fp::ZERO || point.z != Fp::ZERO,
            "native G1 point must not be the zero triple"
        );
        let z3 = point.z.square().mul(&point.z);
        let bz3 = Fp::ONE.double().double().mul(&z3);
        assert_eq!(
            point.y.square().mul(&point.z),
            point.x.square().mul(&point.x).add(&bz3)
        );
    }

    fn assert_g2_native(point: &G2Point) {
        assert!(
            point.x != [Fp::ZERO; 2] || point.y != [Fp::ZERO; 2] || point.z != [Fp::ZERO; 2],
            "native G2 point must not be the zero triple"
        );
        let z3 = word::fp2_mul(&word::fp2_square(&point.z), &point.z);
        let bz3 = word::fp2_double(&word::fp2_double(&word::fp2_mul_by_u_plus_one(&z3)));
        assert_eq!(
            word::fp2_mul(&word::fp2_square(&point.y), &point.z),
            word::fp2_add(&word::fp2_mul(&word::fp2_square(&point.x), &point.x), &bz3,)
        );
    }

    fn assert_g1_word_coordinates(actual: &G1Point, expected: &G1Point) {
        assert_eq!(actual.x, expected.x);
        assert_eq!(actual.y, expected.y);
        assert_eq!(actual.z, expected.z);
    }

    fn assert_g2_word_coordinates(actual: &G2Point, expected: &G2Point) {
        assert_eq!(actual.x[0], expected.x[0]);
        assert_eq!(actual.x[1], expected.x[1]);
        assert_eq!(actual.y[0], expected.y[0]);
        assert_eq!(actual.y[1], expected.y[1]);
        assert_eq!(actual.z[0], expected.z[0]);
        assert_eq!(actual.z[1], expected.z[1]);
    }

    fn oracle_g1_add(left: &G1, right: &G1) -> [u8; 48] {
        let mut left_affine = blst_p1_affine::default();
        let mut right_affine = blst_p1_affine::default();
        let mut left_point = blst_p1::default();
        let mut right_point = blst_p1::default();
        let mut sum = blst_p1::default();
        let mut bytes = [0; 48];
        // SAFETY: All buffers have blst's exact G1 sizes. The Commonware points
        // provide valid canonical encodings, and each output is initialized before use.
        unsafe {
            assert_eq!(
                blst_p1_uncompress(&mut left_affine, left.to_bytes().as_ptr()),
                BLST_ERROR::BLST_SUCCESS
            );
            assert_eq!(
                blst_p1_uncompress(&mut right_affine, right.to_bytes().as_ptr()),
                BLST_ERROR::BLST_SUCCESS
            );
            blst_p1_from_affine(&mut left_point, &left_affine);
            blst_p1_from_affine(&mut right_point, &right_affine);
            blst_p1_add_or_double(&mut sum, &left_point, &right_point);
            blst_p1_compress(bytes.as_mut_ptr(), &sum);
        }
        bytes
    }

    fn oracle_g2_point(point: &G2) -> blst_p2 {
        let mut affine = blst_p2_affine::default();
        let mut result = blst_p2::default();
        // SAFETY: The input has blst's exact compressed G2 size and comes from a
        // valid Commonware point. A successful decode initializes the affine point.
        unsafe {
            assert_eq!(
                blst_p2_uncompress(&mut affine, point.to_bytes().as_ptr()),
                BLST_ERROR::BLST_SUCCESS
            );
            blst_p2_from_affine(&mut result, &affine);
        }
        result
    }

    fn oracle_g2_compress(point: &blst_p2) -> [u8; 96] {
        let mut bytes = [0; 96];
        // SAFETY: The output has blst's exact compressed G2 size and point is initialized.
        unsafe { blst_p2_compress(bytes.as_mut_ptr(), point) };
        bytes
    }

    fn oracle_g2_add(left: &G2, right: &G2) -> [u8; 96] {
        let left = oracle_g2_point(left);
        let right = oracle_g2_point(right);
        let mut sum = blst_p2::default();
        // SAFETY: Both inputs are initialized blst G2 points and output is writable.
        unsafe {
            blst_p2_add_or_double(&mut sum, &left, &right);
        }
        oracle_g2_compress(&sum)
    }

    fn oracle_g2_mul(point: &G2, scalar: &Scalar) -> [u8; 96] {
        let point = oracle_g2_point(point);
        let mut scalar_bytes = scalar.to_bytes();
        scalar_bytes.reverse();
        let mut product = blst_p2::default();
        // SAFETY: The scalar has 256 readable bits, point is initialized, and output is writable.
        unsafe { blst_p2_mult(&mut product, &point, scalar_bytes.as_ptr(), 256) };
        oracle_g2_compress(&product)
    }

    fn assert_g1_operation(left: G1, right: G1) {
        assert_g1_native(&left.0);
        assert_g1_native(&right.0);

        let actual_word = <G1Point as Point<()>>::add(&left.0, &right.0, &());
        assert_g1_native(&actual_word);
        let (expected_word, expected_doubled, expected_negated) =
            g1_rns_operations(&left.0, &right.0);
        assert_g1_word_coordinates(&actual_word, &expected_word);
        let actual = G1(actual_word);
        let expected = left.add(&right);
        assert_eq!(actual, expected);
        assert_eq!(actual.to_bytes(), expected.to_bytes());
        assert_eq!(actual.to_bytes(), oracle_g1_add(&left, &right));

        let doubled_word = <G1Point as Point<()>>::double(&left.0, &());
        assert_g1_native(&doubled_word);
        assert_g1_word_coordinates(&doubled_word, &expected_doubled);
        let doubled = G1(doubled_word);
        assert_eq!(doubled, left.double());
        assert_eq!(doubled.to_bytes(), oracle_g1_add(&left, &left));

        let negated_word = <G1Point as Point<()>>::neg(&left.0, &());
        assert_g1_native(&negated_word);
        assert_g1_word_coordinates(&negated_word, &expected_negated);
        assert_eq!(G1(negated_word), left.neg());
    }

    fn assert_g2_operation(left: G2, right: G2) {
        assert_g2_native(&left.0);
        assert_g2_native(&right.0);

        let actual_word = <G2Point as Point<()>>::add(&left.0, &right.0, &());
        assert_g2_native(&actual_word);
        let (expected_word, expected_doubled, expected_negated) =
            g2_rns_operations(&left.0, &right.0);
        assert_g2_word_coordinates(&actual_word, &expected_word);
        let actual = G2(actual_word);
        let expected = left.add(&right);
        assert_eq!(actual, expected);
        assert_eq!(actual.to_bytes(), expected.to_bytes());
        assert_eq!(actual.to_bytes(), oracle_g2_add(&left, &right));

        let doubled_word = <G2Point as Point<()>>::double(&left.0, &());
        assert_g2_native(&doubled_word);
        assert_g2_word_coordinates(&doubled_word, &expected_doubled);
        let doubled = G2(doubled_word);
        assert_eq!(doubled, left.double());
        assert_eq!(doubled.to_bytes(), oracle_g2_add(&left, &left));

        let negated_word = <G2Point as Point<()>>::neg(&left.0, &());
        assert_g2_native(&negated_word);
        assert_g2_word_coordinates(&negated_word, &expected_negated);
        assert_eq!(G2(negated_word), left.neg());
    }

    #[test]
    fn g1_word_points_match_rns_and_blst() {
        let generator = homogeneous_g1(G1::generator(), RnsFp::from_u64(7));
        let other = homogeneous_g1(G1::generator().double(), RnsFp::from_u64(13));
        let noncanonical_identity =
            g1_from_homogeneous(RnsFp::ZERO, RnsFp::from_u64(19), RnsFp::ZERO);
        for pair in [
            (generator, other),
            (generator, generator),
            (generator, generator.neg()),
            (generator, G1::IDENTITY),
            (noncanonical_identity, generator),
        ] {
            assert_g1_operation(pair.0, pair.1);
        }
    }

    #[test]
    fn g1_selection_preserves_native_coordinates() {
        let points = [
            homogeneous_g1(G1::generator(), RnsFp::from_u64(7)),
            homogeneous_g1(G1::generator().double(), RnsFp::from_u64(13)),
        ];
        let words = points.map(|point| point.0);
        for word in words {
            assert_g1_native(&word);
        }

        for (choice, expected) in [(0, words[0]), (1, words[1])] {
            let actual = G1Point::conditional_select(&words[0], &words[1], Choice::from(choice));
            assert_g1_word_coordinates(&actual, &expected);
            assert_g1_native(&actual);
        }

        let identities = [
            g1_from_homogeneous(RnsFp::ZERO, RnsFp::from_u64(17), RnsFp::ZERO),
            g1_from_homogeneous(RnsFp::ZERO, RnsFp::from_u64(23), RnsFp::ZERO),
        ];
        for (choice, expected) in [(0, identities[0].0), (1, identities[1].0)] {
            let actual = G1Point::conditional_select(
                &identities[0].0,
                &identities[1].0,
                Choice::from(choice),
            );
            assert_g1_word_coordinates(&actual, &expected);
            assert_g1_native(&actual);
            assert!(G1(actual).is_identity());
        }
    }

    #[test]
    fn g1_window_gather_matches_every_signed_digit() {
        let identity = G1Point::identity();
        let base = G1::generator().0;
        let mut table = [identity; 16];
        msm::precompute_window(&base, &mut table, &());

        for digit in -16i8..=16 {
            let actual = G1Point::gather_window(&table, digit, &identity);
            assert_g1_native(&actual);
            let expected_word = match digit.cmp(&0) {
                core::cmp::Ordering::Less => {
                    <G1Point as Point<()>>::neg(&table[digit.unsigned_abs() as usize - 1], &())
                }
                core::cmp::Ordering::Equal => identity,
                core::cmp::Ordering::Greater => table[digit as usize - 1],
            };
            assert_g1_word_coordinates(&actual, &expected_word);

            let magnitude = digit.unsigned_abs() as u64;
            let expected = G1::generator().mul_words_jacobian(&[magnitude]);
            let expected = if digit < 0 { expected.neg() } else { expected };
            assert_eq!(G1(actual), expected, "digit {digit}");
            assert_eq!(G1(actual).to_bytes(), expected.to_bytes(), "digit {digit}");
        }
    }

    #[test]
    fn g2_word_points_match_rns_and_blst() {
        let generator = homogeneous_g2(
            G2::generator(),
            RnsFp2 {
                c0: RnsFp::from_u64(11),
                c1: RnsFp::ONE,
            },
        );
        let other = homogeneous_g2(
            G2::generator().double(),
            RnsFp2 {
                c0: RnsFp::from_u64(17),
                c1: RnsFp::from_u64(3),
            },
        );
        let noncanonical_identity = g2_from_homogeneous(
            RnsFp2::ZERO,
            RnsFp2 {
                c0: RnsFp::from_u64(31),
                c1: RnsFp::from_u64(37),
            },
            RnsFp2::ZERO,
        );
        for pair in [
            (generator, other),
            (generator, generator),
            (generator, generator.neg()),
            (generator, G2::IDENTITY),
            (noncanonical_identity, generator),
        ] {
            assert_g2_operation(pair.0, pair.1);
        }
    }

    #[test]
    fn g2_selection_preserves_all_native_coordinates() {
        let points = [
            homogeneous_g2(
                G2::generator(),
                RnsFp2 {
                    c0: RnsFp::from_u64(7),
                    c1: RnsFp::ONE,
                },
            ),
            homogeneous_g2(
                G2::generator().double(),
                RnsFp2 {
                    c0: RnsFp::from_u64(13),
                    c1: RnsFp::from_u64(5),
                },
            ),
            homogeneous_g2(
                G2::generator(),
                RnsFp2 {
                    c0: RnsFp::ZERO,
                    c1: RnsFp::ONE,
                },
            ),
        ];
        let words = points.map(|point| point.0);
        for word in words {
            assert_g2_native(&word);
        }

        for (choice, expected) in [(0, words[0]), (1, words[1])] {
            let actual = G2Point::conditional_select(&words[0], &words[1], Choice::from(choice));
            assert_g2_word_coordinates(&actual, &expected);
            assert_g2_native(&actual);
        }

        let identities = [
            g2_from_homogeneous(
                RnsFp2::ZERO,
                RnsFp2 {
                    c0: RnsFp::from_u64(17),
                    c1: RnsFp::from_u64(19),
                },
                RnsFp2::ZERO,
            ),
            g2_from_homogeneous(
                RnsFp2::ZERO,
                RnsFp2 {
                    c0: RnsFp::from_u64(23),
                    c1: RnsFp::from_u64(29),
                },
                RnsFp2::ZERO,
            ),
        ];
        for (choice, expected) in [(0, identities[0].0), (1, identities[1].0)] {
            let actual = G2Point::conditional_select(
                &identities[0].0,
                &identities[1].0,
                Choice::from(choice),
            );
            assert_g2_word_coordinates(&actual, &expected);
            assert_g2_native(&actual);
            assert!(G2(actual).is_identity());
        }
    }

    #[test]
    fn g2_window_gather_matches_every_signed_digit() {
        let identity = G2Point::identity();
        let base = G2::generator().0;
        let mut table = [identity; 16];
        msm::precompute_window(&base, &mut table, &());

        for digit in -16i8..=16 {
            let actual = G2Point::gather_window(&table, digit, &identity);
            assert_g2_native(&actual);
            let expected_word = match digit.cmp(&0) {
                core::cmp::Ordering::Less => {
                    <G2Point as Point<()>>::neg(&table[digit.unsigned_abs() as usize - 1], &())
                }
                core::cmp::Ordering::Equal => identity,
                core::cmp::Ordering::Greater => table[digit as usize - 1],
            };
            assert_g2_word_coordinates(&actual, &expected_word);

            let magnitude = digit.unsigned_abs() as u64;
            let expected = G2::generator().mul_words_jacobian(&[magnitude]);
            let expected = if digit < 0 { expected.neg() } else { expected };
            assert_eq!(G2(actual), expected, "digit {digit}");
            assert_eq!(G2(actual).to_bytes(), expected.to_bytes(), "digit {digit}");
        }
    }

    #[test]
    fn g2_word_psi_maps_match_exact_coordinates_and_rns() {
        let psi_x = Fp::from_element(super::super::PSI_X);
        let psi_y = import_fp2(super::super::PSI_Y);
        let psi2_x = Fp::from_element(super::super::PSI2_X);
        let scaled = homogeneous_g2(
            G2::generator().double(),
            RnsFp2 {
                c0: RnsFp::from_u64(7),
                c1: RnsFp::from_u64(3),
            },
        );

        for point in [G2::IDENTITY, G2::generator(), G2::generator().neg(), scaled] {
            let word_point = point.0;
            assert_g2_native(&word_point);
            let actual_psi = word_point.psi(&psi_x, &psi_y);
            assert_g2_native(&actual_psi);
            let expected_psi = G2Point {
                x: [word_point.x[1].mul(&psi_x), word_point.x[0].mul(&psi_x)],
                y: word::fp2_mul(&[word_point.y[0], word_point.y[1].neg()], &psi_y),
                z: [word_point.z[0], word_point.z[1].neg()],
            };
            assert_g2_word_coordinates(&actual_psi, &expected_psi);
            assert_eq!(G2(actual_psi), point.psi());
            assert_eq!(G2(actual_psi).to_bytes(), point.psi().to_bytes());

            let actual_psi2 = word_point.psi2(&psi2_x);
            assert_g2_native(&actual_psi2);
            let expected_psi2 = G2Point {
                x: [word_point.x[0].mul(&psi2_x), word_point.x[1].mul(&psi2_x)],
                y: [word_point.y[0].neg(), word_point.y[1].neg()],
                z: word_point.z,
            };
            assert_g2_word_coordinates(&actual_psi2, &expected_psi2);
            assert_eq!(G2(actual_psi2), point.psi2());
            assert_eq!(G2(actual_psi2).to_bytes(), point.psi2().to_bytes());
            assert_g2_word_coordinates(&actual_psi2, &actual_psi.psi(&psi_x, &psi_y));
        }
    }

    #[test]
    fn g2_word_scalar_multiplication_matches_blst_and_chains() {
        let a = 0xd201_0000_0001_0000;
        let radix = Scalar::from_u64(a);
        let radix_squared = radix.mul(&radix);
        let radix_cubed = radix_squared.mul(&radix);
        let mut bit_254 = [0; 32];
        bit_254[0] = 1 << 6;
        let scalars = [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::ONE.neg(),
            Scalar::from_u64(a - 1),
            radix,
            Scalar::from_u64(a + 1),
            radix_squared.sub(&Scalar::ONE),
            radix_squared,
            radix_squared.add(&Scalar::ONE),
            radix_cubed.sub(&Scalar::ONE),
            radix_cubed,
            radix_cubed.add(&Scalar::ONE),
            Scalar::from_u64(u64::MAX),
            Scalar::from_bytes(&bit_254).expect("bit 254 is below the scalar order"),
            Scalar::from_wide_bytes(&[0x55; 64]),
            Scalar::from_wide_bytes(&[0xaa; 64]),
        ];
        let point = homogeneous_g2(
            G2::generator().double(),
            RnsFp2 {
                c0: RnsFp::from_u64(11),
                c1: RnsFp::from_u64(7),
            },
        );
        let chain_scalar = Scalar::from_u64(17);

        for scalar in scalars {
            let actual = G2(mul_g2(&point.0, &scalar));
            assert_g2_native(&actual.0);
            assert_eq!(actual.to_bytes(), oracle_g2_mul(&point, &scalar));
            assert_eq!(G2::from_bytes(&actual.to_bytes()), Some(actual));
            let identity = G2(mul_g2(&G2::IDENTITY.0, &scalar));
            assert_g2_native(&identity.0);
            assert_eq!(identity, G2::IDENTITY);

            let chained = G2(mul_g2(&actual.0, &chain_scalar));
            assert_g2_native(&chained.0);
            assert_eq!(chained.to_bytes(), oracle_g2_mul(&actual, &chain_scalar));
            assert_eq!(chained, G2(mul_g2(&point.0, &scalar.mul(&chain_scalar))));
        }
    }

    macro_rules! public_closure {
        ($test:ident, $group:ident, $valid:ident, $rescale:ident, $identity:expr, $scales:expr) => {
            #[test]
            fn $test() {
                const IDENTITY: $group = $group::identity();
                let generator = $group::generator();
                let hashed = $group::hash_to_curve(b"resident point", b"COMMONWARE_NATIVE_TEST");
                let decoded = $group::from_bytes(&hashed.to_bytes()).unwrap();
                let scalar = Scalar::from_wide_bytes(&[0x55; 64]);
                for point in [IDENTITY, $identity, generator, generator.neg(), hashed, decoded] {
                    $valid(&point.0);
                    for result in [point.double(), point.neg(), point.mul(&scalar)] {
                        $valid(&result.0);
                    }
                    assert_eq!(point.double(), point.double_jacobian());
                    let bytes = scalar.to_bytes();
                    let words: [u64; 4] = core::array::from_fn(|i| {
                        u64::from_be_bytes(bytes[24 - 8 * i..32 - 8 * i].try_into().unwrap())
                    });
                    assert_eq!(point.mul(&scalar), point.mul_words_jacobian(&words));
                    for scale in $scales {
                        let scaled = $rescale(point, scale);
                        $valid(&scaled.0);
                        assert_eq!(scaled, point);
                        assert_eq!(scaled.to_bytes(), point.to_bytes());
                        let sum = scaled.add(&generator);
                        $valid(&sum.0);
                        assert_eq!(sum, point.add_jacobian(&generator));
                        assert_eq!(scaled.mul(&scalar), point.mul(&scalar));
                    }
                    let mut live = point;
                    for _ in 0..3 {
                        let zero = live.sub(&live);
                        $valid(&zero.0);
                        assert!(zero.is_identity());
                        live = zero.add(&generator);
                        $valid(&live.0);
                        assert_eq!(live, generator);
                    }
                    for terms in [0, 2, 32] {
                        let points: alloc::vec::Vec<_> = (0..terms)
                            .map(|i| if i % 2 == 0 { point } else { point.neg() })
                            .collect();
                        for coefficient in [Scalar::ZERO, Scalar::ONE] {
                            let scalars = alloc::vec![coefficient; terms];
                            let zero = $group::msm_vartime(&points, &scalars).unwrap();
                            $valid(&zero.0);
                            assert!(zero.is_identity());
                            assert_eq!(zero.add(&generator), generator);
                        }
                    }
                    let zero = point.mul(&Scalar::ZERO);
                    $valid(&zero.0);
                    assert!(zero.is_identity());
                    assert_eq!(zero.add(&generator), generator);
                }
            }
        };
    }

    public_closure!(
        g1_public_operations_preserve_native_domain,
        G1,
        assert_g1_native,
        homogeneous_g1,
        g1_from_homogeneous(RnsFp::ZERO, RnsFp::from_u64(7), RnsFp::ZERO),
        [RnsFp::ONE, RnsFp::from_u64(7), RnsFp::ONE.neg()]
    );
    public_closure!(
        g2_public_operations_preserve_native_domain,
        G2,
        assert_g2_native,
        homogeneous_g2,
        g2_from_homogeneous(RnsFp2::ZERO, RnsFp2::from_u64(7), RnsFp2::ZERO),
        [
            RnsFp2::ONE,
            RnsFp2 {
                c0: RnsFp::from_u64(2),
                c1: RnsFp::ONE
            },
            RnsFp2 {
                c0: RnsFp::ZERO,
                c1: RnsFp::from_u64(7)
            },
        ]
    );
}

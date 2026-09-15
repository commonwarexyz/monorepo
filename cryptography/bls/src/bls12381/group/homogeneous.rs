// Adapted from VROOM src/ec.hpp and src/scalar_mult.hpp.
// Copyright 2026 Simon Langowski
// SPDX-License-Identifier: MIT

//! Homogeneous points for complete multiplication loops.
//!
//! Both coordinate fields exclude rational 2-torsion, so the reference addition
//! covers the full curves. Jacobian entry normalizes every Z = 0 representative
//! to the nonzero homogeneous identity before these formulas are used.
//!
//! Debug builds retain call boundaries around coordinate conversions and point
//! formulas to keep their temporary field values in separate stack frames.

use super::{G1, G2, PSI_X, PSI_Y, PSI2_X, msm};
use crate::bls12381::{
    Fp,
    extension::{
        Fp2,
        bounded::{Fp2Ring, Fp2Standard},
    },
    scalar::X_SQUARED,
};
use cfg_if::cfg_if;
use commonware_cryptography_vroom::{
    Backend, Bls12381, WithBackend,
    rns::{Ring, Standard},
};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

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
pub(super) struct Add<'a, G>(pub &'a G, pub &'a G);
pub(super) struct Equal<'a, P>(pub &'a P, pub &'a P);
pub(super) struct InSubgroup<'a, P>(pub &'a P);
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
pub(super) struct Msm<'a, G, S>(pub &'a [G], pub &'a [S]);

const G1_HASH_COFACTOR: [u64; 1] = [0xd201_0000_0001_0001];

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
impl WithBackend for Msm<'_, G1, msm::EncodedScalar> {
    type Output = G1;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> G1 {
        let ring = Ring::<Bls12381, B>::new(backend);
        let identity = G1Point::identity();
        let (terms, bits) = msm::prepare_terms!(
            self.0, self.1, scalar => *scalar,
            point => G1Point::from_jacobian(point, &ring)
        );
        msm::compute(terms, bits, &ring, identity).to_jacobian(&ring)
    }
}

macro_rules! point {
    ($name:ident, $group:ident, $raw:ident, $words:ident, $field:ty, $standard:ty,
     words[$($words_cfg:meta),*],
     $base:ident, $ring:ident = $ring_value:expr, $value:ident => $mul_3b:expr) => {
        #[derive(Clone, Copy)]
        #[cfg_attr(target_arch = "x86_64", repr(align(64)))]
        pub(super) struct $name {
            pub(super) x: $standard,
            pub(super) y: $standard,
            pub(super) z: $standard,
        }

        impl $name {
            pub(super) fn from_affine(x: $field, y: $field) -> Self {
                Self {
                    x: x.into(),
                    y: y.into(),
                    z: <$field>::ONE.into(),
                }
            }

            #[inline(always)]
            fn identity() -> Self {
                Self {
                    x: <$field>::ZERO.into(),
                    y: <$field>::ONE.into(),
                    z: <$field>::ZERO.into(),
                }
            }

            #[inline(always)]
            fn select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self {
                    x: <$standard>::conditional_select(&a.x, &b.x, choice),
                    y: <$standard>::conditional_select(&a.y, &b.y, choice),
                    z: <$standard>::conditional_select(&a.z, &b.z, choice),
                }
            }

            #[cfg(any(test, not(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))))]
            #[cfg_attr(not(debug_assertions), inline(always))]
            pub(super) fn from_jacobian<B: Backend>(
                point: &$group,
                $base: &Ring<Bls12381, B>,
            ) -> Self {
                cfg_if! {
                    if #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))] {
                        let _ = $base;
                        point.0.to_rns()
                    } else {
                        let $ring = $ring_value;
                        let x: $standard = point.x.into();
                        let y: $standard = point.y.into();
                        let z: $standard = point.z.into();
                        let zl = $ring.prep_left(z);
                        let [xz, zz] = $ring
                            .batch_reduce_expand(&[$ring.ready::<800>(zl * x), $ring.ready::<800>(zl * z)]);
                        let [zzz] = $ring.batch_reduce_expand(&[$ring.ready::<800>(zl * zz)]);
                        let result = Self { x: xz, y, z: zzz };
                        Self::select(&result, &Self::identity(), $ring.is_zero(z))
                    }
                }
            }

            #[cfg(any(test, not(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))))]
            #[cfg_attr(not(debug_assertions), inline(always))]
            pub(super) fn to_jacobian<B: Backend>(self, $base: &Ring<Bls12381, B>) -> $group {
                cfg_if! {
                    if #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))] {
                        let _ = $base;
                        $group(super::word::$name::from_rns(self))
                    } else {
                        let $ring = $ring_value;
                        let zl = $ring.prep_left(self.z);
                        let [zz] = $ring.batch_reduce_expand(&[$ring.ready::<800>(zl * self.z)]);
                        let [x, y] = $ring.batch_reduce_expand(&[
                            $ring.ready::<800>(zl * self.x),
                            $ring.ready::<800>($ring.prep_left(self.y) * zz),
                        ]);
                        $group {
                            x: x.into(),
                            y: y.into(),
                            z: self.z.into(),
                        }
                    }
                }
            }

            #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))]
            #[cfg_attr(not(debug_assertions), inline(always))]
            pub(super) fn from_raw_jacobian<B: Backend>(
                point: &crate::bls12381::hash::$raw,
                $base: &Ring<Bls12381, B>,
            ) -> Self {
                let $ring = $ring_value;
                let x = point.x;
                let y = point.y;
                let z = point.z;
                let zl = $ring.prep_left(z);
                let [xz, zz] = $ring
                    .batch_reduce_expand(&[$ring.ready::<800>(zl * x), $ring.ready::<800>(zl * z)]);
                let [zzz] = $ring.batch_reduce_expand(&[$ring.ready::<800>(zl * zz)]);
                let result = Self { x: xz, y, z: zzz };
                Self::select(&result, &Self::identity(), $ring.is_zero(z))
            }

            // VROOM PointAdd, ec.hpp:176-225 (RCB Algorithm 7).
            #[cfg_attr(not(debug_assertions), inline(always))]
            pub(super) fn add<B: Backend>(&self, other: &Self, $base: &Ring<Bls12381, B>) -> Self {
                let $ring = $ring_value;
                let t3_4 = self.x + self.y;
                let t3_14 = self.x + self.z;
                let t4_9 = self.y + self.z;
                let t4_5 = other.x + other.y;
                let x3_10 = other.y + other.z;
                let y3_15 = other.x + other.z;

                let [t0_1, t1_2, t2_3, t3_6, t5_11, x3_16] = $ring.batch_reduce_expand(&[
                    $ring.ready::<800>($ring.prep_left(self.x) * other.x),
                    $ring.ready::<800>($ring.prep_left(self.y) * other.y),
                    $ring.ready::<800>($ring.prep_left(self.z) * other.z),
                    $ring.ready::<800>($ring.prep_left(t3_4) * $ring.prep(t4_5)),
                    $ring.ready::<800>($ring.prep_left(t4_9) * $ring.prep(x3_10)),
                    $ring.ready::<800>($ring.prep_left(t3_14) * $ring.prep(y3_15)),
                ]);
                let t4_7 = t0_1 + t1_2;
                let x3_12 = t1_2 + t2_3;
                let y3_17 = t0_1 + t2_3;
                let y3_18 = $ring.prep(x3_16 - y3_17);
                let x3_19 = t0_1 + t0_1;
                let $value = t2_3;
                let t2_21 = $mul_3b;

                let t3_8 = $ring.prep(t3_6 - t4_7);
                let $value = y3_18;
                let y3_24 = $ring.prep($mul_3b);
                let z3_22 = $ring.prep(t1_2 + t2_21);
                let t1_23 = $ring.prep_left(t1_2 - t2_21);
                let t4_13 = $ring.prep_left(t5_11 - x3_12);
                let t0_20 = $ring.prep_left(t0_1 + x3_19);

                let x3_25 = t4_13 * $ring.negate(y3_24);
                let t2_26 = t1_23 * t3_8;
                let y3_28 = t0_20 * y3_24;
                let t1_29 = t1_23 * z3_22;
                let t0_31 = t0_20 * t3_8;
                let z3_32 = t4_13 * z3_22;
                let [x, y, z] = $ring.batch_reduce_expand(&[
                    $ring.ready::<800>(t2_26 + x3_25),
                    $ring.ready::<800>(t1_29 + y3_28),
                    $ring.ready::<800>(z3_32 + t0_31),
                ]);
                Self { x, y, z }
            }

            // VROOM PointDouble, ec.hpp:272-303 (RCB Algorithm 9).
            #[cfg_attr(not(debug_assertions), inline(always))]
            pub(super) fn double<B: Backend>(&self, $base: &Ring<Bls12381, B>) -> Self {
                let $ring = $ring_value;
                let py = $ring.prep_left(self.y);
                let pz = $ring.prep_left(self.z);
                let [yy, zz, xy, yz] = $ring.batch_reduce_expand(&[
                    $ring.ready::<800>(py * self.y),
                    $ring.ready::<800>(pz * self.z),
                    $ring.ready::<800>(py * self.x),
                    $ring.ready::<800>(py * self.z),
                ]);

                let eight_yy = $ring.prep_left(yy.scale::<8>());
                let $value = zz;
                let b3_zz = $ring.prep($mul_3b);
                let yy_plus_b3_zz = $ring.prep(yy + b3_zz);
                let b9_zz = b3_zz.scale::<3>();
                let yy_minus_b9_zz = $ring.prep_left(yy - b9_zz);
                let two_xy = $ring.prep(xy.scale::<2>());

                let y3_14 = yy_minus_b9_zz * yy_plus_b3_zz;
                let x3_18 = yy_minus_b9_zz * two_xy;
                let z3_10 = eight_yy * yz;
                let y3_15 = y3_14 + eight_yy * b3_zz;
                let [x, y, z] = $ring.batch_reduce_expand(&[
                    $ring.ready::<800>(x3_18),
                    $ring.ready::<800>(y3_15),
                    $ring.ready::<800>(z3_10),
                ]);
                Self { x, y, z }
            }

            #[inline(always)]
            fn neg<B: Backend>(&self, $base: &Ring<Bls12381, B>) -> Self {
                let $ring = $ring_value;
                Self {
                    x: self.x,
                    y: $ring.standard_negate(self.y),
                    z: self.z,
                }
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
            #[inline(always)]
            pub(super) fn gather_window<B: Backend>(
                table: &[Self; 16],
                digit: i8,
                $base: &Ring<Bls12381, B>,
            ) -> Self {
                let $ring = $ring_value;
                let mask = (digit as i16) >> 7;
                let magnitude = ((digit as i16 ^ mask).wrapping_sub(mask)) as u8;
                let mut result = Self::identity();
                for (i, point) in table.iter().enumerate() {
                    result = Self::select(&result, point, magnitude.ct_eq(&((i + 1) as u8)));
                }
                result.y = <$standard>::conditional_select(
                    &result.y,
                    &$ring.standard_negate(result.y),
                    Choice::from(mask as u8 & 1),
                );
                result
            }

            $(#[$words_cfg])*
            #[inline(always)]
            fn mul_words<B: Backend>(&self, words: &[u64], ring: &Ring<Bls12381, B>) -> Self {
                let mut result = Self::identity();
                for word in words.iter().rev() {
                    for bit in (0..64).rev() {
                        result = result.double(ring);
                        if (word >> bit) & 1 != 0 {
                            result = result.add(self, ring);
                        }
                    }
                }
                result
            }
        }

        impl<B: Backend> msm::Point<Ring<Bls12381, B>> for $name {
            #[inline(always)]
            fn add(&self, other: &Self, context: &Ring<Bls12381, B>) -> Self {
                $name::add(self, other, context)
            }

            #[inline(always)]
            fn double(&self, context: &Ring<Bls12381, B>) -> Self {
                $name::double(self, context)
            }

            #[inline(always)]
            fn neg(&self, context: &Ring<Bls12381, B>) -> Self {
                $name::neg(self, context)
            }
        }

        #[cfg(any(test, not(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))))]
        impl WithBackend for Add<'_, $group> {
            type Output = $group;

            #[inline(always)]
            fn call<B: Backend>(self, backend: B) -> $group {
                let ring = Ring::<Bls12381, B>::new(backend);
                $name::from_jacobian(self.0, &ring)
                    .add(&$name::from_jacobian(self.1, &ring), &ring)
                    .to_jacobian(&ring)
            }
        }

        impl WithBackend for Equal<'_, $name> {
            type Output = Choice;

            #[inline(always)]
            fn call<B: Backend>(self, backend: B) -> Choice {
                let base = Ring::<Bls12381, B>::new(backend);
                let $base = &base;
                let $ring = $ring_value;
                let a = self.0;
                let b = self.1;
                let a_zero = $ring.is_zero(a.z);
                let b_zero = $ring.is_zero(b.z);
                let [ax, bx, ay, by] = $ring.batch_reduce_expand(&[
                    $ring.ready::<800>($ring.prep_left(a.x) * b.z),
                    $ring.ready::<800>($ring.prep_left(b.x) * a.z),
                    $ring.ready::<800>($ring.prep_left(a.y) * b.z),
                    $ring.ready::<800>($ring.prep_left(b.y) * a.z),
                ]);
                (a_zero & b_zero) | (!a_zero & !b_zero
                    & <$field>::from(ax).ct_eq(&<$field>::from(bx))
                    & <$field>::from(ay).ct_eq(&<$field>::from(by)))
            }
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
        impl WithBackend for Msm<'_, $group, super::Scalar> {
            type Output = $group;

            #[inline(always)]
            fn call<B: Backend>(self, backend: B) -> $group {
                let ring = Ring::<Bls12381, B>::new(backend);
                let identity = $name::identity();
                let (terms, bits) =
                    msm::prepare_terms!(self.0, self.1, scalar => msm::EncodedScalar::new(scalar), point => $name::from_jacobian(point, &ring));
                msm::compute(terms, bits, &ring, identity).to_jacobian(&ring)
            }
        }

        #[cfg(test)]
        pub(super) struct $words<'a>(pub &'a $group, pub &'a [u64]);

        #[cfg(test)]
        impl WithBackend for $words<'_> {
            type Output = $group;

            #[inline(always)]
            fn call<B: Backend>(self, backend: B) -> $group {
                let ring = Ring::<Bls12381, B>::new(backend);
                $name::from_jacobian(self.0, &ring)
                    .mul_words(self.1, &ring)
                    .to_jacobian(&ring)
            }
        }
    };
}

point!(
    G1Point, G1, RnsG1, G1Words, Fp, Standard<Bls12381>,
    words[],
    base, ring = base, value => value.scale::<12>()
);
point!(
    G2Point, G2, RnsG2, G2Words, Fp2, Fp2Standard,
    words[cfg(test)],
    base, ring = Fp2Ring::new(base), value => ring.mul_3b(value)
);

impl G1Point {
    // The eigenvalue of -phi^2 is |x|^2 on the prime-order subgroup.
    #[inline(always)]
    fn endomorphism<B: Backend>(&self, ring: &Ring<Bls12381, B>) -> Self {
        let [x] = ring.batch_reduce_expand(&[
            ring.ready::<800>(ring.prep_left(self.x) * Standard::from(super::BETA_SQUARED))
        ]);
        Self {
            x,
            ..self.neg(ring)
        }
    }
}

impl G2Point {
    #[inline(always)]
    fn psi<B: Backend>(&self, ring: &Ring<Bls12381, B>) -> Self {
        let fp2 = Fp2Ring::new(ring);
        let y = fp2.prep_left(fp2.conjugate(self.y));
        let [y0, y1] = fp2.ready::<800>(y * Fp2Standard::from(PSI_Y));
        let coefficient = Standard::from(PSI_X);
        let [x0, x1, y0, y1] = ring.batch_reduce_expand(&[
            ring.ready::<800>(ring.prep_left(self.x.c1) * coefficient),
            ring.ready::<800>(ring.prep_left(self.x.c0) * coefficient),
            y0,
            y1,
        ]);
        Self {
            x: Fp2Standard { c0: x0, c1: x1 },
            y: Fp2Standard { c0: y0, c1: y1 },
            z: fp2.conjugate(self.z),
        }
    }

    #[inline(always)]
    fn psi2<B: Backend>(&self, ring: &Ring<Bls12381, B>) -> Self {
        let fp2 = Fp2Ring::new(ring);
        let coefficient = Standard::from(PSI2_X);
        let [x0, x1] = ring.batch_reduce_expand(&[
            ring.ready::<800>(ring.prep_left(self.x.c0) * coefficient),
            ring.ready::<800>(ring.prep_left(self.x.c1) * coefficient),
        ]);
        Self {
            x: Fp2Standard { c0: x0, c1: x1 },
            y: fp2.standard_negate(self.y),
            z: self.z,
        }
    }

    #[inline(always)]
    fn mul_by_x<B: Backend>(&self, ring: &Ring<Bls12381, B>) -> Self {
        let mut result = self.double(ring);
        for doubles in [2, 3, 9, 32, 16] {
            result = result.add(self, ring);
            for _ in 0..doubles {
                result = result.double(ring);
            }
        }
        result.neg(ring)
    }
}

// Scott's predicates apply to on-curve points before subgroup validation. The
// integer actions must stay unreduced; GLV/GLS already assume these eigenvalues.
impl WithBackend for InSubgroup<'_, G1Point> {
    type Output = bool;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> bool {
        let ring = Ring::<Bls12381, B>::new(backend);
        let image = self.0.endomorphism(&ring);
        let multiple = self.0.mul_words(&X_SQUARED, &ring);
        Equal(&image, &multiple).call(backend).into()
    }
}

impl WithBackend for InSubgroup<'_, G2Point> {
    type Output = bool;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> bool {
        let ring = Ring::<Bls12381, B>::new(backend);
        let image = self.0.psi(&ring);
        let multiple = self.0.mul_by_x(&ring);
        Equal(&image, &multiple).call(backend).into()
    }
}

impl G1 {
    // Hash-to-curve calls this after both isogeny maps produce points on the target
    // curve. Homogeneous addition and cofactor clearing retain the selected backend.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(in crate::bls12381) fn sum_and_clear_cofactor<B: Backend>(
        points: &[crate::bls12381::hash::RnsG1; 2],
        ring: &Ring<Bls12381, B>,
    ) -> Self {
        cfg_if! {
            if #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))] {
                let point = G1Point::from_raw_jacobian(&points[0], ring)
                    .add(&G1Point::from_raw_jacobian(&points[1], ring), ring);
            } else {
                let points = points.map(|point| Self {
                    x: point.x.into(),
                    y: point.y.into(),
                    z: point.z.into(),
                });
                let point = G1Point::from_jacobian(&points[0], ring)
                    .add(&G1Point::from_jacobian(&points[1], ring), ring);
            }
        }
        let result = point.mul_words(&G1_HASH_COFACTOR, ring);
        cfg_if! {
            if #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))] {
                Self(super::word::G1Point::from_rns(result))
            } else {
                result.to_jacobian(ring)
            }
        }
    }
}

impl G2 {
    // The RFC 9380 G.3 identity holds for target-curve points after the isogeny.
    // Jacobian infinity representatives are normalized on entry.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub(in crate::bls12381) fn sum_and_clear_cofactor<B: Backend>(
        points: &[crate::bls12381::hash::RnsG2; 2],
        ring: &Ring<Bls12381, B>,
    ) -> Self {
        cfg_if! {
            if #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))] {
                let point = G2Point::from_raw_jacobian(&points[0], ring)
                    .add(&G2Point::from_raw_jacobian(&points[1], ring), ring);
            } else {
                let points = points.map(|point| Self {
                    x: point.x.into(),
                    y: point.y.into(),
                    z: point.z.into(),
                });
                let point = G2Point::from_jacobian(&points[0], ring)
                    .add(&G2Point::from_jacobian(&points[1], ring), ring);
            }
        }
        let mut result = point.double(ring).psi2(ring);
        let negated = point.neg(ring);
        let negated_psi = point.psi(ring).neg(ring);
        result = result.add(&negated, ring).add(&negated_psi, ring);

        let term = point
            .mul_by_x(ring)
            .neg(ring)
            .add(&point, ring)
            .add(&negated_psi, ring);
        let result = result.add(&term.mul_by_x(ring).neg(ring), ring);
        cfg_if! {
            if #[cfg(all(target_arch = "aarch64", target_os = "linux", target_endian = "little", target_pointer_width = "64", not(miri)))] {
                Self(super::word::G2Point::from_rns(result))
            } else {
                result.to_jacobian(ring)
            }
        }
    }
}

cfg_if! {
    if #[cfg(not(all(
        target_arch = "aarch64",
        target_os = "linux",
        target_endian = "little",
        target_pointer_width = "64",
        not(miri)
    )))] {
        pub(super) struct G1Mul<'a>(pub &'a G1, pub &'a super::Scalar);

        impl WithBackend for G1Mul<'_> {
            type Output = G1;

            #[inline(always)]
            fn call<B: Backend>(self, backend: B) -> G1 {
                let ring = Ring::<Bls12381, B>::new(backend);
                super::multiply_glv(
                    #[inline(always)]
                    || G1Point::from_jacobian(self.0, &ring),
                    self.1,
                    &ring,
                    G1Point::identity(),
                    #[inline(always)]
                    |point| point.endomorphism(&ring),
                    #[inline(always)]
                    |table, digit| G1Point::gather_window(table, digit, &ring),
                )
                .to_jacobian(&ring)
            }
        }

        pub(super) struct G2Mul<'a>(pub &'a G2, pub &'a super::Scalar);

        impl WithBackend for G2Mul<'_> {
            type Output = G2;

            #[inline(always)]
            fn call<B: Backend>(self, backend: B) -> G2 {
                let ring = Ring::<Bls12381, B>::new(backend);
                super::multiply_gls(
                    #[inline(always)]
                    || G2Point::from_jacobian(self.0, &ring),
                    self.1,
                    &ring,
                    G2Point::identity(),
                    #[inline(always)]
                    |table, i, digit| {
                        let point = G2Point::gather_window(table, digit, &ring);
                        match i {
                            0 => point,
                            1 => point.psi(&ring).neg(&ring),
                            2 => point.psi2(&ring),
                            3 => point.psi2(&ring).psi(&ring).neg(&ring),
                            _ => unreachable!(),
                        }
                    },
                )
                .to_jacobian(&ring)
            }
        }
    }
}

#[cfg(test)]
pub(super) struct G2ByX<'a>(pub &'a G2);

#[cfg(test)]
impl WithBackend for G2ByX<'_> {
    type Output = G2;

    #[inline(always)]
    fn call<B: Backend>(self, backend: B) -> G2 {
        let ring = Ring::<Bls12381, B>::new(backend);
        G2Point::from_jacobian(self.0, &ring)
            .mul_by_x(&ring)
            .to_jacobian(&ring)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::scalar::ORDER;
    use commonware_cryptography_vroom::with_backend;
    #[cfg(target_arch = "x86_64")]
    use core::mem::{align_of, offset_of, size_of};

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn points_and_tables_are_cache_line_aligned_without_padding() {
        for (size, alignment, expected_size) in [
            (size_of::<G1Point>(), align_of::<G1Point>(), 384),
            (size_of::<G2Point>(), align_of::<G2Point>(), 768),
            (
                size_of::<[[G1Point; 16]; 2]>(),
                align_of::<[[G1Point; 16]; 2]>(),
                12_288,
            ),
            (
                size_of::<[G2Point; 16]>(),
                align_of::<[G2Point; 16]>(),
                12_288,
            ),
        ] {
            assert_eq!(size, expected_size);
            assert_eq!(alignment, 64);
        }
        for offset in [
            offset_of!(G1Point, x),
            offset_of!(G1Point, y),
            offset_of!(G1Point, z),
            offset_of!(G2Point, x),
            offset_of!(G2Point, y),
            offset_of!(G2Point, z),
            offset_of!(Fp2Standard, c0),
            offset_of!(Fp2Standard, c1),
        ] {
            assert_eq!(offset % 64, 0);
        }
    }

    macro_rules! check_curve {
        ($module:ident, $point:ident, $group:ident, $field:ty, $b:expr, $scales:expr) => {
            mod $module {
                use super::*;

                fn valid(point: $point) -> bool {
                    let x: $field = point.x.into();
                    let y: $field = point.y.into();
                    let z: $field = point.z.into();
                    !(x.is_zero() && y.is_zero() && z.is_zero())
                        && y.square().mul(z) == x.square().mul(x).add($b.mul(z.square().mul(z)))
                }

                #[test]
                fn subgroup_matches_full_order() {
                    let generator = $group::generator();
                    let mut points = alloc::vec![
                        $group::IDENTITY,
                        generator,
                        generator.neg(),
                        generator.mul_words_jacobian(&[5]),
                    ];
                    let full_curve: alloc::vec::Vec<_> = (0..8)
                        .filter_map(|value| {
                            let x = <$field>::from_u64(value);
                            let y = x.square().mul(x).add($b).sqrt()?;
                            Some($group::from_affine(x, y))
                        })
                        .take(2)
                        .collect();
                    assert_eq!(full_curve.len(), 2);
                    for point in full_curve {
                        let torsion = point.mul_words_jacobian(&ORDER);
                        assert!(!torsion.is_identity());
                        assert!(!torsion.mul_words_jacobian(&ORDER).is_identity());
                        points.extend([
                            point,
                            point.neg(),
                            torsion,
                            generator.add_jacobian(&torsion),
                            generator.add_jacobian(&torsion.neg()),
                        ]);
                    }
                    let expected: alloc::vec::Vec<_> = points
                        .iter()
                        .map(|point| point.mul_words_jacobian(&ORDER).is_identity())
                        .collect();
                    assert_eq!(expected.iter().filter(|&&member| member).count(), 4);

                    struct Check<'a>(&'a [$group], &'a [bool]);
                    impl WithBackend for Check<'_> {
                        type Output = ();

                        fn call<B: Backend>(self, backend: B) {
                            let ring = Ring::<Bls12381, B>::new(backend);
                            for (index, (point, expected)) in self.0.iter().zip(self.1).enumerate()
                            {
                                let point = $point::from_jacobian(point, &ring);
                                assert!(valid(point));
                                assert_eq!(
                                    InSubgroup(&point).call(backend),
                                    *expected,
                                    "full-curve fixture {index}",
                                );
                            }
                        }
                    }
                    with_backend(Check(&points, &expected));
                }

                #[test]
                fn subgroup_preserves_projective_representatives() {
                    let generator = $group::generator();
                    let torsion = (0..8)
                        .find_map(|value| {
                            let x = <$field>::from_u64(value);
                            let y = x.square().mul(x).add($b).sqrt()?;
                            let point = $group::from_affine(x, y);
                            let torsion = point.mul_words_jacobian(&ORDER);
                            (!torsion.is_identity()).then_some(torsion)
                        })
                        .unwrap();
                    assert!(!torsion.mul_words_jacobian(&ORDER).is_identity());
                    let points = [
                        $group::IDENTITY,
                        generator,
                        torsion,
                        generator.add_jacobian(&torsion),
                    ];
                    struct Check<'a>(&'a [$group; 4]);
                    impl WithBackend for Check<'_> {
                        type Output = ();

                        fn call<B: Backend>(self, backend: B) {
                            let ring = Ring::<Bls12381, B>::new(backend);
                            for (index, point) in self.0.iter().enumerate() {
                                let point = $point::from_jacobian(point, &ring);
                                for scale in $scales {
                                    let scaled = $point {
                                        x: <$field>::from(point.x).mul(scale).into(),
                                        y: <$field>::from(point.y).mul(scale).into(),
                                        z: <$field>::from(point.z).mul(scale).into(),
                                    };
                                    assert!(valid(scaled));
                                    assert_eq!(
                                        InSubgroup(&scaled).call(backend),
                                        index < 2,
                                        "projective fixture {index}, scale {scale:?}",
                                    );
                                }
                            }
                        }
                    }
                    with_backend(Check(&points));
                }

                #[test]
                fn full_curve_formulas_and_boundaries() {
                    let generator = $group::generator();
                    let scale = <$field>::from_u64(7);
                    let mut points = alloc::vec![generator, generator.neg()];
                    for value in 0..8 {
                        let x = <$field>::from_u64(value);
                        if let Some(y) = x.square().mul(x).add($b).sqrt() {
                            let point = $group::from_affine(x, y);
                            points.extend([point, point.mul_words_jacobian(&ORDER)]);
                        }
                    }
                    for x in [<$field>::ZERO, <$field>::ONE, scale] {
                        for y in [<$field>::ZERO, <$field>::ONE, scale] {
                            points.push($group::from_jacobian_coordinates(x, y, <$field>::ZERO));
                        }
                    }

                    struct Check<'a>(&'a [$group]);
                    impl WithBackend for Check<'_> {
                        type Output = ();

                        fn call<B: Backend>(self, backend: B) {
                            let ring = Ring::<Bls12381, B>::new(backend);
                            let generator = $group::generator();
                            let scale = <$field>::from_u64(7);
                            let g = $point::from_jacobian(&generator, &ring);
                            let invalid = $point {
                                x: <$field>::ZERO.into(),
                                y: <$field>::ZERO.into(),
                                z: <$field>::ZERO.into(),
                            };
                            assert!(!valid(invalid.add(&g, &ring)));

                            for point in self.0 {
                                for point in [*point, {
                                    let (x, y, z) = point.jacobian_coordinates();
                                    $group::from_jacobian_coordinates(
                                        x.mul(scale.square()),
                                        y.mul(scale.square().mul(scale)),
                                        z.mul(scale),
                                    )
                                }] {
                                    let h = $point::from_jacobian(&point, &ring);
                                    assert!(valid(h));
                                    assert_eq!(h.to_jacobian(&ring), point);
                                    let doubled = h.double(&ring);
                                    assert!(valid(doubled));
                                    assert_eq!(doubled.to_jacobian(&ring), point.double_jacobian());

                                    for q in [generator, point, point.neg(), $group::IDENTITY] {
                                        let qh = $point::from_jacobian(&q, &ring);
                                        let sum = h.add(&qh, &ring);
                                        assert!(valid(sum));
                                        assert_eq!(sum.to_jacobian(&ring), point.add_jacobian(&q));
                                        assert_eq!(point.add(&q), point.add_jacobian(&q));
                                    }
                                    for words in [
                                        &[][..],
                                        &[0][..],
                                        &[1][..],
                                        &[0xd201_0000_0001_0000][..],
                                        &ORDER[..],
                                    ] {
                                        let product = h.mul_words(words, &ring);
                                        assert!(valid(product));
                                        assert_eq!(
                                            product.to_jacobian(&ring),
                                            point.mul_words_jacobian(words),
                                        );
                                    }
                                }
                            }
                        }
                    }
                    with_backend(Check(&points));
                }

                #[test]
                fn signed_window_table() {
                    struct Check;
                    impl WithBackend for Check {
                        type Output = ();

                        fn call<B: Backend>(self, backend: B) {
                            let ring = Ring::<Bls12381, B>::new(backend);
                            for point in [$group::generator(), $group::IDENTITY] {
                                let h = $point::from_jacobian(&point, &ring);
                                let mut table = [$point::identity(); 16];
                                msm::precompute_window(&h, &mut table, &ring);
                                let mut expected = $group::IDENTITY;
                                for magnitude in 0..=16 {
                                    let positive = $point::gather_window(&table, magnitude, &ring);
                                    let negative = $point::gather_window(&table, -magnitude, &ring);
                                    assert!(valid(positive) && valid(negative));
                                    assert_eq!(positive.to_jacobian(&ring), expected);
                                    assert_eq!(negative.to_jacobian(&ring), expected.neg());
                                    expected = expected.add_jacobian(&point);
                                }
                            }
                        }
                    }
                    with_backend(Check);
                }
            }
        };
    }

    check_curve!(
        g1,
        G1Point,
        G1,
        Fp,
        Fp::from_u64(4),
        [Fp::ONE, Fp::from_u64(7), Fp::ONE.neg()]
    );
    check_curve!(
        g2,
        G2Point,
        G2,
        Fp2,
        Fp2 {
            c0: Fp::from_u64(4),
            c1: Fp::from_u64(4),
        },
        [
            Fp2::ONE,
            Fp2 {
                c0: Fp::from_u64(2),
                c1: Fp::ONE
            },
            Fp2 {
                c0: Fp::ZERO,
                c1: Fp::from_u64(7)
            },
        ]
    );

    #[test]
    fn g1_subgroup_root_and_unreduced_integer_contract() {
        struct Check;
        impl WithBackend for Check {
            type Output = ();

            fn call<B: Backend>(self, backend: B) {
                let ring = Ring::<Bls12381, B>::new(backend);

                // At (0, 2), the horizontal tangent has a triple intersection.
                let torsion = G1::from_affine(Fp::ZERO, Fp::from_u64(2));
                assert!(torsion.mul_words_jacobian(&[3]).is_identity());
                let point = G1Point::from_jacobian(&torsion, &ring);
                assert_eq!(point.to_jacobian(&ring), torsion);
                assert!(!InSubgroup(&point).call(backend), "order-three point");
                let mut order_plus_one = ORDER;
                order_plus_one[0] += 1;
                for (words, expected) in [
                    (&[][..], G1::IDENTITY),
                    (&[0][..], G1::IDENTITY),
                    (&ORDER[..], torsion),
                    (&order_plus_one[..], torsion.double_jacobian()),
                    (&[0, 0, 0, 0, 1][..], torsion),
                ] {
                    assert_eq!(torsion.mul_words_jacobian(words), expected);
                    assert_eq!(point.mul_words(words, &ring).to_jacobian(&ring), expected);
                }

                let generator = G1::generator();
                let g = G1Point::from_jacobian(&generator, &ring);
                assert_eq!(
                    g.endomorphism(&ring).to_jacobian(&ring),
                    generator.mul_words_jacobian(&[0x0000000100000000, 0xac45a4010001a402,]),
                );
                assert!(InSubgroup(&g).call(backend));
            }
        }
        with_backend(Check);
    }

    #[test]
    fn g2_endomorphisms_match_jacobian() {
        let b = Fp2 {
            c0: Fp::from_u64(4),
            c1: Fp::from_u64(4),
        };
        let mut points = alloc::vec![G2::generator()];
        for value in 0..8 {
            let x = Fp2 {
                c0: Fp::from_u64(value),
                c1: Fp::ONE,
            };
            if let Some(y) = x.square().mul(x).add(b).sqrt() {
                points.push(G2::from_affine(x, y));
            }
        }

        struct Check<'a>(&'a [G2]);
        impl WithBackend for Check<'_> {
            type Output = ();

            fn call<B: Backend>(self, backend: B) {
                let ring = Ring::<Bls12381, B>::new(backend);
                let scale = Fp2 {
                    c0: Fp::from_u64(2),
                    c1: Fp::ONE,
                };
                for point in self.0 {
                    for point in [*point, {
                        let (x, y, z) = point.jacobian_coordinates();
                        G2::from_jacobian_coordinates(
                            x.mul(scale.square()),
                            y.mul(scale.square().mul(scale)),
                            z.mul(scale),
                        )
                    }] {
                        let homogeneous = G2Point::from_jacobian(&point, &ring);
                        assert_eq!(homogeneous.psi(&ring).to_jacobian(&ring), point.psi());
                        assert_eq!(homogeneous.psi2(&ring).to_jacobian(&ring), point.psi2());
                        assert_eq!(
                            homogeneous.mul_by_x(&ring).to_jacobian(&ring),
                            point.mul_words_jacobian(&[0xd201_0000_0001_0000]).neg(),
                        );
                        assert_eq!(
                            homogeneous.psi(&ring).psi(&ring).to_jacobian(&ring),
                            point.psi2(),
                        );
                    }
                }
            }
        }
        with_backend(Check(&points));
    }
}

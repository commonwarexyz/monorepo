//! Minimal Edwards25519 group arithmetic for ZIP-215 verification.
//!
//! The field and point formulas are vendored from [`curve25519_dalek`]'s serial
//! `u64` backend (radix 2^51, extended twisted Edwards coordinates) which is
//! BSD-3-Clause licensed. We own this code so that points can be built from
//! validated coordinates (see [`Point::from_coordinates`] and
//! [`Point::decompress_with_hint`]) without recomputing a square root, which the
//! public [`curve25519_dalek`] API does not permit.

#![allow(clippy::missing_const_for_fn)]

use curve25519_dalek::scalar::Scalar;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(feature = "std")]
use std::vec::Vec;

const LOW_51_BITS: u64 = (1 << 51) - 1;

/// The standard Ed25519 basepoint, compressed (y = 4/5).
const BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

/// d = -121665/121666 (mod p).
const EDWARDS_D: Fe = Fe([
    929_955_233_495_203,
    466_365_720_129_213,
    1_662_059_464_998_953,
    2_033_849_074_728_123,
    1_442_794_654_840_575,
]);
/// 2*d.
const EDWARDS_D2: Fe = Fe([
    1_859_910_466_990_425,
    932_731_440_258_426,
    1_072_319_116_312_658,
    1_815_898_335_770_999,
    633_789_495_995_903,
]);
/// sqrt(-1) (mod p).
const SQRT_M1: Fe = Fe([
    1_718_705_420_411_056,
    234_908_883_556_509,
    2_233_514_472_574_048,
    2_117_202_627_021_982,
    765_476_049_583_133,
]);

/// A field element modulo 2^255 - 19, stored as five 51-bit limbs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fe([u64; 5]);

#[inline(always)]
fn m(x: u64, y: u64) -> u128 {
    u128::from(x) * u128::from(y)
}

#[inline(always)]
fn carry(mut c: [u128; 5]) -> Fe {
    c[1] += c[0] >> 51;
    let r0 = (c[0] as u64) & LOW_51_BITS;
    c[2] += c[1] >> 51;
    let r1 = (c[1] as u64) & LOW_51_BITS;
    c[3] += c[2] >> 51;
    let r2 = (c[2] as u64) & LOW_51_BITS;
    c[4] += c[3] >> 51;
    let r3 = (c[3] as u64) & LOW_51_BITS;
    let top = (c[4] >> 51) as u64;
    let r4 = (c[4] as u64) & LOW_51_BITS;
    let r0 = r0 + top * 19;
    let r1 = r1 + (r0 >> 51);
    let r0 = r0 & LOW_51_BITS;
    Fe([r0, r1, r2, r3, r4])
}

#[inline(always)]
fn weak_reduce(mut l: [u64; 5]) -> [u64; 5] {
    let c0 = l[0] >> 51;
    let c1 = l[1] >> 51;
    let c2 = l[2] >> 51;
    let c3 = l[3] >> 51;
    let c4 = l[4] >> 51;
    l[0] &= LOW_51_BITS;
    l[1] &= LOW_51_BITS;
    l[2] &= LOW_51_BITS;
    l[3] &= LOW_51_BITS;
    l[4] &= LOW_51_BITS;
    l[0] += c4 * 19;
    l[1] += c0;
    l[2] += c1;
    l[3] += c2;
    l[4] += c3;
    l
}

impl Fe {
    const ZERO: Self = Self([0; 5]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load8 = |o: usize| {
            u64::from_le_bytes([
                bytes[o],
                bytes[o + 1],
                bytes[o + 2],
                bytes[o + 3],
                bytes[o + 4],
                bytes[o + 5],
                bytes[o + 6],
                bytes[o + 7],
            ])
        };
        Self([
            load8(0) & LOW_51_BITS,
            (load8(6) >> 3) & LOW_51_BITS,
            (load8(12) >> 6) & LOW_51_BITS,
            (load8(19) >> 1) & LOW_51_BITS,
            (load8(24) >> 12) & LOW_51_BITS,
        ])
    }

    fn to_bytes(self) -> [u8; 32] {
        let mut h = weak_reduce(weak_reduce(self.0)).map(|limb| limb as i64);
        let mut q = (19 * h[4] + (1 << 24)) >> 25;
        q = (h[0] + q) >> 51;
        q = (h[1] + q) >> 51;
        q = (h[2] + q) >> 51;
        q = (h[3] + q) >> 51;
        q = (h[4] + q) >> 51;
        h[0] += 19 * q;
        let c0 = h[0] >> 51;
        h[1] += c0;
        h[0] -= c0 << 51;
        let c1 = h[1] >> 51;
        h[2] += c1;
        h[1] -= c1 << 51;
        let c2 = h[2] >> 51;
        h[3] += c2;
        h[2] -= c2 << 51;
        let c3 = h[3] >> 51;
        h[4] += c3;
        h[3] -= c3 << 51;
        h[4] &= LOW_51_BITS as i64;
        let l = h.map(|limb| limb as u64);
        let mut s = [0u8; 32];
        s[0] = l[0] as u8;
        s[1] = (l[0] >> 8) as u8;
        s[2] = (l[0] >> 16) as u8;
        s[3] = (l[0] >> 24) as u8;
        s[4] = (l[0] >> 32) as u8;
        s[5] = (l[0] >> 40) as u8;
        s[6] = ((l[0] >> 48) | (l[1] << 3)) as u8;
        s[7] = (l[1] >> 5) as u8;
        s[8] = (l[1] >> 13) as u8;
        s[9] = (l[1] >> 21) as u8;
        s[10] = (l[1] >> 29) as u8;
        s[11] = (l[1] >> 37) as u8;
        s[12] = ((l[1] >> 45) | (l[2] << 6)) as u8;
        s[13] = (l[2] >> 2) as u8;
        s[14] = (l[2] >> 10) as u8;
        s[15] = (l[2] >> 18) as u8;
        s[16] = (l[2] >> 26) as u8;
        s[17] = (l[2] >> 34) as u8;
        s[18] = (l[2] >> 42) as u8;
        s[19] = ((l[2] >> 50) | (l[3] << 1)) as u8;
        s[20] = (l[3] >> 7) as u8;
        s[21] = (l[3] >> 15) as u8;
        s[22] = (l[3] >> 23) as u8;
        s[23] = (l[3] >> 31) as u8;
        s[24] = (l[3] >> 39) as u8;
        s[25] = ((l[3] >> 47) | (l[4] << 4)) as u8;
        s[26] = (l[4] >> 4) as u8;
        s[27] = (l[4] >> 12) as u8;
        s[28] = (l[4] >> 20) as u8;
        s[29] = (l[4] >> 28) as u8;
        s[30] = (l[4] >> 36) as u8;
        s[31] = (l[4] >> 44) as u8;
        s
    }

    fn is_zero(self) -> bool {
        self.to_bytes() == [0u8; 32]
    }

    fn is_negative(self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    fn equals(self, rhs: Self) -> bool {
        self.to_bytes() == rhs.to_bytes()
    }

    fn add(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        Self([
            a[0] + b[0],
            a[1] + b[1],
            a[2] + b[2],
            a[3] + b[3],
            a[4] + b[4],
        ])
    }

    fn sub(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        Self(weak_reduce([
            (a[0] + 36_028_797_018_963_664) - b[0],
            (a[1] + 36_028_797_018_963_952) - b[1],
            (a[2] + 36_028_797_018_963_952) - b[2],
            (a[3] + 36_028_797_018_963_952) - b[3],
            (a[4] + 36_028_797_018_963_952) - b[4],
        ]))
    }

    fn neg(self) -> Self {
        Self::ZERO.sub(self)
    }

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        let a = self.0;
        let b = rhs.0;
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;
        carry([
            m(a[0], b[0]) + m(a[4], b1_19) + m(a[3], b2_19) + m(a[2], b3_19) + m(a[1], b4_19),
            m(a[1], b[0]) + m(a[0], b[1]) + m(a[4], b2_19) + m(a[3], b3_19) + m(a[2], b4_19),
            m(a[2], b[0]) + m(a[1], b[1]) + m(a[0], b[2]) + m(a[4], b3_19) + m(a[3], b4_19),
            m(a[3], b[0]) + m(a[2], b[1]) + m(a[1], b[2]) + m(a[0], b[3]) + m(a[4], b4_19),
            m(a[4], b[0]) + m(a[3], b[1]) + m(a[2], b[2]) + m(a[1], b[3]) + m(a[0], b[4]),
        ])
    }

    #[inline(always)]
    fn square_inner(self) -> [u128; 5] {
        let a = self.0;
        let a0_2 = a[0] * 2;
        let a1_2 = a[1] * 2;
        let a3_19 = a[3] * 19;
        let a4_19 = a[4] * 19;
        [
            m(a[0], a[0]) + m(a1_2, a4_19) + m(a[2], a3_19) * 2,
            m(a0_2, a[1]) + m(a[2], a4_19) * 2 + m(a[3], a3_19),
            m(a0_2, a[2]) + m(a[1], a[1]) + m(a[4], a3_19) * 2,
            m(a0_2, a[3]) + m(a1_2, a[2]) + m(a[4], a4_19),
            m(a0_2, a[4]) + m(a1_2, a[3]) + m(a[2], a[2]),
        ]
    }

    fn square(self) -> Self {
        carry(self.square_inner())
    }

    fn square2(self) -> Self {
        let mut c = self.square_inner();
        for coeff in &mut c {
            *coeff *= 2;
        }
        carry(c)
    }

    fn pow2k(self, k: u32) -> Self {
        debug_assert!(k > 0);
        let mut z = self.square();
        for _ in 1..k {
            z = z.square();
        }
        z
    }

    fn pow22501(self) -> (Self, Self) {
        let t0 = self.square();
        let t1 = t0.square().square();
        let t2 = self.mul(t1);
        let t3 = t0.mul(t2);
        let t4 = t3.square();
        let t5 = t2.mul(t4);
        let t6 = t5.pow2k(5);
        let t7 = t6.mul(t5);
        let t8 = t7.pow2k(10);
        let t9 = t8.mul(t7);
        let t10 = t9.pow2k(20);
        let t11 = t10.mul(t9);
        let t12 = t11.pow2k(10);
        let t13 = t12.mul(t7);
        let t14 = t13.pow2k(50);
        let t15 = t14.mul(t13);
        let t16 = t15.pow2k(100);
        let t17 = t16.mul(t15);
        let t18 = t17.pow2k(50);
        let t19 = t18.mul(t13);
        (t19, t3)
    }

    fn pow_p58(self) -> Self {
        let (t19, _) = self.pow22501();
        let t20 = t19.pow2k(2);
        self.mul(t20)
    }

    fn invert(self) -> Self {
        let (t19, t3) = self.pow22501();
        let t20 = t19.pow2k(5);
        t20.mul(t3)
    }

    /// Returns sqrt(u/v) if it exists, choosing the canonical (ZIP-215) root.
    fn sqrt_ratio(u: Self, v: Self) -> Option<Self> {
        let v2 = v.square();
        let v3 = v2.mul(v);
        let v7 = v3.square().mul(v);
        let mut x = u.mul(v3).mul(u.mul(v7).pow_p58());
        let check = v.mul(x.square());
        let correct_sign = check.equals(u);
        let flipped_sign = check.equals(u.neg());
        let flipped_sign_i = check.equals(u.neg().mul(SQRT_M1));
        if flipped_sign || flipped_sign_i {
            x = x.mul(SQRT_M1);
        }
        (correct_sign || flipped_sign).then_some(x)
    }
}

/// `true` iff `(x, y)` lies on the Edwards curve `-x^2 + y^2 = 1 + d x^2 y^2`.
fn on_curve(x: Fe, y: Fe) -> bool {
    let xx = x.square();
    let yy = y.square();
    yy.sub(xx).sub(Fe::ONE).equals(EDWARDS_D.mul(xx.mul(yy)))
}

/// A point on Edwards25519 in extended coordinates (X:Y:Z:T).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[derive(Clone, Copy)]
struct ProjectivePoint {
    x: Fe,
    y: Fe,
    z: Fe,
}

#[derive(Clone, Copy)]
struct CompletedPoint {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

#[derive(Clone, Copy)]
struct ProjectiveNielsPoint {
    y_plus_x: Fe,
    y_minus_x: Fe,
    z: Fe,
    t2d: Fe,
}

impl Point {
    pub(super) const IDENTITY: Self = Self {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// Decompress a 32-byte encoding (ZIP-215 rules), recovering `x` via a square root.
    pub(super) fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let sign = bytes[31] >> 7 != 0;
        let y = Fe::from_bytes(bytes);
        let yy = y.square();
        let u = yy.sub(Fe::ONE);
        let v = EDWARDS_D.mul(yy).add(Fe::ONE);
        let mut x = Fe::sqrt_ratio(u, v)?;
        if x.is_negative() != sign {
            x = x.neg();
        }
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    /// The affine `(x, y)` coordinates of this point, canonically encoded.
    pub(super) fn coordinates(self) -> ([u8; 32], [u8; 32]) {
        if self.z.equals(Fe::ONE) {
            return (self.x.to_bytes(), self.y.to_bytes());
        }
        let recip = self.z.invert();
        (self.x.mul(recip).to_bytes(), self.y.mul(recip).to_bytes())
    }

    /// Build a point from full affine coordinates, validating it is on the curve.
    /// No square root is computed. Used for decompressed verification keys.
    pub(super) fn from_coordinates(x_bytes: &[u8; 32], y_bytes: &[u8; 32]) -> Option<Self> {
        let x = Fe::from_bytes(x_bytes);
        let y = Fe::from_bytes(y_bytes);
        if !on_curve(x, y) {
            return None;
        }
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    /// Decompress `R` using a committed `x` hint, validated with an on-curve and
    /// sign check instead of a square root. The hint must be the canonical
    /// encoding of the unique decompression of `R`; any other hint is rejected
    /// (returns `None`), with no fallback. Because the hint is committed in the
    /// signature encoding this is a deterministic validity rule: all verifiers
    /// agree, and a bad hint is simply an invalid signature.
    ///
    /// Validity requires: `x` canonically encoded (no malleable re-encoding),
    /// `parity(x) == sign(R)`, and `(x, y)` on the curve. The `x = 0` points
    /// (`y = +-1`) are accepted only via their canonical `sign = 0` encoding,
    /// which the parity check enforces with no special case.
    pub(super) fn decompress_with_hint(r_bytes: &[u8; 32], x_bytes: &[u8; 32]) -> Option<Self> {
        let sign = r_bytes[31] >> 7 != 0;
        let y = Fe::from_bytes(r_bytes);
        let x = Fe::from_bytes(x_bytes);
        let canonical = x.to_bytes();
        if canonical != *x_bytes || (canonical[0] & 1 == 1) != sign || !on_curve(x, y) {
            return None;
        }
        Some(Self {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(y),
        })
    }

    pub(super) fn basepoint() -> Self {
        Self::decompress(&BASEPOINT_COMPRESSED).expect("basepoint is valid")
    }

    pub(super) fn mul_by_cofactor(self) -> Self {
        self.double().double().double()
    }

    pub(super) fn is_identity(self) -> bool {
        self.x.is_zero() && self.y.equals(self.z)
    }

    fn add(self, other: Self) -> Self {
        self.add_projective_niels(other.as_projective_niels())
            .as_extended()
    }

    fn add_niels(self, other: ProjectiveNielsPoint) -> Self {
        self.add_projective_niels(other).as_extended()
    }

    fn double(self) -> Self {
        self.as_projective().double().as_extended()
    }

    #[cfg(test)]
    fn compress(self) -> [u8; 32] {
        let recip = self.z.invert();
        let x = self.x.mul(recip);
        let y = self.y.mul(recip);
        let mut bytes = y.to_bytes();
        bytes[31] ^= (x.is_negative() as u8) << 7;
        bytes
    }

    const fn as_projective(self) -> ProjectivePoint {
        ProjectivePoint {
            x: self.x,
            y: self.y,
            z: self.z,
        }
    }

    fn as_projective_niels(self) -> ProjectiveNielsPoint {
        ProjectiveNielsPoint {
            y_plus_x: self.y.add(self.x),
            y_minus_x: self.y.sub(self.x),
            z: self.z,
            t2d: self.t.mul(EDWARDS_D2),
        }
    }

    fn add_projective_niels(self, other: ProjectiveNielsPoint) -> CompletedPoint {
        let y_plus_x = self.y.add(self.x);
        let y_minus_x = self.y.sub(self.x);
        let pp = y_plus_x.mul(other.y_plus_x);
        let mm = y_minus_x.mul(other.y_minus_x);
        let tt2d = self.t.mul(other.t2d);
        let zz = self.z.mul(other.z);
        let zz2 = zz.add(zz);

        CompletedPoint {
            x: pp.sub(mm),
            y: pp.add(mm),
            z: zz2.add(tt2d),
            t: zz2.sub(tt2d),
        }
    }
}

impl ProjectivePoint {
    fn double(self) -> CompletedPoint {
        let xx = self.x.square();
        let yy = self.y.square();
        let zz2 = self.z.square2();
        let x_plus_y = self.x.add(self.y);
        let x_plus_y_sq = x_plus_y.square();
        let yy_plus_xx = yy.add(xx);
        let yy_minus_xx = yy.sub(xx);

        CompletedPoint {
            x: x_plus_y_sq.sub(yy_plus_xx),
            y: yy_plus_xx,
            z: yy_minus_xx,
            t: zz2.sub(yy_minus_xx),
        }
    }
}

impl CompletedPoint {
    fn as_extended(self) -> Point {
        Point {
            x: self.x.mul(self.t),
            y: self.y.mul(self.z),
            z: self.z.mul(self.t),
            t: self.x.mul(self.y),
        }
    }
}

pub(super) fn vartime_multiscalar_mul(scalars: &[Scalar], points: &[Point]) -> Point {
    debug_assert_eq!(scalars.len(), points.len());
    if scalars.len() < 8 {
        return windowed_small(scalars, points);
    }
    pippenger(scalars, points)
}

fn windowed_small(scalars: &[Scalar], points: &[Point]) -> Point {
    const WINDOW: usize = 5;
    const TABLE_SIZE: usize = 1 << WINDOW;

    let bytes: Vec<_> = scalars.iter().map(Scalar::to_bytes).collect();
    let tables: Vec<_> = points
        .iter()
        .map(|point| {
            let mut table = [Point::IDENTITY; TABLE_SIZE];
            table[1] = *point;
            for i in 2..TABLE_SIZE {
                table[i] = table[i - 1].add(*point);
            }
            table
        })
        .collect();

    let mut acc = Point::IDENTITY;
    for idx in (0..256usize.div_ceil(WINDOW)).rev() {
        for _ in 0..WINDOW {
            acc = acc.double();
        }
        for (scalar, table) in bytes.iter().zip(&tables) {
            let digit = scalar_window(scalar, idx, WINDOW);
            if digit != 0 {
                acc = acc.add(table[digit]);
            }
        }
    }
    acc
}

fn pippenger(scalars: &[Scalar], points: &[Point]) -> Point {
    let window = if scalars.len() >= 4096 {
        10
    } else if scalars.len() >= 1024 {
        8
    } else if scalars.len() >= 512 {
        7
    } else if scalars.len() >= 64 {
        6
    } else {
        4
    };
    let windows = 256usize.div_ceil(window);
    let bucket_count = 1 << window;
    let bytes: Vec<_> = scalars.iter().map(Scalar::to_bytes).collect();
    let niels: Vec<_> = points
        .iter()
        .map(|point| point.as_projective_niels())
        .collect();
    let mut buckets = vec![Point::IDENTITY; bucket_count];
    let mut occupied = vec![false; bucket_count];
    let mut touched = Vec::with_capacity(bucket_count);
    let mut acc = Point::IDENTITY;
    for idx in (0..windows).rev() {
        for _ in 0..window {
            acc = acc.double();
        }

        for ((scalar, point), niels) in bytes.iter().zip(points).zip(&niels) {
            let digit = scalar_window(scalar, idx, window);
            if digit != 0 {
                if occupied[digit] {
                    buckets[digit] = buckets[digit].add_niels(*niels);
                } else {
                    buckets[digit] = *point;
                    occupied[digit] = true;
                    touched.push(digit);
                }
            }
        }

        let mut running = Point::IDENTITY;
        let mut any = false;
        for (bucket, occupied) in buckets[1..].iter().zip(&occupied[1..]).rev() {
            if *occupied {
                running = if any {
                    running.add(*bucket)
                } else {
                    any = true;
                    *bucket
                };
            }
            if !any {
                continue;
            }
            acc = acc.add(running);
        }

        for digit in touched.drain(..) {
            occupied[digit] = false;
        }
    }
    acc
}

fn scalar_window(scalar: &[u8; 32], window: usize, width: usize) -> usize {
    let offset = window * width;
    if offset >= 256 {
        return 0;
    }

    let byte = offset / 8;
    let shift = offset % 8;
    let remaining = 256 - offset;
    let bits = width.min(remaining);
    let mut word = u32::from(scalar[byte]);
    if byte + 1 < 32 {
        word |= u32::from(scalar[byte + 1]) << 8;
    }
    if byte + 2 < 32 {
        word |= u32::from(scalar[byte + 2]) << 16;
    }

    let mask = (1u32 << bits) - 1;
    ((word >> shift) & mask) as usize
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::{
        constants::ED25519_BASEPOINT_POINT,
        edwards::CompressedEdwardsY,
        traits::{IsIdentity, VartimeMultiscalarMul},
    };
    use rand_core::RngCore;

    fn random_point(rng: &mut impl RngCore) -> curve25519_dalek::edwards::EdwardsPoint {
        let mut wide = [0u8; 64];
        rng.fill_bytes(&mut wide);
        Scalar::from_bytes_mod_order_wide(&wide) * ED25519_BASEPOINT_POINT
    }

    #[test]
    fn test_basepoint_compresses_correctly() {
        assert_eq!(
            Point::basepoint().compress(),
            ED25519_BASEPOINT_POINT.compress().to_bytes()
        );
    }

    #[test]
    fn test_field_roundtrip_and_invert() {
        let mut rng = commonware_utils::test_rng();
        for _ in 0..64 {
            let p = random_point(&mut rng);
            let bytes = p.compress().to_bytes();
            let x = Fe::from_bytes(&bytes);
            assert_eq!(x.to_bytes(), Fe::from_bytes(&x.to_bytes()).to_bytes());
            assert!(x.mul(x.invert()).equals(Fe::ONE));
        }
    }

    #[test]
    fn test_zip215_decode_matches_dalek() {
        for mut bytes in [
            ED25519_BASEPOINT_POINT.compress().to_bytes(),
            [0u8; 32],
            [1u8; 32],
            [0xffu8; 32],
        ] {
            bytes[31] &= 0xff;
            assert_eq!(
                Point::decompress(&bytes).map(Point::compress),
                CompressedEdwardsY(bytes)
                    .decompress()
                    .map(|p| p.compress().to_bytes())
            );
        }
    }

    #[test]
    fn test_decompress_with_hint_matches_dalek() {
        let mut rng = commonware_utils::test_rng();
        for _ in 0..64 {
            let p = random_point(&mut rng);
            let r_bytes = p.compress().to_bytes();
            let truth = Point::decompress(&r_bytes).unwrap();
            let x_bytes = truth.compress();
            // Reconstruct x from the truth point to feed as a hint.
            let recip = truth.z.invert();
            let x_hint = truth.x.mul(recip).to_bytes();

            // Honest hint matches decompression.
            let hinted = Point::decompress_with_hint(&r_bytes, &x_hint).unwrap();
            assert_eq!(hinted.compress(), x_bytes);

            // Corrupted hint is rejected (no fallback).
            let mut bad = x_hint;
            bad[0] ^= 1;
            assert!(Point::decompress_with_hint(&r_bytes, &bad).is_none());

            // Wrong-parity (negated x) hint is rejected.
            let neg_x = Fe::from_bytes(&x_hint).neg().to_bytes();
            assert!(Point::decompress_with_hint(&r_bytes, &neg_x).is_none());

            // Non-canonical x encoding (high bit set, ignored by from_bytes) is rejected.
            let mut non_canonical = x_hint;
            non_canonical[31] |= 0x80;
            assert!(Point::decompress_with_hint(&r_bytes, &non_canonical).is_none());
        }
    }

    #[test]
    fn test_from_coordinates() {
        let mut rng = commonware_utils::test_rng();
        for _ in 0..64 {
            let p = random_point(&mut rng);
            let truth = Point::decompress(&p.compress().to_bytes()).unwrap();
            let recip = truth.z.invert();
            let x_bytes = truth.x.mul(recip).to_bytes();
            let y_bytes = truth.y.mul(recip).to_bytes();
            let built = Point::from_coordinates(&x_bytes, &y_bytes).unwrap();
            assert_eq!(built.compress(), truth.compress());

            // Off-curve coordinates are rejected.
            let mut bad_y = y_bytes;
            bad_y[0] ^= 1;
            assert!(Point::from_coordinates(&x_bytes, &bad_y).is_none());
        }
    }

    #[test]
    fn test_multiscalar_matches_dalek() {
        let mut rng = commonware_utils::test_rng();
        for count in [1usize, 2, 7, 8, 16, 33, 100] {
            let mut scalars = Vec::with_capacity(count);
            let mut points = Vec::with_capacity(count);
            let mut dalek_points = Vec::with_capacity(count);
            for _ in 0..count {
                let mut wide = [0u8; 64];
                rng.fill_bytes(&mut wide);
                let scalar = Scalar::from_bytes_mod_order_wide(&wide);
                let dalek_point = random_point(&mut rng);
                let native_point = Point::decompress(&dalek_point.compress().to_bytes()).unwrap();
                scalars.push(scalar);
                points.push(native_point);
                dalek_points.push(dalek_point);
            }

            let native = vartime_multiscalar_mul(&scalars, &points).compress();
            let dalek = curve25519_dalek::edwards::EdwardsPoint::vartime_multiscalar_mul(
                scalars.iter(),
                dalek_points.iter(),
            )
            .compress()
            .to_bytes();
            assert_eq!(native, dalek);
        }
    }

    #[test]
    fn test_cofactor_identity_matches_dalek() {
        for bytes in [[1u8; 32], [0u8; 32]] {
            let native = Point::decompress(&bytes);
            let dalek = CompressedEdwardsY(bytes).decompress();
            match (native, dalek) {
                (Some(n), Some(d)) => assert_eq!(
                    n.mul_by_cofactor().is_identity(),
                    d.mul_by_cofactor().is_identity()
                ),
                (None, None) => {}
                _ => panic!("decode mismatch"),
            }
        }
    }
}

// Portions adapted from blst 0.3.16, blst/src/{ec_ops.h, ec_mult.h, e1.c, e2.c}.
// Copyright Supranational LLC
// SPDX-License-Identifier: Apache-2.0

//! The prime-order G1 and G2 groups of BLS12-381.
//!
//! Compressed decoding validates canonical field coordinates, the curve equation, and subgroup
//! membership. The canonical identity encoding is accepted. Protocols requiring nonidentity
//! public keys or signatures must enforce that requirement separately.

use crate::bls12381::{Fp, extension::Fp2, scalar::Scalar};
use alloc::vec::Vec;
use bytes::BufMut;
use commonware_codec::{Buf, FixedSize, Read, Write};
use commonware_cryptography_vroom::with_backend;
use rand_core::CryptoRng;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

mod homogeneous;
mod msm;
pub(crate) mod subgroup;
pub(super) use msm::EncodedScalar;

// Thirteen windows cover a u64; twenty-six cover a u128. The final partial
// window absorbs the carry without exceeding the table's magnitude bound of 16.
fn recode_w5<const N: usize>(value: u128) -> Zeroizing<[i8; N]> {
    const { assert!(N == 13 || N == 26) };
    let mut value = Zeroizing::new(value);
    let mut carry = Zeroizing::new(0i16);
    let mut digits = Zeroizing::new([0; N]);
    for digit in &mut digits[..N - 1] {
        let window = (*value & 31) as i16 + *carry;
        *value >>= 5;
        *carry = (window + 16) >> 5;
        *digit = (window - (*carry << 5)) as i8;
    }
    digits[N - 1] = (*value as i16 + *carry) as i8;
    digits
}

/// Every component supplies a fixed number of radix-32 digits. Point arithmetic
/// must have a fixed schedule, and gather must scan its complete table and select
/// without secret indexing.
#[inline(always)]
fn multiply_windows<P: msm::Point<C>, C, const N: usize, const W: usize>(
    digits: &[[i8; W]; N],
    gather: impl Fn(usize, i8) -> P,
    context: &C,
) -> P {
    const { assert!(N > 0 && W > 0) };
    let mut result = gather(0, digits[0][W - 1]);
    for (i, component) in digits[1..].iter().enumerate() {
        result = result.add(&gather(i + 1, component[W - 1]), context);
    }
    for window in (0..W - 1).rev() {
        for _ in 0..5 {
            result = result.double(context);
        }
        for (i, component) in digits.iter().enumerate() {
            result = result.add(&gather(i, component[window]), context);
        }
    }
    result
}

/// Import returns a G1 prime-order subgroup point, and image implements -phi^2.
/// Both operations require a fixed schedule. Split components and signed digits
/// remain owned here through the secret loop.
#[inline(always)]
fn multiply_glv<P: msm::Point<C>, C>(
    import: impl FnOnce() -> P,
    scalar: &Scalar,
    context: &C,
    identity: P,
    image: impl Fn(&P) -> P,
    gather: impl Fn(&[P; 16], i8) -> P,
) -> P {
    let components = scalar.split_glv();
    let digits = Zeroizing::new([
        *recode_w5::<26>(components[0]),
        *recode_w5::<26>(components[1]),
    ]);
    let point = import();
    let mut tables = [[identity; 16]; 2];
    let [base, images] = &mut tables;
    msm::precompute_window(&point, base, context);
    for (output, point) in images.iter_mut().zip(base.iter()) {
        *output = image(point);
    }
    multiply_windows(
        &digits,
        #[inline(always)]
        |i, digit| gather(&tables[i], digit),
        context,
    )
}

/// Import returns a G2 prime-order subgroup point. Gather scans the full table
/// and applies [P, -psi(P), psi2(P), -psi3(P)] for its public component index.
/// Split components and signed digits remain owned here through the secret loop.
#[inline(always)]
fn multiply_gls<P: msm::Point<C>, C>(
    import: impl FnOnce() -> P,
    scalar: &Scalar,
    context: &C,
    identity: P,
    gather: impl Fn(&[P; 16], usize, i8) -> P,
) -> P {
    let components = scalar.split_gls();
    let digits = Zeroizing::new(core::array::from_fn::<_, 4, _>(|i| {
        *recode_w5::<13>(components[i] as u128)
    }));
    let point = import();
    let mut table = [identity; 16];
    msm::precompute_window(&point, &mut table, context);
    multiply_windows(
        &digits,
        #[cfg_attr(not(debug_assertions), inline(always))]
        |i, digit| gather(&table, i, digit),
        context,
    )
}

macro_rules! group {
    ($name:ident, $words:ident, $field:ty, $size:literal, $description:literal) => {
        #[doc = $description]
        #[derive(Clone, Copy, Debug)]
        pub struct $name {
            pub(crate) x: $field,
            pub(crate) y: $field,
            pub(crate) z: $field,
        }

        impl $name {
            /// Decodes a batch of canonical compressed points with randomized subgroup checks.
            ///
            /// The original points are returned in order, including identities and duplicates.
            /// Empty input returns an empty vector. Invalid encodings, failed subgroup checks,
            /// and allocation failures return `None`; no partial result is returned.
            ///
            /// All encodings are checked before sampling private, single-use coefficients.
            /// For any fixed batch containing a point outside the subgroup, the probability
            /// of acceptance is at most 2^-128 per call under the crate's
            /// [randomness requirements](crate#randomness). Retrying rejected batches and
            /// accepting any successful retry increases that probability.
            ///
            /// Timing and memory access depend on the public inputs and sampled coefficients.
            pub fn batch_from_bytes(
                rng: &mut impl CryptoRng,
                bytes: &[[u8; $size]],
            ) -> Option<Vec<Self>> {
                with_backend(subgroup::DecodeBatch { rng, bytes })
            }

            /// The additive identity.
            pub const IDENTITY: Self = Self {
                x: <$field>::ZERO,
                y: <$field>::ONE,
                z: <$field>::ZERO,
            };

            /// Returns whether this point is the identity.
            pub fn is_identity(&self) -> bool {
                bool::from(self.z.ct_eq(&<$field>::ZERO))
            }

            /// Adds two points, including equal, opposite, and identity operands.
            pub fn add(&self, rhs: &Self) -> Self {
                with_backend(homogeneous::Add(self, rhs))
            }

            /// Returns twice this point.
            pub fn double(&self) -> Self {
                let xx = self.x.square();
                let yy = self.y.square();
                let yyyy = yy.square();
                let d = self.x.add(yy).square().sub(xx).sub(yyyy);
                let d = d.add(d);
                let e = xx.add(xx).add(xx);
                let x = e.square().sub(d.add(d));
                let eight_yyyy = yyyy.add(yyyy);
                let eight_yyyy = eight_yyyy.add(eight_yyyy);
                let eight_yyyy = eight_yyyy.add(eight_yyyy);
                let y = e.mul(d.sub(x)).sub(eight_yyyy);
                let yz = self.y.mul(self.z);
                Self {
                    x,
                    y,
                    z: yz.add(yz),
                }
            }

            /// Returns the additive inverse.
            pub fn neg(&self) -> Self {
                Self {
                    x: self.x,
                    y: self.y.neg(),
                    z: self.z,
                }
            }

            // Coordinates represent (X/Z^2, Y/Z^3), with every Z = 0 representing infinity.
            // Callers supply on-curve coordinates and establish subgroup membership before
            // exposing a point outside the crate.
            pub(crate) const fn from_affine(x: $field, y: $field) -> Self {
                Self {
                    x,
                    y,
                    z: <$field>::ONE,
                }
            }

            pub(crate) fn to_affine(self) -> Option<($field, $field)> {
                let inverse = self.z.invert()?;
                let inverse_squared = inverse.square();
                Some((
                    self.x.mul(inverse_squared),
                    self.y.mul(inverse_squared).mul(inverse),
                ))
            }
        }

        impl ConstantTimeEq for $name {
            fn ct_eq(&self, other: &Self) -> Choice {
                let self_identity = self.z.ct_eq(&<$field>::ZERO);
                let other_identity = other.z.ct_eq(&<$field>::ZERO);
                let self_zz = self.z.square();
                let other_zz = other.z.square();
                let x_equal = self.x.mul(other_zz).ct_eq(&other.x.mul(self_zz));
                let y_equal = self
                    .y
                    .mul(other_zz)
                    .mul(other.z)
                    .ct_eq(&other.y.mul(self_zz).mul(self.z));
                (self_identity & other_identity)
                    | (!self_identity & !other_identity & x_equal & y_equal)
            }
        }

        impl ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self {
                    x: <$field>::conditional_select(&a.x, &b.x, choice),
                    y: <$field>::conditional_select(&a.y, &b.y, choice),
                    z: <$field>::conditional_select(&a.z, &b.z, choice),
                }
            }
        }

        impl $name {
            /// Returns the additive identity.
            pub const fn identity() -> Self {
                Self::IDENTITY
            }

            /// Computes a multi-scalar multiplication with public points and scalars.
            ///
            /// Returns `None` for unequal slice lengths. Empty inputs return the identity;
            /// identity points and zero scalars are accepted. This operation uses heap scratch
            /// proportional to the input length and a bounded bucket table.
            ///
            /// Timing and memory access depend on both inputs. Use [`Self::mul`] for secret
            /// scalars.
            pub fn msm_vartime(points: &[Self], scalars: &[Scalar]) -> Option<Self> {
                if points.len() != scalars.len() {
                    return None;
                }
                if let [point] = points {
                    return Some(point.mul(&scalars[0]));
                }
                Some(with_backend(homogeneous::Msm(points, scalars)))
            }

            #[cfg(test)]
            pub(super) fn add_jacobian(&self, rhs: &Self) -> Self {
                // Unified Jacobian addition from blst's POINT_DADD_IMPL (a = 0). Equal
                // affine coordinates select the doubling slope; inverses yield Z = 0.
                let (x1, y1, z1) = (self.x, self.y, self.z);
                let (x2, y2, z2) = (rhs.x, rhs.y, rhs.z);
                let z1z1 = z1.square();
                let z2z2 = z2.square();
                let u1 = x1.mul(z2z2);
                let u2 = x2.mul(z1z1);
                let s1 = y1.mul(z2).mul(z2z2);
                let s2 = y2.mul(z1).mul(z1z1);
                let h = u2.sub(u1);
                let r = s2.sub(s1);
                let doubling = h.ct_eq(&<$field>::ZERO) & r.ct_eq(&<$field>::ZERO);
                let xx = x1.square();
                let h = <$field>::conditional_select(&h, &y1.add(y1), doubling);
                let r = <$field>::conditional_select(&r, &xx.add(xx).add(xx), doubling);
                let sx = <$field>::conditional_select(&u1.add(u2), &x1.add(x1), doubling);
                let u = <$field>::conditional_select(&u1, &x1, doubling);
                let s = <$field>::conditional_select(&s1, &y1, doubling);
                let zz = <$field>::conditional_select(&z1.mul(z2), &z1, doubling);
                let hh = h.square();
                let hhh = hh.mul(h);
                let x = r.square().sub(hh.mul(sx));
                let y = r.mul(hh.mul(u).sub(x)).sub(hhh.mul(s));
                let result = Self { x, y, z: h.mul(zz) };
                let result = Self::conditional_select(&result, self, z2.ct_eq(&<$field>::ZERO));
                Self::conditional_select(&result, rhs, z1.ct_eq(&<$field>::ZERO))
            }

            #[cfg(test)]
            pub(super) fn mul_words_jacobian(&self, words: &[u64]) -> Self {
                let mut result = Self::IDENTITY;
                for word in words.iter().rev() {
                    for bit in (0..64).rev() {
                        result = result.double();
                        if (word >> bit) & 1 != 0 {
                            result = result.add_jacobian(self);
                        }
                    }
                }
                result
            }

            /// Subtracts a point.
            pub fn sub(&self, rhs: &Self) -> Self {
                self.add(&rhs.neg())
            }

            /// Multiplies by public little-endian words without reducing modulo the group order.
            /// This also applies to on-curve points before their cofactor has been cleared.
            #[cfg(test)]
            pub(crate) fn mul_words(&self, words: &[u64]) -> Self {
                with_backend(homogeneous::$words(self, words))
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                bool::from(self.ct_eq(other))
            }
        }

        impl Eq for $name {}

        impl Write for $name {
            fn write(&self, buf: &mut impl BufMut) {
                self.to_bytes().write(buf);
            }
        }

        impl FixedSize for $name {
            const SIZE: usize = $size;
        }

        impl Read for $name {
            type Cfg = ();

            fn read_cfg(
                buf: &mut impl Buf,
                cfg: &Self::Cfg,
            ) -> Result<Self, commonware_codec::Error> {
                Self::from_bytes(&<[u8; $size]>::read_cfg(buf, cfg)?).ok_or(
                    commonware_codec::Error::Invalid(stringify!($name), "invalid point"),
                )
            }
        }

        #[cfg(feature = "arbitrary")]
        impl arbitrary::Arbitrary<'_> for $name {
            fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                Ok(Self::generator().mul(&u.arbitrary()?))
            }
        }
    };
}

group!(
    G1,
    G1Words,
    Fp,
    48,
    "A point in the prime-order subgroup of y^2 = x^3 + 4 over Fp."
);
group!(
    G2,
    G2Words,
    Fp2,
    96,
    "A point in the prime-order subgroup of y^2 = x^3 + 4(1 + u) over Fp2."
);

fn compressed_flags<const N: usize>(bytes: &[u8; N]) -> Option<(bool, bool, [u8; N])> {
    let compressed = bytes[0] & 0x80 != 0;
    let infinity = bytes[0] & 0x40 != 0;
    let sort = bytes[0] & 0x20 != 0;
    let mut coordinate = *bytes;
    coordinate[0] &= 0x1f;
    if !compressed || (infinity && (sort || coordinate.iter().any(|&byte| byte != 0))) {
        return None;
    }
    Some((infinity, sort, coordinate))
}

impl G1 {
    pub(super) fn msm_vartime_encoded(points: &[Self], scalars: &[EncodedScalar]) -> Option<Self> {
        if points.len() != scalars.len() {
            return None;
        }
        Some(with_backend(homogeneous::Msm(points, scalars)))
    }

    /// Multiplies by a scalar with a fixed schedule and constant-time selections.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        with_backend(homogeneous::G1Mul(self, scalar))
    }

    // On G1, -phi^2 has eigenvalue |x|^2, where phi multiplies X by beta.
    #[cfg(test)]
    pub(super) fn endomorphism(&self) -> Self {
        let (x, y, z) = (self.x, self.y, self.z);
        Self {
            x: x.mul(BETA_SQUARED),
            y: y.neg(),
            z,
        }
    }

    /// Hashes a public message to G1 using RFC 9380 and the supplied ciphersuite tag.
    ///
    /// This operation is variable time with respect to the message and tag.
    pub fn hash_to_curve(message: &[u8], dst: &[u8]) -> Self {
        super::hash::hash_to_g1(message, dst)
    }

    /// Returns the standard BLS12-381 G1 generator.
    pub fn generator() -> Self {
        Self::from_affine(
            Fp::from_bytes(&G1_X).unwrap(),
            Fp::from_bytes(&G1_Y).unwrap(),
        )
    }

    /// Returns the canonical compressed encoding, including the identity encoding.
    pub fn to_bytes(self) -> [u8; 48] {
        let Some((x, y)) = self.to_affine() else {
            let mut bytes = [0; 48];
            bytes[0] = 0xc0;
            return bytes;
        };
        let mut bytes = x.to_bytes();
        bytes[0] |= 0x80 | (y.lexicographically_largest().unwrap_u8() << 5);
        bytes
    }

    /// Decodes a canonical compressed point in G1. The identity is accepted.
    pub fn from_bytes(bytes: &[u8; 48]) -> Option<Self> {
        let point = Self::on_curve(bytes)?;
        (bytes[0] & 0x40 != 0 || with_backend(homogeneous::InSubgroup(&point))).then(|| Self {
            x: point.x.into(),
            y: point.y.into(),
            z: point.z.into(),
        })
    }

    fn on_curve(bytes: &[u8; 48]) -> Option<homogeneous::G1Point> {
        let (infinity, sort, coordinate) = compressed_flags(bytes)?;
        if infinity {
            return Some(homogeneous::G1Point::identity());
        }
        let x = Fp::from_bytes(&coordinate)?;
        let y = x.square().mul(x).add(Fp::from_u64(4)).sqrt()?;
        let y = Fp::conditional_select(
            &y,
            &y.neg(),
            y.lexicographically_largest() ^ Choice::from(u8::from(sort)),
        );
        Some(homogeneous::G1Point::from_affine(x, y))
    }
}

impl G2 {
    /// Multiplies by a scalar with a fixed schedule and constant-time selections.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        with_backend(homogeneous::G2Mul(self, scalar))
    }

    // Frobenius transported through the sextic twist. These maps are defined on the
    // full curve; their scalar eigenvalues apply only inside the prime-order subgroup.
    #[cfg(test)]
    pub(crate) fn psi(&self) -> Self {
        let (x, y, z) = (self.x, self.y, self.z);
        Self {
            x: Fp2 {
                c0: x.c1.mul(PSI_X),
                c1: x.c0.mul(PSI_X),
            },
            y: y.conjugate().mul(PSI_Y),
            z: z.conjugate(),
        }
    }

    #[cfg(test)]
    pub(crate) fn psi2(&self) -> Self {
        let (x, y, z) = (self.x, self.y, self.z);
        Self {
            x: x.mul_by_fp(PSI2_X),
            y: y.neg(),
            z,
        }
    }

    // The BLS parameter is negative. This integer chain is valid before cofactor
    // clearing and therefore does not use a subgroup endomorphism shortcut.
    #[cfg(test)]
    pub(crate) fn mul_by_x(&self) -> Self {
        with_backend(homogeneous::G2ByX(self))
    }

    /// Hashes a public message to G2 using RFC 9380 and the supplied ciphersuite tag.
    ///
    /// This operation is variable time with respect to the message and tag.
    pub fn hash_to_curve(message: &[u8], dst: &[u8]) -> Self {
        super::hash::hash_to_g2(message, dst)
    }

    /// Returns the standard BLS12-381 G2 generator.
    pub fn generator() -> Self {
        Self::from_affine(
            Fp2 {
                c0: Fp::from_bytes(&G2_X0).unwrap(),
                c1: Fp::from_bytes(&G2_X1).unwrap(),
            },
            Fp2 {
                c0: Fp::from_bytes(&G2_Y0).unwrap(),
                c1: Fp::from_bytes(&G2_Y1).unwrap(),
            },
        )
    }

    /// Returns the canonical compressed encoding, with the imaginary x-coordinate first.
    pub fn to_bytes(self) -> [u8; 96] {
        let mut bytes = [0; 96];
        let Some((x, y)) = self.to_affine() else {
            bytes[0] = 0xc0;
            return bytes;
        };
        bytes[..48].copy_from_slice(&x.c1.to_bytes());
        bytes[48..].copy_from_slice(&x.c0.to_bytes());
        bytes[0] |= 0x80 | (u8::from(y.lexicographically_largest()) << 5);
        bytes
    }

    /// Decodes a canonical compressed point in G2. The identity is accepted.
    pub fn from_bytes(bytes: &[u8; 96]) -> Option<Self> {
        let point = Self::on_curve(bytes)?;
        (bytes[0] & 0x40 != 0 || with_backend(homogeneous::InSubgroup(&point))).then(|| Self {
            x: point.x.into(),
            y: point.y.into(),
            z: point.z.into(),
        })
    }

    fn on_curve(bytes: &[u8; 96]) -> Option<homogeneous::G2Point> {
        let (infinity, sort, coordinate) = compressed_flags(bytes)?;
        if infinity {
            return Some(homogeneous::G2Point::identity());
        }
        let x = Fp2 {
            c0: Fp::from_bytes(coordinate[48..].try_into().unwrap())?,
            c1: Fp::from_bytes(coordinate[..48].try_into().unwrap())?,
        };
        let four = Fp::from_u64(4);
        let y = x.square().mul(x).add(Fp2 { c0: four, c1: four }).sqrt()?;
        let y = Fp2::conditional_select(
            &y,
            &y.neg(),
            Choice::from(u8::from(y.lexicographically_largest() != sort)),
        );
        Some(homogeneous::G2Point::from_affine(x, y))
    }
}

// RFC 9380, Appendix G.3: the x coefficient is purely imaginary, and the
// square of psi has a real x coefficient and negates y.
const PSI_X: Fp = Fp::from_raw(&[
    0x8bfd00000000aaad,
    0x409427eb4f49fffd,
    0x897d29650fb85f9b,
    0xaa0d857d89759ad4,
    0xec02408663d4de85,
    0x1a0111ea397fe699,
])
.expect("canonical psi x coefficient");
const PSI_Y: Fp2 = Fp2 {
    c0: Fp::from_raw(&[
        0xf1ee7b04121bdea2,
        0x304466cf3e67fa0a,
        0xef396489f61eb45e,
        0x1c3dedd930b1cf60,
        0xe2e9c448d77a2cd9,
        0x135203e60180a68e,
    ])
    .expect("canonical psi y coefficient"),
    c1: Fp::from_raw(&[
        0xc81084fbede3cc09,
        0xee67992f72ec05f4,
        0x77f76e17009241c5,
        0x48395dabc2d3435e,
        0x6831e36d6bd17ffe,
        0x06af0e0437ff400b,
    ])
    .expect("canonical psi y coefficient"),
};
const PSI2_X: Fp = Fp::from_raw(&[
    0x8bfd00000000aaac,
    0x409427eb4f49fffd,
    0x897d29650fb85f9b,
    0xaa0d857d89759ad4,
    0xec02408663d4de85,
    0x1a0111ea397fe699,
])
.expect("canonical psi squared x coefficient");
const BETA_SQUARED: Fp = Fp::from_raw(&[
    0x2e01fffffffefffe,
    0xde17d813620a0002,
    0xddb3a93be6f89688,
    0xba69c6076a0f77ea,
    0x5f19672fdf76ce51,
    0,
])
.expect("canonical beta squared");

const G1_X: [u8; 48] = [
    0x17, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c, 0x4f, 0xa9, 0xac, 0x0f,
    0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05, 0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58,
    0x6c, 0x55, 0xe8, 0x3f, 0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
];
const G1_Y: [u8; 48] = [
    0x08, 0xb3, 0xf4, 0x81, 0xe3, 0xaa, 0xa0, 0xf1, 0xa0, 0x9e, 0x30, 0xed, 0x74, 0x1d, 0x8a, 0xe4,
    0xfc, 0xf5, 0xe0, 0x95, 0xd5, 0xd0, 0x0a, 0xf6, 0x00, 0xdb, 0x18, 0xcb, 0x2c, 0x04, 0xb3, 0xed,
    0xd0, 0x3c, 0xc7, 0x44, 0xa2, 0x88, 0x8a, 0xe4, 0x0c, 0xaa, 0x23, 0x29, 0x46, 0xc5, 0xe7, 0xe1,
];
const G2_X0: [u8; 48] = [
    0x02, 0x4a, 0xa2, 0xb2, 0xf0, 0x8f, 0x0a, 0x91, 0x26, 0x08, 0x05, 0x27, 0x2d, 0xc5, 0x10, 0x51,
    0xc6, 0xe4, 0x7a, 0xd4, 0xfa, 0x40, 0x3b, 0x02, 0xb4, 0x51, 0x0b, 0x64, 0x7a, 0xe3, 0xd1, 0x77,
    0x0b, 0xac, 0x03, 0x26, 0xa8, 0x05, 0xbb, 0xef, 0xd4, 0x80, 0x56, 0xc8, 0xc1, 0x21, 0xbd, 0xb8,
];
const G2_X1: [u8; 48] = [
    0x13, 0xe0, 0x2b, 0x60, 0x52, 0x71, 0x9f, 0x60, 0x7d, 0xac, 0xd3, 0xa0, 0x88, 0x27, 0x4f, 0x65,
    0x59, 0x6b, 0xd0, 0xd0, 0x99, 0x20, 0xb6, 0x1a, 0xb5, 0xda, 0x61, 0xbb, 0xdc, 0x7f, 0x50, 0x49,
    0x33, 0x4c, 0xf1, 0x12, 0x13, 0x94, 0x5d, 0x57, 0xe5, 0xac, 0x7d, 0x05, 0x5d, 0x04, 0x2b, 0x7e,
];
const G2_Y0: [u8; 48] = [
    0x0c, 0xe5, 0xd5, 0x27, 0x72, 0x7d, 0x6e, 0x11, 0x8c, 0xc9, 0xcd, 0xc6, 0xda, 0x2e, 0x35, 0x1a,
    0xad, 0xfd, 0x9b, 0xaa, 0x8c, 0xbd, 0xd3, 0xa7, 0x6d, 0x42, 0x9a, 0x69, 0x51, 0x60, 0xd1, 0x2c,
    0x92, 0x3a, 0xc9, 0xcc, 0x3b, 0xac, 0xa2, 0x89, 0xe1, 0x93, 0x54, 0x86, 0x08, 0xb8, 0x28, 0x01,
];
const G2_Y1: [u8; 48] = [
    0x06, 0x06, 0xc4, 0xa0, 0x2e, 0xa7, 0x34, 0xcc, 0x32, 0xac, 0xd2, 0xb0, 0x2b, 0xc2, 0x8b, 0x99,
    0xcb, 0x3e, 0x28, 0x7e, 0x85, 0xa7, 0x63, 0xaf, 0x26, 0x74, 0x92, 0xab, 0x57, 0x2e, 0x99, 0xab,
    0x3f, 0x37, 0x0d, 0x27, 0x5c, 0xec, 0x1d, 0xa1, 0xaa, 0xa9, 0x07, 0x5f, 0xf0, 0x5f, 0x79, 0xbe,
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::scalar::ORDER;
    #[cfg(not(miri))]
    use blst::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::test_rng;
    use num_bigint::BigInt;
    use rand_core::Rng;

    #[test]
    fn signed_windows_reconstruct_integers() {
        let mut values = alloc::vec![0, 1, u64::MAX as u128, u128::MAX];
        for bit in (5..128).step_by(5) {
            let value = 1u128 << bit;
            values.extend([value - 1, value, value + 1, value >> 1]);
        }
        for value in values {
            let digits = recode_w5::<26>(value);
            assert!(digits.iter().all(|digit| (-16..=16).contains(digit)));
            let reconstructed = digits.iter().rev().fold(BigInt::from(0), |sum, digit| {
                (sum << 5) + BigInt::from(*digit)
            });
            assert_eq!(reconstructed, BigInt::from(value));
            if value <= u64::MAX as u128 {
                let short = recode_w5::<13>(value);
                assert_eq!(
                    short.iter().rev().fold(BigInt::from(0), |sum, digit| {
                        (sum << 5) + BigInt::from(*digit)
                    }),
                    BigInt::from(value)
                );
            }
        }
        assert_eq!(BETA_SQUARED.square().mul(BETA_SQUARED), Fp::ONE);
        assert_ne!(BETA_SQUARED, Fp::ONE);
        let generator = G1::generator();
        assert_eq!(
            generator.endomorphism(),
            generator.mul_words(&[0x100000000, 0xac45a4010001a402])
        );
    }

    #[test]
    fn batch_msm_matches_scalar_path() {
        let generator = G1::generator();
        let mut points = alloc::vec![generator, G1::IDENTITY];
        let mut point = generator.double();
        let scale = Fp::from_u64(7);
        while points.len() < 65 {
            points.push({
                let (x, y, z) = (point.x, point.y, point.z);
                G1 {
                    x: x.mul(scale.square()),
                    y: y.mul(scale.square().mul(scale)),
                    z: z.mul(scale),
                }
            });
            point = point.add_jacobian(&generator);
        }

        let mut coefficients = alloc::vec::Vec::new();
        let mut scalars = alloc::vec::Vec::new();
        for i in 0..points.len() {
            let bytes = match i {
                0 => core::array::from_fn(|i| i as u8),
                2 => [0; 16],
                3 => [0xff; 16],
                _ => {
                    let mut bytes = [0; 16];
                    bytes[0] = 0x80 | i as u8;
                    bytes[7] = (i as u8).wrapping_mul(17);
                    bytes[15] = i as u8;
                    bytes
                }
            };
            coefficients.push(msm::EncodedScalar::from_batch_be_bytes(&bytes));
            let mut scalar = [0; 32];
            scalar[16..].copy_from_slice(&bytes);
            scalars.push(Scalar::from_bytes(&scalar).unwrap());
        }

        // The zero at index two leaves 31 and 32 retained terms at lengths 32 and 33.
        for n in [0, 1, 2, 3, 8, 31, 32, 33, 64, 65] {
            assert_eq!(
                G1::msm_vartime_encoded(&points[..n], &coefficients[..n])
                    .unwrap()
                    .to_bytes(),
                G1::msm_vartime(&points[..n], &scalars[..n])
                    .unwrap()
                    .to_bytes(),
                "terms={n}",
            );
        }
        assert_eq!(G1::msm_vartime_encoded(&points[..1], &[]), None);
        assert_eq!(G1::msm_vartime_encoded(&[], &coefficients[..1]), None);
        coefficients.fill(msm::EncodedScalar::from_batch_be_bytes(&[0; 16]));
        assert_eq!(
            G1::msm_vartime_encoded(&points, &coefficients),
            Some(G1::IDENTITY)
        );
    }

    #[test]
    fn batch_msm_preserves_full_curve_points() {
        let torsion = G1::from_affine(Fp::ZERO, Fp::from_u64(2));
        let points = [
            torsion,
            torsion.add_jacobian(&G1::generator()),
            G1::IDENTITY,
        ];
        for value in [0u128, 1, 1 << 127, u128::MAX] {
            let coefficient = msm::EncodedScalar::from_batch_be_bytes(&value.to_be_bytes());
            let words = [value as u64, (value >> 64) as u64];
            for n in 1..=points.len() {
                let expected = points[..n].iter().fold(G1::IDENTITY, |sum, point| {
                    sum.add_jacobian(&point.mul_words_jacobian(&words))
                });
                assert_eq!(
                    G1::msm_vartime_encoded(&points[..n], &alloc::vec![coefficient; n])
                        .unwrap()
                        .to_bytes(),
                    expected.to_bytes(),
                );
            }
        }
    }

    #[cfg(not(miri))]
    #[test]
    fn batch_msm_full_curve_bucket_inputs() {
        let torsion = G1::from_affine(Fp::ZERO, Fp::from_u64(2));
        let mixed = torsion.add_jacobian(&G1::generator());
        let raw_identity = G1 {
            x: Fp::from_u64(13),
            y: Fp::from_u64(17),
            z: Fp::ZERO,
        };
        for retained in [31, 32, 33, 65] {
            let mut points = alloc::vec::Vec::new();
            let mut coefficients = alloc::vec::Vec::new();
            let mut expected = G1::IDENTITY;
            for i in 0..retained {
                let point = match i % 5 {
                    0 => torsion,
                    1 => mixed,
                    2 => mixed.neg(),
                    3 => raw_identity,
                    _ => torsion.neg(),
                };
                let scale = Fp::from_u64(2 + i as u64 % 11);
                let scaled = G1 {
                    x: point.x.mul(scale.square()),
                    y: point.y.mul(scale.square().mul(scale)),
                    z: point.z.mul(scale),
                };
                let value = [1u128, 1 << 127, u128::MAX][i % 3];
                expected = expected
                    .add_jacobian(&point.mul_words_jacobian(&[value as u64, (value >> 64) as u64]));
                points.extend([raw_identity, scaled]);
                coefficients.extend([
                    EncodedScalar::from_batch_be_bytes(&[0; 16]),
                    EncodedScalar::from_batch_be_bytes(&value.to_be_bytes()),
                ]);
            }
            assert_eq!(
                G1::msm_vartime_encoded(&points, &coefficients)
                    .unwrap()
                    .to_bytes(),
                expected.to_bytes(),
                "retained={retained}",
            );
        }
    }

    #[test]
    fn full_curve_endomorphisms() {
        let b = Fp2 {
            c0: Fp::from_u64(4),
            c1: Fp::from_u64(4),
        };
        let cx = Fp2 {
            c0: Fp::ZERO,
            c1: PSI_X,
        };
        assert_eq!(cx.square().mul(cx), PSI_Y.square());
        assert_eq!(b.conjugate().mul(PSI_Y.square()), b);
        assert_eq!(PSI_X.square(), PSI2_X);
        assert_eq!(PSI_Y.mul(PSI_Y.conjugate()), Fp2::ONE.neg());

        let mut points = alloc::vec![
            G2::IDENTITY,
            G2 {
                x: Fp2::ONE,
                y: Fp2::ZERO,
                z: Fp2::ZERO
            },
            G2::generator(),
            G2::generator().neg(),
        ];
        for value in 0..8 {
            let x = Fp2 {
                c0: Fp::from_u64(value),
                c1: Fp::ONE,
            };
            if let Some(y) = x.square().mul(x).add(b).sqrt() {
                let point = G2::from_affine(x, y);
                points.extend([point, point.mul_words(&ORDER)]);
            }
        }
        let scale = Fp2 {
            c0: Fp::from_u64(2),
            c1: Fp::ONE,
        };
        for point in points {
            for point in [point, {
                let (x, y, z) = (point.x, point.y, point.z);
                G2 {
                    x: x.mul(scale.square()),
                    y: y.mul(scale.square().mul(scale)),
                    z: z.mul(scale),
                }
            }] {
                assert_eq!(point.psi2(), point.psi().psi());
                assert_eq!(
                    point.mul_by_x(),
                    point.mul_words(&[0xd201000000010000]).neg()
                );
                for image in [point.psi(), point.psi2()] {
                    if image.is_identity() {
                        assert!(point.is_identity());
                    } else {
                        let (x, y, z) = (image.x, image.y, image.z);
                        let z2 = z.square();
                        assert_eq!(
                            y.square(),
                            x.square().mul(x).add(b.mul(z2.square().mul(z2)))
                        );
                    }
                }
            }
        }
        assert_eq!(G2::generator().psi(), G2::generator().mul_by_x());
    }

    fn scalars() -> alloc::vec::Vec<Scalar> {
        let mut scalars = alloc::vec![
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::ONE.neg(),
            Scalar::from_u64(u64::MAX)
        ];
        let t = Scalar::from_raw([0x100000000, 0xac45a4010001a402, 0, 0]);
        scalars.extend([t.sub(&Scalar::ONE), t, t.add(&Scalar::ONE)]);
        for bit in [1, 63, 64, 127, 128, 191, 192, 254] {
            let mut bytes = [0; 32];
            bytes[31 - bit / 8] = 1 << (bit % 8);
            scalars.push(Scalar::from_bytes(&bytes).unwrap());
        }
        for byte in [0x55, 0xaa, 0xff] {
            scalars.push(Scalar::from_wide_bytes(&[byte; 64]));
        }
        let mut rng = test_rng();
        for _ in 0..16 {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            scalars.push(Scalar::from_wide_bytes(&bytes));
        }
        scalars
    }

    macro_rules! group_tests {
        ($module:ident, $group:ident, $field:ty, $size:literal, $b:expr,
         $raw:ty, $affine:ty, $generator:path, $uncompress:path, $in_group:path,
         $from_affine:path, $mult:path, $add:path, $compress:path) => {
            mod $module {
                use super::*;

                #[cfg(not(miri))]
                fn oracle_point(bytes: &[u8; $size]) -> $raw {
                    let mut affine = <$affine>::default();
                    let mut point = <$raw>::default();
                    // SAFETY: Buffers have blst's exact sizes. Both accepted statuses initialize
                    // the affine output, including G1's explicit rejection of x = 0 torsion.
                    unsafe {
                        let status = $uncompress(&mut affine, bytes.as_ptr());
                        assert!(matches!(
                            status,
                            BLST_ERROR::BLST_SUCCESS | BLST_ERROR::BLST_POINT_NOT_IN_GROUP
                        ));
                        $from_affine(&mut point, &affine);
                    }
                    point
                }

                #[cfg(not(miri))]
                fn oracle_compress(point: &$raw) -> [u8; $size] {
                    let mut bytes = [0; $size];
                    // SAFETY: The output buffer has the group's compressed size and point is initialized.
                    unsafe { $compress(bytes.as_mut_ptr(), point) };
                    bytes
                }

                #[cfg(not(miri))]
                fn oracle_mul(point: &$raw, scalar: &Scalar) -> [u8; $size] {
                    let mut bytes = scalar.to_bytes();
                    bytes.reverse();
                    let mut result = <$raw>::default();
                    // SAFETY: The scalar has 256 readable bits and both point pointers are valid.
                    unsafe { $mult(&mut result, point, bytes.as_ptr(), 256) };
                    oracle_compress(&result)
                }

                #[cfg(not(miri))]
                fn oracle_accepts(bytes: &[u8; $size]) -> bool {
                    let mut affine = <$affine>::default();
                    // SAFETY: The input and output have blst's required fixed sizes; subgroup
                    // testing only observes the initialized output of successful decompression.
                    unsafe {
                        $uncompress(&mut affine, bytes.as_ptr()) == BLST_ERROR::BLST_SUCCESS
                            && $in_group(&affine)
                    }
                }

                fn assert_decoding(bytes: &[u8; $size]) {
                    let decoded = $group::from_bytes(bytes);
                    #[cfg(not(miri))]
                    assert_eq!(
                        decoded.is_some(),
                        oracle_accepts(bytes),
                        "bytes={bytes:02x?}"
                    );
                    if let Some(point) = decoded {
                        assert_eq!(point.to_bytes(), *bytes);
                    }
                }

                #[test]
                fn generators_and_scalar_chains_match_blst() {
                    let generator = $group::generator();
                    #[cfg(not(miri))]
                    // SAFETY: blst returns a pointer to its static group generator.
                    let oracle_generator = unsafe { *$generator() };
                    #[cfg(not(miri))]
                    assert_eq!(generator.to_bytes(), oracle_compress(&oracle_generator));
                    assert!(!generator.is_identity());
                    assert!($group::IDENTITY.is_identity());
                    assert_eq!($group::IDENTITY.mul_words(&[]), $group::IDENTITY);
                    assert_eq!(generator.mul_words(&ORDER), $group::IDENTITY);

                    let scalars = scalars();
                    for (index, scalar) in scalars.iter().enumerate() {
                        let point = generator.mul(scalar);
                        #[cfg(not(miri))]
                        assert_eq!(point.to_bytes(), oracle_mul(&oracle_generator, scalar));
                        assert_eq!($group::from_bytes(&point.to_bytes()), Some(point));
                        assert_eq!(point.mul(&Scalar::ZERO), $group::IDENTITY);
                        assert_eq!(point.mul(&Scalar::ONE), point);
                        assert_eq!(point.mul(&Scalar::ONE.neg()), point.neg());
                        assert_eq!(point.add(&point), point.double());
                        assert_eq!(point.add(&point.neg()), $group::IDENTITY);
                        assert_eq!(point.add(&$group::IDENTITY), point);
                        assert_eq!($group::IDENTITY.add(&point), point);

                        let other_scalar = scalars[(index + 7) % scalars.len()];
                        let other = generator.mul(&other_scalar);
                        #[cfg(not(miri))]
                        assert_eq!(
                            point.mul(&other_scalar).to_bytes(),
                            oracle_mul(&oracle_point(&point.to_bytes()), &other_scalar)
                        );
                        assert_eq!(point.add(&other), generator.mul(&scalar.add(&other_scalar)));
                        assert_eq!(point.sub(&other), generator.mul(&scalar.sub(&other_scalar)));
                        #[cfg(not(miri))]
                        {
                            let mut oracle_sum = <$raw>::default();
                            // SAFETY: Both input points are initialized and output is writable.
                            unsafe {
                                $add(
                                    &mut oracle_sum,
                                    &oracle_point(&point.to_bytes()),
                                    &oracle_point(&other.to_bytes()),
                                )
                            };
                            assert_eq!(point.add(&other).to_bytes(), oracle_compress(&oracle_sum));
                        }
                    }
                }

                #[test]
                fn projective_equivalence_and_exceptional_addition() {
                    let generator = $group::generator();
                    let scale = <$field>::from_u64(7);
                    let scaled = {
                        let (x, y, _) = (generator.x, generator.y, generator.z);
                        $group { x: x.mul(scale.square()), y: y.mul(scale.square()).mul(scale), z: scale }
                    };
                    assert_eq!(scaled, generator);
                    assert_eq!(scaled.to_bytes(), generator.to_bytes());
                    assert_eq!(scaled.add(&generator), generator.double());
                    assert_eq!(scaled.add(&generator.neg()), $group::IDENTITY);
                    assert_eq!(generator.add(&scaled.neg()), $group::IDENTITY);
                    let scalar = Scalar::from_wide_bytes(&[42; 64]);
                    assert_eq!(scaled.mul(&scalar), generator.mul(&scalar));
                    for identity in [
                        $group::IDENTITY,
                        $group { x: <$field>::ONE, y: <$field>::ZERO, z: <$field>::ZERO },
                        generator.sub(&generator),
                    ] {
                        assert_eq!(identity, $group::IDENTITY);
                        assert_eq!(identity.mul(&scalar), $group::IDENTITY);
                        assert_ne!(identity, generator);
                        assert_eq!(identity.add(&scaled), generator);
                        assert_eq!(scaled.add(&identity), generator);
                        assert_eq!(identity.double(), $group::IDENTITY);
                        assert_eq!(identity.neg(), $group::IDENTITY);
                        assert_eq!(identity.to_bytes(), $group::IDENTITY.to_bytes());
                    }
                    let a = generator.double();
                    let b = a.add(&generator);
                    assert_eq!(scaled.add(&a).add(&b), scaled.add(&a.add(&b)));
                }

                #[cfg(not(miri))]
                #[test]
                fn msm_vartime_matches_blst() {
                    let mut points = alloc::vec![$group::IDENTITY];
                    for i in 1..65 {
                        points.push(points[i - 1].add_jacobian(&$group::generator()));
                    }
                    let values = scalars();
                    for bits in [128, 255] {
                        let coefficients: alloc::vec::Vec<_> = (0..points.len())
                            .map(|i| {
                                let scalar = values[1 + i % (values.len() - 1)];
                                if bits == 128 {
                                    let mut bytes = scalar.to_bytes();
                                    bytes[..16].fill(0);
                                    Scalar::from_bytes(&bytes).unwrap()
                                } else {
                                    scalar
                                }
                            })
                            .collect();
                        for n in [0, 1, 2, 8, 31, 32, 33, 64, 65] {
                            let mut expected = <$raw>::default();
                            for (point, scalar) in points[..n].iter().zip(&coefficients[..n]) {
                                let product = oracle_point(&oracle_mul(
                                    &oracle_point(&point.to_bytes()),
                                    scalar,
                                ));
                                let previous = expected;
                                // SAFETY: All points are initialized and the output is writable.
                                unsafe { $add(&mut expected, &previous, &product) };
                            }
                            assert_eq!(
                                $group::msm_vartime(&points[..n], &coefficients[..n])
                                    .unwrap()
                                    .to_bytes(),
                                oracle_compress(&expected),
                                "terms={n} scalar_bits={bits}",
                            );
                        }
                    }
                    assert_eq!($group::msm_vartime(&[], &[]), Some($group::IDENTITY));
                    assert_eq!($group::msm_vartime(&points[..1], &[]), None);
                    assert_eq!($group::msm_vartime(&[], &[Scalar::ONE]), None);
                    assert_eq!(
                        $group::msm_vartime(&points, &alloc::vec![Scalar::ZERO; points.len()]),
                        Some($group::IDENTITY),
                    );
                }

                #[cfg(not(miri))]
                #[test]
                fn msm_vartime_filters_before_window_selection() {
                    for retained in [31, 32] {
                        for bits in [128, 255] {
                            let mut points = alloc::vec::Vec::new();
                            let mut coefficients = alloc::vec::Vec::new();
                            let mut point = $group::generator();
                            let scale = <$field>::from_u64(7);
                            let mut expected = <$raw>::default();
                            for i in 0..retained {
                                let mut bytes = [0; 32];
                                bytes[31 - (bits - 1) / 8] = 1 << ((bits - 1) % 8);
                                bytes[31] = i as u8 + 1;
                                let scalar = Scalar::from_bytes(&bytes).unwrap();
                                let projective = {
                                    let (x, y, z) = (point.x, point.y, point.z);
                                    $group { x: x.mul(scale.square()), y: y.mul(scale.square().mul(scale)), z: z.mul(scale) }
                                };
                                points.extend([projective, projective.neg()]);
                                coefficients.extend([scalar, Scalar::ZERO]);
                                let product = oracle_point(&oracle_mul(
                                    &oracle_point(&projective.to_bytes()),
                                    &scalar,
                                ));
                                let previous = expected;
                                // SAFETY: All points are initialized and the output is writable.
                                unsafe { $add(&mut expected, &previous, &product) };
                                point = point.add_jacobian(&$group::generator());
                            }
                            let result = $group::msm_vartime(&points, &coefficients).unwrap();
                            assert_eq!(result.to_bytes(), oracle_compress(&expected));
                            assert_eq!(
                                result.to_bytes(),
                                with_backend(homogeneous::Msm(&points, &coefficients)).to_bytes(),
                            );
                            coefficients.fill(Scalar::ZERO);
                            assert_eq!(
                                $group::msm_vartime(&points, &coefficients).unwrap().to_bytes(),
                                $group::IDENTITY.to_bytes(),
                            );
                        }
                    }
                }

                #[cfg(not(miri))]
                #[test]
                fn msm_vartime_projective_and_repeated_points() {
                    let point = $group::generator();
                    let scale = <$field>::from_u64(7);
                    let point = {
                        let (x, y, z) = (point.x, point.y, point.z);
                        $group { x: x.mul(scale.square()), y: y.mul(scale.square().mul(scale)), z: z.mul(scale) }
                    };
                    let raw = oracle_point(&point.to_bytes());
                    for scalar in scalars() {
                        assert_eq!(
                            $group::msm_vartime(&[point], &[scalar]).unwrap().to_bytes(),
                            oracle_mul(&raw, &scalar),
                        );
                    }
                    let coefficient = Scalar::ONE.neg();
                    let expected = point.neg();
                    assert_eq!(
                        $group::msm_vartime(
                            &[point, $group::IDENTITY],
                            &[coefficient, Scalar::ONE],
                        ),
                        Some(expected),
                    );
                    assert_eq!(
                        $group::msm_vartime(
                            &[$group::IDENTITY, point],
                            &[Scalar::ONE, coefficient],
                        ),
                        Some(expected),
                    );
                    let mut points: alloc::vec::Vec<_> = (0..32)
                        .map(|i| if i % 2 == 0 { point } else { point.neg() })
                        .collect();
                    let mut coefficients = alloc::vec![Scalar::ONE; 32];
                    assert_eq!(
                        $group::msm_vartime(&points, &coefficients),
                        Some($group::IDENTITY),
                    );
                    points[31] = $group::IDENTITY;
                    coefficients[0] = coefficient;
                    assert_eq!(
                        $group::msm_vartime(&points, &coefficients),
                        Some(expected),
                    );
                }

                #[cfg(not(miri))]
                #[test]
                fn msm_vartime_normalization_boundaries() {
                    let chunk = 192 * 1024 / core::mem::size_of::<$field>();
                    let generator = $group::generator();
                    let raw_identity = $group {
                        x: <$field>::from_u64(13),
                        y: <$field>::from_u64(17),
                        z: <$field>::ONE.sub(<$field>::ONE),
                    };
                    for finite in [0, 1, chunk - 1, chunk, chunk + 1] {
                        let mut points = alloc::vec::Vec::new();
                        let mut coefficients = alloc::vec::Vec::new();
                        let mut weight = 0i64;
                        for i in 0..finite {
                            let negative = i % 3 == 1;
                            let point = if negative { generator.neg() } else { generator };
                            let scale = <$field>::from_u64(2 + i as u64 % 11);
                            points.push($group {
                                x: point.x.mul(scale.square()),
                                y: point.y.mul(scale.square().mul(scale)),
                                z: point.z.mul(scale),
                            });
                            let coefficient = 1 + (i % 2) as u64;
                            coefficients.push(Scalar::from_u64(coefficient));
                            weight += if negative { -(coefficient as i64) } else { coefficient as i64 };
                        }
                        if finite < 32 {
                            points.extend(alloc::vec![raw_identity; 32]);
                            coefficients.extend(alloc::vec![Scalar::ONE; 32]);
                        }
                        let expected_point = if weight < 0 { generator.neg() } else { generator };
                        let expected = oracle_mul(
                            &oracle_point(&expected_point.to_bytes()),
                            &Scalar::from_u64(weight.unsigned_abs()),
                        );
                        assert_eq!(
                            $group::msm_vartime(&points, &coefficients).unwrap().to_bytes(),
                            expected,
                            "finite={finite}",
                        );
                        points.insert(points.len() / 2, raw_identity);
                        coefficients.insert(coefficients.len() / 2, Scalar::ONE);
                        points.insert(0, generator);
                        coefficients.insert(0, Scalar::ZERO);
                        assert_eq!(
                            $group::msm_vartime(&points, &coefficients).unwrap().to_bytes(),
                            expected,
                            "finite={finite} interleaved identity and zero coefficient",
                        );
                    }
                }

                #[test]
                fn compressed_hostile_domain_matches_blst() {
                    let generator = $group::generator().to_bytes();
                    let identity = $group::IDENTITY.to_bytes();
                    for base in [generator, identity] {
                        for flags in 0..8 {
                            let mut bytes = base;
                            bytes[0] = (bytes[0] & 0x1f) | (flags << 5);
                            assert_decoding(&bytes);
                        }
                    }
                    for index in 1..$size {
                        let mut malformed_identity = identity;
                        malformed_identity[index] = 1;
                        assert_decoding(&malformed_identity);
                    }
                    let modulus = [
                        0x1a, 0x01, 0x11, 0xea, 0x39, 0x7f, 0xe6, 0x9a, 0x4b, 0x1b, 0xa7, 0xb6,
                        0x43, 0x4b, 0xac, 0xd7, 0x64, 0x77, 0x4b, 0x84, 0xf3, 0x85, 0x12, 0xbf,
                        0x67, 0x30, 0xd2, 0xa0, 0xf6, 0xb0, 0xf6, 0x24, 0x1e, 0xab, 0xff, 0xfe,
                        0xb1, 0x53, 0xff, 0xff, 0xb9, 0xfe, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xab,
                    ];
                    for coordinate in 0..($size / 48) {
                        let mut bytes = generator;
                        bytes[coordinate * 48..(coordinate + 1) * 48].copy_from_slice(&modulus);
                        bytes[0] |= 0x80;
                        assert_decoding(&bytes);
                    }
                    for byte in [0, 0x1f, 0x80, 0xff] {
                        assert_decoding(&[byte; $size]);
                    }
                    let mut rng = test_rng();
                    for _ in 0..32 {
                        let mut bytes = [0; $size];
                        rng.fill_bytes(&mut bytes);
                        bytes[0] = (bytes[0] & 0x1f) | 0x80;
                        assert_decoding(&bytes);
                    }
                }

                #[test]
                fn torsion_and_mixed_subgroups_are_rejected() {
                    let torsion = (0..32)
                        .find_map(|value| {
                            let x = <$field>::from_u64(value);
                            let y = x.square().mul(x).add($b).sqrt()?;
                            let point = $group::from_affine(x, y);
                            let point = point.mul_words_jacobian(&ORDER);
                            (!point.is_identity()).then_some(point)
                        })
                        .expect("small x-coordinate on the full curve");
                    let generator = $group::generator();
                    for point in [
                        torsion,
                        torsion.neg(),
                        generator.add_jacobian(&torsion),
                        generator.add_jacobian(&torsion.neg()),
                    ] {
                        let (x, y) = point.to_affine().expect("nonidentity full-curve fixture");
                        assert_eq!(y.square(), x.square().mul(x).add($b));
                        assert!(!point.mul_words_jacobian(&ORDER).is_identity());
                        assert!($group::from_bytes(&point.to_bytes()).is_none());
                        #[cfg(not(miri))]
                        assert!(!oracle_accepts(&point.to_bytes()));
                        assert_eq!(point.add(&point.neg()), $group::IDENTITY);
                        assert_eq!(point.add(&point), point.double());
                        #[cfg(not(miri))]
                        {
                            let raw = oracle_point(&point.to_bytes());
                            let mut doubled = <$raw>::default();
                            // SAFETY: Both operands are initialized on-curve points and output is writable.
                            unsafe { $add(&mut doubled, &raw, &raw) };
                            assert_eq!(point.double().to_bytes(), oracle_compress(&doubled));
                        }
                    }
                }

                #[test]
                fn codec_roundtrip_and_truncation() {
                    for point in [
                        $group::IDENTITY,
                        $group::generator(),
                        $group::generator().neg(),
                    ] {
                        assert_eq!($group::decode(point.encode()).unwrap(), point);
                        for len in 0..$size {
                            assert!($group::decode(point.to_bytes()[..len].to_vec()).is_err());
                        }
                    }
                }
            }
        };
    }

    group_tests!(
        g1,
        G1,
        Fp,
        48,
        Fp::from_u64(4),
        blst_p1,
        blst_p1_affine,
        blst_p1_generator,
        blst_p1_uncompress,
        blst_p1_affine_in_g1,
        blst_p1_from_affine,
        blst_p1_mult,
        blst_p1_add_or_double,
        blst_p1_compress
    );
    group_tests!(
        g2,
        G2,
        Fp2,
        96,
        Fp2 {
            c0: Fp::from_u64(4),
            c1: Fp::from_u64(4)
        },
        blst_p2,
        blst_p2_affine,
        blst_p2_generator,
        blst_p2_uncompress,
        blst_p2_affine_in_g2,
        blst_p2_from_affine,
        blst_p2_mult,
        blst_p2_add_or_double,
        blst_p2_compress
    );

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::{G1, G2};
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<G1> => 32,
            CodecConformance<G2> => 32,
        }
    }
}

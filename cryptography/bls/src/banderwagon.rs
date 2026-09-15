//! The prime-order Banderwagon quotient of the Bandersnatch curve.
//!
//! Coordinates use the BLS12-381 scalar field. Group exponents use the distinct
//! 253-bit [`Scalar`] field. Group encodings are big-endian; scalar encodings are
//! little-endian. Decoding accepts the identity and checks subgroup membership.

use crate::{bls12381::scalar::Scalar as Coordinate, hash::expand_message_xmd};
use alloc::{vec, vec::Vec};
use bytes::BufMut;
use commonware_codec::{Buf, FixedSize, Read, Write};
use commonware_cryptography_vroom::{
    Backend, BanderScalar, BlsScalar, Element, WithBackend,
    rns::{Ring, Standard},
    with_backend,
};
use core::fmt;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::{Zeroize, Zeroizing};

/// A Banderwagon exponent with a canonical 32-byte little-endian encoding.
///
/// Zero is valid. Debug output is redacted; [Zeroize] erases the value.
#[derive(Clone, Copy, Zeroize)]
pub struct Scalar(Element<BanderScalar>);

impl Scalar {
    /// The additive identity.
    pub const ZERO: Self = Self(Element::ZERO);

    /// The multiplicative identity.
    pub const ONE: Self = Self(Element::ONE);

    /// Constructs a scalar from an unsigned integer.
    pub const fn from_u64(value: u64) -> Self {
        Self(Element::from_u64(value))
    }

    /// Decodes a little-endian integer strictly below the group order.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let mut bytes = *bytes;
        bytes.reverse();
        Element::from_bytes(&bytes).map(Self)
    }

    /// Reduces a 512-bit little-endian integer modulo the group order.
    pub fn from_wide_bytes(bytes: &[u8; 64]) -> Self {
        let mut bytes = *bytes;
        bytes.reverse();
        Self(Element::from_bytes_mod_order(&bytes))
    }

    /// Returns the canonical little-endian encoding.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut bytes = self.0.to_bytes();
        bytes.reverse();
        bytes
    }

    /// Returns whether this scalar is zero.
    pub fn is_zero(&self) -> bool {
        bool::from(self.ct_eq(&Self::ZERO))
    }

    /// Adds two scalars modulo the group order.
    pub fn add(&self, rhs: &Self) -> Self {
        Self(self.0.add(rhs.0))
    }

    /// Subtracts two scalars modulo the group order.
    pub fn sub(&self, rhs: &Self) -> Self {
        Self(self.0.sub(rhs.0))
    }

    /// Returns the additive inverse.
    pub fn neg(&self) -> Self {
        Self(self.0.neg())
    }

    /// Multiplies two scalars modulo the group order.
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(self.0.mul(rhs.0))
    }

    /// Squares this scalar modulo the group order.
    pub fn square(&self) -> Self {
        Self(self.0.square())
    }

    /// Returns the multiplicative inverse, or `None` for zero.
    ///
    /// Uses a fixed schedule; the returned variant reveals zero.
    pub fn invert(&self) -> Option<Self> {
        self.0.invert().map(Self)
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar(REDACTED)")
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for Scalar {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for Scalar {}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(Element::conditional_select(&a.0, &b.0, choice))
    }
}

// Canonical Bandersnatch parameters: arkworks-rs/curves@e2d16a27e2cfa9f972ae9772df827a22730011b4,
// ed_on_bls12_381_bandersnatch/src/curves/mod.rs. The blst constants are Montgomery
// residues; these limbs equal those residues * 2^-256 modulo the coordinate field.
const D: Coordinate = Coordinate::from_raw([
    0xb369_f2f5_188d_58e7,
    0xcb66_6771_77e5_4f92,
    0xc66e_3bf8_6be3_b6d8,
    0x6389_c126_33c2_67cb,
]);

fn mul_by_a(value: Coordinate) -> Coordinate {
    let twice = value.add(&value);
    twice.add(&twice).add(&value).neg()
}

/// A Banderwagon group element in extended Edwards coordinates.
///
/// The representation stays in the subgroup of order `2r`, with `z != 0` and
/// `xy = tz`. Quotient equality identifies `(x, y)` with `(-x, -y)`, giving a
/// group of prime order `r`. Coordinates are private to preserve these invariants.
#[derive(Clone, Copy, Debug)]
pub struct G {
    x: Coordinate,
    y: Coordinate,
    t: Coordinate,
    z: Coordinate,
}

impl G {
    /// The additive identity.
    pub const IDENTITY: Self = Self {
        x: Coordinate::ZERO,
        y: Coordinate::ONE,
        t: Coordinate::ZERO,
        z: Coordinate::ONE,
    };

    /// Returns the additive identity.
    pub const fn identity() -> Self {
        Self::IDENTITY
    }

    /// Returns the standard Bandersnatch generator in the Banderwagon quotient.
    pub const fn generator() -> Self {
        Self {
            x: Coordinate::from_raw([
                0xe1e7_1866_a252_ae18,
                0x2b79_c022_ad99_8465,
                0x7437_1177_7bbe_42f3,
                0x29c1_32cc_2c0b_34c5,
            ]),
            y: Coordinate::from_raw([
                0x5e31_67b6_cc97_4166,
                0x358c_ad81_eee4_6460,
                0x157d_8b50_badc_d586,
                0x2a6c_669e_da12_3e0f,
            ]),
            t: Coordinate::from_raw([
                0xe259_4f7a_0d47_81ab,
                0x53e5_1c12_1b53_8d00,
                0x571f_0fdc_470a_c5ea,
                0x5e61_c8a1_1056_2844,
            ]),
            z: Coordinate::ONE,
        }
    }

    /// Returns whether this element is the quotient identity.
    pub fn is_identity(&self) -> bool {
        bool::from(self.x.ct_eq(&Coordinate::ZERO))
    }

    /// Adds two group elements, including equal, opposite, and identity operands.
    pub fn add(&self, rhs: &Self) -> Self {
        with_backend(Add(self, rhs))
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn add_with_ring<B: Backend>(&self, rhs: &Self, ring: &Ring<BlsScalar, B>) -> Self {
        // Extended Edwards addition with a = -5. The subgroup of order 2r excludes
        // the points at infinity where this curve's addition law is exceptional.
        let [x1, y1, t1, z1] = [self.x.0, self.y.0, self.t.0, self.z.0].map(Standard::from);
        let [x2, y2, t2, z2] = [rhs.x.0, rhs.y.0, rhs.t.0, rhs.z.0].map(Standard::from);
        let [xx, yy, c, d1, zz] = ring.batch_reduce_expand(&[
            ring.ready::<800>(ring.prep_left(x1) * x2),
            ring.ready::<800>(ring.prep_left(y1) * y2),
            ring.ready::<800>(ring.prep_left(x1 + y1) * ring.prep(x2 + y2)),
            ring.ready::<800>(ring.prep_left(Standard::from(D.0)) * t1),
            ring.ready::<800>(ring.prep_left(z1) * z2),
        ]);
        let [dt] = ring.batch_reduce_expand(&[ring.ready::<800>(ring.prep_left(d1) * t2)]);
        let cross = ring.prep_left(c - xx - yy);
        let y = ring.prep_left(yy - xx.scale::<-5>());
        let minus = ring.prep_left(zz - dt);
        let plus = ring.prep(zz + dt);
        let [x, y, t, z] = ring.batch_reduce_expand(&[
            ring.ready::<800>(cross * minus.into_expanded()),
            ring.ready::<800>(y * plus),
            ring.ready::<800>(cross * y.into_expanded()),
            ring.ready::<800>(minus * plus),
        ]);
        Self {
            x: Coordinate(x.into()),
            y: Coordinate(y.into()),
            t: Coordinate(t.into()),
            z: Coordinate(z.into()),
        }
    }

    /// Returns twice this element.
    pub fn double(&self) -> Self {
        with_backend(Double(self))
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn double_with_ring<B: Backend>(&self, ring: &Ring<BlsScalar, B>) -> Self {
        let [x, y, z] = [self.x.0, self.y.0, self.z.0].map(Standard::from);
        let xy = ring.prep_left(x + y);
        let [xx, yy, zz, c] = ring.batch_reduce_expand(&[
            ring.ready::<800>(ring.prep_left(x) * x),
            ring.ready::<800>(ring.prep_left(y) * y),
            ring.ready::<800>(ring.prep_left(z) * z),
            ring.ready::<800>(xy * xy.into_expanded()),
        ]);
        let axx = xx.scale::<-5>();
        let cross = ring.prep_left(c - xx - yy);
        let g = axx + yy;
        let f = ring.prep_left(g - zz.scale::<2>());
        let h = ring.prep(axx - yy);
        let g = ring.prep_left(g);
        let [x, y, t, z] = ring.batch_reduce_expand(&[
            ring.ready::<800>(cross * f.into_expanded()),
            ring.ready::<800>(g * h),
            ring.ready::<800>(cross * h),
            ring.ready::<800>(f * g.into_expanded()),
        ]);
        Self {
            x: Coordinate(x.into()),
            y: Coordinate(y.into()),
            t: Coordinate(t.into()),
            z: Coordinate(z.into()),
        }
    }

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn gather_window<B: Backend>(table: &[Self; 8], digit: i8, ring: &Ring<BlsScalar, B>) -> Self {
        let mask = (digit as i16) >> 7;
        let magnitude = ((digit as i16 ^ mask).wrapping_sub(mask)) as u8;
        let mut result = Self::IDENTITY;
        for (i, point) in table.iter().enumerate() {
            result = Self::conditional_select(&result, point, magnitude.ct_eq(&((i + 1) as u8)));
        }
        let negative_x = Coordinate(ring.standard_negate(Standard::from(result.x.0)).into());
        let negative_t = Coordinate(ring.standard_negate(Standard::from(result.t.0)).into());
        let sign = Choice::from(mask as u8 & 1);
        result.x = Coordinate::conditional_select(&result.x, &negative_x, sign);
        result.t = Coordinate::conditional_select(&result.t, &negative_t, sign);
        result
    }

    /// Returns the additive inverse.
    pub fn neg(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            t: self.t.neg(),
            z: self.z,
        }
    }

    /// Subtracts a group element.
    pub fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.neg())
    }

    /// Multiplies by a scalar with a fixed schedule and constant-time selections.
    pub fn mul(&self, scalar: &Scalar) -> Self {
        let bytes = Zeroizing::new(scalar.to_bytes());
        with_backend(Mul {
            point: self,
            scalar: &bytes,
        })
    }

    /// Computes the sum of point-scalar products in variable time.
    ///
    /// All points and scalars must be public. Returns `None` for unequal lengths
    /// and the identity for empty inputs. Zero scalars and identity points are valid.
    pub fn msm_vartime(points: &[Self], scalars: &[Scalar]) -> Option<Self> {
        if points.len() != scalars.len() {
            return None;
        }
        if let [point] = points {
            return Some(point.mul(&scalars[0]));
        }
        if points.is_empty() {
            return Some(Self::IDENTITY);
        }
        let scalars: Vec<_> = scalars.iter().map(|scalar| scalar.to_bytes()).collect();
        Some(with_backend(Msm(points, &scalars)))
    }

    /// Returns the squared affine x-coordinate, independent of quotient representative.
    pub fn x_squared(&self) -> Coordinate {
        self.x
            .mul(&self.z.invert().expect("group elements have nonzero z"))
            .square()
    }

    /// Returns the squared x-coordinate after multiplication by a coordinate-field integer.
    ///
    /// The exponent is the canonical 255-bit integer represented by `scalar`. Addition
    /// of these exponents in the coordinate field does not commute with group multiplication.
    pub fn scalar_mul_x_squared_base(&self, scalar: &Coordinate) -> Coordinate {
        let mut bytes = Zeroizing::new(scalar.to_bytes());
        bytes.reverse();
        with_backend(Mul {
            point: self,
            scalar: &bytes,
        })
        .x_squared()
    }

    /// Returns the canonical big-endian group encoding.
    pub fn to_bytes(self) -> [u8; 32] {
        let inverse = self.z.invert().expect("group elements have nonzero z");
        let x = self.x.mul(&inverse);
        let y = self.y.mul(&inverse);
        Coordinate::conditional_select(&x.neg(), &x, y.is_positive()).to_bytes()
    }

    /// Decodes a canonical group encoding, checking the curve equation and subgroup.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        Self::from_x(Coordinate::from_bytes(bytes)?)
    }

    fn from_x(x: Coordinate) -> Option<Self> {
        // The Legendre test selects the subgroup of order 2r. Both a and d are
        // nonsquares, so neither 1-a*x^2 nor 1-d*x^2 can vanish for a field abscissa.
        let xx = x.square();
        let numerator = Coordinate::ONE.sub(&mul_by_a(xx));
        if !numerator.is_square() {
            return None;
        }
        let denominator = Coordinate::ONE.sub(&D.mul(&xx));
        let y = numerator.mul(&denominator.invert()?).sqrt()?;
        let y = Coordinate::conditional_select(&y.neg(), &y, y.is_positive());
        Some(Self {
            x,
            y,
            t: x.mul(&y),
            z: Coordinate::ONE,
        })
    }

    /// Hashes public inputs using Commonware's Banderwagon try-and-increment map.
    ///
    /// Each candidate uses RFC 9380 SHA-256 XMD hash-to-field over
    /// `message || counter.to_be_bytes()`, starting at zero. The first valid encoding
    /// is returned. Allocation failure or exhaustion of 512 attempts returns `None`.
    /// This map is variable-time and must only receive public inputs.
    pub fn hash_to_group(domain_separator: &[u8], message: &[u8]) -> Option<Self> {
        let mut data = Vec::new();
        data.try_reserve_exact(message.len().checked_add(8)?).ok()?;
        data.extend_from_slice(message);
        data.extend_from_slice(&[0; 8]);
        for counter in 0u64..512 {
            data[message.len()..].copy_from_slice(&counter.to_be_bytes());
            let expanded = expand_message_xmd::<48>(&data, domain_separator);
            let mut wide = [0; 64];
            wide[16..].copy_from_slice(&expanded);
            if let Some(point) = Self::from_x(Coordinate::from_wide_bytes(&wide)) {
                return Some(point);
            }
        }
        None
    }
}

struct Add<'a>(&'a G, &'a G);

impl WithBackend for Add<'_> {
    type Output = G;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn call<B: Backend>(self, backend: B) -> G {
        self.0.add_with_ring(self.1, &Ring::new(backend))
    }
}

struct Double<'a>(&'a G);

impl WithBackend for Double<'_> {
    type Output = G;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn call<B: Backend>(self, backend: B) -> G {
        self.0.double_with_ring(&Ring::new(backend))
    }
}

// Both exponent fields contain integers below 2^255. The final nibble and carry
// therefore fit in the positive table range 0..=8.
fn recode_w4(bytes: &[u8; 32]) -> Zeroizing<[i8; 64]> {
    let mut carry = Zeroizing::new(0i16);
    let mut digits = Zeroizing::new([0; 64]);
    for (i, digit) in digits[..63].iter_mut().enumerate() {
        let window = ((bytes[i / 2] >> (4 * (i % 2))) & 15) as i16 + *carry;
        *carry = (window + 8) >> 4;
        *digit = (window - (*carry << 4)) as i8;
    }
    digits[63] = (bytes[31] >> 4) as i8 + *carry as i8;
    digits
}

struct Mul<'a> {
    point: &'a G,
    scalar: &'a [u8; 32],
}

impl WithBackend for Mul<'_> {
    type Output = G;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn call<B: Backend>(self, backend: B) -> G {
        let ring = Ring::<BlsScalar, B>::new(backend);
        let digits = recode_w4(self.scalar);
        let mut table = [G::IDENTITY; 8];
        table[0] = *self.point;
        table[1] = self.point.double_with_ring(&ring);
        for i in 1..4 {
            table[2 * i] = table[i].add_with_ring(&table[i - 1], &ring);
            table[2 * i + 1] = table[i].double_with_ring(&ring);
        }
        let mut result = G::gather_window(&table, digits[63], &ring);
        for window in (0..63).rev() {
            for _ in 0..4 {
                result = result.double_with_ring(&ring);
            }
            result = result.add_with_ring(&G::gather_window(&table, digits[window], &ring), &ring);
        }
        result
    }
}

struct Msm<'a>(&'a [G], &'a [[u8; 32]]);

impl WithBackend for Msm<'_> {
    type Output = G;

    #[cfg_attr(not(debug_assertions), inline(always))]
    fn call<B: Backend>(self, backend: B) -> G {
        let bits = self
            .1
            .iter()
            .map(|scalar| {
                scalar
                    .iter()
                    .rposition(|byte| *byte != 0)
                    .map_or(0, |i| 8 * i + 8 - scalar[i].leading_zeros() as usize)
            })
            .max()
            .unwrap_or(0);
        if bits == 0 {
            return G::IDENTITY;
        }

        // Arkworks' unsigned Pippenger window policy, capped to bound bucket storage.
        let width = if self.0.len() < 32 {
            3
        } else {
            let log2 = usize::BITS - (self.0.len() - 1).leading_zeros();
            (log2 as usize * 69 / 100 + 2).min(10)
        };
        let mask = (1 << width) - 1;
        let windows = bits.div_ceil(width);
        let ring = Ring::<BlsScalar, B>::new(backend);
        let mut buckets = vec![G::IDENTITY; mask];
        let mut result = G::IDENTITY;
        for window in (0..windows).rev() {
            if window != windows - 1 {
                for _ in 0..width {
                    result = result.double_with_ring(&ring);
                }
            }
            buckets.fill(G::IDENTITY);
            let bit = window * width;
            let byte = bit / 8;
            let mut used = 0;
            for (point, scalar) in self.0.iter().zip(self.1) {
                let word = u32::from_le_bytes([
                    scalar[byte],
                    scalar.get(byte + 1).copied().unwrap_or(0),
                    scalar.get(byte + 2).copied().unwrap_or(0),
                    0,
                ]);
                let digit = ((word >> (bit % 8)) as usize) & mask;
                if digit != 0 {
                    buckets[digit - 1] = buckets[digit - 1].add_with_ring(point, &ring);
                    used = used.max(digit);
                }
            }
            let mut running = G::IDENTITY;
            for bucket in buckets[..used].iter().rev() {
                running = running.add_with_ring(bucket, &ring);
                result = result.add_with_ring(&running, &ring);
            }
        }
        result
    }
}

impl ConstantTimeEq for G {
    fn ct_eq(&self, other: &Self) -> Choice {
        // The x:y ratio absorbs both projective scaling and the quotient's sign pair.
        self.x.mul(&other.y).ct_eq(&other.x.mul(&self.y))
    }
}

impl PartialEq for G {
    fn eq(&self, other: &Self) -> bool {
        bool::from(self.ct_eq(other))
    }
}

impl Eq for G {}

impl ConditionallySelectable for G {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self {
            x: Coordinate::conditional_select(&a.x, &b.x, choice),
            y: Coordinate::conditional_select(&a.y, &b.y, choice),
            t: Coordinate::conditional_select(&a.t, &b.t, choice),
            z: Coordinate::conditional_select(&a.z, &b.z, choice),
        }
    }
}

macro_rules! codec {
    ($name:ident) => {
        impl FixedSize for $name {
            const SIZE: usize = 32;
        }

        impl Write for $name {
            fn write(&self, buf: &mut impl BufMut) {
                self.to_bytes().write(buf);
            }
        }

        impl Read for $name {
            type Cfg = ();

            fn read_cfg(buf: &mut impl Buf, cfg: &()) -> Result<Self, commonware_codec::Error> {
                Self::from_bytes(&<[u8; 32]>::read_cfg(buf, cfg)?).ok_or(
                    commonware_codec::Error::Invalid(
                        concat!("banderwagon::", stringify!($name)),
                        "invalid encoding",
                    ),
                )
            }
        }
    };
}

codec!(Scalar);
codec!(G);

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Scalar {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0u8..=3)? {
            0 => Self::ZERO,
            1 => Self::ONE,
            2 => Self::ONE.neg(),
            _ => Self::from_wide_bytes(&u.arbitrary()?),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for G {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::generator().mul(&u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, VariableBaseMSM};
    use ark_ed_on_bls12_381_bandersnatch::{
        EdwardsAffine as ArkAffine, EdwardsProjective as ArkProjective, Fr as ArkScalar,
    };
    use ark_ff::{BigInteger, PrimeField};
    use commonware_codec::{Copying, Decode, DecodeExt, Encode, ReadExt};
    use commonware_cryptography::{
        banderwagon::{F as LegacyScalar, G as LegacyG},
        bls12381::primitives::group::{Scalar as LegacyCoordinate, ScalarReadCfg},
    };
    use commonware_math::algebra::{
        Additive as _, CryptoGroup as _, Field as _, HashToGroup as _, msm_naive,
    };
    use commonware_utils::test_rng;
    use num_bigint::{BigInt, BigUint, Sign};
    use rand_core::Rng;

    const ORDER: [u64; 4] = [
        0x74fd_06b5_2876_e7e1,
        0xff8f_8700_7419_0471,
        0x0cce_7602_0268_7600,
        0x1cfb_69d4_ca67_5f52,
    ];

    fn modulus() -> BigUint {
        let mut bytes = [0; 32];
        for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(ORDER) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        BigUint::from_bytes_le(&bytes)
    }

    fn scalar(value: &BigUint) -> Scalar {
        let encoded = value.to_bytes_le();
        let mut bytes = [0; 32];
        bytes[..encoded.len()].copy_from_slice(&encoded);
        Scalar::from_bytes(&bytes).unwrap()
    }

    fn legacy_scalar(value: &BigUint) -> LegacyScalar {
        LegacyScalar::decode(Copying(&scalar(value).to_bytes())).unwrap()
    }

    fn legacy_group_bytes(point: &LegacyG) -> [u8; 32] {
        point.encode().as_ref().try_into().unwrap()
    }

    fn legacy_coordinate(value: &Coordinate) -> LegacyCoordinate {
        LegacyCoordinate::decode_cfg(Copying(&value.to_bytes()), &ScalarReadCfg::AllowZero).unwrap()
    }

    fn check_group(actual: &G, expected: &LegacyG) {
        assert_eq!(actual.to_bytes(), legacy_group_bytes(expected));
        assert_eq!(G::from_bytes(&actual.to_bytes()), Some(*actual));
    }

    fn random_scalar(rng: &mut impl Rng) -> Scalar {
        let mut bytes = [0; 64];
        rng.fill_bytes(&mut bytes);
        Scalar::from_wide_bytes(&bytes)
    }

    fn random_scalar_128(rng: &mut impl Rng) -> Scalar {
        let mut bytes = [0; 32];
        rng.fill_bytes(&mut bytes[..16]);
        Scalar::from_bytes(&bytes).unwrap()
    }

    fn ark_scalar(scalar: &Scalar) -> ArkScalar {
        let bytes = scalar.to_bytes();
        let scalar = ArkScalar::from_le_bytes_mod_order(&bytes);
        let encoded = scalar.into_bigint().to_bytes_le();
        let mut canonical = [0; 32];
        canonical[..encoded.len()].copy_from_slice(&encoded);
        assert_eq!(canonical, bytes);
        scalar
    }

    fn ark_encoding(point: &ArkAffine) -> [u8; 32] {
        if point.is_zero() {
            return [0; 32];
        }
        let x = if point.y > -point.y {
            point.x
        } else {
            -point.x
        };
        let encoded = x.into_bigint().to_bytes_be();
        let mut bytes = [0; 32];
        bytes[32 - encoded.len()..].copy_from_slice(&encoded);
        bytes
    }

    fn ark_point(weight: &Scalar) -> ArkAffine {
        ArkProjective::generator()
            .mul_bigint(ark_scalar(weight).into_bigint())
            .into_affine()
    }

    fn check_ark_msm(points: &[G], scalars: &[Scalar], ark_points: &[ArkAffine]) {
        let native = G::msm_vartime(points, scalars).unwrap();
        let coefficients: Vec<_> = scalars.iter().map(ark_scalar).collect();
        let arkworks = ArkProjective::msm(ark_points, &coefficients).unwrap();
        assert_eq!(native.to_bytes(), ark_encoding(&arkworks.into_affine()));
    }

    fn check_msm(points: &[G], scalars: &[Scalar]) -> G {
        let actual = G::msm_vartime(points, scalars).unwrap();
        let native = points
            .iter()
            .zip(scalars)
            .fold(G::IDENTITY, |sum, (point, scalar)| {
                sum.add(&point.mul(scalar))
            });
        assert_eq!(actual, native);

        let legacy_points: Vec<_> = points
            .iter()
            .map(|point| LegacyG::decode(Copying(&point.to_bytes())).unwrap())
            .collect();
        let legacy_scalars: Vec<_> = scalars
            .iter()
            .map(|scalar| LegacyScalar::decode(Copying(&scalar.to_bytes())).unwrap())
            .collect();
        check_group(&actual, &msm_naive(&legacy_points, &legacy_scalars));
        actual
    }

    #[test]
    fn scalar_arithmetic_matches_biguint_and_legacy() {
        // Cover scalar and limb boundaries as well as deterministic samples.
        let modulus = modulus();
        let mut rng = test_rng();
        let mut values = vec![
            BigUint::from(0u8),
            BigUint::from(1u8),
            &modulus - 1u8,
            BigUint::from(u64::MAX),
            BigUint::from(1u8) << 252usize,
        ];
        for bit in [63, 64, 127, 128, 191, 192] {
            values.push(BigUint::from(1u8) << bit);
        }
        for _ in 0..16 {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            values.push(BigUint::from_bytes_le(&bytes) % &modulus);
        }

        for a in &values {
            let native = scalar(a);
            let legacy = legacy_scalar(a);
            assert_eq!(native.to_bytes().as_slice(), legacy.encode().as_ref());
            assert_eq!(native.neg(), scalar(&((&modulus - a) % &modulus)));
            assert_eq!(native.square(), scalar(&((a * a) % &modulus)));
            assert_eq!(
                native.neg().to_bytes().as_slice(),
                (-legacy.clone()).encode().as_ref()
            );
            assert_eq!(
                native.square().to_bytes().as_slice(),
                (legacy.clone() * &legacy).encode().as_ref()
            );

            // Zero is rejected by native inversion; the commonware_cryptography API returns its zero sentinel.
            if a == &BigUint::from(0u8) {
                assert!(native.invert().is_none());
                assert_eq!(legacy.inv(), LegacyScalar::zero());
            } else {
                let inverse = native.invert().unwrap();
                assert_eq!(inverse, scalar(&a.modpow(&(&modulus - 2u8), &modulus)));
                assert_eq!(
                    inverse.to_bytes().as_slice(),
                    legacy.inv().encode().as_ref()
                );
            }

            // Check each pair against both integer arithmetic and commonware_cryptography.
            for b in &values {
                let other = scalar(b);
                let legacy_other = legacy_scalar(b);
                let sum = native.add(&other);
                let difference = native.sub(&other);
                let product = native.mul(&other);
                assert_eq!(sum, scalar(&((a + b) % &modulus)));
                assert_eq!(difference, scalar(&((a + &modulus - b) % &modulus)));
                assert_eq!(product, scalar(&((a * b) % &modulus)));
                assert_eq!(
                    sum.to_bytes().as_slice(),
                    (legacy.clone() + &legacy_other).encode().as_ref()
                );
                assert_eq!(
                    difference.to_bytes().as_slice(),
                    (legacy.clone() - &legacy_other).encode().as_ref()
                );
                assert_eq!(
                    product.to_bytes().as_slice(),
                    (legacy.clone() * &legacy_other).encode().as_ref()
                );
            }
        }
    }

    #[test]
    fn scalar_reduction_and_codec_match_biguint_and_legacy() {
        let modulus = modulus();
        let mut rng = test_rng();
        assert_eq!(Scalar::from_wide_bytes(&[0; 64]), Scalar::ZERO);
        for index in 0..24 {
            let mut bytes = [0xff; 64];
            if index != 0 {
                rng.fill_bytes(&mut bytes);
            }
            let expected = BigUint::from_bytes_le(&bytes) % &modulus;
            let reduced = Scalar::from_wide_bytes(&bytes);
            assert_eq!(reduced, scalar(&expected));
            assert_eq!(
                reduced.to_bytes().as_slice(),
                legacy_scalar(&expected).encode().as_ref()
            );
            assert_eq!(
                Scalar::decode(Copying(&reduced.to_bytes())).unwrap(),
                reduced
            );
        }

        let mut order = [0; 32];
        for (chunk, limb) in order.as_chunks_mut::<8>().0.iter_mut().zip(ORDER) {
            chunk.copy_from_slice(&limb.to_le_bytes());
        }
        for bytes in [order, [0xff; 32]] {
            assert!(Scalar::from_bytes(&bytes).is_none());
            assert!(Scalar::decode(Copying(&bytes)).is_err());
            assert!(LegacyScalar::decode(Copying(&bytes)).is_err());
        }
    }

    #[test]
    fn group_arithmetic_matches_legacy() {
        let modulus = modulus();
        let mut rng = test_rng();
        check_group(&G::IDENTITY, &LegacyG::zero());
        check_group(&G::generator(), &LegacyG::generator());

        for _ in 0..24 {
            let mut a_bytes = [0; 32];
            let mut b_bytes = [0; 32];
            rng.fill_bytes(&mut a_bytes);
            rng.fill_bytes(&mut b_bytes);
            let a = BigUint::from_bytes_le(&a_bytes) % &modulus;
            let b = BigUint::from_bytes_le(&b_bytes) % &modulus;
            let native_a = G::generator().mul(&scalar(&a));
            let native_b = G::generator().mul(&scalar(&b));
            let legacy_a = LegacyG::generator() * &legacy_scalar(&a);
            let legacy_b = LegacyG::generator() * &legacy_scalar(&b);

            check_group(&native_a, &legacy_a);
            check_group(&native_a.add(&native_b), &(legacy_a.clone() + &legacy_b));
            check_group(&native_a.sub(&native_b), &(legacy_a.clone() - &legacy_b));
            check_group(&native_a.neg(), &(-legacy_a.clone()));
            check_group(&native_a.double(), &{
                let mut point = legacy_a.clone();
                point.double();
                point
            });
            let one = LegacyCoordinate::from_u64(1);
            assert_eq!(
                native_a.x_squared().to_bytes().as_slice(),
                legacy_a.scalar_mul_x_squared_base(&one).encode().as_ref()
            );
        }
    }

    #[test]
    fn hash_and_group_decoding_match_legacy() {
        let mut rng = test_rng();
        for length in [0, 1, 255, 256, 300] {
            let dst = vec![0x5a; length];
            let native = G::hash_to_group(&dst, b"domain-length").unwrap();
            let legacy = LegacyG::hash_to_group(&dst, b"domain-length");
            check_group(&native, &legacy);
        }

        for index in 0..16 {
            let mut dst = [0; 24];
            let mut message = [0; 48];
            rng.fill_bytes(&mut dst);
            rng.fill_bytes(&mut message);
            let dst = &dst[..index + 1];
            let message = &message[..index * 3];
            let native = G::hash_to_group(dst, message).unwrap();
            let legacy = LegacyG::hash_to_group(dst, message);
            check_group(&native, &legacy);
        }

        for _ in 0..32 {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            let native = G::from_bytes(&bytes);
            let legacy = LegacyG::decode(Copying(&bytes)).ok();
            assert_eq!(native.is_some(), legacy.is_some());
            if let (Some(native), Some(legacy)) = (native, legacy) {
                check_group(&native, &legacy);
                assert_eq!(G::decode(Copying(&bytes)).unwrap(), native);
            } else {
                assert!(G::decode(Copying(&bytes)).is_err());
            }
        }

        let bytes = [0xff; 32];
        assert!(G::from_bytes(&bytes).is_none());
        assert!(LegacyG::decode(Copying(&bytes)).is_err());
    }

    #[test]
    fn coordinate_and_exponent_moduli_remain_distinct() {
        let integer = BigUint::from(1u8) << 254usize;
        let mut base_bytes = [0; 32];
        let encoded = integer.to_bytes_be();
        base_bytes[32 - encoded.len()..].copy_from_slice(&encoded);
        let base = Coordinate::from_bytes(&base_bytes).unwrap();
        let legacy_base = legacy_coordinate(&base);

        let mut exponent_bytes = [0; 32];
        exponent_bytes.copy_from_slice(&base_bytes);
        exponent_bytes.reverse();
        assert!(Scalar::from_bytes(&exponent_bytes).is_none());
        let mut wide = [0; 64];
        wide[..32].copy_from_slice(&exponent_bytes);
        let reduced = Scalar::from_wide_bytes(&wide);

        let base_result = G::generator().scalar_mul_x_squared_base(&base);
        assert_eq!(base_result, G::generator().mul(&reduced).x_squared());
        assert_eq!(
            base_result.to_bytes().as_slice(),
            LegacyG::generator()
                .scalar_mul_x_squared_base(&legacy_base)
                .encode()
                .as_ref()
        );
    }

    #[test]
    fn msm_singleton_and_sparse_inputs() {
        let point = G::generator().mul(&Scalar::from_u64(17));
        assert!(G::msm_vartime(&[point], &[Scalar::ONE, Scalar::ONE]).is_none());
        assert!(G::msm_vartime(&[point, point], &[Scalar::ONE]).is_none());
        assert!(G::msm_vartime(&[point], &[]).is_none());
        assert!(G::msm_vartime(&[], &[Scalar::ONE]).is_none());
        assert_eq!(G::msm_vartime(&[], &[]), Some(G::IDENTITY));

        let mut full = [0x55; 32];
        full[31] = 0x15;
        let mut short = [0xaa; 32];
        short[16..].fill(0);
        let coefficients = [
            Scalar::ZERO,
            Scalar::ONE,
            Scalar::ONE.neg(),
            scalar(&(BigUint::from(1u8) << 252usize)),
            Scalar::from_bytes(&short).unwrap(),
            Scalar::from_bytes(&full).unwrap(),
        ];
        let scale = Coordinate::from_u64(7);
        let representatives = [
            point,
            G {
                x: point.x.neg(),
                y: point.y.neg(),
                ..point
            },
            G {
                x: point.x.mul(&scale),
                y: point.y.mul(&scale),
                t: point.t.mul(&scale),
                z: point.z.mul(&scale),
            },
            G::IDENTITY,
            G {
                y: Coordinate::ONE.neg(),
                ..G::IDENTITY
            },
        ];
        let ark_point = ark_point(&Scalar::from_u64(17));
        for coefficient in coefficients {
            for representative in representatives {
                check_msm(&[representative], &[coefficient]);
            }
            check_ark_msm(&[point], &[coefficient], &[ark_point]);
            assert_eq!(
                check_msm(&[point, point.neg()], &[coefficient, Scalar::ZERO]),
                point.mul(&coefficient)
            );
        }
    }

    #[test]
    fn msm_lengths_match_naive_oracles() {
        let mut rng = test_rng();
        for len in [1, 2, 10, 31, 32, 33, 64] {
            let points: Vec<_> = (0..len)
                .map(|_| G::generator().mul(&random_scalar(&mut rng)))
                .collect();
            let full: Vec<_> = (0..len).map(|_| random_scalar(&mut rng)).collect();
            let short: Vec<_> = (0..len).map(|_| random_scalar_128(&mut rng)).collect();
            check_msm(&points, &full);
            check_msm(&points, &short);
        }
    }

    #[test]
    fn msm_boundaries_and_lengths() {
        assert_eq!(G::msm_vartime(&[], &[]), Some(G::IDENTITY));
        assert!(G::msm_vartime(&[G::generator()], &[]).is_none());
        assert!(G::msm_vartime(&[], &[Scalar::ONE]).is_none());

        let modulus = modulus();
        let mut values = vec![
            BigUint::from(0u8),
            BigUint::from(1u8),
            &modulus - 1u8,
            BigUint::from(1u8) << 252usize,
        ];
        for bit in [63, 64, 127, 128, 191, 192] {
            values.push(BigUint::from(1u8) << bit);
        }
        let scalars: Vec<_> = values.iter().map(scalar).collect();
        let mut points: Vec<_> = scalars
            .iter()
            .map(|scalar| G::generator().mul(scalar))
            .collect();
        points[0] = G::IDENTITY;
        check_msm(&points, &scalars);

        let full_width = scalar(&(&modulus - 1u8));
        assert_eq!(check_msm(&[G::IDENTITY], &[full_width]), G::IDENTITY);
        assert_eq!(check_msm(&[G::generator()], &[Scalar::ZERO]), G::IDENTITY);
    }

    #[test]
    fn msm_matches_arkworks_reference() {
        let modulus = modulus();
        let mut rng = test_rng();
        let mut scalars = vec![
            Scalar::ZERO,
            Scalar::ONE,
            scalar(&(&modulus - 1u8)),
            scalar(&(BigUint::from(1u8) << 252usize)),
            random_scalar(&mut rng),
            random_scalar_128(&mut rng),
        ];
        let weights: Vec<_> = (1..=scalars.len())
            .map(|value| Scalar::from_u64(value as u64))
            .collect();
        let points: Vec<_> = weights
            .iter()
            .map(|weight| G::generator().mul(weight))
            .collect();
        let ark_points: Vec<_> = weights.iter().map(ark_point).collect();
        for (point, ark_point) in points.iter().zip(&ark_points) {
            assert_eq!(point.to_bytes(), ark_encoding(ark_point));
        }
        assert_eq!(G::msm_vartime(&[], &[]), Some(G::IDENTITY));
        assert_eq!(
            ark_encoding(&ArkProjective::default().into_affine()),
            [0; 32]
        );
        check_ark_msm(&points, &scalars, &ark_points);

        let point = points[1];
        let twin = G {
            x: point.x.neg(),
            y: point.y.neg(),
            t: point.t,
            z: point.z,
        };
        assert_eq!(point, twin);
        assert_eq!(point.to_bytes(), ark_encoding(&ark_points[1]));
        scalars.truncate(2);
        let cancellation = [Scalar::ONE, Scalar::ONE];
        let ark_cancellation = [ark_points[1], (-ark_points[1].into_group()).into_affine()];
        check_ark_msm(&[point, point.neg()], &cancellation, &ark_cancellation);
        check_ark_msm(&[point, twin], &scalars, &[ark_points[1], ark_points[1]]);
    }

    #[test]
    fn msm_handles_representatives_and_cancellation() {
        let point = G::generator().mul(&Scalar::from_u64(17));
        let twin = G {
            x: point.x.neg(),
            y: point.y.neg(),
            t: point.t,
            z: point.z,
        };
        let lambda = Coordinate::from_u64(7);
        let scaled = G {
            x: point.x.mul(&lambda),
            y: point.y.mul(&lambda),
            t: point.t.mul(&lambda),
            z: point.z.mul(&lambda),
        };
        assert_eq!(point, twin);
        assert_eq!(point, scaled);
        check_msm(
            &[point, twin, scaled],
            &[
                Scalar::from_u64(3),
                Scalar::from_u64(5),
                Scalar::from_u64(7),
            ],
        );

        let coefficient = scalar(&(modulus() - 1u8));
        assert_eq!(
            check_msm(&[point, point.neg()], &[coefficient, coefficient]),
            G::IDENTITY
        );
        assert_eq!(
            check_msm(&[point, point], &[Scalar::ONE, scalar(&(modulus() - 1u8))]),
            G::IDENTITY
        );
    }

    #[test]
    fn msm_caps_window_for_large_sparse_input() {
        const LEN: usize = 8_193;
        let mut points = vec![G::IDENTITY; LEN];
        let mut scalars = vec![Scalar::ZERO; LEN];
        let terms = [
            (1, Scalar::from_u64(3), BigUint::from(1u8) << 191usize),
            (4_096, Scalar::from_u64(5), BigUint::from(1u8) << 252usize),
            (8_192, Scalar::from_u64(7), modulus() - 1u8),
        ];
        for (index, point_scalar, coefficient) in &terms {
            points[*index] = G::generator().mul(point_scalar);
            scalars[*index] = scalar(coefficient);
        }

        let actual = G::msm_vartime(&points, &scalars).unwrap();
        let legacy_points: Vec<_> = terms
            .iter()
            .map(|(_, point_scalar, _)| {
                LegacyG::generator()
                    * &LegacyScalar::decode(Copying(&point_scalar.to_bytes())).unwrap()
            })
            .collect();
        let legacy_scalars: Vec<_> = terms
            .iter()
            .map(|(_, _, coefficient)| legacy_scalar(coefficient))
            .collect();
        check_group(&actual, &msm_naive(&legacy_points, &legacy_scalars));
    }

    #[test]
    fn window_carries_match_legacy() {
        let mut integers = vec![BigUint::from(0u8), BigUint::from(1u8), modulus() - 1u8];
        for bit in [4usize, 8, 64, 128, 192, 252, 254] {
            let power = BigUint::from(1u8) << bit;
            integers.extend([&power - 1u8, power.clone(), power + 1u8]);
        }
        integers.push(BigUint::from_bytes_be(&Coordinate::ONE.neg().to_bytes()));
        let generator = G::generator();
        let legacy = LegacyG::generator();
        for integer in integers {
            let encoded = integer.to_bytes_be();
            let mut bytes = [0; 32];
            bytes[32 - encoded.len()..].copy_from_slice(&encoded);
            let coordinate = Coordinate::from_bytes(&bytes).unwrap();
            let expected = legacy.scalar_mul_x_squared_base(&legacy_coordinate(&coordinate));
            assert_eq!(
                generator
                    .scalar_mul_x_squared_base(&coordinate)
                    .to_bytes()
                    .as_slice(),
                expected.encode().as_ref()
            );
            bytes.reverse();
            if let Some(exponent) = Scalar::from_bytes(&bytes) {
                check_group(
                    &generator.mul(&exponent),
                    &(legacy.clone() * &legacy_scalar(&integer)),
                );
            }
        }
    }

    #[test]
    fn signed_window_recoding() {
        let mut cases = vec![[0; 32], [0xff; 32]];
        cases[1][31] = 0x7f;
        for nibble in 0..64 {
            for value in 0..16u8 {
                let mut bytes = [0; 32];
                bytes[nibble / 2] = value << (4 * (nibble % 2));
                bytes[31] &= 0x7f;
                cases.push(bytes);
            }
        }
        let mut rng = test_rng();
        for _ in 0..128 {
            let mut bytes = [0; 32];
            rng.fill_bytes(&mut bytes);
            bytes[31] &= 0x7f;
            cases.push(bytes);
        }
        for bytes in cases {
            let digits = recode_w4(&bytes);
            assert!(digits[..63].iter().all(|digit| (-8..8).contains(digit)));
            assert!((0..=8).contains(&digits[63]));
            let reconstructed = digits.iter().rev().fold(BigInt::from(0), |value, digit| {
                (value << 4usize) + BigInt::from(*digit)
            });
            assert_eq!(reconstructed, BigInt::from_bytes_le(Sign::Plus, &bytes));
        }
    }

    fn assert_valid(point: &G) {
        assert!(!point.z.is_zero());
        assert_eq!(point.x.mul(&point.y), point.t.mul(&point.z));
        let xx = point.x.square();
        let yy = point.y.square();
        let zz = point.z.square();
        assert_eq!(mul_by_a(xx).add(&yy), zz.add(&D.mul(&point.t.square())));
        let numerator = zz.sub(&mul_by_a(xx));
        assert!(!numerator.is_zero());
        assert!(numerator.is_square());
    }

    fn twin(point: G) -> G {
        G {
            x: point.x.neg(),
            y: point.y.neg(),
            ..point
        }
    }

    fn scaled(point: G, scale: Coordinate) -> G {
        G {
            x: point.x.mul(&scale),
            y: point.y.mul(&scale),
            t: point.t.mul(&scale),
            z: point.z.mul(&scale),
        }
    }

    #[test]
    fn canonical_constants_and_order() {
        let a = Coordinate::from_u64(5).neg();
        assert!(!a.is_square());
        assert!(!D.is_square());
        assert_valid(&G::generator());
        assert_valid(&G::IDENTITY);
        let bytes = core::array::from_fn(|i| ORDER[i / 8].to_le_bytes()[i % 8]);
        let identity = with_backend(Mul {
            point: &G::generator(),
            scalar: &bytes,
        });
        assert_eq!(identity, G::IDENTITY);
        assert_valid(&identity);
        assert_eq!(G::generator().mul(&Scalar::ONE.neg()), G::generator().neg());
    }

    #[test]
    fn external_codec_vectors() {
        // Successive generator doublings from crate-crypto/rust-verkle
        // e27b8b4edf1992b4afa636c2fc7983bcc27ddb88, banderwagon/src/element.rs.
        let vectors = [
            "4a2c7486fd924882bf02c6908de395122843e3e05264d7991e18e7985dad51e9",
            "43aa74ef706605705989e8fd38df46873b7eae5921fbed115ac9d937399ce4d5",
            "5e5f550494159f38aa54d2ed7f11a7e93e4968617990445cc93ac8e59808c126",
            "0e7e3748db7c5c999a7bcd93d71d671f1f40090423792266f94cb27ca43fce5c",
            "14ddaa48820cb6523b9ae5fe9fe257cbbd1f3d598a28e670a40da5d1159d864a",
            "6989d1c82b2d05c74b62fb0fbdf8843adae62ff720d370e209a7b84e14548a7d",
            "26b8df6fa414bf348a3dc780ea53b70303ce49f3369212dec6fbe4b349b832bf",
            "37e46072db18f038f2cc7d3d5b5d1374c0eb86ca46f869d6a95fc2fb092c0d35",
            "2c1ce64f26e1c772282a6633fac7ca73067ae820637ce348bb2c8477d228dc7d",
            "297ab0f5a8336a7a4e2657ad7a33a66e360fb6e50812d4be3326fab73d6cee07",
            "5b285811efa7a965bd6ef5632151ebf399115fcc8f5b9b8083415ce533cc39ce",
            "1f939fa2fd457b3effb82b25d3fe8ab965f54015f108f8c09d67e696294ab626",
            "3088dcb4d3f4bacd706487648b239e0be3072ed2059d981fe04ce6525af6f1b8",
            "35fbc386a16d0227ff8673bc3760ad6b11009f749bb82d4facaea67f58fc60ed",
            "00f29b4f3255e318438f0a31e058e4c081085426adb0479f14c64985d0b956e0",
            "3fa4384b2fa0ecc3c0582223602921daaa893a97b64bdf94dcaa504e8b7b9e5f",
        ];
        let mut point = G::generator();
        for vector in vectors {
            let bytes = core::array::from_fn(|i| {
                u8::from_str_radix(&vector[2 * i..2 * i + 2], 16).unwrap()
            });
            assert_eq!(point.to_bytes(), bytes);
            let decoded = G::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, point);
            assert!(bool::from(decoded.y.is_positive()));
            assert_valid(&point);
            point = point.double();
        }
        assert_eq!(G::IDENTITY.to_bytes(), [0; 32]);
        assert_eq!(G::from_bytes(&[0; 32]), Some(G::IDENTITY));
        assert_eq!(twin(G::IDENTITY).to_bytes(), [0; 32]);
    }

    #[test]
    fn quotient_and_projective_representatives() {
        let mut rng = test_rng();
        for _ in 0..16 {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            let scalar = Scalar::from_wide_bytes(&bytes);
            let point = G::generator().mul(&scalar);
            let mut scale = Coordinate::from_wide_bytes(&bytes);
            if scale.is_zero() {
                scale = Coordinate::ONE;
            }
            for representative in [
                point,
                twin(point),
                scaled(point, scale),
                scaled(twin(point), scale),
            ] {
                assert_valid(&representative);
                assert_eq!(point, representative);
                assert_eq!(point.to_bytes(), representative.to_bytes());
                assert_eq!(point.x_squared(), representative.x_squared());
                assert_eq!(point.mul(&scalar), representative.mul(&scalar));
                for result in [
                    representative.add(&G::IDENTITY),
                    representative.add(&twin(G::IDENTITY)),
                    representative.add(&point),
                    representative.sub(&point),
                    representative.double(),
                ] {
                    assert_valid(&result);
                }
                assert_eq!(representative.add(&twin(G::IDENTITY)), point);
                assert_eq!(representative.sub(&point), G::IDENTITY);
                assert_eq!(representative.add(&point), point.double());
            }
        }
    }

    #[test]
    fn group_laws_for_decoded_points() {
        let mut rng = test_rng();
        for _ in 0..8 {
            let mut bytes = [0; 64];
            rng.fill_bytes(&mut bytes);
            let a = Scalar::from_wide_bytes(&bytes);
            rng.fill_bytes(&mut bytes);
            let b = Scalar::from_wide_bytes(&bytes);
            let p = G::from_bytes(&G::generator().mul(&a).to_bytes()).unwrap();
            let q = G::from_bytes(&G::generator().mul(&b).to_bytes()).unwrap();
            let r = twin(G::generator());
            assert_eq!(p.add(&q), q.add(&p));
            assert_eq!(p.add(&q).add(&r), p.add(&q.add(&r)));
            assert_eq!(p.mul(&a.add(&b)), p.mul(&a).add(&p.mul(&b)));
            assert_eq!(p.mul(&a.mul(&b)), p.mul(&a).mul(&b));
            assert_eq!(p.mul(&Scalar::ZERO), G::IDENTITY);
            assert_eq!(p.mul(&Scalar::ONE), p);
            assert_valid(&p.add(&q));
            assert_valid(&p.mul(&a));
        }
    }

    #[test]
    fn rejects_other_torsion_cosets_and_noncanonical_inputs() {
        // These abscissae lie on the curve, but 1-a*x^2 is a nonsquare.
        for value in [7, 10, 15, 16] {
            let x = Coordinate::from_u64(value);
            let numerator = Coordinate::ONE.sub(&mul_by_a(x.square()));
            let denominator = Coordinate::ONE.sub(&D.mul(&x.square()));
            assert!(!numerator.is_square());
            assert!(
                numerator
                    .mul(&denominator.invert().unwrap())
                    .sqrt()
                    .is_some()
            );
            assert!(G::from_bytes(&x.to_bytes()).is_none());
        }
        // A square subgroup numerator alone does not establish an on-curve point.
        for value in [4, 6, 9] {
            let x = Coordinate::from_u64(value);
            assert!(Coordinate::ONE.sub(&mul_by_a(x.square())).is_square());
            assert!(G::from_bytes(&x.to_bytes()).is_none());
        }
        let modulus = crate::bls12381::scalar::ORDER;
        let bytes = core::array::from_fn(|i| modulus[3 - i / 8].to_be_bytes()[i % 8]);
        for bytes in [bytes, [0xff; 32]] {
            assert!(G::from_bytes(&bytes).is_none());
            assert!(G::decode(bytes.to_vec()).is_err());
        }
        let max = Coordinate::ONE.neg().to_bytes();
        assert!(Coordinate::from_bytes(&max).is_some());
        assert!(G::from_bytes(&max).is_some());
    }

    #[test]
    fn codec_boundaries_and_erasure() {
        let point = G::generator();
        for len in 0..32 {
            let mut input = bytes::Bytes::copy_from_slice(&point.to_bytes()[..len]);
            assert!(matches!(
                G::read(&mut input),
                Err(commonware_codec::Error::EndOfBuffer)
            ));
            assert_eq!(input.len(), len);
            assert!(Scalar::decode(Scalar::ONE.to_bytes()[..len].to_vec()).is_err());
        }
        let mut input = point.encode_mut();
        input.put_u8(42);
        assert_eq!(G::read(&mut input).unwrap(), point);
        assert_eq!(input.as_ref(), &[42]);
        let mut scalar = Scalar::ONE.neg();
        assert_eq!(alloc::format!("{scalar:?}"), "Scalar(REDACTED)");
        scalar.zeroize();
        assert_eq!(scalar, Scalar::ZERO);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Scalar> => 1024,
            CodecConformance<G> => 1024,
        }
    }
}

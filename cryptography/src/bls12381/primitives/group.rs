//! Group operations over the BLS12-381 scalar field.
//!
//! This crate implements basic group operations over BLS12-381 elements,
//! including point addition, scalar multiplication, and pairing operations.
//!
//! # Warning
//!
//! Ensure that points are checked to belong to the correct subgroup
//! (G1 or G2) to prevent small subgroup attacks. This is particularly important
//! when handling deserialized points or points received from untrusted sources. This
//! is already taken care of for you if you use the provided `deserialize` function.

use super::variant::Variant;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use blst::{
    blst_bendian_from_fp12, blst_bendian_from_scalar, blst_expand_message_xmd, blst_fp12, blst_fr,
    blst_fr_add, blst_fr_from_scalar, blst_fr_from_uint64, blst_fr_inverse, blst_fr_mul,
    blst_fr_sub, blst_hash_to_g1, blst_hash_to_g2, blst_keygen, blst_p1, blst_p1_add_or_double,
    blst_p1_affine, blst_p1_compress, blst_p1_from_affine, blst_p1_in_g1, blst_p1_is_inf,
    blst_p1_mult, blst_p1_to_affine, blst_p1_uncompress, blst_p1s_mult_pippenger,
    blst_p1s_mult_pippenger_scratch_sizeof, blst_p2, blst_p2_add_or_double, blst_p2_affine,
    blst_p2_compress, blst_p2_from_affine, blst_p2_in_g2, blst_p2_is_inf, blst_p2_mult,
    blst_p2_to_affine, blst_p2_uncompress, blst_p2s_mult_pippenger,
    blst_p2s_mult_pippenger_scratch_sizeof, blst_scalar, blst_scalar_from_be_bytes,
    blst_scalar_from_bendian, blst_scalar_from_fr, blst_sk_check, BLS12_381_G1, BLS12_381_G2,
    BLST_ERROR,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt,
    EncodeSize,
    Error::{self, Invalid},
    FixedSize, Read, ReadExt, Write,
};
use commonware_utils::hex;
use core::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    mem::MaybeUninit,
    ptr,
};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation tag used when hashing a message to a curve (G1 or G2).
///
/// Reference: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-ciphersuites>
pub type DST = &'static [u8];

/// An element of a group.
pub trait Element:
    Read<Cfg = ()> + Write + FixedSize + Clone + Eq + PartialEq + Ord + PartialOrd + Hash + Send + Sync
{
    /// Returns the additive identity.
    fn zero() -> Self;

    /// Returns the multiplicative identity.
    fn one() -> Self;

    /// Adds to self in-place.
    fn add(&mut self, rhs: &Self);

    /// Multiplies self in-place.
    fn mul(&mut self, rhs: &Scalar);
}

/// A point on a curve.
pub trait Point: Element {
    /// Maps the provided data to a group element.
    fn map(&mut self, dst: DST, message: &[u8]);

    /// Performs a multi‑scalar multiplication of the provided points and scalars.
    fn msm(points: &[Self], scalars: &[Scalar]) -> Self;
}

/// Wrapper around [blst_fr] that represents an element of the BLS12‑381
/// scalar field `F_r`.
///
/// The new‑type is marked `#[repr(transparent)]`, so it has exactly the same
/// memory layout as the underlying `blst_fr`, allowing safe passage across
/// the C FFI boundary without additional transmutation.
///
/// All arithmetic is performed modulo the prime
/// `r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001`,
/// the order of the BLS12‑381 G1/G2 groups.
#[derive(Clone, Eq, PartialEq)]
#[repr(transparent)]
pub struct Scalar(blst_fr);

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Scalar {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Generate 32 bytes and convert to scalar with automatic modular reduction
        let bytes = u.arbitrary::<[u8; SCALAR_LENGTH]>()?;
        let mut fr = blst_fr::default();
        // SAFETY: bytes is a valid 32-byte array; blst_scalar_from_bendian handles reduction.
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
            blst_fr_from_scalar(&mut fr, &scalar);
        }
        let result = Self(fr);
        // If zero, return one instead (scalars shouldn't be zero per BLS spec)
        if result == Self::zero() {
            Ok(BLST_FR_ONE)
        } else {
            Ok(result)
        }
    }
}

/// Number of bytes required to encode a scalar in its canonical
/// little‑endian form (`32 × 8 = 256 bits`).
///
/// Because `r` is only 255 bits wide, the most‑significant byte is always in
/// the range `0x00‥=0x7f`, leaving the top bit clear.
pub const SCALAR_LENGTH: usize = 32;

/// Effective bit‑length of the field modulus `r` (`⌈log_2 r⌉ = 255`).
///
/// Useful for constant‑time exponentiation loops and for validating that a
/// decoded integer lies in the range `0 ≤ x < r`.
const SCALAR_BITS: usize = 255;

/// This constant serves as the multiplicative identity (i.e., "one") in the
/// BLS12-381 finite field, ensuring that arithmetic is carried out within the
/// correct modulo.
///
/// `R = 2^256 mod q` in little-endian Montgomery form which is equivalent to 1 in little-endian
/// non-Montgomery form:
///
/// ```txt
/// mod(2^256, 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001) = 0x1824b159acc5056f998c4fefecbc4ff55884b7fa0003480200000001fffffffe
/// ```
///
/// Reference: <https://github.com/filecoin-project/blstrs/blob/ffbb41d1495d84e40a712583346439924603b49a/src/scalar.rs#L77-L89>
const BLST_FR_ONE: Scalar = Scalar(blst_fr {
    l: [
        0x0000_0001_ffff_fffe,
        0x5884_b7fa_0003_4802,
        0x998c_4fef_ecbc_4ff5,
        0x1824_b159_acc5_056f,
    ],
});

/// A point on the BLS12-381 G1 curve.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct G1(blst_p1);

/// The size in bytes of an encoded G1 element.
pub const G1_ELEMENT_BYTE_LENGTH: usize = 48;

/// Domain separation tag for hashing a proof of possession (compressed G2) to G1.
pub const G1_PROOF_OF_POSSESSION: DST = b"BLS_POP_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

/// Domain separation tag for hashing a message to G1.
///
/// We use the `POP` scheme for hashing all messages because this crate is expected to be
/// used in a Byzantine environment (where any player may attempt a rogue key attack) and
/// any message could be aggregated into a multi-signature (which requires a proof-of-possession
/// to be safely deployed in this environment).
pub const G1_MESSAGE: DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for G1 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let scalar = u.arbitrary::<Scalar>()?;
        let mut point = Self::one();
        point.mul(&scalar);
        Ok(point)
    }
}

/// A point on the BLS12-381 G2 curve.
#[derive(Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct G2(blst_p2);

/// The size in bytes of an encoded G2 element.
pub const G2_ELEMENT_BYTE_LENGTH: usize = 96;

/// Domain separation tag for hashing a proof of possession (compressed G1) to G2.
pub const G2_PROOF_OF_POSSESSION: DST = b"BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

/// Domain separation tag for hashing a message to G2.
///
/// We use the `POP` scheme for hashing all messages because this crate is expected to be
/// used in a Byzantine environment (where any player may attempt a rogue key attack) and
/// any message could be aggregated into a multi-signature (which requires a proof-of-possession
/// to be safely deployed in this environment).
pub const G2_MESSAGE: DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for G2 {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        // Generate a random scalar and multiply the generator point.
        // This is guaranteed to produce a valid G2 point on the first try.
        let scalar = u.arbitrary::<Scalar>()?;
        let mut point = Self::one();
        point.mul(&scalar);
        Ok(point)
    }
}

/// The target group of the BLS12-381 pairing.
///
/// This is an element in the extension field `F_p^12` and is
/// produced as the result of a pairing operation.
#[derive(Debug, Clone, Eq, PartialEq, Copy)]
#[repr(transparent)]
pub struct GT(blst_fp12);

/// The size in bytes of an encoded GT element.
///
/// GT is a 12-tuple of Fp elements, each 48 bytes.
pub const GT_ELEMENT_BYTE_LENGTH: usize = 576;

impl GT {
    /// Create GT from blst_fp12.
    pub(crate) const fn from_blst_fp12(fp12: blst_fp12) -> Self {
        Self(fp12)
    }

    /// Converts the GT element to its canonical big-endian byte representation.
    pub fn as_slice(&self) -> [u8; GT_ELEMENT_BYTE_LENGTH] {
        let mut slice = [0u8; GT_ELEMENT_BYTE_LENGTH];
        // SAFETY: blst_bendian_from_fp12 writes exactly 576 bytes to a valid buffer.
        // Using the proper serialization function ensures portable, canonical encoding.
        unsafe {
            blst_bendian_from_fp12(slice.as_mut_ptr(), &self.0);
        }
        slice
    }
}

/// The private key type.
pub type Private = Scalar;

/// The private key length.
pub const PRIVATE_KEY_LENGTH: usize = SCALAR_LENGTH;

impl Scalar {
    /// Generates a random scalar using the provided RNG.
    pub fn from_rand<R: CryptoRngCore>(rng: &mut R) -> Self {
        // Generate a random 64 byte buffer
        let mut ikm = [0u8; 64];
        rng.fill_bytes(&mut ikm);

        // Generate a scalar from the randomly populated buffer
        let mut ret = blst_fr::default();
        // SAFETY: ikm is a valid 64-byte buffer; blst_keygen handles null key_info.
        unsafe {
            let mut sc = blst_scalar::default();
            blst_keygen(&mut sc, ikm.as_ptr(), ikm.len(), ptr::null(), 0);
            blst_fr_from_scalar(&mut ret, &sc);
        }

        // Zeroize the ikm buffer
        ikm.zeroize();

        Self(ret)
    }

    /// Maps arbitrary bytes to a scalar using RFC9380 hash-to-field.
    pub fn map(dst: DST, msg: &[u8]) -> Self {
        // The BLS12-381 scalar field has a modulus of approximately 255 bits.
        // According to RFC9380, when mapping to a field element, we need to
        // generate uniform bytes with length L = ceil((ceil(log2(p)) + k) / 8),
        // where p is the field modulus and k is the security parameter.
        //
        // For BLS12-381's scalar field:
        // - log2(p) ≈ 255 bits
        // - k = 128 bits (for 128-bit security)
        // - L = ceil((255 + 128) / 8) = ceil(383 / 8) = 48 bytes
        //
        // These 48 bytes provide sufficient entropy to ensure uniform distribution
        // in the scalar field after modular reduction, maintaining the security
        // properties required by the hash-to-field construction.
        const L: usize = 48;
        let mut uniform_bytes = [0u8; L];
        // SAFETY: All buffers are valid with correct lengths; blst handles empty inputs.
        unsafe {
            blst_expand_message_xmd(
                uniform_bytes.as_mut_ptr(),
                L,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
            );
        }

        // Transform expanded bytes with modular reduction
        let mut fr = blst_fr::default();
        // SAFETY: uniform_bytes is a valid 48-byte buffer.
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_be_bytes(&mut scalar, uniform_bytes.as_ptr(), L);
            blst_fr_from_scalar(&mut fr, &scalar);
        }

        Self(fr)
    }

    /// Creates a new scalar from the provided integer.
    fn from_u64(i: u64) -> Self {
        // Create a new scalar
        let mut ret = blst_fr::default();

        let buffer = [i, 0, 0, 0];

        // SAFETY: blst_fr_from_uint64 reads exactly 4 u64 values from the buffer.
        //
        // Reference: https://github.com/supranational/blst/blob/415d4f0e2347a794091836a3065206edfd9c72f3/bindings/blst.h#L102
        unsafe { blst_fr_from_uint64(&mut ret, buffer.as_ptr()) };
        Self(ret)
    }

    /// Creates a new scalar from the provided index (a scalar offset by 1).
    pub fn from_index(i: u32) -> Self {
        Self::from_u64(i as u64 + 1)
    }

    /// Computes the inverse of the scalar.
    pub fn inverse(&self) -> Option<Self> {
        if *self == Self::zero() {
            return None;
        }
        let mut ret = blst_fr::default();
        // SAFETY: Input is non-zero (checked above); blst_fr_inverse is defined for non-zero.
        unsafe { blst_fr_inverse(&mut ret, &self.0) };
        Some(Self(ret))
    }

    /// Subtracts the provided scalar from self in-place.
    pub fn sub(&mut self, rhs: &Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_fr_sub supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe { blst_fr_sub(ptr, ptr, &rhs.0) }
    }

    /// Encodes the scalar into a slice.
    fn as_slice(&self) -> [u8; Self::SIZE] {
        let mut slice = [0u8; Self::SIZE];
        // SAFETY: All pointers valid; blst_bendian_from_scalar writes exactly 32 bytes.
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_fr(&mut scalar, &self.0);
            blst_bendian_from_scalar(slice.as_mut_ptr(), &scalar);
        }
        slice
    }

    /// Converts the scalar to the raw `blst_scalar` type.
    pub(crate) fn as_blst_scalar(&self) -> blst_scalar {
        let mut scalar = blst_scalar::default();
        // SAFETY: Both pointers are valid and properly aligned.
        unsafe { blst_scalar_from_fr(&mut scalar, &self.0) };
        scalar
    }
}

impl Element for Scalar {
    fn zero() -> Self {
        Self(blst_fr::default())
    }

    fn one() -> Self {
        BLST_FR_ONE
    }

    fn add(&mut self, rhs: &Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_fr_add supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_fr_add(ptr, ptr, &rhs.0);
        }
    }

    fn mul(&mut self, rhs: &Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_fr_mul supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_fr_mul(ptr, ptr, &rhs.0);
        }
    }
}

impl Write for Scalar {
    fn write(&self, buf: &mut impl BufMut) {
        let slice = self.as_slice();
        buf.put_slice(&slice);
    }
}

impl Read for Scalar {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let bytes = <[u8; Self::SIZE]>::read(buf)?;
        let mut ret = blst_fr::default();
        // SAFETY: bytes is a valid 32-byte array. blst_sk_check validates non-zero and in-range.
        // We use blst_sk_check instead of blst_scalar_fr_check because it also checks non-zero
        // per IETF BLS12-381 spec (Draft 4+).
        //
        // References:
        // * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-03#section-2.3
        // * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
            if !blst_sk_check(&scalar) {
                return Err(Invalid("Scalar", "Invalid"));
            }
            blst_fr_from_scalar(&mut ret, &scalar);
        }
        Ok(Self(ret))
    }
}

impl FixedSize for Scalar {
    const SIZE: usize = SCALAR_LENGTH;
}

impl Hash for Scalar {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let slice = self.as_slice();
        state.write(&slice);
    }
}

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_slice().cmp(&other.as_slice())
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl Display for Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.l.zeroize();
    }
}

impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Scalar {}

/// A share of a threshold signing key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct Share {
    /// The share's index in the polynomial.
    pub index: u32,
    /// The scalar corresponding to the share's secret.
    pub private: Private,
}

impl AsRef<Private> for Share {
    fn as_ref(&self) -> &Private {
        &self.private
    }
}

impl Share {
    /// Returns the public key corresponding to the share.
    ///
    /// This can be verified against the public polynomial.
    pub fn public<V: Variant>(&self) -> V::Public {
        let mut public = V::Public::one();
        public.mul(&self.private);
        public
    }
}

impl Write for Share {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.private.write(buf);
    }
}

impl Read for Share {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let index = UInt::read(buf)?.into();
        let private = Private::read(buf)?;
        Ok(Self { index, private })
    }
}

impl EncodeSize for Share {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + self.private.encode_size()
    }
}

impl Display for Share {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Share(index={}, private={})", self.index, self.private)
    }
}

impl Debug for Share {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Share(index={}, private={})", self.index, self.private)
    }
}

impl G1 {
    /// Encodes the G1 element into a slice.
    fn as_slice(&self) -> [u8; Self::SIZE] {
        let mut slice = [0u8; Self::SIZE];
        // SAFETY: blst_p1_compress writes exactly 48 bytes to a valid buffer.
        unsafe {
            blst_p1_compress(slice.as_mut_ptr(), &self.0);
        }
        slice
    }

    /// Converts the G1 point to its affine representation.
    pub(crate) fn as_blst_p1_affine(&self) -> blst_p1_affine {
        let mut affine = blst_p1_affine::default();
        // SAFETY: Both pointers are valid and properly aligned.
        unsafe { blst_p1_to_affine(&mut affine, &self.0) };
        affine
    }

    /// Creates a G1 point from a raw `blst_p1`.
    pub(crate) const fn from_blst_p1(p: blst_p1) -> Self {
        Self(p)
    }
}

impl Element for G1 {
    fn zero() -> Self {
        Self(blst_p1::default())
    }

    fn one() -> Self {
        let mut ret = blst_p1::default();
        // SAFETY: BLS12_381_G1 is a valid generator point constant.
        unsafe {
            blst_p1_from_affine(&mut ret, &BLS12_381_G1);
        }
        Self(ret)
    }

    fn add(&mut self, rhs: &Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_p1_add_or_double supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_p1_add_or_double(ptr, ptr, &rhs.0);
        }
    }

    fn mul(&mut self, rhs: &Scalar) {
        let ptr = &raw mut self.0;
        let mut scalar: blst_scalar = blst_scalar::default();
        // SAFETY: blst_p1_mult supports in-place (ret==a). Using SCALAR_BITS (255) ensures
        // constant-time execution. Raw pointer avoids aliased refs.
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.0);
            blst_p1_mult(ptr, ptr, scalar.b.as_ptr(), SCALAR_BITS);
        }
    }
}

impl Write for G1 {
    fn write(&self, buf: &mut impl BufMut) {
        let slice = self.as_slice();
        buf.put_slice(&slice);
    }
}

impl Read for G1 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let bytes = <[u8; Self::SIZE]>::read(buf)?;
        let mut ret = blst_p1::default();
        // SAFETY: bytes is a valid 48-byte array. blst_p1_uncompress validates encoding.
        // Additional checks for infinity and subgroup membership prevent small subgroup attacks.
        unsafe {
            let mut affine = blst_p1_affine::default();
            match blst_p1_uncompress(&mut affine, bytes.as_ptr()) {
                BLST_ERROR::BLST_SUCCESS => {}
                BLST_ERROR::BLST_BAD_ENCODING => return Err(Invalid("G1", "Bad encoding")),
                BLST_ERROR::BLST_POINT_NOT_ON_CURVE => return Err(Invalid("G1", "Not on curve")),
                BLST_ERROR::BLST_POINT_NOT_IN_GROUP => return Err(Invalid("G1", "Not in group")),
                BLST_ERROR::BLST_AGGR_TYPE_MISMATCH => return Err(Invalid("G1", "Type mismatch")),
                BLST_ERROR::BLST_VERIFY_FAIL => return Err(Invalid("G1", "Verify fail")),
                BLST_ERROR::BLST_PK_IS_INFINITY => return Err(Invalid("G1", "PK is Infinity")),
                BLST_ERROR::BLST_BAD_SCALAR => return Err(Invalid("G1", "Bad scalar")),
            }
            blst_p1_from_affine(&mut ret, &affine);

            // Verify that deserialized element isn't infinite
            if blst_p1_is_inf(&ret) {
                return Err(Invalid("G1", "Infinity"));
            }

            // Verify that the deserialized element is in G1
            if !blst_p1_in_g1(&ret) {
                return Err(Invalid("G1", "Outside G1"));
            }
        }
        Ok(Self(ret))
    }
}

impl FixedSize for G1 {
    const SIZE: usize = G1_ELEMENT_BYTE_LENGTH;
}

impl Hash for G1 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let slice = self.as_slice();
        state.write(&slice);
    }
}

impl PartialOrd for G1 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for G1 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_slice().cmp(&other.as_slice())
    }
}

impl Point for G1 {
    fn map(&mut self, dst: DST, data: &[u8]) {
        // SAFETY: All pointers valid; blst_hash_to_g1 handles empty data. Aug is null/0 (unused).
        unsafe {
            blst_hash_to_g1(
                &mut self.0,
                data.as_ptr(),
                data.len(),
                dst.as_ptr(),
                dst.len(),
                ptr::null(),
                0,
            );
        }
    }

    /// Performs multi-scalar multiplication (MSM) on G1 points using Pippenger's algorithm.
    /// Computes `sum(scalars[i] * points[i])`.
    ///
    /// Filters out pairs where the point is the identity element (infinity).
    /// Returns an error if the lengths of the input slices mismatch.
    fn msm(points: &[Self], scalars: &[Scalar]) -> Self {
        // Assert input validity
        assert_eq!(points.len(), scalars.len(), "mismatched lengths");

        // Prepare points (affine) and scalars (raw blst_scalar)
        let mut points_filtered = Vec::with_capacity(points.len());
        let mut scalars_filtered = Vec::with_capacity(scalars.len());
        for (point, scalar) in points.iter().zip(scalars.iter()) {
            // `blst` does not filter out infinity, so we must ensure it is impossible.
            //
            // Sources:
            // * https://github.com/supranational/blst/blob/cbc7e166a10d7286b91a3a7bea341e708962db13/src/multi_scalar.c#L10-L12
            // * https://github.com/MystenLabs/fastcrypto/blob/0acf0ff1a163c60e0dec1e16e4fbad4a4cf853bd/fastcrypto/src/groups/bls12381.rs#L160-L194
            if *point == Self::zero() || scalar == &Scalar::zero() {
                continue;
            }

            // Add to filtered vectors
            points_filtered.push(point.as_blst_p1_affine());
            scalars_filtered.push(scalar.as_blst_scalar());
        }

        // If all points were filtered, return zero.
        if points_filtered.is_empty() {
            return Self::zero();
        }

        // Create vectors of pointers for the blst API.
        // These vectors hold pointers *to* the elements in the filtered vectors above.
        let points: Vec<*const blst_p1_affine> =
            points_filtered.iter().map(|p| p as *const _).collect();
        let scalars: Vec<*const u8> = scalars_filtered.iter().map(|s| s.b.as_ptr()).collect();

        // Allocate scratch space for Pippenger's algorithm.
        // SAFETY: blst_p1s_mult_pippenger_scratch_sizeof returns size in bytes for valid input.
        let scratch_size = unsafe { blst_p1s_mult_pippenger_scratch_sizeof(points.len()) };
        // Ensure scratch_size is a multiple of 8 to avoid truncation in division.
        assert_eq!(scratch_size % 8, 0, "scratch_size must be multiple of 8");
        let mut scratch = vec![MaybeUninit::<u64>::uninit(); scratch_size / 8];

        // Perform multi-scalar multiplication
        let mut msm_result = blst_p1::default();
        // SAFETY: All pointer arrays are valid and point to data that outlives this call.
        // points_filtered and scalars_filtered remain alive until after this block.
        unsafe {
            blst_p1s_mult_pippenger(
                &mut msm_result,
                points.as_ptr(),
                points.len(),
                scalars.as_ptr(),
                SCALAR_BITS, // Using SCALAR_BITS (255) ensures full scalar range
                scratch.as_mut_ptr() as *mut _,
            );
        }

        Self::from_blst_p1(msm_result)
    }
}

impl Debug for G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl Display for G1 {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl G2 {
    /// Encodes the G2 element into a slice.
    fn as_slice(&self) -> [u8; Self::SIZE] {
        let mut slice = [0u8; Self::SIZE];
        // SAFETY: blst_p2_compress writes exactly 96 bytes to a valid buffer.
        unsafe {
            blst_p2_compress(slice.as_mut_ptr(), &self.0);
        }
        slice
    }

    /// Converts the G2 point to its affine representation.
    pub(crate) fn as_blst_p2_affine(&self) -> blst_p2_affine {
        let mut affine = blst_p2_affine::default();
        // SAFETY: Both pointers are valid and properly aligned.
        unsafe { blst_p2_to_affine(&mut affine, &self.0) };
        affine
    }

    /// Creates a G2 point from a raw `blst_p2`.
    pub(crate) const fn from_blst_p2(p: blst_p2) -> Self {
        Self(p)
    }
}

impl Element for G2 {
    fn zero() -> Self {
        Self(blst_p2::default())
    }

    fn one() -> Self {
        let mut ret = blst_p2::default();
        // SAFETY: BLS12_381_G2 is a valid generator point constant.
        unsafe {
            blst_p2_from_affine(&mut ret, &BLS12_381_G2);
        }
        Self(ret)
    }

    fn add(&mut self, rhs: &Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_p2_add_or_double supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_p2_add_or_double(ptr, ptr, &rhs.0);
        }
    }

    fn mul(&mut self, rhs: &Scalar) {
        let mut scalar = blst_scalar::default();
        let ptr = &raw mut self.0;
        // SAFETY: blst_p2_mult supports in-place (ret==a). Using SCALAR_BITS (255) ensures
        // constant-time execution. Raw pointer avoids aliased refs.
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.0);
            blst_p2_mult(ptr, ptr, scalar.b.as_ptr(), SCALAR_BITS);
        }
    }
}

impl Write for G2 {
    fn write(&self, buf: &mut impl BufMut) {
        let slice = self.as_slice();
        buf.put_slice(&slice);
    }
}

impl Read for G2 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let bytes = <[u8; Self::SIZE]>::read(buf)?;
        let mut ret = blst_p2::default();
        // SAFETY: bytes is a valid 96-byte array. blst_p2_uncompress validates encoding.
        // Additional checks for infinity and subgroup membership prevent small subgroup attacks.
        unsafe {
            let mut affine = blst_p2_affine::default();
            match blst_p2_uncompress(&mut affine, bytes.as_ptr()) {
                BLST_ERROR::BLST_SUCCESS => {}
                BLST_ERROR::BLST_BAD_ENCODING => return Err(Invalid("G2", "Bad encoding")),
                BLST_ERROR::BLST_POINT_NOT_ON_CURVE => return Err(Invalid("G2", "Not on curve")),
                BLST_ERROR::BLST_POINT_NOT_IN_GROUP => return Err(Invalid("G2", "Not in group")),
                BLST_ERROR::BLST_AGGR_TYPE_MISMATCH => return Err(Invalid("G2", "Type mismatch")),
                BLST_ERROR::BLST_VERIFY_FAIL => return Err(Invalid("G2", "Verify fail")),
                BLST_ERROR::BLST_PK_IS_INFINITY => return Err(Invalid("G2", "PK is Infinity")),
                BLST_ERROR::BLST_BAD_SCALAR => return Err(Invalid("G2", "Bad scalar")),
            }
            blst_p2_from_affine(&mut ret, &affine);

            // Verify that deserialized element isn't infinite
            if blst_p2_is_inf(&ret) {
                return Err(Invalid("G2", "Infinity"));
            }

            // Verify that the deserialized element is in G2
            if !blst_p2_in_g2(&ret) {
                return Err(Invalid("G2", "Outside G2"));
            }
        }
        Ok(Self(ret))
    }
}

impl FixedSize for G2 {
    const SIZE: usize = G2_ELEMENT_BYTE_LENGTH;
}

impl Hash for G2 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        let slice = self.as_slice();
        state.write(&slice);
    }
}

impl PartialOrd for G2 {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for G2 {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.as_slice().cmp(&other.as_slice())
    }
}

impl Point for G2 {
    fn map(&mut self, dst: DST, data: &[u8]) {
        // SAFETY: All pointers valid; blst_hash_to_g2 handles empty data. Aug is null/0 (unused).
        unsafe {
            blst_hash_to_g2(
                &mut self.0,
                data.as_ptr(),
                data.len(),
                dst.as_ptr(),
                dst.len(),
                ptr::null(),
                0,
            );
        }
    }

    /// Performs multi-scalar multiplication (MSM) on G2 points using Pippenger's algorithm.
    /// Computes `sum(scalars[i] * points[i])`.
    ///
    /// Filters out pairs where the point is the identity element (infinity).
    /// Returns an error if the lengths of the input slices mismatch.
    fn msm(points: &[Self], scalars: &[Scalar]) -> Self {
        // Assert input validity
        assert_eq!(points.len(), scalars.len(), "mismatched lengths");

        // Prepare points (affine) and scalars (raw blst_scalar), filtering identity points
        let mut points_filtered = Vec::with_capacity(points.len());
        let mut scalars_filtered = Vec::with_capacity(scalars.len());
        for (point, scalar) in points.iter().zip(scalars.iter()) {
            // `blst` does not filter out infinity, so we must ensure it is impossible.
            //
            // Sources:
            // * https://github.com/supranational/blst/blob/cbc7e166a10d7286b91a3a7bea341e708962db13/src/multi_scalar.c#L10-L12
            // * https://github.com/MystenLabs/fastcrypto/blob/0acf0ff1a163c60e0dec1e16e4fbad4a4cf853bd/fastcrypto/src/groups/bls12381.rs#L160-L194
            if *point == Self::zero() || scalar == &Scalar::zero() {
                continue;
            }
            points_filtered.push(point.as_blst_p2_affine());
            scalars_filtered.push(scalar.as_blst_scalar());
        }

        // If all points were filtered, return zero.
        if points_filtered.is_empty() {
            return Self::zero();
        }

        // Create vectors of pointers for the blst API
        let points: Vec<*const blst_p2_affine> =
            points_filtered.iter().map(|p| p as *const _).collect();
        let scalars: Vec<*const u8> = scalars_filtered.iter().map(|s| s.b.as_ptr()).collect();

        // Allocate scratch space for Pippenger algorithm
        // SAFETY: blst_p2s_mult_pippenger_scratch_sizeof returns size in bytes for valid input.
        let scratch_size = unsafe { blst_p2s_mult_pippenger_scratch_sizeof(points.len()) };
        // Ensure scratch_size is a multiple of 8 to avoid truncation in division.
        assert_eq!(scratch_size % 8, 0, "scratch_size must be multiple of 8");
        let mut scratch = vec![MaybeUninit::<u64>::uninit(); scratch_size / 8];

        // Perform multi-scalar multiplication
        let mut msm_result = blst_p2::default();
        // SAFETY: All pointer arrays are valid and point to data that outlives this call.
        // points_filtered and scalars_filtered remain alive until after this block.
        unsafe {
            blst_p2s_mult_pippenger(
                &mut msm_result,
                points.as_ptr(),
                points.len(),
                scalars.as_ptr(),
                SCALAR_BITS, // Using SCALAR_BITS (255) ensures full scalar range
                scratch.as_mut_ptr() as *mut _,
            );
        }

        Self::from_blst_p2(msm_result)
    }
}

impl Debug for G2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl Display for G2 {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use rand::prelude::*;
    use std::collections::{BTreeSet, HashMap};

    #[test]
    fn basic_group() {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/b0ef82ff79769d085a5a7d3f4fe690b1c8fe6dc9/crates/threshold-bls/src/curve/bls12381.rs#L200-L220
        let s = Scalar::from_rand(&mut thread_rng());
        let mut e1 = s.clone();
        let e2 = s.clone();
        let mut s2 = s.clone();
        s2.add(&s);
        s2.mul(&s);
        e1.add(&e2);
        e1.mul(&e2);

        // p1 = s2 * G = (s+s)G
        let mut p1 = G1::zero();
        p1.mul(&s2);

        // p2 = sG + sG = s2 * G
        let mut p2 = G1::zero();
        p2.mul(&s);
        p2.add(&p2.clone());
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_scalar_codec() {
        let original = Scalar::from_rand(&mut thread_rng());
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), Scalar::SIZE);
        let decoded = Scalar::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_g1_codec() {
        let mut original = G1::one();
        original.mul(&Scalar::from_rand(&mut thread_rng()));
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), G1::SIZE);
        let decoded = G1::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_g2_codec() {
        let mut original = G2::one();
        original.mul(&Scalar::from_rand(&mut thread_rng()));
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), G2::SIZE);
        let decoded = G2::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// Naive calculation of Multi-Scalar Multiplication: sum(scalar * point)
    fn naive_msm<P: Point>(points: &[P], scalars: &[Scalar]) -> P {
        assert_eq!(points.len(), scalars.len());
        let mut total = P::zero();
        for (point, scalar) in points.iter().zip(scalars.iter()) {
            // Skip identity points or zero scalars, similar to the optimized MSM
            if *point == P::zero() || *scalar == Scalar::zero() {
                continue;
            }
            let mut term = point.clone();
            term.mul(scalar);
            total.add(&term);
        }
        total
    }

    #[test]
    fn test_g1_msm() {
        let mut rng = thread_rng();
        let n = 10; // Number of points/scalars

        // Case 1: Random points and scalars
        let points_g1: Vec<G1> = (0..n)
            .map(|_| {
                let mut point = G1::one();
                point.mul(&Scalar::from_rand(&mut rng));
                point
            })
            .collect();
        let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::from_rand(&mut rng)).collect();
        let expected_g1 = naive_msm(&points_g1, &scalars);
        let result_g1 = G1::msm(&points_g1, &scalars);
        assert_eq!(expected_g1, result_g1, "G1 MSM basic case failed");

        // Case 2: Include identity point
        let mut points_with_zero_g1 = points_g1.clone();
        points_with_zero_g1[n / 2] = G1::zero();
        let expected_zero_pt_g1 = naive_msm(&points_with_zero_g1, &scalars);
        let result_zero_pt_g1 = G1::msm(&points_with_zero_g1, &scalars);
        assert_eq!(
            expected_zero_pt_g1, result_zero_pt_g1,
            "G1 MSM with identity point failed"
        );

        // Case 3: Include zero scalar
        let mut scalars_with_zero = scalars.clone();
        scalars_with_zero[n / 2] = Scalar::zero();
        let expected_zero_sc_g1 = naive_msm(&points_g1, &scalars_with_zero);
        let result_zero_sc_g1 = G1::msm(&points_g1, &scalars_with_zero);
        assert_eq!(
            expected_zero_sc_g1, result_zero_sc_g1,
            "G1 MSM with zero scalar failed"
        );

        // Case 4: All points identity
        let zero_points_g1 = vec![G1::zero(); n];
        let expected_all_zero_pt_g1 = naive_msm(&zero_points_g1, &scalars);
        let result_all_zero_pt_g1 = G1::msm(&zero_points_g1, &scalars);
        assert_eq!(
            expected_all_zero_pt_g1,
            G1::zero(),
            "G1 MSM all identity points (naive) failed"
        );
        assert_eq!(
            result_all_zero_pt_g1,
            G1::zero(),
            "G1 MSM all identity points failed"
        );

        // Case 5: All scalars zero
        let zero_scalars = vec![Scalar::zero(); n];
        let expected_all_zero_sc_g1 = naive_msm(&points_g1, &zero_scalars);
        let result_all_zero_sc_g1 = G1::msm(&points_g1, &zero_scalars);
        assert_eq!(
            expected_all_zero_sc_g1,
            G1::zero(),
            "G1 MSM all zero scalars (naive) failed"
        );
        assert_eq!(
            result_all_zero_sc_g1,
            G1::zero(),
            "G1 MSM all zero scalars failed"
        );

        // Case 6: Single element
        let single_point_g1 = [points_g1[0]];
        let single_scalar = [scalars[0].clone()];
        let expected_single_g1 = naive_msm(&single_point_g1, &single_scalar);
        let result_single_g1 = G1::msm(&single_point_g1, &single_scalar);
        assert_eq!(
            expected_single_g1, result_single_g1,
            "G1 MSM single element failed"
        );

        // Case 7: Empty input
        let empty_points_g1: [G1; 0] = [];
        let empty_scalars: [Scalar; 0] = [];
        let expected_empty_g1 = naive_msm(&empty_points_g1, &empty_scalars);
        let result_empty_g1 = G1::msm(&empty_points_g1, &empty_scalars);
        assert_eq!(expected_empty_g1, G1::zero(), "G1 MSM empty (naive) failed");
        assert_eq!(result_empty_g1, G1::zero(), "G1 MSM empty failed");

        // Case 8: Random points and scalars (big)
        let points_g1: Vec<G1> = (0..50_000)
            .map(|_| {
                let mut point = G1::one();
                point.mul(&Scalar::from_rand(&mut rng));
                point
            })
            .collect();
        let scalars: Vec<Scalar> = (0..50_000).map(|_| Scalar::from_rand(&mut rng)).collect();
        let expected_g1 = naive_msm(&points_g1, &scalars);
        let result_g1 = G1::msm(&points_g1, &scalars);
        assert_eq!(expected_g1, result_g1, "G1 MSM basic case failed");
    }

    #[test]
    fn test_g2_msm() {
        let mut rng = thread_rng();
        let n = 10; // Number of points/scalars

        // Case 1: Random points and scalars
        let points_g2: Vec<G2> = (0..n)
            .map(|_| {
                let mut point = G2::one();
                point.mul(&Scalar::from_rand(&mut rng));
                point
            })
            .collect();
        let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::from_rand(&mut rng)).collect();
        let expected_g2 = naive_msm(&points_g2, &scalars);
        let result_g2 = G2::msm(&points_g2, &scalars);
        assert_eq!(expected_g2, result_g2, "G2 MSM basic case failed");

        // Case 2: Include identity point
        let mut points_with_zero_g2 = points_g2.clone();
        points_with_zero_g2[n / 2] = G2::zero();
        let expected_zero_pt_g2 = naive_msm(&points_with_zero_g2, &scalars);
        let result_zero_pt_g2 = G2::msm(&points_with_zero_g2, &scalars);
        assert_eq!(
            expected_zero_pt_g2, result_zero_pt_g2,
            "G2 MSM with identity point failed"
        );

        // Case 3: Include zero scalar
        let mut scalars_with_zero = scalars.clone();
        scalars_with_zero[n / 2] = Scalar::zero();
        let expected_zero_sc_g2 = naive_msm(&points_g2, &scalars_with_zero);
        let result_zero_sc_g2 = G2::msm(&points_g2, &scalars_with_zero);
        assert_eq!(
            expected_zero_sc_g2, result_zero_sc_g2,
            "G2 MSM with zero scalar failed"
        );

        // Case 4: All points identity
        let zero_points_g2 = vec![G2::zero(); n];
        let expected_all_zero_pt_g2 = naive_msm(&zero_points_g2, &scalars);
        let result_all_zero_pt_g2 = G2::msm(&zero_points_g2, &scalars);
        assert_eq!(
            expected_all_zero_pt_g2,
            G2::zero(),
            "G2 MSM all identity points (naive) failed"
        );
        assert_eq!(
            result_all_zero_pt_g2,
            G2::zero(),
            "G2 MSM all identity points failed"
        );

        // Case 5: All scalars zero
        let zero_scalars = vec![Scalar::zero(); n];
        let expected_all_zero_sc_g2 = naive_msm(&points_g2, &zero_scalars);
        let result_all_zero_sc_g2 = G2::msm(&points_g2, &zero_scalars);
        assert_eq!(
            expected_all_zero_sc_g2,
            G2::zero(),
            "G2 MSM all zero scalars (naive) failed"
        );
        assert_eq!(
            result_all_zero_sc_g2,
            G2::zero(),
            "G2 MSM all zero scalars failed"
        );

        // Case 6: Single element
        let single_point_g2 = [points_g2[0]];
        let single_scalar = [scalars[0].clone()];
        let expected_single_g2 = naive_msm(&single_point_g2, &single_scalar);
        let result_single_g2 = G2::msm(&single_point_g2, &single_scalar);
        assert_eq!(
            expected_single_g2, result_single_g2,
            "G2 MSM single element failed"
        );

        // Case 7: Empty input
        let empty_points_g2: [G2; 0] = [];
        let empty_scalars: [Scalar; 0] = [];
        let expected_empty_g2 = naive_msm(&empty_points_g2, &empty_scalars);
        let result_empty_g2 = G2::msm(&empty_points_g2, &empty_scalars);
        assert_eq!(expected_empty_g2, G2::zero(), "G2 MSM empty (naive) failed");
        assert_eq!(result_empty_g2, G2::zero(), "G2 MSM empty failed");

        // Case 8: Random points and scalars (big)
        let points_g2: Vec<G2> = (0..50_000)
            .map(|_| {
                let mut point = G2::one();
                point.mul(&Scalar::from_rand(&mut rng));
                point
            })
            .collect();
        let scalars: Vec<Scalar> = (0..50_000).map(|_| Scalar::from_rand(&mut rng)).collect();
        let expected_g2 = naive_msm(&points_g2, &scalars);
        let result_g2 = G2::msm(&points_g2, &scalars);
        assert_eq!(expected_g2, result_g2, "G2 MSM basic case failed");
    }

    #[test]
    fn test_trait_implementations() {
        // Generate a set of unique items to test.
        let mut rng = thread_rng();
        const NUM_ITEMS: usize = 10;
        let mut scalar_set = BTreeSet::new();
        let mut g1_set = BTreeSet::new();
        let mut g2_set = BTreeSet::new();
        let mut share_set = BTreeSet::new();
        while scalar_set.len() < NUM_ITEMS {
            let scalar = Scalar::from_rand(&mut rng);
            let mut g1 = G1::one();
            g1.mul(&scalar);
            let mut g2 = G2::one();
            g2.mul(&scalar);
            let share = Share {
                index: scalar_set.len() as u32,
                private: scalar.clone(),
            };

            scalar_set.insert(scalar);
            g1_set.insert(g1);
            g2_set.insert(g2);
            share_set.insert(share);
        }

        // Verify that the sets contain the expected number of unique items.
        assert_eq!(scalar_set.len(), NUM_ITEMS);
        assert_eq!(g1_set.len(), NUM_ITEMS);
        assert_eq!(g2_set.len(), NUM_ITEMS);
        assert_eq!(share_set.len(), NUM_ITEMS);

        // Verify that `BTreeSet` iteration is sorted, which relies on `Ord`.
        let scalars: Vec<_> = scalar_set.iter().collect();
        assert!(scalars.windows(2).all(|w| w[0] <= w[1]));
        let g1s: Vec<_> = g1_set.iter().collect();
        assert!(g1s.windows(2).all(|w| w[0] <= w[1]));
        let g2s: Vec<_> = g2_set.iter().collect();
        assert!(g2s.windows(2).all(|w| w[0] <= w[1]));
        let shares: Vec<_> = share_set.iter().collect();
        assert!(shares.windows(2).all(|w| w[0] <= w[1]));

        // Test that we can use these types as keys in hash maps, which relies on `Hash` and `Eq`.
        let scalar_map: HashMap<_, _> = scalar_set.iter().cloned().zip(0..).collect();
        let g1_map: HashMap<_, _> = g1_set.iter().cloned().zip(0..).collect();
        let g2_map: HashMap<_, _> = g2_set.iter().cloned().zip(0..).collect();
        let share_map: HashMap<_, _> = share_set.iter().cloned().zip(0..).collect();

        // Verify that the maps contain the expected number of unique items.
        assert_eq!(scalar_map.len(), NUM_ITEMS);
        assert_eq!(g1_map.len(), NUM_ITEMS);
        assert_eq!(g2_map.len(), NUM_ITEMS);
        assert_eq!(share_map.len(), NUM_ITEMS);
    }

    #[test]
    fn test_scalar_map() {
        // Test 1: Basic functionality
        let msg = b"test message";
        let dst = b"TEST_DST";
        let scalar1 = Scalar::map(dst, msg);
        let scalar2 = Scalar::map(dst, msg);
        assert_eq!(scalar1, scalar2, "Same input should produce same output");

        // Test 2: Different messages produce different scalars
        let msg2 = b"different message";
        let scalar3 = Scalar::map(dst, msg2);
        assert_ne!(
            scalar1, scalar3,
            "Different messages should produce different scalars"
        );

        // Test 3: Different DSTs produce different scalars
        let dst2 = b"DIFFERENT_DST";
        let scalar4 = Scalar::map(dst2, msg);
        assert_ne!(
            scalar1, scalar4,
            "Different DSTs should produce different scalars"
        );

        // Test 4: Empty message
        let empty_msg = b"";
        let scalar_empty = Scalar::map(dst, empty_msg);
        assert_ne!(
            scalar_empty,
            Scalar::zero(),
            "Empty message should not produce zero"
        );

        // Test 5: Large message
        let large_msg = vec![0x42u8; 1000];
        let scalar_large = Scalar::map(dst, &large_msg);
        assert_ne!(
            scalar_large,
            Scalar::zero(),
            "Large message should not produce zero"
        );

        // Test 6: Verify the scalar is valid (not zero)
        assert_ne!(
            scalar1,
            Scalar::zero(),
            "Hash should not produce zero scalar"
        );
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<G1>,
            CodecConformance<G2>,
            CodecConformance<Scalar>,
            CodecConformance<Share>
        }
    }
}

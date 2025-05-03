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

use blst::{
    blst_bendian_from_scalar, blst_fp12, blst_fr, blst_fr_add, blst_fr_from_scalar,
    blst_fr_from_uint64, blst_fr_inverse, blst_fr_mul, blst_fr_sub, blst_hash_to_g1,
    blst_hash_to_g2, blst_keygen, blst_p1, blst_p1_add_or_double, blst_p1_affine, blst_p1_compress,
    blst_p1_from_affine, blst_p1_in_g1, blst_p1_is_inf, blst_p1_mult, blst_p1_to_affine,
    blst_p1_uncompress, blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_compress,
    blst_p2_from_affine, blst_p2_in_g2, blst_p2_is_inf, blst_p2_mult, blst_p2_to_affine,
    blst_p2_uncompress, blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr, blst_sk_check,
    Pairing, BLS12_381_G1, BLS12_381_G2, BLS12_381_NEG_G1, BLST_ERROR,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt,
    EncodeSize,
    Error::{self, Invalid},
    FixedSize, Read, ReadExt, Write,
};
use commonware_utils::hex;
use rand::RngCore;
use std::{
    fmt::{Debug, Display},
    hash::{Hash, Hasher},
    ptr,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Domain separation tag used when hashing a message to a curve (G1 or G2).
///
/// Reference: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-ciphersuites>
pub type DST = &'static [u8];

/// An element of a group.
pub trait Element:
    Read<Cfg = ()> + Write + FixedSize + Clone + Eq + PartialEq + Send + Sync
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

/// An element of a group that supports message hashing.
pub trait Point: Element {
    /// Maps the provided data to a group element.
    fn map(&mut self, dst: DST, message: &[u8]);
}

/// Wrapper around [`blst_fr`] that represents an element of the BLS12‑381
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

/// Number of bytes required to encode a scalar in its canonical
/// little‑endian form (`32 × 8 = 256 bits`).
///
/// Because `r` is only 255 bits wide, the most‑significant byte is always in
/// the range `0x00‥=0x7f`, leaving the top bit clear.
const SCALAR_LENGTH: usize = 32;

/// Effective bit‑length of the field modulus `r` (`⌈log_2 r⌉ = 255`).
///
/// Useful for constant‑time exponentiation loops and for validating that a
/// decoded integer lies in the range `0 ≤ x < r`.
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

/// The target group of the BLS12-381 pairing.
///
/// This is an element in the extension field `F_p^12` and is
/// produced as the result of a pairing operation.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct GT(blst_fp12);

/// The private key type.
pub type Private = Scalar;

/// The private key length.
pub const PRIVATE_KEY_LENGTH: usize = SCALAR_LENGTH;

/// The default public key type (G1).
pub type Public = G1;

/// The default public key length (G1).
pub const PUBLIC_KEY_LENGTH: usize = G1_ELEMENT_BYTE_LENGTH;

/// The default signature type (G2).
pub type Signature = G2;

/// The default signature length (G2).
pub const SIGNATURE_LENGTH: usize = G2_ELEMENT_BYTE_LENGTH;

/// The DST for hashing a proof of possession to the default signature type (G2).
pub const PROOF_OF_POSSESSION: DST = G2_PROOF_OF_POSSESSION;

/// The DST for hashing a message to the default signature type (G2).
pub const MESSAGE: DST = G2_MESSAGE;

impl Scalar {
    /// Generates a random scalar using the provided RNG.
    pub fn rand<R: RngCore>(rng: &mut R) -> Self {
        // Generate a random 64 byte buffer
        let mut ikm = [0u8; 64];
        rng.fill_bytes(&mut ikm);

        // Generate a scalar from the randomly populated buffer
        let mut ret = blst_fr::default();
        unsafe {
            let mut sc = blst_scalar::default();
            blst_keygen(&mut sc, ikm.as_ptr(), ikm.len(), ptr::null(), 0);
            blst_fr_from_scalar(&mut ret, &sc);
        }

        // Zeroize the ikm buffer
        ikm.zeroize();
        Self(ret)
    }

    /// Sets the scalar to be the provided integer.
    pub fn set_int(&mut self, i: u32) {
        // blst requires a buffer of 4 uint64 values. Failure to provide one will
        // result in unexpected behavior (will read past the provided buffer).
        //
        // Reference: https://github.com/supranational/blst/blob/415d4f0e2347a794091836a3065206edfd9c72f3/bindings/blst.h#L102
        let buffer = [i as u64, 0, 0, 0];
        unsafe { blst_fr_from_uint64(&mut self.0, buffer.as_ptr()) };
    }

    /// Computes the inverse of the scalar.
    pub fn inverse(&self) -> Option<Self> {
        if *self == Self::zero() {
            return None;
        }
        let mut ret = blst_fr::default();
        unsafe { blst_fr_inverse(&mut ret, &self.0) };
        Some(Self(ret))
    }

    /// Subtracts the provided scalar from self in-place.
    pub fn sub(&mut self, rhs: &Self) {
        unsafe { blst_fr_sub(&mut self.0, &self.0, &rhs.0) }
    }

    /// Encodes the scalar into a slice.
    fn as_slice(&self) -> [u8; Self::SIZE] {
        let mut slice = [0u8; Self::SIZE];
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_fr(&mut scalar, &self.0);
            blst_bendian_from_scalar(slice.as_mut_ptr(), &scalar);
        }
        slice
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
        unsafe {
            blst_fr_add(&mut self.0, &self.0, &rhs.0);
        }
    }

    fn mul(&mut self, rhs: &Self) {
        unsafe {
            blst_fr_mul(&mut self.0, &self.0, &rhs.0);
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
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
            // We use `blst_sk_check` instead of `blst_scalar_fr_check` because the former
            // performs a non-zero check.
            //
            // The IETF BLS12-381 specification allows for zero scalars up to (inclusive) Draft 3
            // but disallows them after.
            //
            // References:
            // * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-03#section-2.3
            // * https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04#section-2.3
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

impl Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl Display for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
#[derive(Clone, PartialEq, Hash)]
pub struct Share {
    /// The share's index in the polynomial.
    pub index: u32,
    /// The scalar corresponding to the share's secret.
    pub private: Private,
}

impl Share {
    /// Returns the public key corresponding to the share.
    ///
    /// This can be verified against the public polynomial.
    pub fn public(&self) -> Public {
        let mut public = <Public as Element>::one();
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share(index={}, private={})", self.index, self.private)
    }
}

impl Debug for Share {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Share(index={}, private={})", self.index, self.private)
    }
}

impl G1 {
    /// Encodes the G1 element into a slice.
    fn as_slice(&self) -> [u8; Self::SIZE] {
        let mut slice = [0u8; Self::SIZE];
        unsafe {
            blst_p1_compress(slice.as_mut_ptr(), &self.0);
        }
        slice
    }
}

impl Element for G1 {
    fn zero() -> Self {
        Self(blst_p1::default())
    }

    fn one() -> Self {
        let mut ret = blst_p1::default();
        unsafe {
            blst_p1_from_affine(&mut ret, &BLS12_381_G1);
        }
        Self(ret)
    }

    fn add(&mut self, rhs: &Self) {
        unsafe {
            blst_p1_add_or_double(&mut self.0, &self.0, &rhs.0);
        }
    }

    fn mul(&mut self, rhs: &Scalar) {
        let mut scalar: blst_scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.0);
            // To avoid a timing attack during signing, we always perform the same
            // number of iterations during scalar multiplication.
            blst_p1_mult(&mut self.0, &self.0, scalar.b.as_ptr(), SCALAR_BITS);
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

impl Point for G1 {
    fn map(&mut self, dst: DST, data: &[u8]) {
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
}

impl Debug for G1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl Display for G1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl G2 {
    /// Encodes the G2 element into a slice.
    fn as_slice(&self) -> [u8; Self::SIZE] {
        let mut slice = [0u8; Self::SIZE];
        unsafe {
            blst_p2_compress(slice.as_mut_ptr(), &self.0);
        }
        slice
    }
}

impl Element for G2 {
    fn zero() -> Self {
        Self(blst_p2::default())
    }

    fn one() -> Self {
        let mut ret = blst_p2::default();
        unsafe {
            blst_p2_from_affine(&mut ret, &BLS12_381_G2);
        }
        Self(ret)
    }

    fn add(&mut self, rhs: &Self) {
        unsafe {
            blst_p2_add_or_double(&mut self.0, &self.0, &rhs.0);
        }
    }

    fn mul(&mut self, rhs: &Scalar) {
        let mut scalar = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut scalar, &rhs.0);
            // To avoid a timing attack during signing, we always perform the same
            // number of iterations during scalar multiplication.
            blst_p2_mult(&mut self.0, &self.0, scalar.b.as_ptr(), SCALAR_BITS);
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

impl Point for G2 {
    fn map(&mut self, dst: DST, data: &[u8]) {
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
}

impl Debug for G2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

impl Display for G2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.as_slice()))
    }
}

/// Verifies that `e(pk,hm)` is equal to `e(G1::one(),sig)` using a single product check with
/// a negated G1 generator (`e(pk,hm) * e(-G1::one(),sig) == 1`).
pub(super) fn equal(pk: &G1, sig: &G2, hm: &G2) -> bool {
    // Create a pairing context
    //
    // We only handle pre-hashed messages, so we leave the domain separator tag (`DST`) empty.
    let mut pairing = Pairing::new(false, &[]);

    // Convert `sig` into affine and aggregate `e(-G1::one(), sig)`
    let mut q = blst_p2_affine::default();
    unsafe {
        blst_p2_to_affine(&mut q, &sig.0);
        pairing.raw_aggregate(&q, &BLS12_381_NEG_G1);
    }

    // Convert `pk` and `hm` into affine
    let mut p = blst_p1_affine::default();
    let mut q = blst_p2_affine::default();
    unsafe {
        blst_p1_to_affine(&mut p, &pk.0);
        blst_p2_to_affine(&mut q, &hm.0);
    }

    // Aggregate `e(pk, hm)`
    pairing.raw_aggregate(&q, &p);

    // Finalize the pairing accumulation and verify the result
    //
    // If `finalverify()` returns `true`, it means `e(pk,hm) * e(-G1::one(),sig) == 1`. This
    // is equivalent to `e(pk,hm) == e(G1::one(),sig)`.
    pairing.commit();
    pairing.finalverify(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use rand::prelude::*;

    #[test]
    fn basic_group() {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/b0ef82ff79769d085a5a7d3f4fe690b1c8fe6dc9/crates/threshold-bls/src/curve/bls12381.rs#L200-L220
        let s = Scalar::rand(&mut thread_rng());
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
        let original = Scalar::rand(&mut thread_rng());
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), Scalar::SIZE);
        let decoded = Scalar::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_g1_codec() {
        let mut original = G1::one();
        original.mul(&Scalar::rand(&mut thread_rng()));
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), G1::SIZE);
        let decoded = G1::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_g2_codec() {
        let mut original = G2::one();
        original.mul(&Scalar::rand(&mut thread_rng()));
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), G2::SIZE);
        let decoded = G2::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }
}

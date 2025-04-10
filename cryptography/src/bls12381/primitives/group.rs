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
use commonware_codec::FixedSize;
use rand::RngCore;
use std::ptr;
use zeroize::Zeroize;

/// Domain separation tag used when hashing a message to a curve (G1 or G2).
///
/// Reference: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-ciphersuites>
pub type DST = &'static [u8];

/// An element of a group.
pub trait Element: Clone + Eq + PartialEq + Send + Sync {
    /// Returns the additive identity.
    fn zero() -> Self;

    /// Returns the multiplicative identity.
    fn one() -> Self;

    /// Adds to self in-place.
    fn add(&mut self, rhs: &Self);

    /// Multiplies self in-place.
    fn mul(&mut self, rhs: &Scalar);

    /// Canonically serializes the element.
    fn serialize(&self) -> Vec<u8>;

    /// Serialized size of the element.
    fn size() -> usize;

    /// Deserializes an untrusted, canonically-encoded element.
    ///
    /// This function performs any validation necessary to ensure the decoded
    /// element is valid (like an infinity or group check).
    fn deserialize(bytes: &[u8]) -> Option<Self>;
}

/// An element of a group that supports message hashing.
pub trait Point: Element {
    /// Maps the provided data to a group element.
    fn map(&mut self, dst: DST, message: &[u8]);
}

/// A scalar representing an element of the BLS12-381 finite field.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
#[repr(transparent)]
pub struct Scalar(blst_fr);

/// Length of a scalar in bytes.
const SCALAR_LENGTH: usize = 32;

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
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
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

/// Returns the size in bits of a given blst_scalar (represented in little-endian).
fn bits(scalar: &blst_scalar) -> usize {
    let mut bits: usize = SCALAR_LENGTH * 8;
    for i in scalar.b.iter().rev() {
        let leading = i.leading_zeros();
        bits -= leading as usize;
        if leading < 8 {
            break;
        }
    }
    bits
}

/// A share of a threshold signing key.
#[derive(Debug, Clone, PartialEq, Copy)]
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

    /// Canonically serializes the share.
    pub fn serialize(&self) -> Vec<u8> {
        let mut bytes = [0u8; u32::SIZE + SCALAR_LENGTH];
        bytes[..u32::SIZE].copy_from_slice(&self.index.to_be_bytes());
        bytes[u32::SIZE..].copy_from_slice(&self.private.serialize());
        bytes.to_vec()
    }

    /// Deserializes a canonically encoded share.
    pub fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != u32::SIZE + SCALAR_LENGTH {
            return None;
        }
        let index = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let private = Private::deserialize(&bytes[u32::SIZE..])?;
        Some(Self { index, private })
    }
}

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
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.l.zeroize();
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

    fn serialize(&self) -> Vec<u8> {
        let mut bytes = [0u8; SCALAR_LENGTH];
        unsafe {
            let mut scalar = blst_scalar::default();
            blst_scalar_from_fr(&mut scalar, &self.0);
            blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
        }
        bytes.to_vec()
    }

    fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != SCALAR_LENGTH {
            return None;
        }
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
                return None;
            }
            blst_fr_from_scalar(&mut ret, &scalar);
        }
        Some(Self(ret))
    }

    fn size() -> usize {
        SCALAR_LENGTH
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
            blst_p1_mult(&mut self.0, &self.0, scalar.b.as_ptr(), bits(&scalar));
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut bytes = [0u8; G1_ELEMENT_BYTE_LENGTH];
        unsafe {
            blst_p1_compress(bytes.as_mut_ptr(), &self.0);
        }
        bytes.to_vec()
    }

    fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G1_ELEMENT_BYTE_LENGTH {
            return None;
        }
        let mut ret = blst_p1::default();
        unsafe {
            let mut affine = blst_p1_affine::default();
            if blst_p1_uncompress(&mut affine, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return None;
            }
            blst_p1_from_affine(&mut ret, &affine);

            // Verify that deserialized element isn't infinite
            if blst_p1_is_inf(&ret) {
                return None;
            }

            // Verify that the deserialized element is in G1
            if !blst_p1_in_g1(&ret) {
                return None;
            }
        }
        Some(Self(ret))
    }

    fn size() -> usize {
        G1_ELEMENT_BYTE_LENGTH
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
            blst_p2_mult(&mut self.0, &self.0, scalar.b.as_ptr(), bits(&scalar));
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut bytes = [0u8; G2_ELEMENT_BYTE_LENGTH];
        unsafe {
            blst_p2_compress(bytes.as_mut_ptr(), &self.0);
        }
        bytes.to_vec()
    }

    fn deserialize(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != G2_ELEMENT_BYTE_LENGTH {
            return None;
        }
        let mut ret = blst_p2::default();
        unsafe {
            let mut affine = blst_p2_affine::default();
            if blst_p2_uncompress(&mut affine, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                return None;
            }
            blst_p2_from_affine(&mut ret, &affine);

            // Verify that deserialized element isn't infinite
            if blst_p2_is_inf(&ret) {
                return None;
            }

            // Verify that the deserialized element is in G2
            if !blst_p2_in_g2(&ret) {
                return None;
            }
        }
        Some(Self(ret))
    }

    fn size() -> usize {
        G2_ELEMENT_BYTE_LENGTH
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
    use rand::prelude::*;

    #[test]
    fn basic_group() {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/b0ef82ff79769d085a5a7d3f4fe690b1c8fe6dc9/crates/threshold-bls/src/curve/bls12381.rs#L200-L220
        let s = Scalar::rand(&mut thread_rng());
        let mut e1 = s;
        let e2 = s;
        let mut s2 = s;
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
}

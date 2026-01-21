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
use crate::Secret;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};
use blst::{
    blst_bendian_from_fp12, blst_bendian_from_scalar, blst_expand_message_xmd, blst_fp12, blst_fr,
    blst_fr_add, blst_fr_cneg, blst_fr_from_scalar, blst_fr_from_uint64, blst_fr_inverse,
    blst_fr_mul, blst_fr_sub, blst_hash_to_g1, blst_hash_to_g2, blst_keygen, blst_p1,
    blst_p1_add_or_double, blst_p1_affine, blst_p1_cneg, blst_p1_compress, blst_p1_double,
    blst_p1_from_affine, blst_p1_in_g1, blst_p1_is_inf, blst_p1_mult, blst_p1_to_affine,
    blst_p1_uncompress, blst_p1s_mult_pippenger, blst_p1s_mult_pippenger_scratch_sizeof,
    blst_p1s_tile_pippenger, blst_p1s_to_affine, blst_p2, blst_p2_add_or_double, blst_p2_affine,
    blst_p2_cneg, blst_p2_compress, blst_p2_double, blst_p2_from_affine, blst_p2_in_g2,
    blst_p2_is_inf, blst_p2_mult, blst_p2_to_affine, blst_p2_uncompress, blst_p2s_mult_pippenger,
    blst_p2s_mult_pippenger_scratch_sizeof, blst_p2s_tile_pippenger, blst_p2s_to_affine,
    blst_scalar, blst_scalar_from_be_bytes, blst_scalar_from_bendian, blst_scalar_from_fr,
    blst_sk_check, Pairing, BLS12_381_G1, BLS12_381_G2, BLST_ERROR,
};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize,
    Error::{self, Invalid},
    FixedSize, Read, ReadExt, Write,
};
use commonware_math::algebra::{
    Additive, CryptoGroup, Field, HashToGroup, Multiplicative, Object, Random, Ring, Space,
};
use commonware_parallel::Strategy;
use commonware_utils::{hex, Participant};
use core::{
    fmt::{Debug, Display, Formatter},
    hash::{Hash, Hasher},
    iter,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
    ptr,
};
use ctutils::{Choice, CtEq};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

fn all_zero(bytes: &[u8]) -> Choice {
    bytes
        .iter()
        .fold(Choice::TRUE, |acc, b| acc & b.ct_eq(&0u8))
}

/// Calculate the optimal window size for Pippenger's algorithm.
///
/// Reference: <https://github.com/supranational/blst/blob/v0.3.13/bindings/rust/src/pippenger.rs#L540-L550>
const fn pippenger_window_size(npoints: usize) -> usize {
    let wbits = (usize::BITS - npoints.leading_zeros()) as usize;
    if wbits > 13 {
        wbits - 4
    } else if wbits > 5 {
        wbits - 3
    } else {
        2
    }
}

/// Calculate the grid breakdown for parallel MSM.
/// Returns (nx, ny, window) where nx*ny is the number of tiles.
///
/// Reference: <https://github.com/supranational/blst/blob/v0.3.13/bindings/rust/src/pippenger.rs#L503-L538>
fn msm_breakdown(nbits: usize, window: usize, ncpus: usize) -> (usize, usize, usize) {
    let num_bits = |l: usize| (usize::BITS - l.leading_zeros()) as usize;

    let (nx, wnd) = if nbits > window * ncpus {
        let mut wnd = num_bits(ncpus / 4);
        if (window + wnd) > 18 {
            wnd = window.saturating_sub(wnd).max(1);
        } else {
            wnd = (nbits / window).div_ceil(ncpus);
            if (nbits / (window + 1)).div_ceil(ncpus) < wnd {
                wnd = window + 1;
            } else {
                wnd = window;
            }
        }
        (1, wnd)
    } else {
        let mut nx = 2usize;
        let mut wnd = window.saturating_sub(2).max(1);
        while (nbits / wnd + 1) * nx < ncpus {
            nx += 1;
            let new_wnd = window.saturating_sub(num_bits(3 * nx / 2));
            if new_wnd == 0 {
                break;
            }
            wnd = new_wnd;
        }
        nx -= 1;
        wnd = window.saturating_sub(num_bits(3 * nx / 2)).max(1);
        (nx, wnd)
    };

    let ny = nbits / wnd + 1;
    let final_wnd = nbits / ny + 1;

    (nx, ny, final_wnd)
}

/// A tile in the parallel MSM grid.
struct Tile {
    /// Starting point index in the input array.
    x: usize,
    /// Number of points to process in this tile.
    dx: usize,
    /// Starting bit position for scalar window.
    y: usize,
}

/// Build a grid of tiles for parallel MSM computation.
/// Tiles are ordered from highest bit row to lowest.
fn build_tiles(npoints: usize, nx: usize, ny: usize, window: usize) -> Vec<Tile> {
    let mut tiles = Vec::with_capacity(nx * ny);
    let dx = npoints / nx;

    // First row (highest bits)
    let mut y = window * (ny - 1);
    for i in 0..nx {
        let x = i * dx;
        let tile_dx = if i == nx - 1 { npoints - x } else { dx };
        tiles.push(Tile { x, dx: tile_dx, y });
    }

    // Remaining rows
    while y != 0 {
        y -= window;
        for i in 0..nx {
            let x = i * dx;
            let tile_dx = if i == nx - 1 { npoints - x } else { dx };
            tiles.push(Tile { x, dx: tile_dx, y });
        }
    }

    tiles
}

/// Domain separation tag used when hashing a message to a curve (G1 or G2).
///
/// Reference: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-ciphersuites>
pub type DST = &'static [u8];

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
        let ikm = u.arbitrary::<[u8; IKM_LENGTH]>()?;
        Ok(Self::from_ikm(&ikm))
    }
}

/// Number of bytes required to encode a scalar in its canonical
/// big-endian form (`32 × 8 = 256 bits`).
///
/// Because `r` is only 255 bits wide, the most-significant byte is always in
/// the range `0x00..=0x7f`, leaving the top bit clear.
pub const SCALAR_LENGTH: usize = 32;

/// Effective bit-length of the field modulus `r` (`ceil(log_2 r) = 255`).
///
/// Useful for constant-time exponentiation loops and for validating that a
/// decoded integer lies in the range `0 <= x < r`.
const SCALAR_BITS: usize = 255;

/// Number of scalar bits for SmallScalar (128 bits).
///
/// 128 bits provides sufficient security (2^-128 collision probability)
/// while roughly halving MSM computation time compared to full 255-bit scalars.
const SMALL_SCALAR_BITS: usize = 128;

/// Number of bytes for SmallScalar (16 bytes = 128 bits).
const SMALL_SCALAR_LENGTH: usize = 16;

/// Number of bytes of input key material for BLS key generation.
const IKM_LENGTH: usize = 64;

/// Minimum number of points required to use parallel MSM.
const MIN_PARALLEL_POINTS: usize = 32;

/// A 128-bit scalar for use in batch verification random challenges.
///
/// This provides 128-bit security which is sufficient for preventing
/// forgery attacks in batch verification while reducing computational cost
/// compared to full 255-bit scalars.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmallScalar {
    /// Stored as blst_scalar with only lower 128 bits populated.
    inner: blst_scalar,
}

impl SmallScalar {
    /// Generates a random 128-bit scalar.
    pub fn random(mut rng: impl CryptoRngCore) -> Self {
        // blst_scalar is 32 bytes
        let mut bytes = [0u8; 32];
        // Fill the last 16 bytes (128 bits) with entropy.
        // In big-endian, bytes[16..32] are the least significant.
        // Leaving bytes[0..16] as zero ensures the scalar is < 2^128.
        rng.fill_bytes(&mut bytes[SMALL_SCALAR_LENGTH..]);

        let mut scalar = blst_scalar::default();
        // SAFETY: bytes is a valid 32-byte array.
        unsafe {
            blst_scalar_from_bendian(&mut scalar, bytes.as_ptr());
        }
        Self { inner: scalar }
    }

    pub const fn as_bytes(&self) -> &[u8] {
        self.inner.b.as_slice()
    }

    /// Returns the zero scalar.
    pub fn zero() -> Self {
        Self {
            inner: blst_scalar::default(),
        }
    }
}

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
        Ok(Self::generator() * &u.arbitrary::<Scalar>()?)
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
        Ok(Self::generator() * &u.arbitrary::<Scalar>()?)
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
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Private {
    scalar: Secret<Scalar>,
}

impl Private {
    /// Creates a new private key from a scalar.
    pub const fn new(private: Scalar) -> Self {
        Self {
            scalar: Secret::new(private),
        }
    }

    /// Temporarily exposes the inner scalar to a closure.
    ///
    /// See [`Secret::expose`](crate::Secret::expose) for more details.
    pub fn expose<R>(&self, f: impl for<'a> FnOnce(&'a Scalar) -> R) -> R {
        self.scalar.expose(f)
    }

    /// Consumes the private key and returns the inner scalar.
    ///
    /// See [`Secret::expose_unwrap`](crate::Secret::expose_unwrap) for more details.
    pub fn expose_unwrap(self) -> Scalar {
        self.scalar.expose_unwrap()
    }
}

impl Write for Private {
    fn write(&self, buf: &mut impl BufMut) {
        self.expose(|scalar| scalar.write(buf));
    }
}

impl Read for Private {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let scalar = Scalar::read(buf)?;
        Ok(Self::new(scalar))
    }
}

impl FixedSize for Private {
    const SIZE: usize = PRIVATE_KEY_LENGTH;
}

impl Random for Private {
    fn random(rng: impl CryptoRngCore) -> Self {
        Self::new(Scalar::random(rng))
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Private {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary::<Scalar>()?))
    }
}

/// The private key length.
pub const PRIVATE_KEY_LENGTH: usize = SCALAR_LENGTH;

impl Scalar {
    /// Creates a scalar from input key material.
    /// Uses IETF BLS KeyGen which loops internally until a non-zero value is produced.
    fn from_ikm(ikm: &[u8; IKM_LENGTH]) -> Self {
        let mut sc = blst_scalar::default();
        let mut ret = blst_fr::default();
        // SAFETY: ikm is a valid 64-byte buffer; blst_keygen handles null key_info.
        unsafe {
            blst_keygen(&mut sc, ikm.as_ptr(), ikm.len(), ptr::null(), 0);
            blst_fr_from_scalar(&mut ret, &sc);
        }
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
        let mut uniform_bytes = Zeroizing::new([0u8; L]);
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
    pub(crate) fn from_u64(i: u64) -> Self {
        // Create a new scalar
        let mut ret = blst_fr::default();
        let buffer = [i, 0, 0, 0];

        // SAFETY: blst_fr_from_uint64 reads exactly 4 u64 values from the buffer.
        //
        // Reference: https://github.com/supranational/blst/blob/415d4f0e2347a794091836a3065206edfd9c72f3/bindings/blst.h#L102
        unsafe { blst_fr_from_uint64(&mut ret, buffer.as_ptr()) };
        Self(ret)
    }

    /// Encodes the scalar into a byte array.
    fn as_slice(&self) -> Zeroizing<[u8; Self::SIZE]> {
        let mut slice = Zeroizing::new([0u8; Self::SIZE]);
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

impl Write for Scalar {
    fn write(&self, buf: &mut impl BufMut) {
        let slice = self.as_slice();
        buf.put_slice(slice.as_ref());
    }
}

impl Read for Scalar {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let bytes = Zeroizing::new(<[u8; Self::SIZE]>::read(buf)?);
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
        state.write(slice.as_ref());
    }
}

impl CtEq for Scalar {
    fn ct_eq(&self, other: &Self) -> ctutils::Choice {
        self.0.l.ct_eq(&other.0.l)
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
        write!(f, "Scalar([REDACTED])")
    }
}

impl Display for Scalar {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "[REDACTED]")
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

impl Object for Scalar {}

impl<'a> AddAssign<&'a Self> for Scalar {
    fn add_assign(&mut self, rhs: &'a Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_fr_add supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_fr_add(ptr, ptr, &rhs.0);
        }
    }
}

impl<'a> Add<&'a Self> for Scalar {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl<'a> SubAssign<&'a Self> for Scalar {
    fn sub_assign(&mut self, rhs: &'a Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_fr_sub supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe { blst_fr_sub(ptr, ptr, &rhs.0) }
    }
}

impl<'a> Sub<&'a Self> for Scalar {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        let ptr = &raw mut self.0;
        // SAFETY: blst_fr_cneg supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_fr_cneg(ptr, ptr, true);
        }
        self
    }
}

impl Additive for Scalar {
    fn zero() -> Self {
        Self(blst_fr::default())
    }
}

impl<'a> MulAssign<&'a Self> for Scalar {
    fn mul_assign(&mut self, rhs: &'a Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_fr_mul supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_fr_mul(ptr, ptr, &rhs.0);
        }
    }
}

impl<'a> Mul<&'a Self> for Scalar {
    type Output = Self;

    fn mul(mut self, rhs: &'a Self) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Multiplicative for Scalar {}

impl Ring for Scalar {
    fn one() -> Self {
        BLST_FR_ONE
    }
}

impl Field for Scalar {
    fn inv(&self) -> Self {
        if *self == Self::zero() {
            return Self::zero();
        }
        let mut ret = blst_fr::default();
        // SAFETY: Input is non-zero (checked above); blst_fr_inverse is defined for non-zero.
        unsafe { blst_fr_inverse(&mut ret, &self.0) };
        Self(ret)
    }
}

impl Random for Scalar {
    /// Returns a random non-zero scalar.
    fn random(mut rng: impl CryptoRngCore) -> Self {
        let mut ikm = Zeroizing::new([0u8; IKM_LENGTH]);
        rng.fill_bytes(ikm.as_mut());
        Self::from_ikm(&ikm)
    }
}

/// A share of a threshold signing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    /// The share's index in the polynomial.
    pub index: Participant,
    /// The scalar corresponding to the share's secret.
    pub private: Private,
}

impl Share {
    /// Creates a new `Share` with the given index and private key.
    pub const fn new(index: Participant, private: Private) -> Self {
        Self { index, private }
    }

    /// Returns the public key corresponding to the share.
    ///
    /// This can be verified against the public polynomial.
    pub fn public<V: Variant>(&self) -> V::Public {
        self.private
            .expose(|private| V::Public::generator() * private)
    }
}

impl Write for Share {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.private.expose(|private| private.write(buf));
    }
}

impl Read for Share {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let index = Participant::read(buf)?;
        let private = Private::read(buf)?;
        Ok(Self { index, private })
    }
}

impl EncodeSize for Share {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + self.private.expose(|private| private.encode_size())
    }
}

impl Display for Share {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Share {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let index = u.arbitrary()?;
        let private = u.arbitrary::<Private>()?;
        Ok(Self { index, private })
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

    /// Like [`std::ops::Neg::neg`], except operating in place.
    ///
    /// This function exists in order to avoid an extra copy when implement
    /// subtraction. Basically, the compiler (including LLVM) aren't smart
    /// enough to eliminate a copy that happens if you implement subtraction
    /// as `x += &-*rhs`. So, instead, we copy rhs, negate it in place, and then
    /// add it, to avoid a copy.
    fn neg_in_place(&mut self) {
        let ptr = &raw mut self.0;
        // SAFETY: ptr is valid.
        unsafe {
            blst_p1_cneg(ptr, true);
        }
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

    /// Batch converts projective G1 points to affine.
    ///
    /// This uses Montgomery's trick to reduce n field inversions to 1,
    /// providing significant speedup over converting points individually.
    pub fn batch_to_affine(points: &[Self]) -> Vec<blst_p1_affine> {
        if points.is_empty() {
            return Vec::new();
        }

        let n = points.len();
        let mut out = vec![blst_p1_affine::default(); n];

        // SAFETY: blst_p1s_to_affine batch converts projective points to affine.
        // The function uses Montgomery's trick internally for efficiency.
        // All pointers are valid and point to properly sized arrays.
        unsafe {
            let points_ptr: Vec<*const blst_p1> = points.iter().map(|p| &p.0 as *const _).collect();
            blst_p1s_to_affine(out.as_mut_ptr(), points_ptr.as_ptr(), n);
        }

        out
    }

    /// Checks that `sum_i (p1[i] ⊙ p2[i]) + t1 ⊙ t2 == 0`.
    ///
    /// `p1` and `p2` MUST have the same length.
    #[must_use]
    pub(crate) fn multi_pairing_check(p1: &[Self], p2: &[G2], t1: &Self, t2: &G2) -> bool {
        assert_eq!(p1.len(), p2.len());
        // We deal with group elements directly, so there's no need for hashing,
        // or a domain separation tag, hence `false`, `&[]`.
        let mut pairing = Pairing::new(false, &[]);
        let p1_affine = Self::batch_to_affine(p1);
        let p2_affine = G2::batch_to_affine(p2);
        for (p1, p2) in iter::once((&t1.as_blst_p1_affine(), &t2.as_blst_p2_affine()))
            .chain(p1_affine.iter().zip(p2_affine.iter()))
        {
            pairing.raw_aggregate(p2, p1);
        }

        // These final two steps check that the sum of the pairings is equal to 0.
        pairing.commit();
        // Passing `None` here indicates that our target is 0.
        pairing.finalverify(None)
    }

    fn msm_inner<'a>(
        iter: impl Iterator<Item = (&'a Self, &'a [u8])>,
        nbits: usize,
        strategy: &impl Strategy,
    ) -> Self {
        // Filter out zero points/scalars and convert to blst types.
        // `blst` does not filter out infinity, so we must ensure it is impossible.
        //
        // Sources:
        // * https://github.com/supranational/blst/blob/cbc7e166a10d7286b91a3a7bea341e708962db13/src/multi_scalar.c#L10-L12
        // * https://github.com/MystenLabs/fastcrypto/blob/0acf0ff1a163c60e0dec1e16e4fbad4a4cf853bd/fastcrypto/src/groups/bls12381.rs#L160-L194
        let nbytes = nbits.div_ceil(8);
        let (points_filtered, scalars_filtered): (Vec<_>, Vec<_>) = iter
            .filter_map(|(point, scalar)| {
                if *point == Self::zero() || all_zero(scalar).into() {
                    return None;
                }
                Some((point, scalar))
            })
            .unzip();

        if points_filtered.is_empty() {
            return Self::zero();
        }

        let npoints = points_filtered.len();
        let ncpus = strategy.parallelism_hint();

        // Convert to affine points
        let affine_points = Self::batch_to_affine(&points_filtered);

        // Flatten scalars into contiguous byte array
        let scalar_bytes: Vec<u8> = scalars_filtered
            .iter()
            .flat_map(|s| s[..nbytes].iter().copied())
            .collect();

        // For small inputs or single CPU, use single-threaded path
        if ncpus < 2 || npoints < MIN_PARALLEL_POINTS {
            return Self::msm_sequential(&affine_points, &scalar_bytes, nbits);
        }

        // Parallel MSM using tile_pippenger
        Self::msm_parallel(&affine_points, &scalar_bytes, nbits, ncpus, strategy)
    }

    fn msm_sequential(affine_points: &[blst_p1_affine], scalars: &[u8], nbits: usize) -> Self {
        let npoints = affine_points.len();

        // SAFETY: blst_p1s_mult_pippenger_scratch_sizeof returns size in bytes for valid input.
        let scratch_size = unsafe { blst_p1s_mult_pippenger_scratch_sizeof(npoints) };
        assert_eq!(scratch_size % 8, 0, "scratch_size must be multiple of 8");
        let mut scratch = vec![0u64; scratch_size / 8];

        // blst uses null-terminated pointer arrays
        let p: [*const blst_p1_affine; 2] = [affine_points.as_ptr(), ptr::null()];
        let s: [*const u8; 2] = [scalars.as_ptr(), ptr::null()];

        let mut result = blst_p1::default();
        // SAFETY: All pointer arrays are valid and point to data that outlives this call.
        unsafe {
            blst_p1s_mult_pippenger(
                &mut result,
                p.as_ptr(),
                npoints,
                s.as_ptr(),
                nbits,
                scratch.as_mut_ptr(),
            );
        }
        Self::from_blst_p1(result)
    }

    fn msm_parallel(
        affine_points: &[blst_p1_affine],
        scalars: &[u8],
        nbits: usize,
        ncpus: usize,
        strategy: &impl Strategy,
    ) -> Self {
        let npoints = affine_points.len();
        let nbytes = nbits.div_ceil(8);
        let (nx, ny, window) = msm_breakdown(nbits, pippenger_window_size(npoints), ncpus);
        let tiles = build_tiles(npoints, nx, ny, window);

        // Compute all tiles in parallel
        // SAFETY: blst_p1s_mult_pippenger_scratch_sizeof(0) returns base scratch size.
        let scratch_size = unsafe { blst_p1s_mult_pippenger_scratch_sizeof(0) } / 8;
        let tile_results: Vec<(usize, usize, blst_p1)> =
            strategy.map_collect_vec(tiles.iter().enumerate(), |(idx, tile)| {
                let mut scratch = vec![0u64; scratch_size << (window - 1)];
                let mut result = blst_p1::default();

                // blst uses null-terminated pointer arrays
                let p: [*const blst_p1_affine; 2] = [affine_points[tile.x..].as_ptr(), ptr::null()];
                let s: [*const u8; 2] = [scalars[tile.x * nbytes..].as_ptr(), ptr::null()];

                // SAFETY: All pointers valid, scratch sized correctly for window.
                unsafe {
                    blst_p1s_tile_pippenger(
                        &mut result,
                        p.as_ptr(),
                        tile.dx,
                        s.as_ptr(),
                        nbits,
                        scratch.as_mut_ptr(),
                        tile.y,
                        window,
                    );
                }
                (idx / nx, idx % nx, result)
            });

        // Combine results by row
        let mut row_sums: Vec<Option<blst_p1>> = vec![None; ny];
        for (row, _col, point) in tile_results {
            match &mut row_sums[row] {
                // SAFETY: blst_p1_add_or_double is safe for valid blst_p1 points.
                Some(sum) => unsafe { blst_p1_add_or_double(sum, sum, &point) },
                None => row_sums[row] = Some(point),
            }
        }

        // Combine rows with doubling (highest bits first)
        let mut result = blst_p1::default();
        for (i, row_sum) in row_sums.into_iter().enumerate() {
            if let Some(sum) = row_sum {
                // SAFETY: blst_p1_add_or_double is safe for valid blst_p1 points.
                unsafe { blst_p1_add_or_double(&mut result, &result, &sum) };
            }
            // Double `window` times for all but the last row
            if i < ny - 1 {
                for _ in 0..window {
                    // SAFETY: blst_p1_double is safe for valid blst_p1 points.
                    unsafe { blst_p1_double(&mut result, &result) };
                }
            }
        }

        Self::from_blst_p1(result)
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

impl Object for G1 {}

impl<'a> AddAssign<&'a Self> for G1 {
    fn add_assign(&mut self, rhs: &'a Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_p1_add_or_double supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_p1_add_or_double(ptr, ptr, &rhs.0);
        }
    }
}

impl<'a> Add<&'a Self> for G1 {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl Neg for G1 {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.neg_in_place();
        self
    }
}

impl<'a> SubAssign<&'a Self> for G1 {
    fn sub_assign(&mut self, rhs: &'a Self) {
        let mut rhs_cp = *rhs;
        rhs_cp.neg_in_place();
        *self += &rhs_cp;
    }
}

impl<'a> Sub<&'a Self> for G1 {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Additive for G1 {
    fn zero() -> Self {
        Self(blst_p1::default())
    }
}

impl<'a> MulAssign<&'a Scalar> for G1 {
    fn mul_assign(&mut self, rhs: &'a Scalar) {
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

impl<'a> Mul<&'a Scalar> for G1 {
    type Output = Self;

    fn mul(mut self, rhs: &'a Scalar) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<'a> MulAssign<&'a SmallScalar> for G1 {
    fn mul_assign(&mut self, rhs: &'a SmallScalar) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_p1_mult supports in-place (ret==a). Using SMALL_SCALAR_BITS (128)
        // processes only the lower 128 bits of the scalar, halving computation time.
        unsafe {
            blst_p1_mult(ptr, ptr, rhs.inner.b.as_ptr(), SMALL_SCALAR_BITS);
        }
    }
}

impl<'a> Mul<&'a SmallScalar> for G1 {
    type Output = Self;

    fn mul(mut self, rhs: &'a SmallScalar) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Space<Scalar> for G1 {
    fn msm(points: &[Self], scalars: &[Scalar], strategy: &impl Strategy) -> Self {
        assert_eq!(points.len(), scalars.len(), "mismatched lengths");
        let scalar_bytes: Vec<_> = scalars.iter().map(|s| s.as_blst_scalar()).collect();
        Self::msm_inner(
            points
                .iter()
                .zip(scalar_bytes.iter().map(|s| s.b.as_slice())),
            SCALAR_BITS,
            strategy,
        )
    }
}

impl Space<SmallScalar> for G1 {
    fn msm(points: &[Self], scalars: &[SmallScalar], strategy: &impl Strategy) -> Self {
        assert_eq!(points.len(), scalars.len(), "mismatched lengths");
        Self::msm_inner(
            points.iter().zip(scalars.iter().map(|s| s.as_bytes())),
            SMALL_SCALAR_BITS,
            strategy,
        )
    }
}

impl CryptoGroup for G1 {
    type Scalar = Scalar;

    fn generator() -> Self {
        let mut ret = blst_p1::default();
        // SAFETY: BLS12_381_G1 is a valid generator point constant.
        unsafe {
            blst_p1_from_affine(&mut ret, &BLS12_381_G1);
        }
        Self(ret)
    }
}

impl HashToGroup for G1 {
    fn hash_to_group(domain_separator: &[u8], message: &[u8]) -> Self {
        let mut out = blst_p1::default();
        // SAFETY: All pointers valid; blst_hash_to_g1 handles empty data. Aug is null/0 (unused).
        unsafe {
            blst_hash_to_g1(
                &mut out,
                message.as_ptr(),
                message.len(),
                domain_separator.as_ptr(),
                domain_separator.len(),
                ptr::null(),
                0,
            );
        }
        Self(out)
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

    /// c.f. [G1::neg_in_place].
    fn neg_in_place(&mut self) {
        let ptr = &raw mut self.0;
        // SAFETY: ptr is valid.
        unsafe {
            blst_p2_cneg(ptr, true);
        }
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

    /// Batch converts projective G2 points to affine.
    ///
    /// This uses Montgomery's trick to reduce n field inversions to 1,
    /// providing significant speedup over converting points individually.
    pub fn batch_to_affine(points: &[Self]) -> Vec<blst_p2_affine> {
        if points.is_empty() {
            return Vec::new();
        }

        let n = points.len();
        let mut out = vec![blst_p2_affine::default(); n];

        // SAFETY: blst_p2s_to_affine batch converts projective points to affine.
        // The function uses Montgomery's trick internally for efficiency.
        // All pointers are valid and point to properly sized arrays.
        unsafe {
            let points_ptr: Vec<*const blst_p2> = points.iter().map(|p| &p.0 as *const _).collect();
            blst_p2s_to_affine(out.as_mut_ptr(), points_ptr.as_ptr(), n);
        }

        out
    }

    /// Checks that `sum_i (p1[i] ⊙ p2[i]) + t1 ⊙ t2 == 0`.
    ///
    /// `p1` and `p2` MUST have the same length.
    #[must_use]
    pub(crate) fn multi_pairing_check(p1: &[Self], p2: &[G1], t1: &Self, t2: &G1) -> bool {
        G1::multi_pairing_check(p2, p1, t2, t1)
    }

    fn msm_inner<'a>(
        iter: impl Iterator<Item = (&'a Self, &'a [u8])>,
        nbits: usize,
        strategy: &impl Strategy,
    ) -> Self {
        // Filter out zero points/scalars and convert to blst types.
        // `blst` does not filter out infinity, so we must ensure it is impossible.
        //
        // Sources:
        // * https://github.com/supranational/blst/blob/cbc7e166a10d7286b91a3a7bea341e708962db13/src/multi_scalar.c#L10-L12
        // * https://github.com/MystenLabs/fastcrypto/blob/0acf0ff1a163c60e0dec1e16e4fbad4a4cf853bd/fastcrypto/src/groups/bls12381.rs#L160-L194
        let nbytes = nbits.div_ceil(8);
        let (points_filtered, scalars_filtered): (Vec<_>, Vec<_>) = iter
            .filter_map(|(point, scalar)| {
                if *point == Self::zero() || all_zero(scalar).into() {
                    return None;
                }
                Some((point, scalar))
            })
            .unzip();

        if points_filtered.is_empty() {
            return Self::zero();
        }

        let npoints = points_filtered.len();
        let ncpus = strategy.parallelism_hint();

        // Convert to affine points
        let affine_points = Self::batch_to_affine(&points_filtered);

        // Flatten scalars into contiguous byte array
        let scalar_bytes: Vec<u8> = scalars_filtered
            .iter()
            .flat_map(|s| s[..nbytes].iter().copied())
            .collect();

        // For small inputs or single CPU, use single-threaded path
        if ncpus < 2 || npoints < MIN_PARALLEL_POINTS {
            return Self::msm_sequential(&affine_points, &scalar_bytes, nbits);
        }

        // Parallel MSM using tile_pippenger
        Self::msm_parallel(&affine_points, &scalar_bytes, nbits, ncpus, strategy)
    }

    fn msm_sequential(affine_points: &[blst_p2_affine], scalars: &[u8], nbits: usize) -> Self {
        let npoints = affine_points.len();

        // SAFETY: blst_p2s_mult_pippenger_scratch_sizeof returns size in bytes for valid input.
        let scratch_size = unsafe { blst_p2s_mult_pippenger_scratch_sizeof(npoints) };
        assert_eq!(scratch_size % 8, 0, "scratch_size must be multiple of 8");
        let mut scratch = vec![0u64; scratch_size / 8];

        // blst uses null-terminated pointer arrays
        let p: [*const blst_p2_affine; 2] = [affine_points.as_ptr(), ptr::null()];
        let s: [*const u8; 2] = [scalars.as_ptr(), ptr::null()];

        let mut result = blst_p2::default();
        // SAFETY: All pointer arrays are valid and point to data that outlives this call.
        unsafe {
            blst_p2s_mult_pippenger(
                &mut result,
                p.as_ptr(),
                npoints,
                s.as_ptr(),
                nbits,
                scratch.as_mut_ptr(),
            );
        }
        Self::from_blst_p2(result)
    }

    fn msm_parallel(
        affine_points: &[blst_p2_affine],
        scalars: &[u8],
        nbits: usize,
        ncpus: usize,
        strategy: &impl Strategy,
    ) -> Self {
        let npoints = affine_points.len();
        let nbytes = nbits.div_ceil(8);
        let (nx, ny, window) = msm_breakdown(nbits, pippenger_window_size(npoints), ncpus);
        let tiles = build_tiles(npoints, nx, ny, window);

        // Compute all tiles in parallel
        // SAFETY: blst_p2s_mult_pippenger_scratch_sizeof(0) returns base scratch size.
        let scratch_size = unsafe { blst_p2s_mult_pippenger_scratch_sizeof(0) } / 8;
        let tile_results: Vec<(usize, usize, blst_p2)> =
            strategy.map_collect_vec(tiles.iter().enumerate(), |(idx, tile)| {
                let mut scratch = vec![0u64; scratch_size << (window - 1)];
                let mut result = blst_p2::default();

                // blst uses null-terminated pointer arrays
                let p: [*const blst_p2_affine; 2] = [affine_points[tile.x..].as_ptr(), ptr::null()];
                let s: [*const u8; 2] = [scalars[tile.x * nbytes..].as_ptr(), ptr::null()];

                // SAFETY: All pointers valid, scratch sized correctly for window.
                unsafe {
                    blst_p2s_tile_pippenger(
                        &mut result,
                        p.as_ptr(),
                        tile.dx,
                        s.as_ptr(),
                        nbits,
                        scratch.as_mut_ptr(),
                        tile.y,
                        window,
                    );
                }
                (idx / nx, idx % nx, result)
            });

        // Combine results by row
        let mut row_sums: Vec<Option<blst_p2>> = vec![None; ny];
        for (row, _col, point) in tile_results {
            match &mut row_sums[row] {
                // SAFETY: blst_p2_add_or_double is safe for valid blst_p2 points.
                Some(sum) => unsafe { blst_p2_add_or_double(sum, sum, &point) },
                None => row_sums[row] = Some(point),
            }
        }

        // Combine rows with doubling (highest bits first)
        let mut result = blst_p2::default();
        for (i, row_sum) in row_sums.into_iter().enumerate() {
            if let Some(sum) = row_sum {
                // SAFETY: blst_p2_add_or_double is safe for valid blst_p2 points.
                unsafe { blst_p2_add_or_double(&mut result, &result, &sum) };
            }
            // Double `window` times for all but the last row
            if i < ny - 1 {
                for _ in 0..window {
                    // SAFETY: blst_p2_double is safe for valid blst_p2 points.
                    unsafe { blst_p2_double(&mut result, &result) };
                }
            }
        }

        Self::from_blst_p2(result)
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

impl Object for G2 {}

impl<'a> AddAssign<&'a Self> for G2 {
    fn add_assign(&mut self, rhs: &'a Self) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_p2_add_or_double supports in-place (ret==a). Raw pointer avoids aliased refs.
        unsafe {
            blst_p2_add_or_double(ptr, ptr, &rhs.0);
        }
    }
}

impl<'a> Add<&'a Self> for G2 {
    type Output = Self;

    fn add(mut self, rhs: &'a Self) -> Self::Output {
        self += rhs;
        self
    }
}

impl Neg for G2 {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        self.neg_in_place();
        self
    }
}

impl<'a> SubAssign<&'a Self> for G2 {
    fn sub_assign(&mut self, rhs: &'a Self) {
        let mut rhs_cp = *rhs;
        rhs_cp.neg_in_place();
        *self += &rhs_cp;
    }
}

impl<'a> Sub<&'a Self> for G2 {
    type Output = Self;

    fn sub(mut self, rhs: &'a Self) -> Self::Output {
        self -= rhs;
        self
    }
}

impl Additive for G2 {
    fn zero() -> Self {
        Self(blst_p2::default())
    }
}

impl<'a> MulAssign<&'a Scalar> for G2 {
    fn mul_assign(&mut self, rhs: &'a Scalar) {
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

impl<'a> Mul<&'a Scalar> for G2 {
    type Output = Self;

    fn mul(mut self, rhs: &'a Scalar) -> Self::Output {
        self *= rhs;
        self
    }
}

impl<'a> MulAssign<&'a SmallScalar> for G2 {
    fn mul_assign(&mut self, rhs: &'a SmallScalar) {
        let ptr = &raw mut self.0;
        // SAFETY: blst_p2_mult supports in-place (ret==a). Using SMALL_SCALAR_BITS (128)
        // processes only the lower 128 bits of the scalar, halving computation time.
        unsafe {
            blst_p2_mult(ptr, ptr, rhs.inner.b.as_ptr(), SMALL_SCALAR_BITS);
        }
    }
}

impl<'a> Mul<&'a SmallScalar> for G2 {
    type Output = Self;

    fn mul(mut self, rhs: &'a SmallScalar) -> Self::Output {
        self *= rhs;
        self
    }
}

impl Space<Scalar> for G2 {
    fn msm(points: &[Self], scalars: &[Scalar], strategy: &impl Strategy) -> Self {
        assert_eq!(points.len(), scalars.len(), "mismatched lengths");
        let scalar_bytes: Vec<_> = scalars.iter().map(|s| s.as_blst_scalar()).collect();
        Self::msm_inner(
            points
                .iter()
                .zip(scalar_bytes.iter().map(|s| s.b.as_slice())),
            SCALAR_BITS,
            strategy,
        )
    }
}

impl Space<SmallScalar> for G2 {
    fn msm(points: &[Self], scalars: &[SmallScalar], strategy: &impl Strategy) -> Self {
        assert_eq!(points.len(), scalars.len(), "mismatched lengths");
        Self::msm_inner(
            points.iter().zip(scalars.iter().map(|s| s.as_bytes())),
            SMALL_SCALAR_BITS,
            strategy,
        )
    }
}

impl CryptoGroup for G2 {
    type Scalar = Scalar;

    fn generator() -> Self {
        let mut ret = blst_p2::default();
        // SAFETY: BLS12_381_G2 is a valid generator point constant.
        unsafe {
            blst_p2_from_affine(&mut ret, &BLS12_381_G2);
        }
        Self(ret)
    }
}

impl HashToGroup for G2 {
    fn hash_to_group(domain_separator: &[u8], message: &[u8]) -> Self {
        let mut out = blst_p2::default();
        // SAFETY: All pointers valid; blst_hash_to_g2 handles empty data. Aug is null/0 (unused).
        unsafe {
            blst_hash_to_g2(
                &mut out,
                message.as_ptr(),
                message.len(),
                domain_separator.as_ptr(),
                domain_separator.len(),
                ptr::null(),
                0,
            );
        }
        Self(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls12381::primitives::group::Scalar;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_math::algebra::{test_suites, Random};
    use commonware_parallel::{Rayon, Sequential};
    use commonware_utils::test_rng;
    use proptest::{prelude::*, strategy::Strategy};
    use rand::{rngs::StdRng, SeedableRng};
    use std::{
        collections::{BTreeSet, HashMap},
        num::NonZeroUsize,
    };

    impl Arbitrary for Scalar {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            any::<[u8; 32]>()
                .prop_map(|seed| Self::random(&mut StdRng::from_seed(seed)))
                .boxed()
        }
    }

    impl Arbitrary for G1 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(Self::zero()),
                Just(Self::generator()),
                any::<Scalar>().prop_map(|s| Self::generator() * &s)
            ]
            .boxed()
        }
    }

    impl Arbitrary for G2 {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with(_args: Self::Parameters) -> Self::Strategy {
            prop_oneof![
                Just(Self::zero()),
                Just(Self::generator()),
                any::<Scalar>().prop_map(|s| Self::generator() * &s)
            ]
            .boxed()
        }
    }

    #[test]
    fn test_scalar_as_field() {
        test_suites::test_field(file!(), &any::<Scalar>());
    }

    #[test]
    fn test_g1_as_space() {
        test_suites::test_space_ring(file!(), &any::<Scalar>(), &any::<G1>());
    }

    #[test]
    fn test_g2_as_space() {
        test_suites::test_space_ring(file!(), &any::<Scalar>(), &any::<G2>());
    }

    #[test]
    fn test_hash_to_g1() {
        test_suites::test_hash_to_group::<G1>(file!());
    }

    #[test]
    fn test_hash_to_g2() {
        test_suites::test_hash_to_group::<G2>(file!());
    }

    #[test]
    fn basic_group() {
        // Reference: https://github.com/celo-org/celo-threshold-bls-rs/blob/b0ef82ff79769d085a5a7d3f4fe690b1c8fe6dc9/crates/threshold-bls/src/curve/bls12381.rs#L200-L220
        let s = Scalar::random(&mut test_rng());
        let mut s2 = s.clone();
        s2.double();

        // p1 = s2 * G = (s+s)G
        let p1 = G1::generator() * &s2;

        // p2 = sG + sG = s2 * G
        let mut p2 = G1::generator() * &s;
        p2.double();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_scalar_codec() {
        let original = Scalar::random(&mut test_rng());
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), Scalar::SIZE);
        let decoded = Scalar::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_g1_codec() {
        let original = G1::generator() * &Scalar::random(&mut test_rng());
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), G1::SIZE);
        let decoded = G1::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_g2_codec() {
        let original = G2::generator() * &Scalar::random(&mut test_rng());
        let mut encoded = original.encode();
        assert_eq!(encoded.len(), G2::SIZE);
        let decoded = G2::decode(&mut encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// Naive calculation of Multi-Scalar Multiplication: sum(scalar * point)
    fn naive_msm<P: Space<Scalar>>(points: &[P], scalars: &[Scalar]) -> P {
        assert_eq!(points.len(), scalars.len());
        let mut total = P::zero();
        for (point, scalar) in points.iter().zip(scalars.iter()) {
            // Skip identity points or zero scalars, similar to the optimized MSM
            if *point == P::zero() || *scalar == Scalar::zero() {
                continue;
            }
            let term = point.clone() * scalar;
            total += &term;
        }
        total
    }

    #[test]
    fn test_g1_msm() {
        let mut rng = test_rng();
        let n = 10; // Number of points/scalars

        // Case 1: Random points and scalars
        let points_g1: Vec<G1> = (0..n)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();
        let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let expected_g1 = naive_msm(&points_g1, &scalars);
        let result_g1 = G1::msm(&points_g1, &scalars, &Sequential);
        assert_eq!(expected_g1, result_g1, "G1 MSM basic case failed");

        // Case 2: Include identity point
        let mut points_with_zero_g1 = points_g1.clone();
        points_with_zero_g1[n / 2] = G1::zero();
        let expected_zero_pt_g1 = naive_msm(&points_with_zero_g1, &scalars);
        let result_zero_pt_g1 = G1::msm(&points_with_zero_g1, &scalars, &Sequential);
        assert_eq!(
            expected_zero_pt_g1, result_zero_pt_g1,
            "G1 MSM with identity point failed"
        );

        // Case 3: Include zero scalar
        let mut scalars_with_zero = scalars.clone();
        scalars_with_zero[n / 2] = Scalar::zero();
        let expected_zero_sc_g1 = naive_msm(&points_g1, &scalars_with_zero);
        let result_zero_sc_g1 = G1::msm(&points_g1, &scalars_with_zero, &Sequential);
        assert_eq!(
            expected_zero_sc_g1, result_zero_sc_g1,
            "G1 MSM with zero scalar failed"
        );

        // Case 4: All points identity
        let zero_points_g1 = vec![G1::zero(); n];
        let expected_all_zero_pt_g1 = naive_msm(&zero_points_g1, &scalars);
        let result_all_zero_pt_g1 = G1::msm(&zero_points_g1, &scalars, &Sequential);
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
        let result_all_zero_sc_g1 = G1::msm(&points_g1, &zero_scalars, &Sequential);
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
        let result_single_g1 = G1::msm(&single_point_g1, &single_scalar, &Sequential);
        assert_eq!(
            expected_single_g1, result_single_g1,
            "G1 MSM single element failed"
        );

        // Case 7: Empty input
        let empty_points_g1: [G1; 0] = [];
        let empty_scalars: [Scalar; 0] = [];
        let expected_empty_g1 = naive_msm(&empty_points_g1, &empty_scalars);
        let result_empty_g1 = G1::msm(&empty_points_g1, &empty_scalars, &Sequential);
        assert_eq!(expected_empty_g1, G1::zero(), "G1 MSM empty (naive) failed");
        assert_eq!(result_empty_g1, G1::zero(), "G1 MSM empty failed");

        // Case 8: Random points and scalars (big)
        let points_g1: Vec<G1> = (0..50_000)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();
        let scalars: Vec<Scalar> = (0..50_000).map(|_| Scalar::random(&mut rng)).collect();
        let expected_g1 = naive_msm(&points_g1, &scalars);
        let result_g1 = G1::msm(&points_g1, &scalars, &Sequential);
        assert_eq!(expected_g1, result_g1, "G1 MSM basic case failed");
    }

    #[test]
    fn test_g2_msm() {
        let mut rng = test_rng();
        let n = 10; // Number of points/scalars

        // Case 1: Random points and scalars
        let points_g2: Vec<G2> = (0..n)
            .map(|_| G2::generator() * &Scalar::random(&mut rng))
            .collect();
        let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let expected_g2 = naive_msm(&points_g2, &scalars);
        let result_g2 = G2::msm(&points_g2, &scalars, &Sequential);
        assert_eq!(expected_g2, result_g2, "G2 MSM basic case failed");

        // Case 2: Include identity point
        let mut points_with_zero_g2 = points_g2.clone();
        points_with_zero_g2[n / 2] = G2::zero();
        let expected_zero_pt_g2 = naive_msm(&points_with_zero_g2, &scalars);
        let result_zero_pt_g2 = G2::msm(&points_with_zero_g2, &scalars, &Sequential);
        assert_eq!(
            expected_zero_pt_g2, result_zero_pt_g2,
            "G2 MSM with identity point failed"
        );

        // Case 3: Include zero scalar
        let mut scalars_with_zero = scalars.clone();
        scalars_with_zero[n / 2] = Scalar::zero();
        let expected_zero_sc_g2 = naive_msm(&points_g2, &scalars_with_zero);
        let result_zero_sc_g2 = G2::msm(&points_g2, &scalars_with_zero, &Sequential);
        assert_eq!(
            expected_zero_sc_g2, result_zero_sc_g2,
            "G2 MSM with zero scalar failed"
        );

        // Case 4: All points identity
        let zero_points_g2 = vec![G2::zero(); n];
        let expected_all_zero_pt_g2 = naive_msm(&zero_points_g2, &scalars);
        let result_all_zero_pt_g2 = G2::msm(&zero_points_g2, &scalars, &Sequential);
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
        let result_all_zero_sc_g2 = G2::msm(&points_g2, &zero_scalars, &Sequential);
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
        let result_single_g2 = G2::msm(&single_point_g2, &single_scalar, &Sequential);
        assert_eq!(
            expected_single_g2, result_single_g2,
            "G2 MSM single element failed"
        );

        // Case 7: Empty input
        let empty_points_g2: [G2; 0] = [];
        let empty_scalars: [Scalar; 0] = [];
        let expected_empty_g2 = naive_msm(&empty_points_g2, &empty_scalars);
        let result_empty_g2 = G2::msm(&empty_points_g2, &empty_scalars, &Sequential);
        assert_eq!(expected_empty_g2, G2::zero(), "G2 MSM empty (naive) failed");
        assert_eq!(result_empty_g2, G2::zero(), "G2 MSM empty failed");

        // Case 8: Random points and scalars (big)
        let points_g2: Vec<G2> = (0..50_000)
            .map(|_| G2::generator() * &Scalar::random(&mut rng))
            .collect();
        let scalars: Vec<Scalar> = (0..50_000).map(|_| Scalar::random(&mut rng)).collect();
        let expected_g2 = naive_msm(&points_g2, &scalars);
        let result_g2 = G2::msm(&points_g2, &scalars, &Sequential);
        assert_eq!(expected_g2, result_g2, "G2 MSM basic case failed");
    }

    #[test]
    fn test_trait_implementations() {
        // Generate a set of unique items to test.
        let mut rng = test_rng();
        const NUM_ITEMS: usize = 10;
        let mut scalar_set = BTreeSet::new();
        let mut g1_set = BTreeSet::new();
        let mut g2_set = BTreeSet::new();
        while scalar_set.len() < NUM_ITEMS {
            let scalar = Scalar::random(&mut rng);
            let g1 = G1::generator() * &scalar;
            let g2 = G2::generator() * &scalar;

            scalar_set.insert(scalar);
            g1_set.insert(g1);
            g2_set.insert(g2);
        }

        // Verify that the sets contain the expected number of unique items.
        assert_eq!(scalar_set.len(), NUM_ITEMS);
        assert_eq!(g1_set.len(), NUM_ITEMS);
        assert_eq!(g2_set.len(), NUM_ITEMS);

        // Verify that `BTreeSet` iteration is sorted, which relies on `Ord`.
        let scalars: Vec<_> = scalar_set.iter().collect();
        assert!(scalars.windows(2).all(|w| w[0] <= w[1]));
        let g1s: Vec<_> = g1_set.iter().collect();
        assert!(g1s.windows(2).all(|w| w[0] <= w[1]));
        let g2s: Vec<_> = g2_set.iter().collect();
        assert!(g2s.windows(2).all(|w| w[0] <= w[1]));

        // Test that we can use these types as keys in hash maps, which relies on `Hash` and `Eq`.
        let scalar_map: HashMap<_, _> = scalar_set.iter().cloned().zip(0..).collect();
        let g1_map: HashMap<_, _> = g1_set.iter().cloned().zip(0..).collect();
        let g2_map: HashMap<_, _> = g2_set.iter().cloned().zip(0..).collect();

        // Verify that the maps contain the expected number of unique items.
        assert_eq!(scalar_map.len(), NUM_ITEMS);
        assert_eq!(g1_map.len(), NUM_ITEMS);
        assert_eq!(g2_map.len(), NUM_ITEMS);
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

    #[test]
    fn test_secret_scalar_equality() {
        let mut rng = test_rng();
        let scalar1 = Scalar::random(&mut rng);
        let scalar2 = scalar1.clone();
        let scalar3 = Scalar::random(&mut rng);

        let s1 = Secret::new(scalar1);
        let s2 = Secret::new(scalar2);
        let s3 = Secret::new(scalar3);

        // Same scalar should be equal
        assert_eq!(s1, s2);
        // Different scalars should (very likely) be different
        assert_ne!(s1, s3);
    }

    #[test]
    fn test_share_redacted() {
        let mut rng = test_rng();
        let share = Share::new(Participant::new(1), Private::random(&mut rng));
        let debug = format!("{:?}", share);
        let display = format!("{}", share);
        assert!(debug.contains("REDACTED"));
        assert!(display.contains("REDACTED"));
    }

    fn assert_msm_parallel_eq<G, S>(points: &[G], scalars: &[S], par: &Rayon)
    where
        G: Space<S> + std::fmt::Debug + PartialEq,
    {
        let seq = G::msm(points, scalars, &Sequential);
        assert_eq!(seq, G::msm(points, scalars, par));
    }

    #[test]
    fn test_msm_parallel() {
        let mut rng = test_rng();
        let par = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();

        // G1 (include MIN_PARALLEL_POINTS boundary)
        for n in [
            MIN_PARALLEL_POINTS - 1,
            MIN_PARALLEL_POINTS,
            MIN_PARALLEL_POINTS + 1,
            100,
            500,
            1000,
        ] {
            let points: Vec<G1> = (0..n)
                .map(|_| G1::generator() * &Scalar::random(&mut rng))
                .collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            assert_msm_parallel_eq(&points, &scalars, &par);
        }

        // G2 (include MIN_PARALLEL_POINTS boundary)
        for n in [
            MIN_PARALLEL_POINTS - 1,
            MIN_PARALLEL_POINTS,
            MIN_PARALLEL_POINTS + 1,
            100,
            500,
        ] {
            let points: Vec<G2> = (0..n)
                .map(|_| G2::generator() * &Scalar::random(&mut rng))
                .collect();
            let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
            assert_msm_parallel_eq(&points, &scalars, &par);
        }
    }

    #[test]
    fn test_msm_parallel_small_scalar() {
        let mut rng = test_rng();
        let par = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();

        // G1
        for n in [32, 100, 500] {
            let points: Vec<G1> = (0..n)
                .map(|_| G1::generator() * &Scalar::random(&mut rng))
                .collect();
            let scalars: Vec<SmallScalar> = (0..n).map(|_| SmallScalar::random(&mut rng)).collect();
            assert_msm_parallel_eq(&points, &scalars, &par);
        }

        // G2
        for n in [32, 100] {
            let points: Vec<G2> = (0..n)
                .map(|_| G2::generator() * &Scalar::random(&mut rng))
                .collect();
            let scalars: Vec<SmallScalar> = (0..n).map(|_| SmallScalar::random(&mut rng)).collect();
            assert_msm_parallel_eq(&points, &scalars, &par);
        }
    }

    #[test]
    fn test_msm_parallel_edge_cases() {
        let mut rng = test_rng();
        let par = Rayon::new(NonZeroUsize::new(8).unwrap()).unwrap();
        let n = 50;

        // G1: all zero scalars
        let g1_points: Vec<G1> = (0..n)
            .map(|_| G1::generator() * &Scalar::random(&mut rng))
            .collect();
        assert_eq!(
            G1::msm(&g1_points, &vec![Scalar::zero(); n], &par),
            G1::zero()
        );

        // G1: all identity points
        let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        assert_eq!(G1::msm(&vec![G1::zero(); n], &scalars, &par), G1::zero());

        // G1: single nonzero among zeros
        let mut points = vec![G1::zero(); n];
        let mut scalars = vec![Scalar::zero(); n];
        let p = G1::generator() * &Scalar::random(&mut rng);
        let s = Scalar::random(&mut rng);
        points[25] = p;
        scalars[25] = s.clone();
        assert_eq!(G1::msm(&points, &scalars, &par), p * &s);

        // G2: all zero scalars
        let g2_points: Vec<G2> = (0..n)
            .map(|_| G2::generator() * &Scalar::random(&mut rng))
            .collect();
        assert_eq!(
            G2::msm(&g2_points, &vec![Scalar::zero(); n], &par),
            G2::zero()
        );

        // G2: all identity points
        let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        assert_eq!(G2::msm(&vec![G2::zero(); n], &scalars, &par), G2::zero());
    }

    #[test]
    fn test_msm_breakdown_high_parallelism() {
        for npoints in [32, 50, 100, 200] {
            let window = pippenger_window_size(npoints);
            for ncpus in [64, 128, 256, 512, 1024, 2048] {
                let (nx, ny, final_wnd) = msm_breakdown(SCALAR_BITS, window, ncpus);
                assert!(nx >= 1 && ny >= 1 && final_wnd >= 1);
            }
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<G1>,
            CodecConformance<G2>,
            CodecConformance<Private>,
            CodecConformance<Scalar>,
            CodecConformance<Share>
        }
    }
}

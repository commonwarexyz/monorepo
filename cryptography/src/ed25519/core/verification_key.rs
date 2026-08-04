use super::{Error, Signature, msm, point};
use commonware_formatting::Hex;
use core::convert::{TryFrom, TryInto};
use curve25519_dalek::scalar::Scalar;
use sha2::{Sha512, digest::Update};

/// A refinement type for `[u8; 32]` indicating that the bytes represent an
/// encoding of an Ed25519 verification key.
///
/// This is useful for representing an encoded verification key, while the
/// [`VerificationKey`] type in this library caches other decoded state used in
/// signature verification.
///
/// A `VerificationKeyBytes` can be converted into a [`VerificationKey`] for
/// internal signature verification.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VerificationKeyBytes(pub(super) [u8; 32]);

impl VerificationKeyBytes {
    /// Returns the byte encoding of the verification key.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    /// View the byte encoding of the verification key.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for VerificationKeyBytes {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_tuple("VerificationKeyBytes")
            .field(&Hex(&self.0))
            .finish()
    }
}

impl AsRef<[u8]> for VerificationKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl TryFrom<&[u8]> for VerificationKeyBytes {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() == 32 {
            let mut bytes = [0u8; 32];
            bytes[..].copy_from_slice(slice);
            Ok(bytes.into())
        } else {
            Err(Error::InvalidSliceLength)
        }
    }
}

impl From<[u8; 32]> for VerificationKeyBytes {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl From<VerificationKeyBytes> for [u8; 32] {
    fn from(refined: VerificationKeyBytes) -> [u8; 32] {
        refined.0
    }
}

/// A valid Ed25519 verification key.
///
/// This is also called a public key by other implementations.
///
/// This type holds decompressed state used in signature verification; if the
/// verification key may not be used immediately, it is probably better to use
/// [`VerificationKeyBytes`], which is a refinement type for `[u8; 32]`.
///
/// ## Consensus properties
///
/// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol specification and in
/// [ZIP215].  The verification criteria for an (encoded) verification key `A_bytes` are:
///
/// * `A_bytes` MUST be an encoding of a point `A` on the twisted Edwards form of
///   Curve25519, and non-canonical encodings MUST be accepted;
///
/// [ps]: https://zips.z.cash/protocol/protocol.pdf#concreteed25519
/// [ZIP215]:  https://zips.z.cash/zip-0215
#[derive(Copy, Clone)]
#[allow(non_snake_case)]
pub struct VerificationKey {
    pub(super) A_bytes: VerificationKeyBytes,
    /// The decompressed point in this crate's own representation, consumed by
    /// signature verification's owned point arithmetic.
    pub(super) A_own: point::Affine,
    /// `[2^127]A`, precomputed so verification can split its scalar at bit
    /// 127 and halve the shared doubling chain.
    pub(super) A2_own: point::Affine,
}

impl PartialEq for VerificationKey {
    fn eq(&self, other: &Self) -> bool {
        // The decompressed fields are derived deterministically from the
        // encoding, so equality of the encodings is equality of the keys.
        self.A_bytes == other.A_bytes
    }
}

impl Eq for VerificationKey {}

impl PartialOrd for VerificationKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for VerificationKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.A_bytes.cmp(&other.A_bytes)
    }
}

impl core::hash::Hash for VerificationKey {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.A_bytes.hash(state);
    }
}

impl core::fmt::Debug for VerificationKey {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_tuple("VerificationKey")
            .field(&Hex(&self.A_bytes.0))
            .finish()
    }
}

impl From<VerificationKey> for VerificationKeyBytes {
    fn from(vk: VerificationKey) -> Self {
        vk.A_bytes
    }
}

impl AsRef<[u8]> for VerificationKey {
    fn as_ref(&self) -> &[u8] {
        &self.A_bytes.0[..]
    }
}

impl From<VerificationKey> for [u8; 32] {
    fn from(vk: VerificationKey) -> [u8; 32] {
        vk.A_bytes.0
    }
}

impl TryFrom<VerificationKeyBytes> for VerificationKey {
    type Error = Error;
    #[allow(non_snake_case)]
    fn try_from(bytes: VerificationKeyBytes) -> Result<Self, Self::Error> {
        // * `A_bytes` and `R_bytes` MUST be encodings of points `A` and `R` respectively on the
        //   twisted Edwards form of Curve25519, and non-canonical encodings MUST be accepted;
        let A_own = point::decompress(&bytes.0).ok_or(Error::MalformedPublicKey)?;
        let A2_own = A_own.to_extended().mul_by_pow_2(127).to_affine();

        Ok(Self {
            A_bytes: bytes,
            A_own,
            A2_own,
        })
    }
}

impl TryFrom<&[u8]> for VerificationKey {
    type Error = Error;
    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        VerificationKeyBytes::try_from(slice).and_then(|vkb| vkb.try_into())
    }
}

impl TryFrom<[u8; 32]> for VerificationKey {
    type Error = Error;
    fn try_from(bytes: [u8; 32]) -> Result<Self, Self::Error> {
        VerificationKeyBytes::from(bytes).try_into()
    }
}

impl VerificationKey {
    /// Returns the byte encoding of the verification key.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub const fn to_bytes(self) -> [u8; 32] {
        self.A_bytes.0
    }

    /// View the byte encoding of the verification key.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.A_bytes.0
    }

    /// Verify a purported `signature` on the given `msg`.
    ///
    /// ## Consensus properties
    ///
    /// Ed25519 checks are described in [§5.4.5][ps] of the Zcash protocol specification and in
    /// [ZIP215].  The verification criteria for an (encoded) signature `(R_bytes, s_bytes)` with
    /// (encoded) verification key `A_bytes` are:
    ///
    /// * `A_bytes` and `R_bytes` MUST be encodings of points `A` and `R` respectively on the
    ///   twisted Edwards form of Curve25519, and non-canonical encodings MUST be accepted;
    ///
    /// * `s_bytes` MUST represent an integer `s` less than `l`, the order of the prime-order
    ///   subgroup of Curve25519;
    ///
    /// * the verification equation `[8][s]B = [8]R + [8][k]A` MUST be satisfied;
    ///
    /// * the alternate verification equation `[s]B = R + [k]A`, allowed by RFC 8032, MUST NOT be
    ///   used.
    ///
    /// [ps]: https://zips.z.cash/protocol/protocol.pdf#concreteed25519
    /// [ZIP215]: https://github.com/zcash/zips/blob/master/zip-0215.rst
    pub fn verify(&self, signature: &Signature, msg: &[u8]) -> Result<(), Error> {
        let k = Scalar::from_hash(
            Sha512::default()
                .chain(&signature.R_bytes[..])
                .chain(&self.A_bytes.0[..])
                .chain(msg),
        );
        self.verify_prehashed(signature, k)
    }

    /// Verify a signature with a prehashed `k` value. Note that this is not the
    /// same as "prehashing" in RFC8032.
    #[allow(non_snake_case)]
    pub(super) fn verify_prehashed(&self, signature: &Signature, k: Scalar) -> Result<(), Error> {
        // `s_bytes` MUST represent an integer less than the prime `l`.
        let s = Scalar::from_canonical_bytes(signature.s_bytes)
            .into_option()
            .ok_or(Error::InvalidSignature)?;
        // `R_bytes` MUST be an encoding of a point on the twisted Edwards form of Curve25519.
        let R = point::decompress(&signature.R_bytes).ok_or(Error::InvalidSignature)?;
        // We checked the encoding of A_bytes when constructing `self`.

        //       [8][s]B = [8]R + [8][k]A
        // <=>   0 = [8]([s]B - [k]A - R)
        let (_, b_table, b2_table) = msm::basepoint();
        let check = msm::double_mul(
            &s,
            b_table,
            b2_table,
            &k,
            &msm::naf_table(&self.A_own.neg()),
            &msm::naf_table(&self.A2_own.neg()),
        )
        .add(&R.neg().to_extended());

        let mut identity = [0u8; 32];
        identity[0] = 1;
        if check.mul_by_pow_2(3).compress() == identity {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

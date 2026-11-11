use super::Error;
use commonware_formatting::Hex;
use core::convert::TryFrom;
use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};

/// An Ed25519 signature.
///
/// A signature exists only after its encoding was checked. `R` is a point of the twisted
/// Edwards form of Curve25519, accepted from any encoding as [ZIP215] requires, and `s` is
/// an integer less than the group order. Both are kept decoded next to the encoding so
/// verification does not repeat the checks.
///
/// [ZIP215]: https://github.com/zcash/zips/blob/master/zip-0215.rst
#[derive(Copy, Clone, Eq, PartialEq)]
#[allow(non_snake_case)]
pub struct Signature {
    bytes: [u8; 64],
    pub(super) R: EdwardsPoint,
    pub(super) s: Scalar,
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_struct("Signature")
            .field("R_bytes", &Hex(self.R_bytes()))
            .field("s_bytes", &Hex(&self.bytes[32..]))
            .finish()
    }
}

impl TryFrom<[u8; 64]> for Signature {
    type Error = Error;

    #[allow(non_snake_case)]
    fn try_from(bytes: [u8; 64]) -> Result<Self, Error> {
        let mut R_bytes = [0; 32];
        R_bytes.copy_from_slice(&bytes[0..32]);
        let mut s_bytes = [0; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        let R = CompressedEdwardsY(R_bytes)
            .decompress()
            .ok_or(Error::InvalidSignature)?;
        let s = Scalar::from_canonical_bytes(s_bytes)
            .into_option()
            .ok_or(Error::InvalidSignature)?;
        Ok(Self { bytes, R, s })
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() == 64 {
            let mut bytes = [0u8; 64];
            bytes[..].copy_from_slice(slice);
            bytes.try_into()
        } else {
            Err(Error::InvalidSliceLength)
        }
    }
}

impl From<Signature> for [u8; 64] {
    fn from(sig: Signature) -> [u8; 64] {
        sig.to_bytes()
    }
}

impl Signature {
    /// Builds a signature from its decoded parts and their encoding.
    #[allow(non_snake_case)]
    pub(super) fn new(R: EdwardsPoint, R_bytes: [u8; 32], s: Scalar) -> Self {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&R_bytes);
        bytes[32..64].copy_from_slice(&s.to_bytes());
        Self { bytes, R, s }
    }

    /// Returns the bytes of the signature.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub const fn to_bytes(self) -> [u8; 64] {
        self.bytes
    }

    /// View the byte encoding of the signature.
    pub const fn as_bytes(&self) -> &[u8; 64] {
        &self.bytes
    }

    /// View the encoding of `R`.
    #[allow(non_snake_case)]
    pub(super) fn R_bytes(&self) -> &[u8] {
        &self.bytes[..32]
    }
}

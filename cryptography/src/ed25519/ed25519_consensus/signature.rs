use super::Error;
use commonware_utils::hex;
use core::convert::TryFrom;

/// An Ed25519 signature.
#[derive(Copy, Clone, Eq, PartialEq)]
#[allow(non_snake_case)]
pub struct Signature {
    pub(super) R_bytes: [u8; 32],
    pub(super) s_bytes: [u8; 32],
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, fmt: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fmt.debug_struct("Signature")
            .field("R_bytes", &hex(&self.R_bytes))
            .field("s_bytes", &hex(&self.s_bytes))
            .finish()
    }
}

impl From<[u8; 64]> for Signature {
    #[allow(non_snake_case)]
    fn from(bytes: [u8; 64]) -> Self {
        let mut R_bytes = [0; 32];
        R_bytes.copy_from_slice(&bytes[0..32]);
        let mut s_bytes = [0; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        Self { R_bytes, s_bytes }
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Self, Error> {
        if slice.len() == 64 {
            let mut bytes = [0u8; 64];
            bytes[..].copy_from_slice(slice);
            Ok(bytes.into())
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
    /// Returns the bytes of the signature.
    ///
    /// This is the same as `.into()`, but does not require type inference.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0; 64];
        bytes[0..32].copy_from_slice(&self.R_bytes[..]);
        bytes[32..64].copy_from_slice(&self.s_bytes[..]);
        bytes
    }
}

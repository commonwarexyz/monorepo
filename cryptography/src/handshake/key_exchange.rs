use crate::Secret;
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use rand_core::CryptoRngCore;

/// A shared secret derived from X25519 key exchange.
pub struct SharedSecret {
    pub(crate) secret: Secret<x25519_dalek::SharedSecret>,
}

impl SharedSecret {
    /// Creates a new SharedSecret wrapping the given x25519 shared secret.
    const fn new(secret: x25519_dalek::SharedSecret) -> Self {
        Self {
            secret: Secret::new(secret),
        }
    }
}

/// An ephemeral X25519 public key used during handshake.
#[cfg_attr(test, derive(Debug, PartialEq))]
pub struct EphemeralPublicKey {
    inner: x25519_dalek::PublicKey,
}

impl Write for EphemeralPublicKey {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_slice(self.inner.as_bytes());
    }
}

impl FixedSize for EphemeralPublicKey {
    // There's not a good constant anywhere in the x25519_dalek crate for this.
    const SIZE: usize = 32;
}

impl Read for EphemeralPublicKey {
    type Cfg = ();

    fn read_cfg(
        buf: &mut impl bytes::Buf,
        _cfg: &Self::Cfg,
    ) -> Result<Self, commonware_codec::Error> {
        let bytes: [u8; 32] = ReadExt::read(buf)?;
        Ok(Self {
            inner: bytes.into(),
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for EphemeralPublicKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let bytes: [u8; 32] = u.arbitrary()?;
        Ok(Self {
            inner: bytes.into(),
        })
    }
}

/// An ephemeral X25519 secret key used during handshake.
pub struct SecretKey {
    inner: Secret<x25519_dalek::EphemeralSecret>,
}

impl SecretKey {
    /// Generates a new random ephemeral secret key.
    pub fn new(rng: impl CryptoRngCore) -> Self {
        Self {
            inner: Secret::new(x25519_dalek::EphemeralSecret::random_from_rng(rng)),
        }
    }

    /// Derives the corresponding public key.
    pub fn public(&self) -> EphemeralPublicKey {
        self.inner.expose(|secret| EphemeralPublicKey {
            inner: x25519_dalek::PublicKey::from(secret),
        })
    }

    /// Performs X25519 key exchange with another public key.
    /// Returns None if the exchange is non-contributory.
    pub fn exchange(self, other: &EphemeralPublicKey) -> Option<SharedSecret> {
        let secret = self.inner.expose_unwrap();
        let out = secret.diffie_hellman(&other.inner);
        if !out.was_contributory() {
            return None;
        }
        Some(SharedSecret::new(out))
    }
}

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::*;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<EphemeralPublicKey>,
    }
}

use commonware_codec::{EncodeSize, Read, ReadExt, Write};
use rand_core::CryptoRngCore;

/// A shared secret derived from X25519 key exchange.
pub struct SharedSecret {
    inner: x25519_dalek::SharedSecret,
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes().as_slice()
    }
}

/// An ephemeral X25519 public key used during handshake.
pub struct EphemeralPublicKey {
    inner: x25519_dalek::PublicKey,
}

impl Write for EphemeralPublicKey {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        buf.put_slice(self.inner.as_bytes());
    }
}

impl EncodeSize for EphemeralPublicKey {
    fn encode_size(&self) -> usize {
        // There's not a good constant anywhere in the x25519_dalek crate for this.
        32
    }
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

/// An ephemeral X25519 secret key used during handshake.
pub struct SecretKey {
    inner: x25519_dalek::EphemeralSecret,
}

impl SecretKey {
    /// Generates a new random ephemeral secret key.
    pub fn new(rng: impl CryptoRngCore) -> Self {
        Self {
            inner: x25519_dalek::EphemeralSecret::random_from_rng(rng),
        }
    }

    /// Derives the corresponding public key.
    pub fn public(&self) -> EphemeralPublicKey {
        EphemeralPublicKey {
            inner: (&self.inner).into(),
        }
    }

    /// Performs X25519 key exchange with another public key.
    /// Returns None if the exchange is non-contributory.
    pub fn exchange(self, other: &EphemeralPublicKey) -> Option<SharedSecret> {
        let out = self.inner.diffie_hellman(&other.inner);
        if !out.was_contributory() {
            return None;
        }
        Some(SharedSecret { inner: out })
    }
}

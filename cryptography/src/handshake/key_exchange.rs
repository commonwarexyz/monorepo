use commonware_codec::{EncodeSize, Write};
use rand_core::CryptoRngCore;

pub struct SharedSecret {
    inner: x25519_dalek::SharedSecret,
}

impl AsRef<[u8]> for SharedSecret {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_bytes().as_slice()
    }
}

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

pub struct SecretKey {
    inner: x25519_dalek::EphemeralSecret,
}

impl SecretKey {
    pub fn new(rng: impl CryptoRngCore) -> Self {
        Self {
            inner: x25519_dalek::EphemeralSecret::random_from_rng(rng),
        }
    }

    pub fn public(&self) -> EphemeralPublicKey {
        EphemeralPublicKey {
            inner: (&self.inner).into(),
        }
    }

    pub fn exchange(self, other: &EphemeralPublicKey) -> Option<SharedSecret> {
        let out = self.inner.diffie_hellman(&other.inner);
        if !out.was_contributory() {
            return None;
        }
        Some(SharedSecret { inner: out })
    }
}

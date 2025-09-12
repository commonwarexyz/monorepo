use chacha20poly1305::{aead::AeadMut as _, ChaCha20Poly1305, KeyInit as _};
use rand_core::CryptoRngCore;

// Intentionally avoid depending directly on super, to depend on the sibling.
use super::error::Error;

struct CounterNonce {
    inner: u128,
}

impl CounterNonce {
    pub fn new() -> Self {
        Self { inner: 0 }
    }

    pub fn inc(&mut self) -> Result<[u8; 16], Error> {
        if self.inner >= 1 << 96 {
            return Err(Error::MessageLimitReached);
        }
        let out = self.inner.to_le_bytes();
        self.inner += 1;
        Ok(out)
    }
}

pub struct SendCipher {
    nonce: CounterNonce,
    inner: ChaCha20Poly1305,
}

impl SendCipher {
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key[..]);
        Self {
            nonce: CounterNonce::new(),
            inner: ChaCha20Poly1305::new(&key.into()),
        }
    }

    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner
            .encrypt((&self.nonce.inc()?[..12]).into(), data)
            .map_err(|_| Error::EncryptionFailed)
    }
}

pub struct RecvCipher {
    nonce: CounterNonce,
    inner: ChaCha20Poly1305,
}

impl RecvCipher {
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key[..]);
        Self {
            nonce: CounterNonce::new(),
            inner: ChaCha20Poly1305::new(&key.into()),
        }
    }

    pub fn recv(&mut self, encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner
            .decrypt((&self.nonce.inc()?[..12]).into(), encrypted_data)
            .map_err(|_| Error::DecryptionFailed)
    }
}

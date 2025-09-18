// Intentionally avoid depending directly on super, to depend on the sibling.
use super::error::Error;
use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, Aead},
    AeadCore, ChaCha20Poly1305, KeyInit as _,
};
use rand_core::CryptoRngCore;
use std::vec::Vec;
use zeroize::ZeroizeOnDrop;

/// The amount of overhead in a ciphertext, compared to the plain message.
pub const CIPHERTEXT_OVERHEAD: usize = <ChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

/// How many bytes are in a nonce.
const NONCE_SIZE_BYTES: usize = <ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;

struct CounterNonce {
    inner: u128,
}

// We don't need to zeroize nonces.
impl ZeroizeOnDrop for CounterNonce {}

impl CounterNonce {
    /// Creates a new counter nonce starting at zero.
    pub fn new() -> Self {
        Self { inner: 0 }
    }

    /// Increments the counter and returns the current value as bytes.
    /// Returns an error if the counter would overflow.
    pub fn inc(&mut self) -> Result<[u8; 128 / 8], Error> {
        if self.inner >= 1 << (8 * NONCE_SIZE_BYTES) {
            return Err(Error::MessageLimitReached);
        }
        let out = self.inner.to_le_bytes();
        self.inner += 1;
        Ok(out)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct SendCipher {
    nonce: CounterNonce,
    inner: ChaCha20Poly1305,
}

impl SendCipher {
    /// Creates a new sending cipher with a random key.
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key[..]);
        Self {
            nonce: CounterNonce::new(),
            inner: ChaCha20Poly1305::new(&key.into()),
        }
    }

    /// Encrypts data and returns the ciphertext.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner
            .encrypt((&self.nonce.inc()?[..NONCE_SIZE_BYTES]).into(), data)
            .map_err(|_| Error::EncryptionFailed)
    }
}

#[derive(ZeroizeOnDrop)]
pub struct RecvCipher {
    nonce: CounterNonce,
    inner: ChaCha20Poly1305,
}

impl RecvCipher {
    /// Creates a new receiving cipher with a random key.
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key[..]);
        Self {
            nonce: CounterNonce::new(),
            inner: ChaCha20Poly1305::new(&key.into()),
        }
    }

    /// Decrypts ciphertext and returns the original data.
    pub fn recv(&mut self, encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
        self.inner
            .decrypt(
                (&self.nonce.inc()?[..NONCE_SIZE_BYTES]).into(),
                encrypted_data,
            )
            .map_err(|_| Error::DecryptionFailed)
    }
}

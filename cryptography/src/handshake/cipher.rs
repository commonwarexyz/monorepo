// Intentionally avoid depending directly on super, to depend on the sibling.
use super::error::Error;
use crate::Secret;
use chacha20poly1305::{
    aead::{generic_array::typenum::Unsigned, Aead},
    AeadCore, ChaCha20Poly1305, KeyInit as _,
};
use rand_core::CryptoRngCore;
use std::vec::Vec;
use zeroize::Zeroizing;

/// The amount of overhead in a ciphertext, compared to the plain message.
pub const CIPHERTEXT_OVERHEAD: usize = <ChaCha20Poly1305 as AeadCore>::TagSize::USIZE;

/// How many bytes are in a nonce.
const NONCE_SIZE_BYTES: usize = <ChaCha20Poly1305 as AeadCore>::NonceSize::USIZE;

struct CounterNonce {
    inner: u128,
}

impl CounterNonce {
    /// Creates a new counter nonce starting at zero.
    pub const fn new() -> Self {
        Self { inner: 0 }
    }

    /// Increments the counter and returns the current value as bytes.
    /// Returns an error if the counter would overflow.
    pub const fn inc(&mut self) -> Result<[u8; 128 / 8], Error> {
        if self.inner >= 1 << (8 * NONCE_SIZE_BYTES) {
            return Err(Error::MessageLimitReached);
        }
        let out = self.inner.to_le_bytes();
        self.inner += 1;
        Ok(out)
    }
}

pub struct SendCipher {
    nonce: CounterNonce,
    inner: Secret<ChaCha20Poly1305>,
}

impl SendCipher {
    /// Creates a new sending cipher with a random key.
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let key = Zeroizing::new(ChaCha20Poly1305::generate_key(&mut rng));
        Self {
            nonce: CounterNonce::new(),
            inner: Secret::new(ChaCha20Poly1305::new(&key)),
        }
    }

    /// Encrypts data and returns the ciphertext.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce.inc()?;
        self.inner
            .expose(|cipher| cipher.encrypt((&nonce[..NONCE_SIZE_BYTES]).into(), data))
            .map_err(|_| Error::EncryptionFailed)
    }
}

pub struct RecvCipher {
    nonce: CounterNonce,
    inner: Secret<ChaCha20Poly1305>,
}

impl RecvCipher {
    /// Creates a new receiving cipher with a random key.
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let key = Zeroizing::new(ChaCha20Poly1305::generate_key(&mut rng));
        Self {
            nonce: CounterNonce::new(),
            inner: Secret::new(ChaCha20Poly1305::new(&key)),
        }
    }

    /// Decrypts ciphertext and returns the original data.
    ///
    /// # Errors
    ///
    /// This function will return an error in the following situations:
    ///
    /// - Too many messages have been received with this cipher.
    /// - The ciphertext was corrupted in some way.
    ///
    /// In *both* cases, the `RecvCipher` will no longer be able to return
    /// valid ciphertexts, and will always return an error on subsequent calls
    /// to [`Self::recv`]. Terminating (and optionally reestablishing) the connection
    /// is a simple (and safe) way to handle this scenario.
    pub fn recv(&mut self, encrypted_data: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce.inc()?;
        self.inner
            .expose(|cipher| cipher.decrypt((&nonce[..NONCE_SIZE_BYTES]).into(), encrypted_data))
            .map_err(|_| Error::DecryptionFailed)
    }
}

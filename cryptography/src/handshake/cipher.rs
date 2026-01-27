// Intentionally avoid depending directly on super, to depend on the sibling.
use super::error::Error;
use crate::Secret;
use rand_core::CryptoRngCore;
use std::vec::Vec;
use zeroize::Zeroizing;

/// The amount of overhead in a ciphertext, compared to the plain message.
/// ChaCha20-Poly1305 uses a 128-bit (16 byte) authentication tag.
pub const CIPHERTEXT_OVERHEAD: usize = 16;

/// How many bytes are in a nonce.
/// ChaCha20-Poly1305 uses a 96-bit (12 byte) nonce.
const NONCE_SIZE_BYTES: usize = 12;

/// How many bytes are in a key.
/// ChaCha20-Poly1305 uses a 256-bit (32 byte) key.
const KEY_SIZE_BYTES: usize = 32;

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
    pub fn inc(&mut self) -> Result<[u8; NONCE_SIZE_BYTES], Error> {
        if self.inner >= 1 << (8 * NONCE_SIZE_BYTES) {
            return Err(Error::MessageLimitReached);
        }
        let out = self.inner.to_le_bytes();
        self.inner += 1;
        // Extract only the lower 96 bits (12 bytes) for the nonce
        let mut nonce = [0u8; NONCE_SIZE_BYTES];
        nonce.copy_from_slice(&out[..NONCE_SIZE_BYTES]);
        Ok(nonce)
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))] {
        use aws_lc_rs::aead::{self, LessSafeKey, UnboundKey, CHACHA20_POLY1305};

        pub struct SendCipher {
            nonce: CounterNonce,
            inner: Secret<LessSafeKey>,
        }

        impl SendCipher {
            /// Creates a new sending cipher with a random key.
            pub fn new(mut rng: impl CryptoRngCore) -> Self {
                let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE_BYTES]);
                rng.fill_bytes(key_bytes.as_mut());
                let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes.as_ref())
                    .expect("key size should match algorithm");
                Self {
                    nonce: CounterNonce::new(),
                    inner: Secret::new(LessSafeKey::new(unbound_key)),
                }
            }

            /// Encrypts data and returns the ciphertext.
            pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
                let nonce_bytes = self.nonce.inc()?;
                let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
                let mut in_out = data.to_vec();
                self.inner
                    .expose(|cipher| cipher.seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut in_out))
                    .map_err(|_| Error::EncryptionFailed)?;
                Ok(in_out)
            }
        }

        pub struct RecvCipher {
            nonce: CounterNonce,
            inner: Secret<LessSafeKey>,
        }

        impl RecvCipher {
            /// Creates a new receiving cipher with a random key.
            pub fn new(mut rng: impl CryptoRngCore) -> Self {
                let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE_BYTES]);
                rng.fill_bytes(key_bytes.as_mut());
                let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key_bytes.as_ref())
                    .expect("key size should match algorithm");
                Self {
                    nonce: CounterNonce::new(),
                    inner: Secret::new(LessSafeKey::new(unbound_key)),
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
                let nonce_bytes = self.nonce.inc()?;
                let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
                let mut in_out = encrypted_data.to_vec();
                let plaintext = self.inner
                    .expose(|cipher| cipher.open_in_place(nonce, aead::Aad::empty(), &mut in_out))
                    .map_err(|_| Error::DecryptionFailed)?;
                Ok(plaintext.to_vec())
            }
        }
    } else {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit as _};

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
                    .expose(|cipher| cipher.encrypt((&nonce[..]).into(), data))
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
                    .expose(|cipher| cipher.decrypt((&nonce[..]).into(), encrypted_data))
                    .map_err(|_| Error::DecryptionFailed)
            }
        }
    }
}

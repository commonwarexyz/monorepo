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

trait Backend: Sized {
    /// Creates a new cipher backend from a 256-bit key.
    fn from_key(key: &[u8; KEY_SIZE_BYTES]) -> Self;

    /// Encrypts plaintext using the given nonce, returning ciphertext with appended auth tag.
    fn encrypt(&self, nonce: &[u8; NONCE_SIZE_BYTES], data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Decrypts ciphertext using the given nonce, verifying and stripping the auth tag.
    fn decrypt(&self, nonce: &[u8; NONCE_SIZE_BYTES], data: &[u8]) -> Result<Vec<u8>, Error>;
}

cfg_if::cfg_if! {
    if #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))] {
        use aws_lc_rs::aead::{self, LessSafeKey, UnboundKey, CHACHA20_POLY1305};

        struct Impl(LessSafeKey);

        impl Backend for Impl {
            fn from_key(key: &[u8; KEY_SIZE_BYTES]) -> Self {
                let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
                    .expect("key size should match algorithm");
                Self(LessSafeKey::new(unbound_key))
            }

            fn encrypt(&self, nonce: &[u8; NONCE_SIZE_BYTES], data: &[u8]) -> Result<Vec<u8>, Error> {
                let nonce = aead::Nonce::assume_unique_for_key(*nonce);
                let mut scratch = Vec::with_capacity(data.len() + CIPHERTEXT_OVERHEAD);
                scratch.extend_from_slice(data);
                self.0
                    .seal_in_place_append_tag(nonce, aead::Aad::empty(), &mut scratch)
                    .map_err(|_| Error::EncryptionFailed)?;
                Ok(scratch)
            }

            fn decrypt(&self, nonce: &[u8; NONCE_SIZE_BYTES], data: &[u8]) -> Result<Vec<u8>, Error> {
                let nonce = aead::Nonce::assume_unique_for_key(*nonce);
                let mut scratch = data.to_vec();
                self.0
                    .open_in_place(nonce, aead::Aad::empty(), &mut scratch)
                    .map_err(|_| Error::DecryptionFailed)?;
                scratch.truncate(data.len() - CIPHERTEXT_OVERHEAD);
                Ok(scratch)
            }
        }
    } else {
        use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit as _};

        struct Impl(ChaCha20Poly1305);

        impl Backend for Impl {
            fn from_key(key: &[u8; KEY_SIZE_BYTES]) -> Self {
                Self(ChaCha20Poly1305::new(key.into()))
            }

            fn encrypt(&self, nonce: &[u8; NONCE_SIZE_BYTES], data: &[u8]) -> Result<Vec<u8>, Error> {
                self.0
                    .encrypt(nonce.into(), data)
                    .map_err(|_| Error::EncryptionFailed)
            }

            fn decrypt(&self, nonce: &[u8; NONCE_SIZE_BYTES], data: &[u8]) -> Result<Vec<u8>, Error> {
                self.0
                    .decrypt(nonce.into(), data)
                    .map_err(|_| Error::DecryptionFailed)
            }
        }
    }
}

pub struct SendCipher {
    nonce: CounterNonce,
    inner: Secret<Impl>,
}

impl SendCipher {
    /// Creates a new sending cipher with a random key.
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE_BYTES]);
        rng.fill_bytes(key_bytes.as_mut());
        Self {
            nonce: CounterNonce::new(),
            inner: Secret::new(Impl::from_key(&key_bytes)),
        }
    }

    /// Encrypts data and returns the ciphertext.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce.inc()?;
        self.inner.expose(|cipher| cipher.encrypt(&nonce, data))
    }
}

pub struct RecvCipher {
    nonce: CounterNonce,
    inner: Secret<Impl>,
}

impl RecvCipher {
    /// Creates a new receiving cipher with a random key.
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE_BYTES]);
        rng.fill_bytes(key_bytes.as_mut());
        Self {
            nonce: CounterNonce::new(),
            inner: Secret::new(Impl::from_key(&key_bytes)),
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
            .expose(|cipher| cipher.decrypt(&nonce, encrypted_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{test_rng, test_rng_seeded};

    #[test]
    fn test_send_recv_roundtrip() {
        let mut send = SendCipher::new(&mut test_rng());
        let mut recv = RecvCipher::new(&mut test_rng());

        let plaintext = b"hello world";
        let ciphertext = send.send(plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + CIPHERTEXT_OVERHEAD);

        let decrypted = recv.recv(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_recv_wrong_key_fails() {
        let mut send = SendCipher::new(&mut test_rng_seeded(0));
        let mut recv = RecvCipher::new(&mut test_rng_seeded(1));

        let ciphertext = send.send(b"hello").unwrap();
        assert!(matches!(
            recv.recv(&ciphertext),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_recv_ciphertext_too_short() {
        let mut rng = test_rng();
        let mut recv = RecvCipher::new(&mut rng);
        let short_data = vec![0u8; CIPHERTEXT_OVERHEAD - 1];
        assert!(matches!(
            recv.recv(&short_data),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_recv_ciphertext_exactly_overhead() {
        let mut rng = test_rng();
        let mut recv = RecvCipher::new(&mut rng);
        let tag_only = vec![0u8; CIPHERTEXT_OVERHEAD];
        assert!(matches!(recv.recv(&tag_only), Err(Error::DecryptionFailed)));
    }
}

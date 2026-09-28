//! ChaCha20-Poly1305 [Cipher] with an implicit counter nonce.
//!
//! [ChaCha20Poly1305] holds one key and a 96-bit counter nonce that starts at zero, is encoded
//! little-endian, and advances once per message. It is never transmitted, so a successful open
//! authenticates a message at its expected position. Messages are sealed with empty associated
//! data and a 16-byte tag.

use crate::{Cipher, Secret};
use commonware_math::algebra::Random;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

/// Errors returned by [ChaCha20Poly1305].
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An error indicating that no more messages can (safely) be sealed or opened.
    ///
    /// In practice, you should never see this error, because the limit takes
    /// an ultra-astronomical amount of messages to reach.
    #[error("message limit reached")]
    MessageLimitReached,
    /// Encryption failed for some reason.
    ///
    /// In practice, this error shouldn't happen.
    #[error("encryption failed")]
    EncryptionFailed,
    /// Decryption failed.
    ///
    /// This can happen if the message was corrupted, truncated, or opened out of order.
    #[error("decryption failed")]
    DecryptionFailed,
}

/// Size of the ChaCha20-Poly1305 authentication tag.
const TAG_SIZE: usize = 16;

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
        use aws_lc_rs::aead::{self, CHACHA20_POLY1305, LessSafeKey, UnboundKey};

        struct Key(LessSafeKey);

        impl Key {
            fn from_key(key: &[u8; KEY_SIZE_BYTES]) -> Self {
                let unbound_key = UnboundKey::new(&CHACHA20_POLY1305, key)
                    .expect("key size should match algorithm");
                Self(LessSafeKey::new(unbound_key))
            }

            fn encrypt_in_place(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                data: &mut [u8],
            ) -> Result<[u8; TAG_SIZE], Error> {
                let nonce = aead::Nonce::assume_unique_for_key(*nonce);
                let tag = self
                    .0
                    .seal_in_place_separate_tag(nonce, aead::Aad::empty(), data)
                    .map_err(|_| Error::EncryptionFailed)?;
                Ok(tag.as_ref().try_into().expect("tag size mismatch"))
            }

            fn decrypt_in_place(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                data: &mut [u8],
            ) -> Result<usize, Error> {
                let nonce = aead::Nonce::assume_unique_for_key(*nonce);
                self.0
                    .open_in_place(nonce, aead::Aad::empty(), data)
                    .map_err(|_| Error::DecryptionFailed)?;
                Ok(data.len() - TAG_SIZE)
            }
        }
    } else {
        use chacha20poly1305::{ChaCha20Poly1305 as Aead, KeyInit as _, aead::AeadInOut};

        struct Key(Aead);

        impl Key {
            fn from_key(key: &[u8; KEY_SIZE_BYTES]) -> Self {
                Self(Aead::new(key.into()))
            }

            fn encrypt_in_place(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                data: &mut [u8],
            ) -> Result<[u8; TAG_SIZE], Error> {
                let tag = self
                    .0
                    .encrypt_inout_detached(nonce.into(), &[], data.into())
                    .map_err(|_| Error::EncryptionFailed)?;
                Ok(tag.into())
            }

            fn decrypt_in_place(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                data: &mut [u8],
            ) -> Result<usize, Error> {
                let plaintext_len = data.len() - TAG_SIZE;
                let tag: [u8; TAG_SIZE] = data[plaintext_len..]
                    .try_into()
                    .map_err(|_| Error::DecryptionFailed)?;
                self.0
                    .decrypt_inout_detached(
                        nonce.into(),
                        &[],
                        (&mut data[..plaintext_len]).into(),
                        &tag.into(),
                    )
                    .map_err(|_| Error::DecryptionFailed)?;
                Ok(plaintext_len)
            }
        }
    }
}

/// ChaCha20-Poly1305 [Cipher] with an implicit counter nonce.
pub struct ChaCha20Poly1305 {
    nonce: CounterNonce,
    key: Secret<Key>,
}

impl Random for ChaCha20Poly1305 {
    fn random(mut rng: impl CryptoRng) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE_BYTES]);
        rng.fill_bytes(key_bytes.as_mut());
        Self {
            nonce: CounterNonce::new(),
            key: Secret::new(Key::from_key(&key_bytes)),
        }
    }
}

impl Cipher for ChaCha20Poly1305 {
    type Error = Error;

    const TAG_SIZE: usize = TAG_SIZE;

    #[inline]
    fn seal_in_place(&mut self, buf: &mut [u8]) -> Result<(), Error> {
        let (data, tag) = buf
            .split_last_chunk_mut::<TAG_SIZE>()
            .expect("buffer must have room for the tag");
        let nonce = self.nonce.inc()?;
        *tag = self.key.expose(|key| key.encrypt_in_place(&nonce, data))?;
        Ok(())
    }

    #[inline]
    fn open_in_place(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
        let nonce = self.nonce.inc()?;
        if buf.len() < TAG_SIZE {
            return Err(Error::DecryptionFailed);
        }
        self.key.expose(|key| key.decrypt_in_place(&nonce, buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{TestRng, test_rng};

    #[test]
    fn test_seal_open_roundtrip() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(test_rng());

        let plaintext = b"hello world";
        let ciphertext = send.seal(plaintext).unwrap();
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

        let decrypted = recv.open(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_open_wrong_key_fails() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(TestRng::new(1));

        let ciphertext = send.seal(b"hello").unwrap();
        assert!(matches!(
            recv.open(&ciphertext),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_open_ciphertext_too_short() {
        let mut recv = ChaCha20Poly1305::random(test_rng());
        let short_data = vec![0u8; TAG_SIZE - 1];
        assert!(matches!(
            recv.open(&short_data),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_open_ciphertext_exactly_overhead() {
        let mut recv = ChaCha20Poly1305::random(test_rng());
        let tag_only = vec![0u8; TAG_SIZE];
        assert!(matches!(recv.open(&tag_only), Err(Error::DecryptionFailed)));
    }

    #[test]
    fn test_seal_open_in_place_roundtrip() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(test_rng());

        // Seal the plaintext in place, writing the tag into the reserved tail
        let plaintext = b"hello world";
        let mut buf = vec![0u8; plaintext.len() + TAG_SIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        send.seal_in_place(&mut buf).unwrap();

        // Open the ciphertext and tag in place, getting the plaintext length back
        let plaintext_len = recv.open_in_place(&mut buf).unwrap();
        assert_eq!(plaintext_len, plaintext.len());
        assert_eq!(&buf[..plaintext_len], plaintext);
    }

    #[test]
    #[should_panic(expected = "buffer must have room for the tag")]
    fn test_seal_in_place_buffer_too_short() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut buf = vec![0u8; TAG_SIZE - 1];
        let _ = send.seal_in_place(&mut buf);
    }

    #[test]
    fn test_open_in_place_ciphertext_too_short() {
        let mut recv = ChaCha20Poly1305::random(test_rng());

        // Buffer smaller than tag size
        let mut buf = vec![0u8; TAG_SIZE - 1];
        assert!(matches!(
            recv.open_in_place(&mut buf),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_seal_in_place_open_compatibility() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(test_rng());

        let plaintext = b"cross-api test";
        let mut buf = vec![0u8; plaintext.len() + TAG_SIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);
        send.seal_in_place(&mut buf).unwrap();

        // Use allocating open on in-place sealed data
        let decrypted = recv.open(&buf).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_seal_open_in_place_compatibility() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(test_rng());

        let plaintext = b"cross-api test";
        let mut ciphertext = send.seal(plaintext).unwrap();

        // Use in-place open on allocating seal data
        let plaintext_len = recv.open_in_place(&mut ciphertext).unwrap();
        assert_eq!(&ciphertext[..plaintext_len], plaintext);
    }

    #[test]
    fn test_nonce_sync_after_truncated_open() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(test_rng());

        // Seal message (sender nonce: 0 -> 1)
        let ciphertext = send.seal(b"message 1").unwrap();

        // Receiver gets truncated buffer (recv nonce: 0 -> 1)
        let mut truncated = vec![0u8; TAG_SIZE - 1];
        assert!(recv.open_in_place(&mut truncated).is_err());

        // Original ciphertext (nonce 0) no longer opens because recv nonce advanced to 1
        assert!(recv.open(&ciphertext).is_err());
    }

    #[test]
    fn test_nonce_sync_after_corrupted_open() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(test_rng());

        // Seal message (sender nonce: 0 -> 1)
        let ciphertext = send.seal(b"message 1").unwrap();

        // Corrupt a copy (valid length, bad content)
        let mut corrupted = ciphertext.clone();
        corrupted[0] ^= 0xFF;
        assert!(recv.open_in_place(&mut corrupted).is_err());

        // Original ciphertext (nonce 0) no longer opens because recv nonce advanced to 1
        assert!(recv.open(&ciphertext).is_err());
    }
}

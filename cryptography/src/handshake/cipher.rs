use super::error::Error;
use crate::Secret;
use rand_core::CryptoRngCore;
use std::vec::Vec;
use zeroize::Zeroizing;

/// Size of the ChaCha20-Poly1305 authentication tag.
///
/// This tag is the overhead added to each ciphertext and must be transmitted
/// alongside it for the receiver to verify integrity and authenticity.
pub const TAG_SIZE: usize = 16;

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

        struct Cipher(LessSafeKey);

        impl Cipher {
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
        use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit as _};

        struct Cipher(ChaCha20Poly1305);

        impl Cipher {
            fn from_key(key: &[u8; KEY_SIZE_BYTES]) -> Self {
                Self(ChaCha20Poly1305::new(key.into()))
            }

            fn encrypt_in_place(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                data: &mut [u8],
            ) -> Result<[u8; TAG_SIZE], Error> {
                let tag = self
                    .0
                    .encrypt_in_place_detached(nonce.into(), &[], data)
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
                    .decrypt_in_place_detached(
                        nonce.into(),
                        &[],
                        &mut data[..plaintext_len],
                        &tag.into(),
                    )
                    .map_err(|_| Error::DecryptionFailed)?;
                Ok(plaintext_len)
            }
        }
    }
}

/// Encrypts outgoing messages with an auto-incrementing nonce.
pub struct SendCipher {
    nonce: CounterNonce,
    inner: Secret<Cipher>,
}

impl SendCipher {
    /// Creates a new sending cipher with a random key.
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE_BYTES]);
        rng.fill_bytes(key_bytes.as_mut());
        Self {
            nonce: CounterNonce::new(),
            inner: Secret::new(Cipher::from_key(&key_bytes)),
        }
    }

    /// Encrypts `data` in-place and returns the authentication tag.
    ///
    /// The caller is responsible for appending the returned tag to the buffer.
    #[inline]
    pub fn send_in_place(&mut self, data: &mut [u8]) -> Result<[u8; TAG_SIZE], Error> {
        let nonce = self.nonce.inc()?;
        self.inner
            .expose(|cipher| cipher.encrypt_in_place(&nonce, data))
    }

    /// Encrypts data and returns the ciphertext.
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let mut buf = vec![0u8; data.len() + TAG_SIZE];
        buf[..data.len()].copy_from_slice(data);
        let tag = self.send_in_place(&mut buf[..data.len()])?;
        buf[data.len()..].copy_from_slice(&tag);
        Ok(buf)
    }
}

/// Decrypts incoming messages with an auto-incrementing nonce.
pub struct RecvCipher {
    nonce: CounterNonce,
    inner: Secret<Cipher>,
}

impl RecvCipher {
    /// Creates a new receiving cipher with a random key.
    pub fn new(mut rng: impl CryptoRngCore) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE_BYTES]);
        rng.fill_bytes(key_bytes.as_mut());
        Self {
            nonce: CounterNonce::new(),
            inner: Secret::new(Cipher::from_key(&key_bytes)),
        }
    }

    /// Decrypts `encrypted_data` in-place and returns the plaintext length.
    ///
    /// The buffer must contain ciphertext with the authentication tag appended
    /// (last `TAG_SIZE` bytes). After decryption, the plaintext is in
    /// `encrypted_data[..returned_len]`.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - `encrypted_data.len() < TAG_SIZE`
    /// - Too many messages have been received with this cipher
    /// - The ciphertext was corrupted or tampered with
    ///
    /// In the last two cases, the `RecvCipher` will no longer be able to return
    /// valid ciphertexts, and will always return an error on subsequent calls
    /// to [`Self::recv`]. Terminating (and optionally reestablishing) the connection
    /// is a simple (and safe) way to handle this scenario.
    #[inline]
    pub fn recv_in_place(&mut self, encrypted_data: &mut [u8]) -> Result<usize, Error> {
        let nonce = self.nonce.inc()?;
        if encrypted_data.len() < TAG_SIZE {
            return Err(Error::DecryptionFailed);
        }
        self.inner
            .expose(|cipher| cipher.decrypt_in_place(&nonce, encrypted_data))
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
        let mut buf = encrypted_data.to_vec();
        let plaintext_len = self.recv_in_place(&mut buf)?;
        buf.truncate(plaintext_len);
        Ok(buf)
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
        assert_eq!(ciphertext.len(), plaintext.len() + TAG_SIZE);

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
        let short_data = vec![0u8; TAG_SIZE - 1];
        assert!(matches!(
            recv.recv(&short_data),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_recv_ciphertext_exactly_overhead() {
        let mut rng = test_rng();
        let mut recv = RecvCipher::new(&mut rng);
        let tag_only = vec![0u8; TAG_SIZE];
        assert!(matches!(recv.recv(&tag_only), Err(Error::DecryptionFailed)));
    }

    #[test]
    fn test_send_recv_in_place_roundtrip() {
        let mut send = SendCipher::new(&mut test_rng());
        let mut recv = RecvCipher::new(&mut test_rng());

        let plaintext = b"hello world";
        let mut buf = vec![0u8; plaintext.len() + TAG_SIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        // Encrypt plaintext in place, get tag back
        let tag = send.send_in_place(&mut buf[..plaintext.len()]).unwrap();
        // Append tag to buffer
        buf[plaintext.len()..].copy_from_slice(&tag);

        // Decrypt ciphertext+tag in place, get plaintext length back
        let plaintext_len = recv.recv_in_place(&mut buf).unwrap();

        assert_eq!(plaintext_len, plaintext.len());
        assert_eq!(&buf[..plaintext_len], plaintext);
    }

    #[test]
    fn test_recv_in_place_ciphertext_too_short() {
        let mut recv = RecvCipher::new(&mut test_rng());

        // Buffer smaller than tag size
        let mut buf = vec![0u8; TAG_SIZE - 1];
        assert!(matches!(
            recv.recv_in_place(&mut buf),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_send_in_place_recv_compatibility() {
        let mut send = SendCipher::new(&mut test_rng());
        let mut recv = RecvCipher::new(&mut test_rng());

        let plaintext = b"cross-api test";
        let mut buf = vec![0u8; plaintext.len() + TAG_SIZE];
        buf[..plaintext.len()].copy_from_slice(plaintext);

        let tag = send.send_in_place(&mut buf[..plaintext.len()]).unwrap();
        buf[plaintext.len()..].copy_from_slice(&tag);

        // Use allocating recv on in-place encrypted data
        let decrypted = recv.recv(&buf).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_send_recv_in_place_compatibility() {
        let mut send = SendCipher::new(&mut test_rng());
        let mut recv = RecvCipher::new(&mut test_rng());

        let plaintext = b"cross-api test";
        let mut ciphertext = send.send(plaintext).unwrap();

        // Use in-place recv on allocating send data
        let plaintext_len = recv.recv_in_place(&mut ciphertext).unwrap();
        assert_eq!(&ciphertext[..plaintext_len], plaintext);
    }

    #[test]
    fn test_nonce_sync_after_truncated_recv() {
        let mut send = SendCipher::new(&mut test_rng());
        let mut recv = RecvCipher::new(&mut test_rng());

        // Send message (sender nonce: 0 -> 1)
        let ciphertext = send.send(b"message 1").unwrap();

        // Receiver gets truncated buffer (recv nonce: 0 -> 1)
        let mut truncated = vec![0u8; TAG_SIZE - 1];
        assert!(recv.recv_in_place(&mut truncated).is_err());

        // Original ciphertext (nonce 0) no longer decrypts because recv nonce advanced to 1
        assert!(recv.recv(&ciphertext).is_err());
    }

    #[test]
    fn test_nonce_sync_after_corrupted_recv() {
        let mut send = SendCipher::new(&mut test_rng());
        let mut recv = RecvCipher::new(&mut test_rng());

        // Send message (sender nonce: 0 -> 1)
        let ciphertext = send.send(b"message 1").unwrap();

        // Corrupt a copy (valid length, bad content)
        let mut corrupted = ciphertext.clone();
        corrupted[0] ^= 0xFF;
        assert!(recv.recv_in_place(&mut corrupted).is_err());

        // Original ciphertext (nonce 0) no longer decrypts because recv nonce advanced to 1
        assert!(recv.recv(&ciphertext).is_err());
    }
}

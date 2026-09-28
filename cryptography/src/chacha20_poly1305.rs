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
    /// The nonce counter is exhausted, so no further message can be sealed or opened.
    #[error("nonce exhausted")]
    Exhausted,
    /// The message does not authenticate at its position with the given associated data.
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
            return Err(Error::Exhausted);
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

            fn encrypt(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                aad: &[u8],
                data: &mut [u8],
            ) -> [u8; TAG_SIZE] {
                let nonce = aead::Nonce::assume_unique_for_key(*nonce);
                let tag = self
                    .0
                    .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), data)
                    .expect("message too long for ChaCha20-Poly1305");
                tag.as_ref().try_into().expect("tag size mismatch")
            }

            fn decrypt(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<(), Error> {
                let nonce = aead::Nonce::assume_unique_for_key(*nonce);
                self.0
                    .open_in_place(nonce, aead::Aad::from(aad), buf)
                    .map(|_| ())
                    .map_err(|_| Error::DecryptionFailed)
            }
        }
    } else {
        use chacha20poly1305::{ChaCha20Poly1305 as Aead, KeyInit as _, aead::AeadInOut};

        struct Key(Aead);

        impl Key {
            fn from_key(key: &[u8; KEY_SIZE_BYTES]) -> Self {
                Self(Aead::new(key.into()))
            }

            fn encrypt(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                aad: &[u8],
                data: &mut [u8],
            ) -> [u8; TAG_SIZE] {
                self.0
                    .encrypt_inout_detached(nonce.into(), aad, data.into())
                    .expect("message too long for ChaCha20-Poly1305")
                    .into()
            }

            fn decrypt(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                aad: &[u8],
                buf: &mut [u8],
            ) -> Result<(), Error> {
                let (data, tag) = buf
                    .split_last_chunk_mut::<TAG_SIZE>()
                    .ok_or(Error::DecryptionFailed)?;
                self.0
                    .decrypt_inout_detached(nonce.into(), aad, data.into(), (&*tag).into())
                    .map_err(|_| Error::DecryptionFailed)
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
    fn seal(mut self, aad: &[u8], buf: &mut [u8]) -> Result<Self, Error> {
        let (data, tag) = buf
            .split_last_chunk_mut::<TAG_SIZE>()
            .expect("buffer must have room for the tag");
        let nonce = self.nonce.inc()?;
        *tag = self.key.expose(|key| key.encrypt(&nonce, aad, data));
        Ok(self)
    }

    #[inline]
    fn open(mut self, aad: &[u8], buf: &mut [u8]) -> Result<(Self, usize), Error> {
        let nonce = self.nonce.inc()?;
        let Some(len) = buf.len().checked_sub(TAG_SIZE) else {
            return Err(Error::DecryptionFailed);
        };
        self.key.expose(|key| key.decrypt(&nonce, aad, buf))?;
        Ok((self, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{TestRng, test_rng};

    fn seal(cipher: ChaCha20Poly1305, aad: &[u8], msg: &[u8]) -> (ChaCha20Poly1305, Vec<u8>) {
        let mut buf = msg.to_vec();
        buf.resize(msg.len() + TAG_SIZE, 0);
        (cipher.seal(aad, &mut buf).unwrap(), buf)
    }

    #[test]
    fn test_seal_open_roundtrip() {
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(test_rng());
        for msg in [&b""[..], b"hello", b"world"] {
            let (next, mut buf) = seal(send, b"aad", msg);
            send = next;
            assert_eq!(buf.len(), msg.len() + TAG_SIZE);
            if !msg.is_empty() {
                assert_ne!(&buf[..msg.len()], msg);
            }

            let (next, len) = recv.open(b"aad", &mut buf).unwrap();
            recv = next;
            assert_eq!(&buf[..len], msg);
        }
    }

    #[test]
    fn test_open_wrong_key_fails() {
        let (_, mut buf) = seal(ChaCha20Poly1305::random(test_rng()), b"", b"hello");
        let recv = ChaCha20Poly1305::random(TestRng::new(1));
        assert!(matches!(
            recv.open(b"", &mut buf),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_open_wrong_aad_fails() {
        let (_, mut buf) = seal(ChaCha20Poly1305::random(test_rng()), b"aad", b"hello");
        let recv = ChaCha20Poly1305::random(test_rng());
        assert!(matches!(
            recv.open(b"other", &mut buf),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_open_wrong_position_fails() {
        let (send, _) = seal(ChaCha20Poly1305::random(test_rng()), b"", b"first");
        let (_, mut second) = seal(send, b"", b"second");
        let recv = ChaCha20Poly1305::random(test_rng());
        assert!(matches!(
            recv.open(b"", &mut second),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_open_corrupted_fails() {
        let (_, mut buf) = seal(ChaCha20Poly1305::random(test_rng()), b"", b"hello");
        buf[0] ^= 0xFF;
        let recv = ChaCha20Poly1305::random(test_rng());
        assert!(matches!(
            recv.open(b"", &mut buf),
            Err(Error::DecryptionFailed)
        ));
    }

    #[test]
    fn test_open_short_buffer_fails() {
        for len in [0, TAG_SIZE - 1, TAG_SIZE] {
            let recv = ChaCha20Poly1305::random(test_rng());
            let mut buf = vec![0u8; len];
            assert!(matches!(
                recv.open(b"", &mut buf),
                Err(Error::DecryptionFailed)
            ));
        }
    }

    #[test]
    fn test_exhausted_positions_fail() {
        let exhausted = |mut cipher: ChaCha20Poly1305| {
            cipher.nonce.inner = 1 << (8 * NONCE_SIZE_BYTES);
            cipher
        };
        let mut buf = vec![0u8; TAG_SIZE];
        let send = exhausted(ChaCha20Poly1305::random(test_rng()));
        assert!(matches!(send.seal(b"", &mut buf), Err(Error::Exhausted)));
        let recv = exhausted(ChaCha20Poly1305::random(test_rng()));
        assert!(matches!(recv.open(b"", &mut buf), Err(Error::Exhausted)));
    }

    #[test]
    #[should_panic(expected = "buffer must have room for the tag")]
    fn test_seal_short_buffer_panics() {
        let send = ChaCha20Poly1305::random(test_rng());
        let mut buf = vec![0u8; TAG_SIZE - 1];
        let _ = send.seal(b"", &mut buf);
    }
}

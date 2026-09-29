//! ChaCha20-Poly1305 [Cipher] with an implicit counter nonce.
//!
//! [ChaCha20Poly1305] holds one key and a 96-bit counter nonce that starts at zero, is encoded
//! little-endian, and advances once per message. The nonce is never transmitted, so a message
//! opens only in the order it was sealed. Each message carries a 16-byte tag.

use crate::{Cipher, Secret};
use commonware_math::algebra::Random;
use commonware_utils::sequence::FixedBytes;
use rand_core::CryptoRng;
use zeroize::Zeroizing;

/// Size of the ChaCha20-Poly1305 authentication tag.
const TAG_SIZE: usize = 16;

/// How many bytes are in a nonce.
/// ChaCha20-Poly1305 uses a 96-bit (12 byte) nonce.
const NONCE_SIZE_BYTES: usize = 12;

/// How many bytes are in a key.
/// ChaCha20-Poly1305 uses a 256-bit (32 byte) key.
const KEY_SIZE_BYTES: usize = 32;

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
            ) -> Option<[u8; TAG_SIZE]> {
                let nonce = aead::Nonce::assume_unique_for_key(*nonce);
                let tag = self
                    .0
                    .seal_in_place_separate_tag(nonce, aead::Aad::from(aad), data)
                    .ok()?;
                tag.as_ref().try_into().ok()
            }

            fn decrypt(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                aad: &[u8],
                data: &mut [u8],
                tag: &[u8; TAG_SIZE],
            ) -> Option<()> {
                let nonce = aead::Nonce::assume_unique_for_key(*nonce);
                self.0
                    .open_in_place_separate_tag(nonce, aead::Aad::from(aad), tag, data)
                    .ok()
                    .map(|_| ())
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
            ) -> Option<[u8; TAG_SIZE]> {
                self.0
                    .encrypt_inout_detached(nonce.into(), aad, data.into())
                    .ok()
                    .map(Into::into)
            }

            fn decrypt(
                &self,
                nonce: &[u8; NONCE_SIZE_BYTES],
                aad: &[u8],
                data: &mut [u8],
                tag: &[u8; TAG_SIZE],
            ) -> Option<()> {
                self.0
                    .decrypt_inout_detached(nonce.into(), aad, data.into(), tag.into())
                    .ok()
            }
        }
    }
}

/// ChaCha20-Poly1305 [Cipher] with an implicit counter nonce.
pub struct ChaCha20Poly1305 {
    nonce: u128,
    key: Secret<Key>,
}

impl ChaCha20Poly1305 {
    /// Returns the current nonce and advances the counter, or `None` if no nonce remains.
    fn next_nonce(&mut self) -> Option<[u8; NONCE_SIZE_BYTES]> {
        if self.nonce >= 1 << (8 * NONCE_SIZE_BYTES) {
            return None;
        }
        let out = self.nonce.to_le_bytes();
        self.nonce += 1;

        // Extract only the lower 96 bits (12 bytes) for the nonce
        let mut nonce = [0u8; NONCE_SIZE_BYTES];
        nonce.copy_from_slice(&out[..NONCE_SIZE_BYTES]);
        Some(nonce)
    }
}

impl Random for ChaCha20Poly1305 {
    fn random(mut rng: impl CryptoRng) -> Self {
        let mut key_bytes = Zeroizing::new([0u8; KEY_SIZE_BYTES]);
        rng.fill_bytes(key_bytes.as_mut());
        Self {
            nonce: 0,
            key: Secret::new(Key::from_key(&key_bytes)),
        }
    }
}

impl Cipher for ChaCha20Poly1305 {
    type Tag = FixedBytes<TAG_SIZE>;

    #[inline]
    fn seal(mut self, aad: &[u8], data: &mut [u8]) -> Option<(Self, Self::Tag)> {
        let nonce = self.next_nonce()?;
        let tag = self.key.expose(|key| key.encrypt(&nonce, aad, data))?;
        Some((self, FixedBytes::new(tag)))
    }

    #[inline]
    fn open(mut self, aad: &[u8], data: &mut [u8], tag: &Self::Tag) -> Option<Self> {
        let nonce = self.next_nonce()?;
        let tag: &[u8; TAG_SIZE] = tag.as_ref().try_into().expect("tag size is fixed");
        self.key.expose(|key| key.decrypt(&nonce, aad, data, tag))?;
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_utils::{TestRng, test_rng};

    /// Seals a copy of `msg`, returning the advanced cipher, the ciphertext, and the tag.
    fn seal(
        cipher: ChaCha20Poly1305,
        aad: &[u8],
        msg: &[u8],
    ) -> (ChaCha20Poly1305, Vec<u8>, FixedBytes<TAG_SIZE>) {
        let mut data = msg.to_vec();
        let (cipher, tag) = cipher.seal(aad, &mut data).unwrap();
        (cipher, data, tag)
    }

    #[test]
    fn test_seal_open_roundtrip() {
        // test_rng() has a fixed seed, so both ciphers get the same key.
        let mut send = ChaCha20Poly1305::random(test_rng());
        let mut recv = ChaCha20Poly1305::random(test_rng());
        for msg in [&b""[..], b"hello", b"world"] {
            let (next, mut data, tag) = seal(send, b"aad", msg);
            send = next;
            if !msg.is_empty() {
                assert_ne!(data, msg);
            }
            recv = recv.open(b"aad", &mut data, &tag).unwrap();
            assert_eq!(data, msg);
        }
    }

    #[test]
    fn test_open_wrong_key_fails() {
        let (_, mut data, tag) = seal(ChaCha20Poly1305::random(test_rng()), b"", b"hello");
        let recv = ChaCha20Poly1305::random(TestRng::new(1));
        assert!(recv.open(b"", &mut data, &tag).is_none());
    }

    #[test]
    fn test_open_wrong_aad_fails() {
        let (_, mut data, tag) = seal(ChaCha20Poly1305::random(test_rng()), b"aad", b"hello");
        let recv = ChaCha20Poly1305::random(test_rng());
        assert!(recv.open(b"other", &mut data, &tag).is_none());
    }

    #[test]
    fn test_open_out_of_order_fails() {
        let (send, _, _) = seal(ChaCha20Poly1305::random(test_rng()), b"", b"first");
        let (_, mut second, tag) = seal(send, b"", b"second");

        // The receiver expects the first message, so the second fails to open.
        let recv = ChaCha20Poly1305::random(test_rng());
        assert!(recv.open(b"", &mut second, &tag).is_none());
    }

    #[test]
    fn test_open_corrupted_fails() {
        let (_, mut data, tag) = seal(ChaCha20Poly1305::random(test_rng()), b"", b"hello");
        data[0] ^= 0xFF;
        let recv = ChaCha20Poly1305::random(test_rng());
        assert!(recv.open(b"", &mut data, &tag).is_none());
    }

    #[test]
    fn test_open_corrupted_tag_fails() {
        let (_, mut data, tag) = seal(ChaCha20Poly1305::random(test_rng()), b"", b"hello");
        let mut tag: [u8; TAG_SIZE] = tag.as_ref().try_into().unwrap();
        tag[0] ^= 0xFF;
        let recv = ChaCha20Poly1305::random(test_rng());
        assert!(recv.open(b"", &mut data, &FixedBytes::new(tag)).is_none());
    }

    #[test]
    fn test_exhausted_counter_fails() {
        // Set the counter to its limit so no nonce remains.
        let exhausted = |mut cipher: ChaCha20Poly1305| {
            cipher.nonce = 1 << (8 * NONCE_SIZE_BYTES);
            cipher
        };
        let send = exhausted(ChaCha20Poly1305::random(test_rng()));
        assert!(send.seal(b"", &mut []).is_none());
        let recv = exhausted(ChaCha20Poly1305::random(test_rng()));
        let tag = FixedBytes::new([0u8; TAG_SIZE]);
        assert!(recv.open(b"", &mut [], &tag).is_none());
    }
}

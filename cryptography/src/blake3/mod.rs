//! BLAKE3 implementation of the [Hasher] trait.
//!
//! This implementation uses the [blake3] crate to generate BLAKE3 digests.
//!
//! # Example
//! ```rust
//! use commonware_cryptography::{Hasher, blake3::Blake3};
//!
//! // Create a new BLAKE3 hasher
//! let mut hasher = Blake3::new();
//!
//! // Update the hasher with some messages
//! hasher.update(b"hello,");
//! hasher.update(b"world!");
//!
//! // Finalize the hasher to get the digest
//! let digest = hasher.finalize();
//!
//! // Print the digest
//! println!("digest: {:?}", digest);
//! ```

use crate::Hasher;
use blake3::Hash;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_utils::{hex, Array, Span};
use rand::{CryptoRng, Rng};
use std::{
    fmt::{Debug, Display},
    ops::Deref,
};
use zeroize::Zeroize;

/// Re-export [blake3::Hasher] as `CoreBlake3` for external use if needed.
pub type CoreBlake3 = blake3::Hasher;

const DIGEST_LENGTH: usize = blake3::OUT_LEN;

/// Generate a BLAKE3 [Digest] from a message.
pub fn hash(message: &[u8]) -> Digest {
    let mut hasher = Blake3::new();
    hasher.update(message);
    hasher.finalize()
}

/// BLAKE3 hasher.
#[cfg_attr(
    feature = "parallel-blake3",
    doc = "When the input message is larger than 128KiB, `rayon` is used to parallelize hashing."
)]
#[derive(Debug, Default)]
pub struct Blake3 {
    hasher: CoreBlake3,
}

impl Clone for Blake3 {
    fn clone(&self) -> Self {
        // We manually implement `Clone` to avoid cloning the hasher state.
        Self::default()
    }
}

impl Hasher for Blake3 {
    type Digest = Digest;

    fn new() -> Self {
        Self {
            hasher: CoreBlake3::new(),
        }
    }

    fn update(&mut self, message: &[u8]) -> &mut Self {
        #[cfg(not(feature = "parallel-blake3"))]
        self.hasher.update(message);

        #[cfg(feature = "parallel-blake3")]
        {
            // 128 KiB
            const PARALLEL_THRESHOLD: usize = 2usize.pow(17);

            // Heuristic defined @ https://docs.rs/blake3/latest/blake3/struct.Hasher.html#method.update_rayon
            if message.len() >= PARALLEL_THRESHOLD {
                self.hasher.update_rayon(message);
            } else {
                self.hasher.update(message);
            }
        }

        self
    }

    fn finalize(&mut self) -> Self::Digest {
        let finalized = self.hasher.finalize();
        self.hasher.reset();
        let array: [u8; DIGEST_LENGTH] = finalized.into();
        Self::Digest::from(array)
    }

    fn reset(&mut self) -> &mut Self {
        self.hasher = CoreBlake3::new();
        self
    }

    fn empty() -> Self::Digest {
        Self::default().finalize()
    }
}

/// Digest of a BLAKE3 hashing operation.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Digest(pub [u8; DIGEST_LENGTH]);

impl Write for Digest {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Digest {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let array = <[u8; DIGEST_LENGTH]>::read(buf)?;
        Ok(Self(array))
    }
}

impl FixedSize for Digest {
    const SIZE: usize = DIGEST_LENGTH;
}

impl Span for Digest {}

impl Array for Digest {}

impl From<Hash> for Digest {
    fn from(value: Hash) -> Self {
        Self(value.into())
    }
}

impl From<[u8; DIGEST_LENGTH]> for Digest {
    fn from(value: [u8; DIGEST_LENGTH]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Digest {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Digest {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

impl crate::Digest for Digest {
    fn random<R: Rng + CryptoRng>(rng: &mut R) -> Self {
        let mut array = [0u8; DIGEST_LENGTH];
        rng.fill_bytes(&mut array);
        Self(array)
    }
}

impl Zeroize for Digest {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};
    use commonware_utils::hex;

    const HELLO_DIGEST: &str = "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";

    #[test]
    fn test_blake3() {
        let msg = b"hello world";

        // Generate initial hash
        let mut hasher = Blake3::new();
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(hex(digest.as_ref()), HELLO_DIGEST);

        // Reuse hasher
        hasher.update(msg);
        let digest = hasher.finalize();
        assert!(Digest::decode(digest.as_ref()).is_ok());
        assert_eq!(hex(digest.as_ref()), HELLO_DIGEST);

        // Test simple hasher
        let hash = hash(msg);
        assert_eq!(hex(hash.as_ref()), HELLO_DIGEST);
    }

    #[test]
    fn test_blake3_len() {
        assert_eq!(Digest::SIZE, DIGEST_LENGTH);
    }

    #[test]
    fn test_hash_empty() {
        let digest1 = Blake3::empty();
        let digest2 = Blake3::empty();

        assert_eq!(digest1, digest2);
    }

    #[test]
    fn test_blake3_empty() {
        let empty_digest = Blake3::empty();

        // BLAKE3 hash of empty string:
        // af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262
        let expected_bytes = [
            0xaf, 0x13, 0x49, 0xb9, 0xf5, 0xf9, 0xa1, 0xa6, 0xa0, 0x40, 0x4d, 0xea, 0x36, 0xdc,
            0xc9, 0x49, 0x9b, 0xcb, 0x25, 0xc9, 0xad, 0xc1, 0x12, 0xb7, 0xcc, 0x9a, 0x93, 0xca,
            0xe4, 0x1f, 0x32, 0x62,
        ];
        let expected_digest = Digest::from(expected_bytes);

        assert_eq!(empty_digest, expected_digest);
    }

    #[test]
    fn test_codec() {
        let msg = b"hello world";
        let mut hasher = Blake3::new();
        hasher.update(msg);
        let digest = hasher.finalize();

        let encoded = digest.encode();
        assert_eq!(encoded.len(), DIGEST_LENGTH);
        assert_eq!(encoded, digest.as_ref());

        let decoded = Digest::decode(encoded).unwrap();
        assert_eq!(digest, decoded);
    }
}

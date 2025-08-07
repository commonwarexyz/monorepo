//! CRC32 hash implementation using crc32fast.

use crate::{Digest, Hasher};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use commonware_utils::{Array, Span};
use rand::{CryptoRng, RngCore};
use std::{
    fmt::{Debug, Display},
    ops::Deref,
};

const DIGEST_LENGTH: usize = 4;

/// A 32-bit CRC digest.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Crc32(pub [u8; DIGEST_LENGTH]);

impl Crc32 {
    /// Create a new CRC32 from a u32 value.
    pub fn from_u32(value: u32) -> Self {
        Self(value.to_be_bytes())
    }

    /// Convert to u32.
    pub fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }
}

impl Write for Crc32 {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for Crc32 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let array = <[u8; DIGEST_LENGTH]>::read(buf)?;
        Ok(Self(array))
    }
}

impl FixedSize for Crc32 {
    const SIZE: usize = DIGEST_LENGTH;
}

impl Span for Crc32 {}

impl Array for Crc32 {}

impl From<[u8; DIGEST_LENGTH]> for Crc32 {
    fn from(value: [u8; DIGEST_LENGTH]) -> Self {
        Self(value)
    }
}

impl AsRef<[u8]> for Crc32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Crc32 {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Debug for Crc32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.to_u32())
    }
}

impl Display for Crc32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:08x}", self.to_u32())
    }
}

impl Digest for Crc32 {
    fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut array = [0u8; DIGEST_LENGTH];
        rng.fill_bytes(&mut array);
        Self(array)
    }
}

/// A CRC32 hasher using crc32fast.
#[derive(Clone)]
pub struct Crc32Hasher {
    hasher: crc32fast::Hasher,
}

impl Hasher for Crc32Hasher {
    type Digest = Crc32;

    fn new() -> Self {
        Self {
            hasher: crc32fast::Hasher::new(),
        }
    }

    fn update(&mut self, message: &[u8]) {
        self.hasher.update(message);
    }

    fn finalize(&mut self) -> Self::Digest {
        let result = self.hasher.clone().finalize();
        self.hasher.reset();
        Crc32::from_u32(result)
    }

    fn reset(&mut self) {
        self.hasher.reset();
    }

    fn empty() -> Self::Digest {
        Crc32::from_u32(0)
    }
}

/// Convenience function to hash data with CRC32.
pub fn hash(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_hasher() {
        let mut hasher = Crc32Hasher::new();
        hasher.update(b"hello");
        hasher.update(b" world");
        let digest = hasher.finalize();

        let expected = crc32fast::hash(b"hello world");
        assert_eq!(digest.to_u32(), expected);
    }

    #[test]
    fn test_crc32_hasher_reset() {
        let mut hasher = Crc32Hasher::new();
        hasher.update(b"hello world");
        hasher.reset();
        hasher.update(b"test");
        let digest = hasher.finalize();

        let expected = crc32fast::hash(b"test");
        assert_eq!(digest.to_u32(), expected);
    }

    #[test]
    fn test_crc32_empty() {
        let empty_digest = Crc32Hasher::empty();
        assert_eq!(empty_digest.to_u32(), 0);
    }

    #[test]
    fn test_hash_convenience_function() {
        let data = b"hello world";
        let result = hash(data);
        let expected = crc32fast::hash(data);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_crc32_digest_from_u32() {
        let value = 0x12345678u32;
        let digest = Crc32::from_u32(value);
        assert_eq!(digest.to_u32(), value);
    }
}

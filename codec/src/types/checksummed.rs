//! A wrapper type that automatically adds and verifies checksums.
//!
//! # Overview
//!
//! [Checksummed] wraps any [Codec] type and adds a checksum during encoding, which is
//! automatically verified during decoding. This is useful for detecting data corruption
//! in storage or transmission.
//!
//! # Example
//!
//! ```
//! use commonware_codec::{Checksummed, Codec, Encode, DecodeExt, FixedSize};
//! use bytes::{Buf, BufMut};
//!
//! // Define a simple CRC32 hasher for demonstration
//! #[derive(Default, Clone)]
//! struct Crc32Hasher(u32);
//!
//! impl commonware_codec::checksummed::Hasher for Crc32Hasher {
//!     type Digest = [u8; 4];
//!
//!     fn update(&mut self, data: &[u8]) {
//!         for &byte in data {
//!             self.0 = self.0.wrapping_add(byte as u32);
//!         }
//!     }
//!
//!     fn finalize(self) -> Self::Digest {
//!         self.0.to_be_bytes()
//!     }
//! }
//!
//! // Use the hasher with Checksummed
//! let data = 12345u64;
//! let checksummed = Checksummed::<_, Crc32Hasher>::from(data);
//! let encoded = checksummed.encode();
//! let decoded = Checksummed::<u64, Crc32Hasher>::decode(encoded).unwrap();
//! assert_eq!(decoded.into_inner(), data);
//! ```

use crate::{Codec, EncodeSize, Error, FixedSize, Read, Write};
use bytes::{Buf, BufMut};
use core::marker::PhantomData;

/// A trait for hash functions used by [Checksummed].
///
/// This is a simplified hasher trait specifically designed for checksumming data.
/// It avoids circular dependencies with the cryptography crate.
///
/// # Example
///
/// ```
/// use commonware_codec::checksummed::Hasher;
///
/// #[derive(Default, Clone)]
/// struct SimpleHasher(u32);
///
/// impl Hasher for SimpleHasher {
///     type Digest = [u8; 4];
///
///     fn update(&mut self, data: &[u8]) {
///         for &byte in data {
///             self.0 = self.0.wrapping_add(byte as u32);
///         }
///     }
///
///     fn finalize(self) -> Self::Digest {
///         self.0.to_be_bytes()
///     }
/// }
/// ```
pub trait Hasher: Default + Clone + Send + Sync + 'static {
    /// The digest type produced by this hasher.
    ///
    /// Must implement [Codec], [FixedSize], and [PartialEq].
    type Digest: Codec<Cfg = ()> + FixedSize + PartialEq;

    /// Update the hasher state with the given data.
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash and return the digest, consuming the hasher.
    fn finalize(self) -> Self::Digest;

    /// Convenience method to hash a single message.
    fn hash(data: &[u8]) -> Self::Digest {
        let mut hasher = Self::default();
        hasher.update(data);
        hasher.finalize()
    }
}

/// A wrapper around a [Codec] type that has a checksum.
///
/// Automatically creates the checksum when writing and verifies it when reading.
///
/// # Type Parameters
///
/// - `T`: The inner type to be checksummed. Must implement [Codec].
/// - `H`: The hasher to use for generating checksums. Must implement [Hasher].
///
/// # Example
///
/// ```
/// use commonware_codec::{Checksummed, Codec, Encode, DecodeExt, checksummed::Hasher};
///
/// // Define a simple hasher
/// #[derive(Default, Clone)]
/// struct SimpleHasher(u32);
///
/// impl Hasher for SimpleHasher {
///     type Digest = [u8; 4];
///     fn update(&mut self, data: &[u8]) {
///         for &byte in data {
///             self.0 = self.0.wrapping_add(byte as u32);
///         }
///     }
///     fn finalize(self) -> Self::Digest {
///         self.0.to_be_bytes()
///     }
/// }
///
/// let original = 42u32;
/// let checksummed = Checksummed::<_, SimpleHasher>::from(original);
/// let encoded = checksummed.encode();
/// let decoded = Checksummed::<u32, SimpleHasher>::decode(encoded).unwrap();
/// assert_eq!(decoded.into_inner(), original);
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checksummed<T: Codec, H: Hasher> {
    /// The underlying data.
    pub data: T,
    _hasher: PhantomData<H>,
}

impl<T: Codec, H: Hasher> Checksummed<T, H> {
    /// Wraps a value in a [Checksummed] wrapper.
    ///
    /// This is equivalent to using `Checksummed::from(data)`.
    pub fn new(data: T) -> Self {
        Self {
            data,
            _hasher: PhantomData,
        }
    }

    /// Extracts the inner value, consuming the [Checksummed] wrapper.
    pub fn into_inner(self) -> T {
        self.data
    }

    /// Returns a reference to the inner value.
    pub fn inner(&self) -> &T {
        &self.data
    }

    /// Returns a mutable reference to the inner value.
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.data
    }
}

impl<T: Codec, H: Hasher> From<T> for Checksummed<T, H> {
    fn from(data: T) -> Self {
        Self::new(data)
    }
}

impl<T: Codec, H: Hasher> Write for Checksummed<T, H> {
    fn write(&self, buf: &mut impl BufMut) {
        // Encode the data first
        let data_bytes = self.data.encode();

        // Compute the hash
        let hash = H::hash(&data_bytes);

        // Write: data first, then hash
        buf.put_slice(&data_bytes);
        hash.write(buf);
    }
}

impl<T: Codec, H: Hasher> Read for Checksummed<T, H>
where
    T::Cfg: Default,
{
    type Cfg = T::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        // Read the data first - T::read_cfg will consume exactly the bytes it needs
        let data = T::read_cfg(buf, cfg)?;

        // Read the hash
        let hash = H::Digest::read_cfg(buf, &())?;

        // Verify the checksum by re-encoding the data
        let data_bytes = data.encode();
        let expected_hash = H::hash(&data_bytes);

        if hash != expected_hash {
            return Err(Error::Invalid("Checksummed", "checksum mismatch"));
        }

        Ok(Self {
            data,
            _hasher: PhantomData,
        })
    }
}

impl<T: Codec, H: Hasher> EncodeSize for Checksummed<T, H> {
    fn encode_size(&self) -> usize {
        self.data.encode_size() + H::Digest::SIZE
    }
}

// Implement Hasher for commonware_cryptography types in tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecodeExt, Encode};

    // Simple test hasher for unit tests
    #[derive(Default, Clone)]
    struct TestHasher(u32);

    impl Hasher for TestHasher {
        type Digest = [u8; 4];

        fn update(&mut self, data: &[u8]) {
            for &byte in data {
                self.0 = self.0.wrapping_add(byte as u32);
            }
        }

        fn finalize(self) -> Self::Digest {
            self.0.to_be_bytes()
        }
    }

    #[test]
    fn test_checksummed_u32() {
        let original = 42u32;
        let checksummed = Checksummed::<_, TestHasher>::from(original);

        let encoded = checksummed.encode();
        let decoded = Checksummed::<u32, TestHasher>::decode(encoded).unwrap();

        assert_eq!(decoded.into_inner(), original);
    }

    #[test]
    fn test_checksummed_option() {
        let original = Some(42u32);
        let checksummed = Checksummed::<_, TestHasher>::from(original);

        let encoded = checksummed.encode();
        let decoded = Checksummed::<Option<u32>, TestHasher>::decode(encoded).unwrap();

        assert_eq!(decoded.into_inner(), original);
    }

    #[test]
    fn test_checksum_mismatch() {
        let original = 42u32;
        let checksummed = Checksummed::<_, TestHasher>::from(original);

        let mut encoded = checksummed.encode();

        // Corrupt the checksum (last byte)
        let len = encoded.len();
        encoded[len - 1] ^= 0xFF;

        let result = Checksummed::<u32, TestHasher>::decode(encoded);
        assert!(matches!(
            result,
            Err(Error::Invalid("Checksummed", "checksum mismatch"))
        ));
    }

    #[test]
    fn test_checksum_data_corruption() {
        let original = 12345u64;
        let checksummed = Checksummed::<_, TestHasher>::from(original);

        let mut encoded = checksummed.encode();

        // Corrupt the data (first byte)
        encoded[0] ^= 0xFF;

        let result = Checksummed::<u64, TestHasher>::decode(encoded);
        assert!(matches!(
            result,
            Err(Error::Invalid("Checksummed", "checksum mismatch"))
        ));
    }

    #[test]
    fn test_encode_size() {
        let data = (42u32, 100u64);
        let checksummed = Checksummed::<_, TestHasher>::from(data);

        let expected_size = data.encode_size() + <TestHasher as Hasher>::Digest::SIZE;
        assert_eq!(checksummed.encode_size(), expected_size);

        let encoded = checksummed.encode();
        assert_eq!(encoded.len(), expected_size);
    }

    #[test]
    fn test_inner_methods() {
        let original = (1u32, 2u32);
        let mut checksummed = Checksummed::<_, TestHasher>::from(original);

        // Test inner()
        assert_eq!(checksummed.inner(), &original);

        // Test inner_mut()
        checksummed.inner_mut().0 = 10;
        assert_eq!(checksummed.inner(), &(10u32, 2u32));

        // Test into_inner()
        assert_eq!(checksummed.into_inner(), (10u32, 2u32));
    }

    #[test]
    fn test_option_none() {
        let original: Option<u32> = None;
        let checksummed = Checksummed::<_, TestHasher>::from(original);

        let encoded = checksummed.encode();
        let decoded = Checksummed::<Option<u32>, TestHasher>::decode(encoded).unwrap();

        assert_eq!(decoded.into_inner(), original);
    }
}

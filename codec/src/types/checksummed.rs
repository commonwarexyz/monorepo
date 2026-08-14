//! This module exports the [`Checksummed`] type.

use crate::{Encode, EncodeSize, Error, FixedSize, Read, Write};
use bytes::{Buf, BufMut};
use core::{fmt::Debug, marker::PhantomData};

const CHECKSUMMED_TYPE: &str = "Checksummed";

/// Computes a fixed-size checksum over a slice of bytes.
///
/// [`Checksummed`] is generic over this trait rather than over a hasher from a dedicated hashing
/// crate because those crates depend on this one.
///
/// # Example
///
/// ```
/// use commonware_codec::types::checksummed::Checksummer;
///
/// /// Sums every byte, wrapping on overflow.
/// struct Sum;
///
/// impl Checksummer for Sum {
///     type Digest = u32;
///
///     fn checksum(data: &[u8]) -> u32 {
///         data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
///     }
/// }
/// ```
pub trait Checksummer: Send + Sync + 'static {
    /// The checksum written after the encoded value.
    type Digest: Read<Cfg = ()> + Write + FixedSize + PartialEq;

    /// Returns the checksum of `data`.
    fn checksum(data: &[u8]) -> Self::Digest;
}

/// A value encoded with a trailing checksum of its encoding.
///
/// The checksum is appended when writing and verified when reading, which detects accidental
/// corruption of data at rest or in transit.
///
/// # Warning
///
/// A checksum is not authentication. Anyone able to modify the payload can also recompute the
/// checksum, so this must not be used to detect tampering.
///
/// # Canonical Encodings
///
/// Reading verifies the checksum against a re-encoding of the decoded value rather than against
/// the consumed bytes. For types whose encoding is canonical (as all implementations in this crate
/// are) the two are identical. For any other type, an encoding that decodes to the same value but
/// differs byte-for-byte is rejected as a checksum mismatch.
///
/// # Example
///
/// ```
/// use commonware_codec::{DecodeExt, Encode, types::checksummed::{Checksummed, Checksummer}};
///
/// struct Sum;
///
/// impl Checksummer for Sum {
///     type Digest = u32;
///
///     fn checksum(data: &[u8]) -> u32 {
///         data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
///     }
/// }
///
/// let encoded = Checksummed::<u64, Sum>::new(4000).encode();
/// let decoded = Checksummed::<u64, Sum>::decode(encoded.clone()).unwrap();
/// assert_eq!(decoded.into_inner(), 4000);
///
/// // Corrupting any byte is detected.
/// let mut corrupted = encoded.to_vec();
/// corrupted[0] ^= 0xFF;
/// assert!(Checksummed::<u64, Sum>::decode(corrupted.as_slice()).is_err());
/// ```
pub struct Checksummed<T, C: Checksummer> {
    value: T,
    // `fn() -> C` keeps the auto traits of this type independent of `C`.
    _checksummer: PhantomData<fn() -> C>,
}

impl<T, C: Checksummer> Checksummed<T, C> {
    /// Wraps `value` so that its encoding carries a checksum.
    pub const fn new(value: T) -> Self {
        Self {
            value,
            _checksummer: PhantomData,
        }
    }

    /// Returns a reference to the wrapped value.
    pub const fn get(&self) -> &T {
        &self.value
    }

    /// Returns a mutable reference to the wrapped value.
    pub const fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Consumes the wrapper, returning the wrapped value.
    pub fn into_inner(self) -> T {
        self.value
    }
}

impl<T, C: Checksummer> From<T> for Checksummed<T, C> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T: EncodeSize, C: Checksummer> EncodeSize for Checksummed<T, C> {
    fn encode_size(&self) -> usize {
        self.value.encode_size() + C::Digest::SIZE
    }
}

impl<T: Encode, C: Checksummer> Write for Checksummed<T, C> {
    fn write(&self, buf: &mut impl BufMut) {
        // The checksum covers the encoded value, so it must be materialized before either can be
        // written.
        let encoded = self.value.encode();
        buf.put_slice(&encoded);
        C::checksum(&encoded).write(buf);
    }
}

impl<T: Encode + Read, C: Checksummer> Read for Checksummed<T, C> {
    type Cfg = T::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        let value = T::read_cfg(buf, cfg)?;
        let found = C::Digest::read_cfg(buf, &())?;
        if found != C::checksum(&value.encode()) {
            return Err(Error::Invalid(CHECKSUMMED_TYPE, "checksum mismatch"));
        }
        Ok(Self::new(value))
    }
}

impl<T: Debug, C: Checksummer> Debug for Checksummed<T, C> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Checksummed").field(&self.value).finish()
    }
}

impl<T: Clone, C: Checksummer> Clone for Checksummed<T, C> {
    fn clone(&self) -> Self {
        Self::new(self.value.clone())
    }
}

impl<T: Copy, C: Checksummer> Copy for Checksummed<T, C> {}

impl<T: PartialEq, C: Checksummer> PartialEq for Checksummed<T, C> {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl<T: Eq, C: Checksummer> Eq for Checksummed<T, C> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, DecodeExt, RangeCfg, ReadExt};
    use bytes::Bytes;

    /// Sums every byte, wrapping on overflow.
    struct Sum;

    impl Checksummer for Sum {
        type Digest = u32;

        fn checksum(data: &[u8]) -> u32 {
            data.iter().fold(0u32, |acc, &b| acc.wrapping_add(b as u32))
        }
    }

    #[test]
    fn test_roundtrip_fixed_size() {
        let encoded = Checksummed::<u64, Sum>::new(4000).encode();
        assert_eq!(encoded.len(), u64::SIZE + u32::SIZE);

        let decoded = Checksummed::<u64, Sum>::decode(encoded).unwrap();
        assert_eq!(decoded.into_inner(), 4000);
    }

    #[test]
    fn test_roundtrip_variable_size() {
        let value = vec![1u8, 2, 3];
        let encoded = Checksummed::<Vec<u8>, Sum>::new(value.clone()).encode();

        let cfg = ((..=8usize).into(), ());
        let decoded = Checksummed::<Vec<u8>, Sum>::decode_cfg(encoded, &cfg).unwrap();
        assert_eq!(decoded.into_inner(), value);
    }

    #[test]
    fn test_config_is_forwarded_to_inner() {
        let encoded = Checksummed::<Vec<u8>, Sum>::new(vec![1u8, 2, 3]).encode();

        // A range that rejects the encoded length must fail before any checksum work.
        let cfg: (RangeCfg<usize>, ()) = ((..=2usize).into(), ());
        assert!(matches!(
            Checksummed::<Vec<u8>, Sum>::decode_cfg(encoded, &cfg),
            Err(Error::InvalidLength(3))
        ));
    }

    #[test]
    fn test_encode_size_matches_written_bytes() {
        let checksummed = Checksummed::<Vec<u8>, Sum>::new(vec![7u8; 5]);
        assert_eq!(checksummed.encode().len(), checksummed.encode_size());
    }

    #[test]
    fn test_corrupted_payload_is_rejected() {
        let mut encoded = Checksummed::<u64, Sum>::new(4000).encode().to_vec();
        encoded[0] ^= 0xFF;

        assert!(matches!(
            Checksummed::<u64, Sum>::decode(encoded.as_slice()),
            Err(Error::Invalid(CHECKSUMMED_TYPE, "checksum mismatch"))
        ));
    }

    #[test]
    fn test_corrupted_checksum_is_rejected() {
        let mut encoded = Checksummed::<u64, Sum>::new(4000).encode().to_vec();
        let last = encoded.len() - 1;
        encoded[last] ^= 0xFF;

        assert!(matches!(
            Checksummed::<u64, Sum>::decode(encoded.as_slice()),
            Err(Error::Invalid(CHECKSUMMED_TYPE, "checksum mismatch"))
        ));
    }

    #[test]
    fn test_missing_checksum_is_rejected() {
        // The payload is intact but the trailing checksum was never written.
        let encoded = 4000u64.encode();

        assert!(matches!(
            Checksummed::<u64, Sum>::decode(encoded),
            Err(Error::EndOfBuffer)
        ));
    }

    #[test]
    fn test_read_consumes_exactly_one_value() {
        let mut buf = Checksummed::<u64, Sum>::new(4000).encode().to_vec();
        buf.extend_from_slice(&7u8.encode());
        let mut buf = Bytes::from(buf);

        let decoded = Checksummed::<u64, Sum>::read(&mut buf).unwrap();
        assert_eq!(decoded.into_inner(), 4000);
        assert_eq!(u8::read(&mut buf).unwrap(), 7);
        assert!(!buf.has_remaining());
    }
}

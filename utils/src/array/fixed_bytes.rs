use crate::{hex, Array};
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, ReadExt, Write};
use std::{
    cmp::{Ord, PartialOrd},
    fmt::{Debug, Display},
    hash::Hash,
    ops::Deref,
};
use thiserror::Error;

/// Errors returned by `Bytes` functions.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("invalid length")]
    InvalidLength,
}

/// An `Array` implementation for fixed-length byte arrays.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[repr(transparent)]
pub struct FixedBytes<const N: usize>([u8; N]);

impl<const N: usize> FixedBytes<N> {
    /// Creates a new `FixedBytes` instance from an array of length `N`.
    pub fn new(value: [u8; N]) -> Self {
        Self(value)
    }
}

impl<const N: usize> Write for FixedBytes<N> {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl<const N: usize> Read for FixedBytes<N> {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(<[u8; N]>::read(buf)?))
    }
}

impl<const N: usize> FixedSize for FixedBytes<N> {
    const SIZE: usize = N;
}

impl<const N: usize> Array for FixedBytes<N> {}

impl<const N: usize> AsRef<[u8]> for FixedBytes<N> {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Deref for FixedBytes<N> {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> Display for FixedBytes<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Buf, BytesMut};
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_codec() {
        let original = FixedBytes::new([1, 2, 3, 4]);
        let encoded = original.encode();
        assert_eq!(encoded.len(), original.len());
        let decoded = FixedBytes::decode(encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_bytes_creation_and_conversion() {
        let value = [1, 2, 3, 4];
        let bytes = FixedBytes::new(value);
        assert_eq!(bytes.as_ref(), &value);

        let slice = [1, 2, 3, 4];
        let bytes_from_slice = FixedBytes::decode(slice.as_ref()).unwrap();
        assert_eq!(bytes_from_slice, bytes);

        let vec = vec![1, 2, 3, 4];
        let bytes_from_vec = FixedBytes::decode(vec.as_ref()).unwrap();
        assert_eq!(bytes_from_vec, bytes);

        // Test with incorrect length
        let slice_too_short = [1, 2, 3];
        assert!(matches!(
            FixedBytes::<4>::decode(slice_too_short.as_ref()),
            Err(CodecError::EndOfBuffer)
        ));

        let vec_too_long = vec![1, 2, 3, 4, 5];
        assert!(matches!(
            FixedBytes::<4>::decode(vec_too_long.as_ref()),
            Err(CodecError::ExtraData(1))
        ));
    }

    #[test]
    fn test_read() {
        let mut buf = BytesMut::from(&[1, 2, 3, 4][..]);
        let bytes = FixedBytes::<4>::read(&mut buf).unwrap();
        assert_eq!(bytes.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(buf.remaining(), 0);

        let mut buf = BytesMut::from(&[1, 2, 3][..]);
        let result = FixedBytes::<4>::read(&mut buf);
        assert!(matches!(result, Err(CodecError::EndOfBuffer)));

        let mut buf = BytesMut::from(&[1, 2, 3, 4, 5][..]);
        let bytes = FixedBytes::<4>::read(&mut buf).unwrap();
        assert_eq!(bytes.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(buf.remaining(), 1);
        assert_eq!(buf[0], 5);
    }

    #[test]
    fn test_display() {
        let bytes = FixedBytes::new([0x01, 0x02, 0x03, 0x04]);
        assert_eq!(format!("{}", bytes), "01020304");
    }

    #[test]
    fn test_ord_and_eq() {
        let a = FixedBytes::new([1, 2, 3, 4]);
        let b = FixedBytes::new([1, 2, 3, 5]);
        assert!(a < b);
        assert_ne!(a, b);

        let c = FixedBytes::new([1, 2, 3, 4]);
        assert_eq!(a, c);
    }
}

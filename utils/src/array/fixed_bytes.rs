use crate::{hex, Array};
use commonware_codec::{Codec, Error as CodecError, Reader, SizedCodec, Writer};
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

impl<const N: usize> Codec for FixedBytes<N> {
    fn write(&self, writer: &mut impl Writer) {
        writer.write_fixed(&self.0);
    }

    fn read(reader: &mut impl Reader) -> Result<Self, CodecError> {
        let value = reader.read_fixed()?;
        Ok(Self(value))
    }

    fn len_encoded(&self) -> usize {
        N
    }
}

impl<const N: usize> SizedCodec for FixedBytes<N> {
    const LEN_ENCODED: usize = N;
}

impl<const N: usize> Array for FixedBytes<N> {
    type Error = Error;
}

impl<const N: usize> TryFrom<&[u8]> for FixedBytes<N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let array: [u8; N] = value.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Self(array))
    }
}

impl<const N: usize> TryFrom<&Vec<u8>> for FixedBytes<N> {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        Self::try_from(value.as_slice())
    }
}

impl<const N: usize> TryFrom<Vec<u8>> for FixedBytes<N> {
    type Error = Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        if value.len() != N {
            return Err(Error::InvalidLength);
        }
        let boxed_slice = value.into_boxed_slice();
        let boxed_array: Box<[u8; N]> = boxed_slice.try_into().map_err(|_| Error::InvalidLength)?;
        Ok(Self(*boxed_array))
    }
}

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
    use crate::array::Error as ArrayError;
    use bytes::{Buf, BytesMut};

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
        let bytes_from_slice = FixedBytes::try_from(slice.as_ref()).unwrap();
        assert_eq!(bytes_from_slice, bytes);

        let vec = vec![1, 2, 3, 4];
        let bytes_from_vec_ref = FixedBytes::try_from(&vec).unwrap();
        assert_eq!(bytes_from_vec_ref, bytes);

        let bytes_from_vec = FixedBytes::try_from(vec).unwrap();
        assert_eq!(bytes_from_vec, bytes);

        // Test with incorrect length
        let slice_too_short = [1, 2, 3];
        assert_eq!(
            FixedBytes::<4>::try_from(slice_too_short.as_ref()),
            Err(Error::InvalidLength)
        );

        let vec_too_long = vec![1, 2, 3, 4, 5];
        assert_eq!(
            FixedBytes::<4>::try_from(&vec_too_long),
            Err(Error::InvalidLength)
        );
        assert_eq!(
            FixedBytes::<4>::try_from(vec_too_long),
            Err(Error::InvalidLength)
        );
    }

    #[test]
    fn test_read_from() {
        let mut buf = BytesMut::from(&[1, 2, 3, 4][..]);
        let bytes = FixedBytes::<4>::read_from(&mut buf).unwrap();
        assert_eq!(bytes.as_ref(), &[1, 2, 3, 4]);
        assert_eq!(buf.remaining(), 0);

        let mut buf = BytesMut::from(&[1, 2, 3][..]);
        let result = FixedBytes::<4>::read_from(&mut buf);
        assert_eq!(result, Err(ArrayError::InsufficientBytes));

        let mut buf = BytesMut::from(&[1, 2, 3, 4, 5][..]);
        let bytes = FixedBytes::<4>::read_from(&mut buf).unwrap();
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

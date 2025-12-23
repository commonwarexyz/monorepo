//! Codec implementation for [`Vec<T>`].
//!
//! For portability and consistency between architectures,
//! the length of the vector must fit within a [u32].

use crate::{EncodeSize, Error, RangeCfg, Read, Write};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};

impl<T: Write> Write for Vec<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.as_slice().write(buf)
    }
}

impl<T: EncodeSize> EncodeSize for Vec<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.as_slice().encode_size()
    }
}

impl<T: Write> Write for &[T] {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);
        for item in self.iter() {
            item.write(buf);
        }
    }
}

impl<T: EncodeSize> EncodeSize for &[T] {
    #[inline]
    fn encode_size(&self) -> usize {
        self.len().encode_size() + self.iter().map(EncodeSize::encode_size).sum::<usize>()
    }
}

impl<T: Read> Read for Vec<T> {
    type Cfg = (RangeCfg<usize>, T::Cfg);

    #[inline]
    fn read_cfg(buf: &mut impl Buf, (range, cfg): &Self::Cfg) -> Result<Self, Error> {
        let len = usize::read_cfg(buf, range)?;
        let mut vec = Self::with_capacity(len);
        for _ in 0..len {
            vec.push(T::read_cfg(buf, cfg)?);
        }
        Ok(vec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DecodeRangeExt, Encode};
    #[cfg(not(feature = "std"))]
    use alloc::vec;

    #[test]
    fn test_vec() {
        let vec_values = [vec![], vec![1u8], vec![1u8, 2u8, 3u8]];
        for value in vec_values {
            let encoded = value.encode();
            assert_eq!(encoded.len(), value.len() * core::mem::size_of::<u8>() + 1);

            // Valid decoding
            let len = value.len();
            let decoded = Vec::<u8>::decode_range(encoded, len..=len).unwrap();
            assert_eq!(value, decoded);

            // Failure for too long
            assert!(matches!(
                Vec::<u8>::decode_range(value.encode(), 0..len),
                Err(Error::InvalidLength(_))
            ));

            // Failure for too short
            assert!(matches!(
                Vec::<u8>::decode_range(value.encode(), len + 1..),
                Err(Error::InvalidLength(_))
            ));
        }
    }

    #[test]
    fn test_slice() {
        let slice_values: [&[u8]; 3] =
            [[].as_slice(), [1u8].as_slice(), [1u8, 2u8, 3u8].as_slice()];
        for value in slice_values {
            let encoded = value.encode();
            assert_eq!(encoded.len(), core::mem::size_of_val(value) + 1);

            // Valid decoding
            let len = value.len();
            let decoded = Vec::<u8>::decode_range(encoded, len..=len).unwrap();
            assert_eq!(value, decoded);

            // Failure for too long
            assert!(matches!(
                Vec::<u8>::decode_range(value.encode(), 0..len),
                Err(Error::InvalidLength(_))
            ));

            // Failure for too short
            assert!(matches!(
                Vec::<u8>::decode_range(value.encode(), len + 1..),
                Err(Error::InvalidLength(_))
            ));
        }
    }

    #[test]
    fn test_conformity() {
        assert_eq!(Vec::<u8>::new().encode(), &[0x00][..]);
        assert_eq!(
            vec![0x01u8, 0x02u8, 0x03u8].encode(),
            &[0x03, 0x01, 0x02, 0x03][..]
        );

        let v_u16: Vec<u16> = vec![0x1234, 0xABCD];
        assert_eq!(v_u16.encode(), &[0x02, 0x12, 0x34, 0xAB, 0xCD][..]);

        let v_bool: Vec<bool> = vec![true, false, true];
        assert_eq!(v_bool.encode(), &[0x03, 0x01, 0x00, 0x01][..]);

        let v_empty_u32: Vec<u32> = Vec::new();
        assert_eq!(v_empty_u32.encode(), &[0x00][..]);

        // Test with a length that requires a multi-byte varint
        let v_long_u8: Vec<u8> = vec![0xCC; 200]; // 200 = 0xC8 = 0x80 + 0x48 -> 0xC8 0x01
        let mut expected_long_u8 = vec![0xC8, 0x01];
        expected_long_u8.extend_from_slice(&[0xCC; 200]);
        assert_eq!(v_long_u8.encode(), expected_long_u8.as_slice());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use crate::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Vec<u8>>,
            CodecConformance<Vec<u16>>,
            CodecConformance<Vec<u32>>,
        }
    }
}

//! Codec implementation for [`Vec<T>`].
//!
//! For portability and consistency between architectures,
//! the length of the vector must fit within a [u32].

use crate::{BufsMut, EncodeSize, Error, RangeCfg, Read, Write};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::{Buf, BufMut};

impl<T: Write> Write for Vec<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.as_slice().write(buf)
    }

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.as_slice().write_bufs(buf)
    }
}

impl<T: EncodeSize> EncodeSize for Vec<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        self.as_slice().encode_size()
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.as_slice().encode_inline_size()
    }
}

impl<T: Write> Write for &[T] {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);
        T::write_slice(self, buf);
    }

    #[inline]
    fn write_bufs(&self, buf: &mut impl BufsMut) {
        self.len().write(buf);
        T::write_slice_bufs(self, buf);
    }
}

impl<T: EncodeSize> EncodeSize for &[T] {
    #[inline]
    fn encode_size(&self) -> usize {
        self.len().encode_size() + T::encode_size_slice(self)
    }

    #[inline]
    fn encode_inline_size(&self) -> usize {
        self.len().encode_size() + T::encode_inline_size_slice(self)
    }
}

impl<T: Read> Read for Vec<T> {
    type Cfg = (RangeCfg<usize>, T::Cfg);

    #[inline]
    fn read_cfg(buf: &mut impl Buf, (range, cfg): &Self::Cfg) -> Result<Self, Error> {
        let len = usize::read_cfg(buf, range)?;
        T::read_vec(buf, len, cfg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::tests::{Byte, TrackingReadBuf, TrackingWriteBuf},
        DecodeRangeExt, Encode,
    };
    use bytes::{Bytes, BytesMut};

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

        // The length prefix advertises two payload bytes, but only one byte follows.
        assert!(matches!(
            Vec::<u8>::decode_range([0x02, 0x01].as_slice(), ..),
            Err(Error::EndOfBuffer)
        ));
        assert!(matches!(
            Vec::<Byte>::decode_range([0x02, 0x01].as_slice(), ..),
            Err(Error::EndOfBuffer)
        ));

        // The length prefix advertises two payload bytes, and one extra byte remains after
        // those two payload bytes are consumed.
        assert!(matches!(
            Vec::<u8>::decode_range([0x02, 0x01, 0x02, 0x03].as_slice(), ..),
            Err(Error::ExtraData(1))
        ));
        assert!(matches!(
            Vec::<Byte>::decode_range([0x02, 0x01, 0x02, 0x03].as_slice(), ..),
            Err(Error::ExtraData(1))
        ));
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
    fn test_specialization_selection() {
        // `Vec<u8>` writes the length prefix, then the payload in one bulk write.
        let mut buf = TrackingWriteBuf::new();
        vec![1u8, 2, 3].write(&mut buf);
        assert_eq!(buf.put_slice_calls, 1);
        assert_eq!(buf.put_u8_calls, 1);

        // Other one-byte element types keep the generic per-element path.
        let mut buf = TrackingWriteBuf::new();
        vec![Byte(1), Byte(2), Byte(3)].write(&mut buf);
        assert_eq!(buf.put_slice_calls, 0);
        assert_eq!(buf.put_u8_calls, 4);

        // Slices use the same bulk payload path as vectors.
        let values = [1u8, 2, 3];
        let mut buf = TrackingWriteBuf::new();
        values.as_slice().write(&mut buf);
        assert_eq!(buf.put_slice_calls, 1);
        assert_eq!(buf.put_u8_calls, 1);

        // Non-`u8` slices keep the generic per-element path.
        let values = [Byte(1), Byte(2), Byte(3)];
        let mut buf = TrackingWriteBuf::new();
        values.as_slice().write(&mut buf);
        assert_eq!(buf.put_slice_calls, 0);
        assert_eq!(buf.put_u8_calls, 4);

        // `write_bufs` mirrors `write` for byte vectors.
        let mut buf = TrackingWriteBuf::new();
        vec![1u8, 2, 3].write_bufs(&mut buf);
        assert_eq!(buf.put_slice_calls, 1);
        assert_eq!(buf.put_u8_calls, 1);

        // The `write_bufs` fallback remains element-by-element.
        let mut buf = TrackingWriteBuf::new();
        vec![Byte(1), Byte(2), Byte(3)].write_bufs(&mut buf);
        assert_eq!(buf.put_slice_calls, 0);
        assert_eq!(buf.put_u8_calls, 4);

        // `Vec<u8>` reads the length prefix, then bulk-copies the payload.
        let mut buf = TrackingReadBuf::new(&[0x03, 0x01, 0x02, 0x03]);
        let value = Vec::<u8>::read_cfg(&mut buf, &((..).into(), ())).unwrap();
        assert_eq!(value, vec![1, 2, 3]);
        assert_eq!(buf.copy_to_slice_calls, 1);
        assert_eq!(buf.get_u8_calls, 1);

        // Other element types still read one element at a time.
        let mut buf = TrackingReadBuf::new(&[0x03, 0x01, 0x02, 0x03]);
        let value = Vec::<Byte>::read_cfg(&mut buf, &((..).into(), ())).unwrap();
        assert_eq!(value, vec![Byte(1), Byte(2), Byte(3)]);
        assert_eq!(buf.copy_to_slice_calls, 0);
        assert_eq!(buf.get_u8_calls, 4);
    }

    #[test]
    fn test_write_bufs_equivalence() {
        fn assert_equivalent<T: Write>(value: &T) {
            let mut write = BytesMut::new();
            value.write(&mut write);

            let mut write_bufs = TrackingWriteBuf::new();
            value.write_bufs(&mut write_bufs);

            assert_eq!(write.freeze(), write_bufs.freeze());
        }

        assert_equivalent(&vec![1u8, 2, 3]);
        assert_equivalent(&vec![0x0102u16, 0x0304, 0x0506]);
        assert_equivalent(&vec![Byte(1), Byte(2), Byte(3)]);
        assert_equivalent(&vec![
            Bytes::from_static(&[1u8, 2, 3]),
            Bytes::from_static(&[4u8, 5, 6]),
        ]);

        let values = [1u8, 2, 3];
        assert_equivalent(&values.as_slice());

        let values = [0x0102u16, 0x0304, 0x0506];
        assert_equivalent(&values.as_slice());

        let values = [Byte(1), Byte(2), Byte(3)];
        assert_equivalent(&values.as_slice());

        let values = [
            Bytes::from_static(&[1u8, 2, 3]),
            Bytes::from_static(&[4u8, 5, 6]),
        ];
        assert_equivalent(&values.as_slice());
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

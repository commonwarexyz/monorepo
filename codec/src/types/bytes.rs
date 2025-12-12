//! Implementations of Codec for byte types.
//!
//! For portability and consistency between architectures,
//! the length of the [Bytes] must fit within a [u32].

use crate::{util::at_least, EncodeSize, Error, RangeCfg, Read, Write};
use bytes::{Buf, BufMut, Bytes};

impl Write for Bytes {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.len().write(buf);
        buf.put_slice(self);
    }
}

impl EncodeSize for Bytes {
    #[inline]
    fn encode_size(&self) -> usize {
        self.len().encode_size() + self.len()
    }
}

impl Read for Bytes {
    type Cfg = RangeCfg<usize>;

    #[inline]
    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, Error> {
        let len = usize::read_cfg(buf, range)?;
        at_least(buf, len)?;
        Ok(buf.copy_to_bytes(len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Decode, Encode};
    #[cfg(not(feature = "std"))]
    use alloc::vec;
    use bytes::Bytes;

    #[test]
    fn test_bytes() {
        let values = [
            Bytes::new(),
            Bytes::from_static(&[1, 2, 3]),
            Bytes::from(vec![0; 300]),
        ];
        for value in values {
            let encoded = value.encode();
            let len = value.len();

            // Valid decoding
            let decoded = Bytes::decode_cfg(encoded, &(len..=len).into()).unwrap();
            assert_eq!(value, decoded);

            // Failure for too long
            assert!(matches!(
                Bytes::decode_cfg(value.encode(), &(0..len).into()),
                Err(Error::InvalidLength(_))
            ));

            // Failure for too short
            assert!(matches!(
                Bytes::decode_cfg(value.encode(), &(len + 1..).into()),
                Err(Error::InvalidLength(_))
            ));
        }
    }

    #[test]
    fn test_conformity() {
        assert_eq!(Bytes::new().encode(), &[0x00][..]);
        assert_eq!(
            Bytes::from_static(b"hello").encode(),
            &[0x05, b'h', b'e', b'l', b'l', b'o'][..]
        );
        let long_bytes = Bytes::from(vec![0xAA; 150]);
        let mut expected = vec![0x96, 0x01]; // Varint for 150
        expected.extend_from_slice(&[0xAA; 150]);
        assert_eq!(long_bytes.encode(), expected.as_slice());
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use crate::conformance::CodecConformance;
        use arbitrary::Arbitrary;

        /// Newtype wrapper to implement Arbitrary for [super::Bytes].
        #[derive(Debug)]
        struct Bytes(super::Bytes);

        impl Write for Bytes {
            fn write(&self, buf: &mut impl BufMut) {
                self.0.write(buf);
            }
        }

        impl EncodeSize for Bytes {
            fn encode_size(&self) -> usize {
                self.0.encode_size()
            }
        }

        impl Read for Bytes {
            type Cfg = RangeCfg<usize>;

            fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
                Ok(Self(super::Bytes::read_cfg(buf, cfg)?))
            }
        }

        impl Arbitrary<'_> for Bytes {
            fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
                let len = u.arbitrary::<u8>()?;
                let bytes: Vec<u8> = u
                    .arbitrary_iter()?
                    .take(len as usize)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap();
                Ok(Self(super::Bytes::from(bytes)))
            }
        }

        commonware_conformance::conformance_tests! {
            CodecConformance<Bytes>
        }
    }
}

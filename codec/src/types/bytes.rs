//! Implementations of Codec for byte types.
//!
//! For portability and consistency between architectures,
//! the length of the [`Bytes`] must fit within a [`u32`].

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
    type Cfg = RangeCfg;

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
}

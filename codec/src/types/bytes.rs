//! Implementations of Codec for byte types.
//!
//! For portability and consistency between architectures,
//! the length of the [`Bytes`] must fit within a [`u32`].

use crate::{util::at_least, varint, EncodeSize, Error, RangeConfig, Read, Write};
use bytes::{Buf, BufMut, Bytes};

impl Write for Bytes {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        let len = u32::try_from(self.len()).expect("Bytes length exceeds u32");
        varint::write(len, buf);
        buf.put_slice(self);
    }
}

impl EncodeSize for Bytes {
    #[inline]
    fn encode_size(&self) -> usize {
        let len = u32::try_from(self.len()).expect("Bytes length exceeds u32");
        varint::size(len) + self.len()
    }
}

impl<R: RangeConfig> Read<&'static R> for Bytes {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, cfg: &R) -> Result<Self, Error> {
        let len32 = varint::read::<u32>(buf)?;
        let len = usize::try_from(len32).map_err(|_| Error::InvalidVarint)?;
        if !cfg.contains(&len) {
            return Err(Error::InvalidLength(len));
        }
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
            assert_eq!(
                encoded.len(),
                varint::size(value.len() as u64) + value.len()
            );
            let len = value.len();

            // Valid decoding
            let decoded = Bytes::decode_cfg(encoded, len..=len).unwrap();
            assert_eq!(value, decoded);

            // Failure for too long
            matches!(
                Bytes::decode_cfg(value.encode(), 0..len),
                Err(Error::InvalidLength(_))
            );

            // Failure for too short
            matches!(
                Bytes::decode_cfg(value.encode(), len + 1..),
                Err(Error::InvalidLength(_))
            );
        }
    }
}

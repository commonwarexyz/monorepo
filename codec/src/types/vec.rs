//! Codec implementation for [`Vec<T>`].
//!
//! For portability and consistency between architectures,
//! the length of the vector must fit within a [`u32`].

use crate::{varint, Config, EncodeSize, Error, Pair, RangeConfig, Read, Write};
use bytes::{Buf, BufMut};

impl<T: Write> Write for Vec<T> {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        let len = u32::try_from(self.len()).expect("Vec length exceeds u32");
        varint::write(len, buf);
        for item in self {
            item.write(buf);
        }
    }
}

impl<T: EncodeSize> EncodeSize for Vec<T> {
    #[inline]
    fn encode_size(&self) -> usize {
        let len = u32::try_from(self.len()).expect("Vec length exceeds u32");
        varint::size(len) + self.iter().map(EncodeSize::encode_size).sum::<usize>()
    }
}

impl<R: RangeConfig, C: Config, T: Read<C>> Read<Pair<&'static R, C>> for Vec<T> {
    #[inline]
    fn read_cfg(buf: &mut impl Buf, Pair(range, cfg): Pair<&'static R, C>) -> Result<Self, Error> {
        let len32 = varint::read::<u32>(buf)?;
        let len = usize::try_from(len32).map_err(|_| Error::InvalidVarint)?;
        if !range.contains(&len) {
            return Err(Error::InvalidLength(len));
        }
        let mut vec = Vec::with_capacity(len);
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

    #[test]
    fn test_vec() {
        let vec_values = [vec![], vec![1u8], vec![1u8, 2u8, 3u8]];
        for value in vec_values {
            let encoded = value.encode();
            assert_eq!(encoded.len(), value.len() * std::mem::size_of::<u8>() + 1);

            // Valid decoding
            let len = value.len();
            let decoded = Vec::<u8>::decode_range(encoded, &(len..=len)).unwrap();
            assert_eq!(value, decoded);

            // Failure for too long
            matches!(
                Vec::<u8>::decode_range(value.encode(), &(0..len)),
                Err(Error::InvalidLength(_))
            );

            // Failure for too short
            matches!(
                Vec::<u8>::decode_range(value.encode(), &(len + 1..)),
                Err(Error::InvalidLength(_))
            );
        }
    }
}

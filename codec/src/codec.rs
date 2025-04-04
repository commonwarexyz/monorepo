//! Core codec traits and implementations

use crate::error::Error;
use bytes::{Buf, BufMut, BytesMut};

/// Trait for types that can be encoded to and decoded from bytes
pub trait Codec<C>: Sized {
    /// Encodes this value to a writer.
    fn write(&self, buf: &mut impl BufMut);

    /// Returns the encoded length of this value.
    fn len_encoded(&self) -> usize;

    /// Encodes a value to bytes.
    fn encode(&self) -> BytesMut {
        let len = self.len_encoded();
        let mut buffer = BytesMut::with_capacity(len);
        self.write(&mut buffer);
        assert_eq!(buffer.len(), len);
        buffer
    }

    /// Reads a value from a buffer, returning an error if there is an error while reading.
    fn read(buf: &mut impl Buf, cfg: C) -> Result<Self, Error>;

    /// Decodes a value from a buffer.
    ///
    /// Returns an error if there is an error while decoding or if there is extra data remaining
    /// after decoding the value from the buffer.
    fn decode(mut buf: impl Buf, cfg: C) -> Result<Self, Error> {
        let result = Self::read(&mut buf, cfg)?;
        let remaining = buf.remaining();
        if remaining > 0 {
            return Err(Error::ExtraData(remaining));
        }
        Ok(result)
    }
}

/// Trait for types that have a fixed-length encoding
pub trait SizedCodec: Codec<()> {
    /// The encoded length of this value.
    const LEN_ENCODED: usize;

    /// Returns the encoded length of this value.
    ///
    /// Should not be overridden by implementations.
    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    /// Encodes a value to fixed-size bytes.
    fn encode_fixed<const N: usize>(&self) -> [u8; N] {
        // Ideally this is a compile-time check, but we can't do that in the current Rust version
        // without adding a new generic parameter to the trait.
        assert_eq!(
            N,
            Self::LEN_ENCODED,
            "Can't encode {} bytes into {} bytes",
            Self::LEN_ENCODED,
            N
        );

        let buf = self.encode();
        assert_eq!(buf.len(), N);
        let mut array = [0u8; N];
        array.copy_from_slice(&buf);
        array
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Codec, Error};
    use bytes::Bytes;

    #[test]
    fn test_insufficient_buffer() {
        let mut reader = Bytes::from_static(&[0x01, 0x02]);
        assert!(matches!(u32::read(&mut reader), Err(Error::EndOfBuffer)));
    }

    #[test]
    fn test_extra_data() {
        let encoded = Bytes::from_static(&[0x01, 0x02]);
        assert!(matches!(u8::decode(encoded), Err(Error::ExtraData(1))));
    }

    #[test]
    fn test_encode_fixed() {
        let value = 42u32;
        let encoded: [u8; 4] = value.encode_fixed();
        let decoded = u32::decode(Bytes::copy_from_slice(&encoded)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[should_panic(expected = "Can't encode 4 bytes into 5 bytes")]
    fn test_encode_fixed_panic() {
        let _: [u8; 5] = 42u32.encode_fixed();
    }
}

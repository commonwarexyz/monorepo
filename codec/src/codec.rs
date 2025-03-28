//! Core codec traits and implementations

use crate::error::Error;
use bytes::{Buf, BufMut, BytesMut};
use std::error::Error as StdError;

/// Trait for types that can be encoded to and decoded from bytes
pub trait Codec: Sized {
    /// Encodes this value to a writer.
    fn write<B: BufMut>(&self, buf: &mut B);

    /// Returns the encoded length of this value.
    fn len_encoded(&self) -> usize;

    /// Encodes a value to bytes.
    fn encode(&self) -> BytesMut {
        let len = self.len_encoded();
        let mut buffer = BytesMut::with_capacity(len);
        self.write(&mut buffer);
        assert!(buffer.len() == len);
        buffer
    }

    /// Reads a value from a buffer, returning an error if there is an error while reading.
    fn read<B: Buf>(buf: &mut B) -> Result<Self, Error>;

    /// Decodes a value from a buffer.
    ///
    /// Returns an error if there is an error while decoding or if there is extra data remaining
    /// after decoding the value from the buffer.
    fn decode<B: Buf>(buf: impl Into<B>) -> Result<Self, Error> {
        let mut reader: B = buf.into();
        let result = Self::read(&mut reader);
        let remaining = reader.remaining();
        if remaining > 0 {
            return Err(Error::ExtraData(remaining));
        }
        result
    }
}

/// Trait for types that have a fixed-length encoding
pub trait SizedCodec: Codec {
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

pub trait SliceCodec: SizedCodec + for<'a> TryFrom<&'a [u8], Error: StdError> {
    /// Reads a value from a slice, returning an error if there is an error while reading.
    fn read_from_slice<B: Buf>(buf: &mut B) -> Result<Self, Error> {
        let len = Self::LEN_ENCODED;
        if buf.remaining() < len {
            return Err(Error::EndOfBuffer);
        }

        let chunk = buf.chunk();
        if chunk.len() >= len {
            let array = Self::try_from(&chunk[..len])
                .map_err(|err| Error::Wrapped("Decode", err.to_string().into()))?;

            buf.advance(len);
            return Ok(array);
        }

        let mut temp = vec![0u8; len];
        buf.copy_to_slice(&mut temp);
        buf.advance(len);
        let res = Self::try_from(temp.as_slice())
            .map_err(|err| Error::Wrapped("Decode", err.to_string().into()))?;
        Ok(res)
    }
}

/// Blanket implementation for all types that implement [`SizedCodec`] and `TryFrom<&[u8]>`.
impl<T> SliceCodec for T where T: SizedCodec + for<'a> TryFrom<&'a [u8], Error: StdError> {}

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
        assert!(matches!(
            u8::decode::<Bytes>(encoded),
            Err(Error::ExtraData(1))
        ));
    }

    #[test]
    fn test_encode_fixed() {
        let value = 42u32;
        let encoded: [u8; 4] = value.encode_fixed();
        let decoded = u32::decode::<Bytes>(Bytes::copy_from_slice(&encoded)).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[should_panic(expected = "Can't encode 4 bytes into 5 bytes")]
    fn test_encode_fixed_panic() {
        let _: [u8; 5] = 42u32.encode_fixed();
    }
}

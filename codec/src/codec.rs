//! Core codec traits and implementations

use crate::error::Error;
use bytes::{Buf, BufMut, BytesMut};

/// Trait for types that know their encoded length and can be written to a buffer.
pub trait Encode {
    /// Returns the encoded length of this value.
    fn len_encoded(&self) -> usize;

    /// Encodes this value by writing to a buffer.
    ///
    /// Implementers MUST write exactly `len_encoded()` bytes.
    fn write(&self, buf: &mut impl BufMut);

    /// Encodes a value to a `BytesMut` buffer.
    ///
    /// (Provided method).
    fn encode(&self) -> BytesMut {
        let len = self.len_encoded();
        let mut buffer = BytesMut::with_capacity(len);
        self.write(&mut buffer);
        assert_eq!(
            buffer.len(),
            len,
            "write() did not write expected len_encoded() bytes"
        );
        buffer
    }
}

/// Trait for types that can be read/decoded from a buffer.
pub trait Decode<C>: Sized {
    /// Reads a value from the buffer, consuming the necessary bytes.
    /// Returns an error if decoding fails (e.g., invalid data, not enough bytes initially).
    fn read(buf: &mut impl Buf, cfg: C) -> Result<Self, Error>;

    /// Decodes a value from a buffer, ensuring the buffer is fully consumed.
    ///
    /// (Provided method).
    fn decode<B: Buf>(mut buf: B, cfg: C) -> Result<Self, Error> {
        let result = Self::read(&mut buf, cfg)?;
        let remaining = buf.remaining();
        if remaining > 0 {
            return Err(Error::ExtraData(remaining));
        }
        Ok(result)
    }
}

/// Trait for types that can be encoded and decoded.
pub trait Codec<C>: Encode + Decode<C> {}

/// Trait for types with a known, fixed encoded length.
pub trait SizedInfo {
    const LEN_ENCODED: usize;
}

/// Trait for types that can be encoded to a fixed-size byte array.
pub trait SizedEncode: Encode + SizedInfo {
    /// Returns the encoded length of this value.
    ///
    /// (Provided method. Overrides [`Encode::len_encoded`]).
    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }

    /// Encodes a value to a fixed-size byte array.
    ///
    /// (Provided method).
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

        let mut array = [0u8; N];
        let mut buf = &mut array[..];
        self.write(&mut buf);
        assert_eq!(buf.len(), 0);
        array
    }
}

/// Trait for types that can be decoded from a buffer with a fixed size.
pub trait SizedDecode<C>: Decode<C> + SizedInfo {
    /// Decodes a value from a buffer, ensuring exactly LEN_ENCODED bytes are consumed.
    ///
    /// (Provided method. Overrides [`Decode::decode`]).
    fn decode<B: Buf>(mut buf: B, cfg: C) -> Result<Self, Error> {
        // Before doing work, check that the buffer has exactly the expected size.
        if buf.remaining() < Self::LEN_ENCODED {
            return Err(Error::EndOfBuffer);
        }
        if buf.remaining() > Self::LEN_ENCODED {
            return Err(Error::ExtraData(buf.remaining() - Self::LEN_ENCODED));
        }

        // Read the value from the buffer.
        let result = Self::read(&mut buf, cfg)?;
        assert!(
            !buf.has_remaining(),
            "Read() did not consume the expected number of bytes"
        );
        Ok(result)
    }
}

/// Trait for types that are both encodable and decodable with a fixed size.
pub trait SizedCodec<C>: SizedEncode + SizedDecode<C> + SizedInfo {}

// Blanket implementations.
impl<C, T: Encode + Decode<C>> Codec<C> for T {}
impl<T: Encode + SizedInfo> SizedEncode for T {}
impl<C, T: Decode<C> + SizedInfo> SizedDecode<C> for T {}
impl<C, T: SizedEncode + SizedDecode<C>> SizedCodec<C> for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
    use bytes::Bytes;

    #[test]
    fn test_insufficient_buffer() {
        let mut reader = Bytes::from_static(&[0x01, 0x02]);
        assert!(matches!(
            u32::read(&mut reader, ()),
            Err(Error::EndOfBuffer)
        ));
    }

    #[test]
    fn test_extra_data() {
        let encoded = Bytes::from_static(&[0x01, 0x02]);
        assert!(matches!(
            <u8 as Decode<()>>::decode(encoded, ()),
            Err(Error::ExtraData(1))
        ));
    }

    #[test]
    fn test_encode_fixed() {
        let value = 42u32;
        let encoded: [u8; 4] = value.encode_fixed();
        let decoded =
            <u32 as SizedDecode<()>>::decode(Bytes::copy_from_slice(&encoded), ()).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[should_panic(expected = "Can't encode 4 bytes into 5 bytes")]
    fn test_encode_fixed_panic() {
        let _: [u8; 5] = 42u32.encode_fixed();
    }
}

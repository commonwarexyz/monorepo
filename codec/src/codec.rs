//! Core codec traits and implementations

use crate::error::Error;
use bytes::{Buf, BufMut, BytesMut};
use std::ops::RangeBounds;

/// Trait for types that can be used as configuration during decoding.
pub trait Config: Clone + Send + 'static {}

// Automatically implement `Config` for matching types.
impl<T: Clone + Send + 'static> Config for T {}

/// A trait for a `Config` type that is also a `RangeBounds<usize>`.
pub trait RangeConfig: Config + RangeBounds<usize> {}

// Automatically implement `RangeConfig` for matching types.
impl<T: Config + RangeBounds<usize>> RangeConfig for T {}

/// Trait for types that can be written (encoded) to a buffer.
pub trait Write {
    /// Encodes this value by writing to a buffer.
    ///
    /// Implementations should panic if the buffer doesn't have enough capacity.
    fn write(&self, buf: &mut impl BufMut);
}

/// Trait for types that can be read/decoded from a buffer.
///
/// The `Cfg` type parameter allows for configuration during the read process. For example, it can
/// be used to limit the maximum size of allocated buffers for safety when decoding untrusted data.
/// Use `()` for types that do not require configuration.
pub trait Read<Cfg: Config = ()>: Sized {
    /// Reads a value from the buffer using the provided configuration `cfg`, consuming the
    /// necessary bytes.
    ///
    /// Returns an error if decoding fails (e.g., invalid data, not enough bytes initially).
    fn read_cfg(buf: &mut impl Buf, cfg: Cfg) -> Result<Self, Error>;
}

/// Trait for types that can be encoded to a buffer.
pub trait Encode: Write {
    /// Returns the encoded length of this value.
    ///
    /// This method MUST return the exact number of bytes that will be written by `write()`.
    fn len_encoded(&self) -> usize;

    /// Encodes a value to a `BytesMut` buffer.
    ///
    /// Panics if the `write` implementation does not write the expected number of bytes.
    ///
    /// (Provided method).
    fn encode(&self) -> BytesMut {
        let len = self.len_encoded();
        let mut buffer = BytesMut::with_capacity(len);
        self.write(&mut buffer);
        assert_eq!(buffer.len(), len, "write() did not write expected bytes");
        buffer
    }
}

// Automatically implement `Encode` for types with a known size.
// Otherwise, the type must define its own `len_encoded()` method.
impl<T: EncodeFixed> Encode for T {
    fn len_encoded(&self) -> usize {
        Self::LEN_ENCODED
    }
}

/// Trait for types that can be decoded from a buffer, ensuring the entire buffer is consumed.
pub trait Decode<Cfg: Config = ()>: Read<Cfg> {
    /// Decodes a value from a buffer, ensuring the buffer is fully consumed.
    ///
    /// (Provided method).
    fn decode_cfg(mut buf: impl Buf, cfg: Cfg) -> Result<Self, Error> {
        let result = Self::read_cfg(&mut buf, cfg)?;

        // Check that the buffer is fully consumed.
        let remaining = buf.remaining();
        if remaining > 0 {
            return Err(Error::ExtraData(remaining));
        }

        Ok(result)
    }
}

// Automatically implement `Decode` for types that implement `Read`.
impl<Cfg: Config, T: Read<Cfg>> Decode<Cfg> for T {}

/// Trait for types that can be encoded and decoded.
pub trait Codec<Cfg: Config = ()>: Encode + Decode<Cfg> {}

/// Automatically implement `Codec` for types that implement `Encode` and `Decode`.
impl<Cfg: Config, T: Encode + Decode<Cfg>> Codec<Cfg> for T {}

/// Trait for types with a known, fixed encoded length.
pub trait FixedSize {
    /// The length of the encoded value.
    const LEN_ENCODED: usize;
}

/// Trait for types that can be encoded to a fixed-size byte array.
pub trait EncodeFixed: Write + FixedSize {
    /// Encodes a value to a fixed-size byte array.
    ///
    /// The caller MUST ensure `N` is equal to `Self::LEN_ENCODED`.
    /// Panics if the `write` implementation does not write exactly `N` bytes.
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

// Automatically implement `EncodeFixed` for types that implement `Write` and `FixedSize`.
impl<T: Write + FixedSize> EncodeFixed for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        extensions::{DecodeExt, ReadExt},
        Error,
    };
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
        let decoded = <u32>::decode(&encoded[..]).unwrap();
        assert_eq!(value, decoded);
    }

    #[test]
    #[should_panic(expected = "Can't encode 4 bytes into 5 bytes")]
    fn test_encode_fixed_panic() {
        let _: [u8; 5] = 42u32.encode_fixed();
    }
}

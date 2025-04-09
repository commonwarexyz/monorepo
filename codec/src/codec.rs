//! Core codec traits and implementations

use crate::error::Error;
use bytes::{Buf, BufMut, BytesMut};

/// Trait for all types. By default, types have no size information.
pub trait Size {
    /// The length of the encoded value.
    ///
    /// Should be left as `None` for types that do not have a fixed size.
    const FIXED_SIZE: Option<usize> = None;
}

impl<T> Size for T {}

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
pub trait Read<Cfg = ()>: Sized {
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
pub trait Decode<Cfg = ()>: Read<Cfg> + Size {
    /// Decodes a value from a buffer, ensuring the buffer is fully consumed.
    ///
    /// For types with a known size, this method first checks that the buffer has the expected size.
    ///
    /// (Provided method).
    fn decode_cfg(mut buf: impl Buf, cfg: Cfg) -> Result<Self, Error> {
        // If we can, before reading, check that the buffer has the expected size.
        if let Some(size) = Self::FIXED_SIZE {
            if buf.remaining() < size {
                return Err(Error::EndOfBuffer);
            }
            if buf.remaining() > size {
                return Err(Error::ExtraData(buf.remaining() - size));
            }
        }

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
impl<Cfg, T: Read<Cfg>> Decode<Cfg> for T {}

/// Trait for types that can be encoded and decoded.
pub trait Codec<Cfg = ()>: Encode + Decode<Cfg> {}

/// Automatically implement `Codec` for types that implement `Encode` and `Decode`.
impl<Cfg, T: Encode + Decode<Cfg>> Codec<Cfg> for T {}

/// Trait for types with a known, fixed encoded length.
pub trait FixedSize: Size {
    /// The length of the encoded value.
    const LEN_ENCODED: usize;

    /// Overwrites [`Size::FIXED_SIZE`] with the encoded length.
    const FIXED_SIZE: Option<usize> = Some(Self::LEN_ENCODED);
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

/// Extension trait providing an ergonomic read method for types requiring no configuration.
pub trait ReadExt: Read<()> {
    /// Reads a value using the default `()` config.
    fn read(buf: &mut impl Buf) -> Result<Self, Error> {
        <Self as Read<()>>::read_cfg(buf, ())
    }
}

// Automatically implement `ReadExt` for types that implement `Read` with no config.
impl<T: Read<()>> ReadExt for T {}

/// Extension trait providing ergonomic decode method for types requiring no configuration.
pub trait DecodeExt: Decode<()> {
    /// Decodes a value using the default `()` config.
    fn decode(buf: impl Buf) -> Result<Self, Error> {
        <Self as Decode<()>>::decode_cfg(buf, ())
    }
}

// Automatically implement `DecodeExt` for types that implement `Decode` with no config.
impl<T: Decode<()>> DecodeExt for T {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Error;
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

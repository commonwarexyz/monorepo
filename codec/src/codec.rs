//! Core traits for encoding and decoding.

use crate::error::Error;
use bytes::{Buf, BufMut, BytesMut};
use std::ops::RangeBounds;

/// Marker trait for types that can be used as configuration during decoding.
///
/// Configuration is primarily used with the [`Read`] trait to pass parameters (like size limits)
/// needed to safely decode untrusted data. Types implementing `Config` must also be
/// `Clone + Send + 'static`.
///
/// Use the unit type `()` if no configuration is required for a specific [`Read`] implementation.
pub trait Config: Clone + Send + 'static {}

// Automatically implement `Config` for matching types.
impl<T: Clone + Send + 'static> Config for T {}

/// A marker trait for a [`Config`] type that is also a [`RangeBounds<usize>`].
///
/// This is often used to configure length limits for variable-length collections like `Vec<T>` or
/// `Bytes`.
pub trait RangeConfig: Config + RangeBounds<usize> {}

// Automatically implement `RangeConfig` for matching types.
impl<T: Config + RangeBounds<usize>> RangeConfig for T {}

/// Trait for types with a known, fixed encoded size.
///
/// Implementing this trait signifies that the encoded representation of this type *always* has the
/// same byte length, regardless of the specific value.
///
/// This automatically provides an implementation of [`EncodeSize`].
pub trait FixedSize {
    /// The size of the encoded value (in bytes).
    const SIZE: usize;
}

/// Trait for types that can provide their encoded size in bytes.
///
/// This must be implemented by all encodable types. For types implementing [`FixedSize`], this
/// trait is implemented automatically. For variable-size types, this requires calculating the size
/// based on the value.
pub trait EncodeSize {
    /// Returns the encoded size of this value (in bytes).
    fn encode_size(&self) -> usize;
}

// Automatically implement `EncodeSize` for types that are `FixedSize`.
impl<T: FixedSize> EncodeSize for T {
    fn encode_size(&self) -> usize {
        Self::SIZE
    }
}

/// Trait for types that can be written (encoded) to a byte buffer.
pub trait Write {
    /// Writes the binary representation of `self` to the provided buffer `buf`.
    ///
    /// Implementations should panic if the buffer doesn't have enough capacity.
    fn write(&self, buf: &mut impl BufMut);
}

/// Trait for types that can be read (decoded) from a byte buffer.
///
/// The `Cfg` type parameter allows passing configuration during the read process. This is crucial
/// for safely decoding untrusted data, for example, by providing size limits for collections or
/// strings.
///
/// Use `Cfg = ()` if no configuration is needed for a specific type.
pub trait Read<Cfg: Config = ()>: Sized {
    /// Reads a value from the buffer using the provided configuration `cfg`.
    ///
    /// Implementations should consume the exact number of bytes required from `buf` to reconstruct
    /// the value.
    ///
    /// Returns [`Error`] if decoding fails due to invalid data, insufficient bytes in the buffer,
    /// or violation of constraints imposed by the `cfg`.
    fn read_cfg(buf: &mut impl Buf, cfg: &Cfg) -> Result<Self, Error>;
}

/// Trait combining [`Write`] and [`EncodeSize`] for types that can be fully encoded.
///
/// This trait provides the convenience [`encode`](Encode::encode) method which handles
/// buffer allocation, writing, and size assertion in one go.
pub trait Encode: Write + EncodeSize {
    /// Encodes `self` into a new [`BytesMut`] buffer.
    ///
    /// This method calculates the required size using [`EncodeSize::encode_size`], allocates a
    /// buffer of that exact capacity, writes the value using [`Write::write`], and performs a
    /// sanity check assertion.
    ///
    /// Panics if `encode_size()` does not return the same number of bytes actually written by
    /// `write()`
    fn encode(&self) -> BytesMut {
        let len = self.encode_size();
        let mut buffer = BytesMut::with_capacity(len);
        self.write(&mut buffer);
        assert_eq!(buffer.len(), len, "write() did not write expected bytes");
        buffer
    }
}

// Automatically implement `Encode` for types that implement `Write` and `EncodeSize`.
impl<T: Write + EncodeSize> Encode for T {}

/// Trait combining [`Read<Cfg>`] with a check for remaining bytes.
///
/// Ensures that *all* bytes from the input buffer were consumed during decoding.
pub trait Decode<Cfg: Config = ()>: Read<Cfg> {
    /// Decodes a value from `buf` using `cfg`, ensuring the entire buffer is consumed.
    ///
    /// Returns [`Error`] if decoding fails via [`Read::read_cfg`] or if there are leftover bytes in
    /// `buf` after reading.
    fn decode_cfg(mut buf: impl Buf, cfg: &Cfg) -> Result<Self, Error> {
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

/// Convenience trait combining [`Encode`] and [`Decode<Cfg>`].
///
/// Represents types that can be both fully encoded and decoded.
pub trait Codec<Cfg: Config = ()>: Encode + Decode<Cfg> {}

/// Automatically implement `Codec` for types that implement `Encode` and `Decode`.
impl<Cfg: Config, T: Encode + Decode<Cfg>> Codec<Cfg> for T {}

/// Convenience trait for [`FixedSize`] types that can be encoded directly into a fixed-size array.
pub trait EncodeFixed: Write + FixedSize {
    /// Encodes `self` into a fixed-size byte array `[u8; N]`.
    ///
    /// `N` **must** be equal to `<Self as FixedSize>::SIZE`.
    /// Panics if `N` is not equal to `<Self as FixedSize>::SIZE`.
    /// Also panics if the `write()` implementation does not write exactly `N` bytes.
    fn encode_fixed<const N: usize>(&self) -> [u8; N] {
        // Ideally this is a compile-time check, but we can't do that in the current Rust version
        // without adding a new generic parameter to the trait.
        assert_eq!(
            N,
            Self::SIZE,
            "Can't encode {} bytes into {} bytes",
            Self::SIZE,
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

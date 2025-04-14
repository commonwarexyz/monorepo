//! Extension traits for ergonomic operations on encoding and decoding.
//!
//! These traits provide convenience methods (like `read()`, `decode()`, `read_range()`, and
//! `decode_range()`) that simplify common use cases of the core [`Read`] and [`Decode`] traits,
//! particularly when default configurations (`()`) or [`RangeConfig`] are involved.

use crate::{Config, Decode, Error, RangeConfig, Read};
use bytes::Buf;

/// Extension trait providing ergonomic read method for types requiring no configuration
/// (i.e. `Cfg = ()`).
///
/// Import this trait to use the `.read(buf)` method as a shorthand for `.read_cfg(buf, ())`.
pub trait ReadExt: Read<()> {
    /// Reads a value using the default `()` config.
    fn read(buf: &mut impl Buf) -> Result<Self, Error> {
        <Self as Read<()>>::read_cfg(buf, ())
    }
}

// Automatically implement `ReadExt` for types that implement `Read` with no config.
impl<T: Read<()>> ReadExt for T {}

/// Extension trait providing ergonomic decode method for types requiring no configuration
/// (i.e. `Cfg = ()`).
///
/// Import this trait to use the `.decode(buf)` method as a shorthand for `.decode_cfg(buf, ())`.
pub trait DecodeExt: Decode<()> {
    /// Decodes a value using the default `()` config.
    fn decode(buf: impl Buf) -> Result<Self, Error> {
        <Self as Decode<()>>::decode_cfg(buf, ())
    }
}

// Automatically implement `DecodeExt` for types that implement `Decode` with no config.
impl<T: Decode<()>> DecodeExt for T {}

/// Extension trait for reading types whose config is `(RangeConfig, T)` where `T` is a unit type
/// (a type of one possible value, such as `()` or `((), ())`).
///
/// Useful for reading collections like `Vec<T>` where `T` implements `Read<()>`.
/// Import this trait to use the `.read_range()` method.
pub trait ReadRangeExt<R: RangeConfig, RR: Config + From<R>>: Read<RR> {
    /// Reads a value using only a range configuration.
    /// Assumes the inner configuration is a unit type.
    fn read_range(buf: &mut impl Buf, range: R) -> Result<Self, Error> {
        Self::read_cfg(buf, RR::from(range))
    }
}

// Blanket implementation
impl<R: RangeConfig, RR: Config + From<R>, U: Read<RR>> ReadRangeExt<R, RR> for U {}

pub trait DecodeRangeExt<R: RangeConfig, RR: Config + From<R>>: Decode<RR> {
    /// Decodes a value using only a range configuration.
    /// Assumes the inner configuration is a unit type.
    fn decode_range(buf: impl Buf, range: R) -> Result<Self, Error> {
        Self::decode_cfg(buf, RR::from(range))
    }
}

// Blanket implementation
impl<R: RangeConfig, RR: Config + From<R>, U: Decode<RR>> DecodeRangeExt<R, RR> for U {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Encode, ReadRangeExt};
    use bytes::Bytes;
    use std::ops::RangeTo;

    #[test]
    fn test_read_ext() {
        let original: u64 = 1234;
        let mut encoded = original.encode();
        let result = u64::read(&mut encoded).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decode_ext() {
        let original: u64 = 1234;
        let encoded = original.encode();
        let result = u64::decode(encoded).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_decode_range_ext() {
        let original = vec![1, 2, 3, 4, 5];
        let mut encoded = original.encode();
        let result = Vec::<i32>::read_range(&mut encoded, ..12usize).unwrap();
        assert_eq!(result, original);

        let original = Bytes::from_static(b"hello");
        let mut encoded = original.encode();
        let range: RangeTo<usize> = ..12;
        let result = Bytes::read_range(&mut encoded, range).unwrap();
        assert_eq!(result, original);
    }
}

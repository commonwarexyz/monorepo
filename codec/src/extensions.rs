//! Extension traits for ergonomic operations on encoding and decoding.
//!
//! These traits provide convenience methods (like `read()`, `decode()`, `read_range()`, and
//! `decode_range()`) that simplify common use cases of the core [`Read`] and [`Decode`] traits,
//! particularly when default configurations (`()`) or [`RangeConfig`] are involved.

use crate::{Decode, Error, RangeConfig, Read};
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

/// Extension trait for reading types whose config is `(RangeConfig, ())`,
/// i.e., requiring a range but no specific inner configuration.
///
/// Useful for reading collections like `Vec<T>` where `T` implements `Read<()>`.
/// Import this trait to use the `.read_range()` method.
pub trait ReadRangeExt<R: RangeConfig>: Read<(R, ())> {
    /// Reads a value using only a range configuration, assuming the inner config is `()`.
    fn read_range(buf: &mut impl Buf, range: R) -> Result<Self, Error> {
        Self::read_cfg(buf, (range, ()))
    }
}

// Automatically implement `ReadRangeExt` for types that implement `Read` with a range and no config.
impl<R: RangeConfig, T: Read<(R, ())>> ReadRangeExt<R> for T {}

/// Extension trait for decoding types whose config is `(RangeConfig, ())`,
/// i.e., requiring a range but no specific inner configuration, ensuring the buffer is consumed.
///
/// Useful for decoding collections like `Vec<T>` where `T` implements `Read<()>`.
/// Import this trait to use the `.decode_range()` method.
pub trait DecodeRangeExt<R: RangeConfig>: Decode<(R, ())> {
    fn decode_range(buf: impl Buf, range: R) -> Result<Self, Error> {
        Self::decode_cfg(buf, (range, ()))
    }
}

// Automatically implement `DecodeRangeExt` for types that implement `Decode` with a range and no config.
impl<R: RangeConfig, T: Decode<(R, ())>> DecodeRangeExt<R> for T {}

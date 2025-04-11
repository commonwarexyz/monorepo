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
        <Self as Read<()>>::read_cfg(buf, &())
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
        <Self as Decode<()>>::decode_cfg(buf, &())
    }
}

// Automatically implement `DecodeExt` for types that implement `Decode` with no config.
impl<T: Decode<()>> DecodeExt for T {}

/// Extension trait for reading types whose config is `(RangeConfig, T)`,
/// i.e., requiring a range but no specific inner configuration.
///
/// Useful for reading collections like `Vec<T>` where `T` implements `Read<()>`.
/// Import this trait to use the `.read_range()` method.
pub trait ReadRangeExt<T: Config + Default, R: RangeConfig>: Read<(R, T)> {
    /// Reads a value using only a range configuration, assuming the inner config is `()`.
    fn read_range(buf: &mut impl Buf, range: R) -> Result<Self, Error> {
        Self::read_cfg(buf, &(range, T::default()))
    }
}

// Blanket implementation ONLY for T = ()
// Applies to types like Vec<U> where U: Read<()>
impl<R: RangeConfig, U: Read<(R, ())>> ReadRangeExt<(), R> for U {}

// Blanket implementation ONLY for T = ((), ())
// Applies to types like HashMap<K, V> where K: Read<()>, V: Read<()>
impl<R: RangeConfig, U: Read<(R, ((), ()))>> ReadRangeExt<((), ()), R> for U {}

/// Extension trait for decoding types whose config is `(RangeConfig, T)`,
/// i.e., requiring a range but no specific inner configuration, ensuring the buffer is consumed.
///
/// Useful for decoding collections like `Vec<T>` where `T` implements `Read<()>`.
/// Import this trait to use the `.decode_range()` method.
pub trait DecodeRangeExt<T: Config + Default, R: RangeConfig>: Decode<(R, T)> {
    fn decode_range(buf: impl Buf, range: R) -> Result<Self, Error> {
        Self::decode_cfg(buf, &(range, T::default()))
    }
}

// Blanket implementation ONLY for T = ()
impl<R: RangeConfig, U: Decode<(R, ())>> DecodeRangeExt<(), R> for U {}

// Blanket implementation ONLY for T = ((), ())
impl<R: RangeConfig, U: Decode<(R, ((), ()))>> DecodeRangeExt<((), ()), R> for U {}

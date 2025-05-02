//! Extension traits for ergonomic operations on encoding and decoding.
//!
//! These traits provide convenience methods (like `read()`, `decode()`, `read_range()`, and
//! `decode_range()`) that simplify common use cases of the core [`Read`] and [`Decode`] traits,
//! particularly when default configurations (`()`) or [`RangeCfg`] are involved.

use crate::{Decode, Error, RangeCfg, Read};
use bytes::Buf;

/// Extension trait providing ergonomic read method for types requiring no configuration
/// (i.e. `Cfg = ()`).
///
/// Import this trait to use the `.read(buf)` method as a shorthand for `.read_cfg(buf, ())`.
pub trait ReadExt: Read<Cfg = ()> {
    /// Reads a value using the default `()` config.
    fn read(buf: &mut impl Buf) -> Result<Self, Error> {
        Self::read_cfg(buf, &())
    }
}

// Automatically implement `ReadExt` for types that implement `Read` with no config.
impl<T: Read<Cfg = ()>> ReadExt for T {}

/// Extension trait providing ergonomic decode method for types requiring no specific configuration.
///
/// Import this trait to use the `.decode(buf)` method as a shorthand for `.decode_cfg(buf, ())`.
pub trait DecodeExt<X: Default>: Decode<Cfg = X> {
    /// Decodes a value using the default `()` config.
    fn decode(buf: impl Buf) -> Result<Self, Error> {
        Self::decode_cfg(buf, &X::default())
    }
}

// Automatically implement `DecodeExt` for types that implement `Decode` with no config.
impl<X: Default, T: Decode<Cfg = X>> DecodeExt<X> for T {}

/// Extension trait for reading types whose config is `(RangeCfg, X)` where `X` is [`Default`].
///
/// Useful for reading collections like [`Vec<T>`] where `T` implements [`Read`] with no specific
/// configuration. Import this trait to use the `.read_range()` method.
pub trait ReadRangeExt<X: Default>: Read<Cfg = (RangeCfg, X)> {
    /// Reads a value using only a range configuration.
    ///
    /// The inner configuration type `X` must be [`Default`] and `X::default()` is used for it.
    fn read_range(buf: &mut impl Buf, range: impl Into<RangeCfg>) -> Result<Self, Error> {
        Self::read_cfg(buf, &(range.into(), X::default()))
    }
}

// Automatically implement `ReadRangeExt` for types that implement `Read` with config
// `(RangeCfg, X)`, where `X` is `Default`.
impl<X: Default, U: Read<Cfg = (RangeCfg, X)>> ReadRangeExt<X> for U {}

/// Extension trait for reading types whose config is `(RangeCfg, X)` where `X` is [`Default`],
/// ensuring the buffer is consumed.
///
/// Useful for decoding collections like [`Vec<T>`] where `T` implements [`Read`] with no specific
/// configuration. Import this trait to use the `.decode_range()` method.
pub trait DecodeRangeExt<X: Default>: Decode<Cfg = (RangeCfg, X)> {
    /// Decodes a value using only a range configuration.
    ///
    /// The inner configuration type `X` must be [`Default`] and `X::default()` is used for it.
    fn decode_range(buf: impl Buf, range: impl Into<RangeCfg>) -> Result<Self, Error> {
        Self::decode_cfg(buf, &(range.into(), X::default()))
    }
}

// Automatically implement `DecodeRangeExt` for types that implement `Decode` with config
// `(RangeCfg, X)`, where `X` has a default implementation.
impl<X: Default, U: Decode<Cfg = (RangeCfg, X)>> DecodeRangeExt<X> for U {}

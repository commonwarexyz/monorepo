//! Extension traits for ergonomic operations on encoding and decoding.
//!
//! These traits provide convenience methods (like `read()`, `decode()`, `read_range()`, and
//! `decode_range()`) that simplify common use cases of the core [Read] and [Decode] traits,
//! particularly when default configurations (`()`) or [RangeCfg] are involved.

use crate::{Decode, DecodeRef, Error, RangeCfg, Read, ReadRef};
use bytes::Buf;
use core::ops::RangeBounds;

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

/// Trait for types that are unit-like, i.e. have only one possible value.
///
/// This is typically used to implement the `DefaultExt` trait for types that are unit-like.
pub trait IsUnit: Default {}

// Generate `IsUnit` implementations for types with only one possible value.
impl IsUnit for () {}
impl<T: IsUnit, const N: usize> IsUnit for [T; N] where [T; N]: Default {}

// Generate `IsUnit` implementations for `IsUnit` tuples up to 12 elements.
macro_rules! impl_is_unit_for_tuple {
    ( $($T:ident),+ ) => {
        impl<$($T),+> IsUnit for ( $($T),+ ) where $($T: IsUnit),+ {}
    }
}
impl_is_unit_for_tuple!(A, B);
impl_is_unit_for_tuple!(A, B, C);
impl_is_unit_for_tuple!(A, B, C, D);
impl_is_unit_for_tuple!(A, B, C, D, E);
impl_is_unit_for_tuple!(A, B, C, D, E, F);
impl_is_unit_for_tuple!(A, B, C, D, E, F, G);
impl_is_unit_for_tuple!(A, B, C, D, E, F, G, H);
impl_is_unit_for_tuple!(A, B, C, D, E, F, G, H, I);
impl_is_unit_for_tuple!(A, B, C, D, E, F, G, H, I, J);
impl_is_unit_for_tuple!(A, B, C, D, E, F, G, H, I, J, K);
impl_is_unit_for_tuple!(A, B, C, D, E, F, G, H, I, J, K, L);

/// Extension trait providing ergonomic decode method for types requiring no specific configuration.
/// This is typically types with only one possible value, such as the unit type `()` or tuples of
/// such types.
///
/// Import this trait to use the `.decode(buf)` method as a shorthand for
/// `.decode_cfg(buf, &X::default())`.
pub trait DecodeExt<X: IsUnit>: Decode<Cfg = X> {
    /// Decodes a value using the default `()` config.
    fn decode(buf: impl Buf) -> Result<Self, Error> {
        Self::decode_cfg(buf, &X::default())
    }
}

// Automatically implement `DecodeExt` for types that implement `Decode` with no config.
impl<X: IsUnit, T: Decode<Cfg = X>> DecodeExt<X> for T {}

/// Extension trait for reading types whose config is `(RangeCfg<usize>, X)` where `X` is [Default].
///
/// Useful for reading collections like [`Vec<T>`] where `T` implements [Read] with no specific
/// configuration. Import this trait to use the `.read_range()` method.
pub trait ReadRangeExt<X: IsUnit>: Read<Cfg = (RangeCfg<usize>, X)> {
    /// Reads a value using only a range configuration.
    ///
    /// The inner configuration type `X` must be [IsUnit] and `X::default()` is used for it.
    fn read_range(buf: &mut impl Buf, range: impl RangeBounds<usize>) -> Result<Self, Error> {
        Self::read_cfg(buf, &(RangeCfg::new(range), X::default()))
    }
}

// Automatically implement `ReadRangeExt` for types that implement `Read` with config
// `(RangeCfg<usize>, X)`, where `X` is `IsUnit`.
impl<X: IsUnit, U: Read<Cfg = (RangeCfg<usize>, X)>> ReadRangeExt<X> for U {}

/// Extension trait for reading types whose config is `(RangeCfg<usize>, X)` where `X` is [IsUnit],
/// ensuring the buffer is consumed.
///
/// Useful for decoding collections like [`Vec<T>`] where `T` implements [Read] with no specific
/// configuration. Import this trait to use the `.decode_range()` method.
pub trait DecodeRangeExt<X: IsUnit>: Decode<Cfg = (RangeCfg<usize>, X)> {
    /// Decodes a value using only a range configuration.
    ///
    /// The inner configuration type `X` must be [IsUnit] and `X::default()` is used for it.
    fn decode_range(buf: impl Buf, range: impl RangeBounds<usize>) -> Result<Self, Error> {
        Self::decode_cfg(buf, &(RangeCfg::new(range), X::default()))
    }
}

// Automatically implement `DecodeRangeExt` for types that implement `Decode` with config
// `(RangeCfg<usize>, X)`, where `X` is `IsUnit`.
impl<X: IsUnit, U: Decode<Cfg = (RangeCfg<usize>, X)>> DecodeRangeExt<X> for U {}

/// Extension trait providing ergonomic zero-copy read method for types requiring no configuration
/// (i.e. `Cfg = ()`).
///
/// Import this trait to use the `.read_ref(buf)` method as a shorthand for
/// `.read_ref(buf, &())`.
pub trait ReadRefExt<'a>: ReadRef<'a, Cfg = ()> {
    /// Reads a value using the default `()` config (zero-copy).
    fn read_ref(buf: &mut &'a [u8]) -> Result<Self, Error> {
        <Self as ReadRef>::read_ref(buf, &())
    }
}

// Automatically implement `ReadRefExt` for types that implement `ReadRef` with no config.
impl<'a, T: ReadRef<'a, Cfg = ()>> ReadRefExt<'a> for T {}

/// Extension trait providing ergonomic zero-copy decode method for types requiring no specific
/// configuration.
///
/// Import this trait to use the `.decode_ref(buf)` method as a shorthand for
/// `.decode_ref(buf, &X::default())`.
pub trait DecodeRefExt<'a, X: IsUnit>: DecodeRef<'a, Cfg = X> {
    /// Decodes a value using the default config (zero-copy).
    fn decode_ref(buf: &'a [u8]) -> Result<Self, Error> {
        <Self as DecodeRef>::decode_ref(buf, &X::default())
    }
}

// Automatically implement `DecodeRefExt` for types that implement `DecodeRef` with unit-like config.
impl<'a, X: IsUnit, T: DecodeRef<'a, Cfg = X>> DecodeRefExt<'a, X> for T {}

/// Extension trait for zero-copy reading types whose config is `RangeCfg<usize>`.
///
/// Useful for reading byte slices (`&[u8]`) with length constraints.
/// Import this trait to use the `.read_ref_range()` method.
pub trait ReadRefRangeExt<'a>: ReadRef<'a, Cfg = RangeCfg<usize>> {
    /// Reads a value using only a range configuration (zero-copy).
    fn read_ref_range(buf: &mut &'a [u8], range: impl RangeBounds<usize>) -> Result<Self, Error> {
        <Self as ReadRef>::read_ref(buf, &RangeCfg::new(range))
    }
}

// Automatically implement `ReadRefRangeExt` for types with RangeCfg config.
impl<'a, T: ReadRef<'a, Cfg = RangeCfg<usize>>> ReadRefRangeExt<'a> for T {}

/// Extension trait for zero-copy decoding types whose config is `RangeCfg<usize>`,
/// ensuring the buffer is consumed.
///
/// Useful for decoding byte slices (`&[u8]`) with length constraints.
/// Import this trait to use the `.decode_ref_range()` method.
pub trait DecodeRefRangeExt<'a>: DecodeRef<'a, Cfg = RangeCfg<usize>> {
    /// Decodes a value using only a range configuration (zero-copy).
    fn decode_ref_range(buf: &'a [u8], range: impl RangeBounds<usize>) -> Result<Self, Error> {
        <Self as DecodeRef>::decode_ref(buf, &RangeCfg::new(range))
    }
}

// Automatically implement `DecodeRefRangeExt` for types with RangeCfg config.
impl<'a, T: DecodeRef<'a, Cfg = RangeCfg<usize>>> DecodeRefRangeExt<'a> for T {}

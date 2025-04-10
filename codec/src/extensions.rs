use crate::{Config, Decode, Error, RangeConfig, Read};
use bytes::Buf;

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

/// Extension trait for types that can read a range of items with a configuration.
pub trait ReadRangeCfgExt<R: RangeConfig, Cfg: Config>: Read<(R, Cfg)> {
    fn read_range_cfg(buf: &mut impl Buf, range: R, cfg: Cfg) -> Result<Self, Error> {
        Self::read_cfg(buf, (range, cfg))
    }
}

// Automatically implement `ReadRangeCfgExt` for types that implement `Read` with a range and config.
impl<R: RangeConfig, Cfg: Config, T: Read<(R, Cfg)>> ReadRangeCfgExt<R, Cfg> for T {}

/// Extension trait for types that can read a range of items without configuration.
pub trait ReadRangeExt<R: RangeConfig>: ReadRangeCfgExt<R, ()> {
    fn read_range(buf: &mut impl Buf, range: R) -> Result<Self, Error> {
        Self::read_range_cfg(buf, range, ())
    }
}

// Automatically implement `ReadRangeExt` for types that implement `Read` with a range and no config.
impl<R: RangeConfig, T: Read<(R, ())>> ReadRangeExt<R> for T {}

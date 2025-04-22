//! Provides wrappers of common types to allow for alternative implementations.

use crate::{varint, EncodeSize, Error, Read, Write};

pub struct VarU64(u64);
pub struct VarU32(u32);
pub struct VarU16(u16);
pub struct VarI64(i64);
pub struct VarI32(i32);
pub struct VarI16(i16);

impl Write for VarU64 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        varint::write::<u64>(self.0, buf);
    }
}

impl EncodeSize for VarU64 {
    fn encode_size(&self) -> usize {
        varint::size::<u64>(self.0)
    }
}

impl Read for VarU64 {
    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &()) -> Result<Self, Error> {
        Ok(Self(varint::read::<u64>(buf)?))
    }
}

impl Write for VarU32 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        varint::write::<u32>(self.0, buf);
    }
}

impl EncodeSize for VarU32 {
    fn encode_size(&self) -> usize {
        varint::size::<u32>(self.0)
    }
}

impl Read for VarU32 {
    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &()) -> Result<Self, Error> {
        Ok(Self(varint::read::<u32>(buf)?))
    }
}

impl Write for VarU16 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        varint::write::<u16>(self.0, buf);
    }
}

impl EncodeSize for VarU16 {
    fn encode_size(&self) -> usize {
        varint::size::<u16>(self.0)
    }
}

impl Read for VarU16 {
    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &()) -> Result<Self, Error> {
        Ok(Self(varint::read::<u16>(buf)?))
    }
}

impl Write for VarI64 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        varint::write_i64::<i64>(self.0, buf);
    }
}

impl EncodeSize for VarI64 {
    fn encode_size(&self) -> usize {
        varint::size_i64::<i64>(self.0)
    }
}

impl Read for VarI64 {
    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &()) -> Result<Self, Error> {
        Ok(Self(varint::read_i64::<i64>(buf)?))
    }
}

impl Write for VarI32 {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        varint::write_i64::<i32>(self.0, buf);
    }
}

impl EncodeSize for VarI32 {
    fn encode_size(&self) -> usize {
        varint::size_i64::<i32>(self.0)
    }
}

impl Read for VarI32 {
    fn read_cfg(buf: &mut impl bytes::Buf, _cfg: &()) -> Result<Self, Error> {
        Ok(Self(varint::read_i64::<i32>(buf)?))
    }
}

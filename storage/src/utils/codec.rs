//! Fixed-size retained bytes for checking storage decode ownership.

use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, Error, FixedSize, Read, Write, util::at_least};

#[derive(Clone, Debug)]
pub(crate) struct FixedByteView {
    pub(crate) bytes: Bytes,
    source: usize,
}

impl FixedByteView {
    pub(crate) fn new(value: u64) -> Self {
        Self {
            bytes: Bytes::copy_from_slice(&value.to_be_bytes()),
            source: 0,
        }
    }

    pub(crate) fn assert_shared(&self) {
        assert_eq!(self.bytes.as_ptr() as usize, self.source);
    }
}

impl FixedSize for FixedByteView {
    const SIZE: usize = u64::SIZE;
}

impl Write for FixedByteView {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.bytes);
    }
}

impl Read for FixedByteView {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        at_least(buf, Self::SIZE)?;
        let source = buf.chunk().as_ptr() as usize;
        Ok(Self {
            bytes: buf.copy_to_bytes(Self::SIZE),
            source,
        })
    }
}

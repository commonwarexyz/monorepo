//! Codec fixtures for checking storage encoding and decode ownership.

use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, Error, FixedSize, Read, Write, util::at_least};

/// Claims a fixed encoded size but writes the configured number of bytes.
pub(crate) struct MisreportedSize<const N: usize>(pub(crate) usize);

impl<const N: usize> FixedSize for MisreportedSize<N> {
    const SIZE: usize = N;
}

impl<const N: usize> Write for MisreportedSize<N> {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_bytes(0, self.0);
    }
}

impl<const N: usize> Read for MisreportedSize<N> {
    type Cfg = ();

    fn read_cfg(_: &mut impl Buf, _: &()) -> Result<Self, Error> {
        unreachable!("misreported encodings must not be persisted");
    }
}

/// A fixed-size byte view for checking shared decoding.
#[derive(Clone, Debug)]
pub(crate) struct View {
    pub(crate) bytes: Bytes,
    source: usize,
}

impl View {
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

impl FixedSize for View {
    const SIZE: usize = u64::SIZE;
}

impl Write for View {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(&self.bytes);
    }
}

impl Read for View {
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

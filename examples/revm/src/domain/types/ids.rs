use alloy_evm::revm::primitives::B256;
use bytes::{Buf, BufMut};
use commonware_codec::{Error as CodecError, FixedSize, Read, Write};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Block identifier (32 bytes).
pub struct BlockId(pub B256);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Transaction identifier (32 bytes).
pub struct TxId(pub B256);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// State commitment (32 bytes) computed from merkleized, non-durable QMDB partition roots.
pub struct StateRoot(pub B256);

impl FixedSize for BlockId {
    const SIZE: usize = 32;
}

impl FixedSize for TxId {
    const SIZE: usize = 32;
}

impl FixedSize for StateRoot {
    const SIZE: usize = 32;
}

pub(super) fn write_b256(value: &B256, buf: &mut impl BufMut) {
    buf.put_slice(value.as_slice());
}

pub(super) fn read_b256(buf: &mut impl Buf) -> Result<B256, CodecError> {
    if buf.remaining() < 32 {
        return Err(CodecError::EndOfBuffer);
    }
    let mut out = [0u8; 32];
    buf.copy_to_slice(&mut out);
    Ok(B256::from(out))
}

impl Write for BlockId {
    fn write(&self, buf: &mut impl BufMut) {
        write_b256(&self.0, buf);
    }
}

impl Read for BlockId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(read_b256(buf)?))
    }
}

impl Write for TxId {
    fn write(&self, buf: &mut impl BufMut) {
        write_b256(&self.0, buf);
    }
}

impl Read for TxId {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(read_b256(buf)?))
    }
}

impl Write for StateRoot {
    fn write(&self, buf: &mut impl BufMut) {
        write_b256(&self.0, buf);
    }
}

impl Read for StateRoot {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        Ok(Self(read_b256(buf)?))
    }
}

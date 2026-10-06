//! Shared fixtures for the codec benchmarks.

use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, EncodeSize, Error, FixedSize, RangeCfg, Read, ReadExt as _, Write};

/// A fixed-size transaction fixture for codec benchmarks.
#[derive(Clone)]
pub struct Tx {
    pub nonce: u64,
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub fee: u64,
    pub signature: [u8; 64],
}

impl Write for Tx {
    fn write(&self, buf: &mut impl BufMut) {
        self.nonce.write(buf);
        self.sender.write(buf);
        self.recipient.write(buf);
        self.amount.write(buf);
        self.fee.write(buf);
        self.signature.write(buf);
    }
}

impl FixedSize for Tx {
    const SIZE: usize = 3 * u64::SIZE + 2 * <[u8; 32]>::SIZE + <[u8; 64]>::SIZE;
}

impl Read for Tx {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            nonce: u64::read(buf)?,
            sender: <[u8; 32]>::read(buf)?,
            recipient: <[u8; 32]>::read(buf)?,
            amount: u64::read(buf)?,
            fee: u64::read(buf)?,
            signature: <[u8; 64]>::read(buf)?,
        })
    }
}

/// [Tx] plus a short retained memo.
#[derive(Clone)]
pub struct MemoTx {
    pub tx: Tx,
    pub memo: Bytes,
}

impl Write for MemoTx {
    fn write(&self, buf: &mut impl BufMut) {
        self.tx.write(buf);
        self.memo.write(buf);
    }
}

impl EncodeSize for MemoTx {
    fn encode_size(&self) -> usize {
        self.tx.encode_size() + self.memo.encode_size()
    }
}

impl Read for MemoTx {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let tx = Tx::read(buf)?;
        let memo = Bytes::read_cfg(buf, &RangeCfg::new(..=64))?;
        Ok(Self { tx, memo })
    }
}

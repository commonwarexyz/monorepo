//! A transaction-shaped value (~147 encoded bytes) shared by the codec benchmarks.

use bytes::{BufMut, Bytes};
use commonware_codec::{Buf, EncodeSize, Error, RangeCfg, Read, ReadExt as _, Write, varint::UInt};

#[derive(Clone)]
pub struct Tx {
    pub nonce: u64,
    pub sender: [u8; 32],
    pub recipient: [u8; 32],
    pub amount: u64,
    pub fee: u64,
    pub signature: [u8; 64],
}

impl Tx {
    pub fn sample(i: u64) -> Self {
        let mut sender = [0u8; 32];
        sender[..8].copy_from_slice(&i.to_be_bytes());
        let mut recipient = [7u8; 32];
        recipient[24..].copy_from_slice(&i.wrapping_mul(31).to_be_bytes());
        Self {
            nonce: i,
            sender,
            recipient,
            amount: 1_000_000 + i,
            fee: 20_000 + (i % 1000),
            signature: [i as u8; 64],
        }
    }
}

impl Write for Tx {
    fn write(&self, buf: &mut impl BufMut) {
        self.nonce.write(buf);
        self.sender.write(buf);
        self.recipient.write(buf);
        self.amount.write(buf);
        UInt(self.fee).write(buf);
        self.signature.write(buf);
    }
}

impl EncodeSize for Tx {
    fn encode_size(&self) -> usize {
        8 + 32 + 32 + 8 + UInt(self.fee).encode_size() + 64
    }
}

impl Read for Tx {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        Ok(Self {
            nonce: u64::read(buf)?,
            sender: <[u8; 32]>::read(buf)?,
            recipient: <[u8; 32]>::read(buf)?,
            amount: u64::read(buf)?,
            fee: UInt::<u64>::read(buf)?.into(),
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

//! Canonical types and encodings for the example chain.
//!
//! The example uses `commonware-codec` for deterministic, bounded decoding of untrusted bytes.
//!
//! - `BlockId` is `keccak256(Encode(Block))`.
//! - Consensus orders `ConsensusDigest = sha256(BlockId)` (the block's `Committable`).
//! - `StateRoot` is a 32-byte rolling commitment (see `crate::commitment`).

use alloy_evm::revm::primitives::{keccak256, Address, Bytes, B256, U256};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode, EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use commonware_cryptography::{Committable, Digestible, Hasher as _, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Block identifier (32 bytes).
pub struct BlockId(pub B256);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
/// Transaction identifier (32 bytes).
pub struct TxId(pub B256);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// State commitment (32 bytes).
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

fn write_b256(value: &B256, buf: &mut impl BufMut) {
    buf.put_slice(value.as_slice());
}

fn read_b256(buf: &mut impl Buf) -> Result<B256, CodecError> {
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

#[derive(Clone, Copy, Debug)]
pub struct TxCfg {
    pub max_calldata_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Minimal transaction type for the example.
///
/// This is not a signed Ethereum transaction. It is just enough information to build a `TxEnv`
/// for REVM execution in the simulation.
pub struct Tx {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub gas_limit: u64,
    pub data: Bytes,
}

impl Tx {
    pub fn id(&self) -> TxId {
        TxId(keccak256(self.encode()))
    }
}

impl Write for Tx {
    fn write(&self, buf: &mut impl BufMut) {
        buf.put_slice(self.from.as_slice());
        buf.put_slice(self.to.as_slice());
        buf.put_slice(&self.value.to_be_bytes::<32>());
        self.gas_limit.write(buf);
        self.data.as_ref().write(buf);
    }
}

impl EncodeSize for Tx {
    fn encode_size(&self) -> usize {
        20 + 20 + 32 + self.gas_limit.encode_size() + self.data.as_ref().encode_size()
    }
}

impl Read for Tx {
    type Cfg = TxCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        if buf.remaining() < 20 + 20 + 32 {
            return Err(CodecError::EndOfBuffer);
        }
        let mut from = [0u8; 20];
        buf.copy_to_slice(&mut from);
        let mut to = [0u8; 20];
        buf.copy_to_slice(&mut to);
        let mut value = [0u8; 32];
        buf.copy_to_slice(&mut value);
        let gas_limit = u64::read(buf)?;
        let data = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(0..=cfg.max_calldata_bytes), ()))?;
        Ok(Self {
            from: Address::from(from),
            to: Address::from(to),
            value: U256::from_be_bytes(value),
            gas_limit,
            data: Bytes::from(data),
        })
    }
}

#[derive(Clone, Copy, Debug)]
pub struct BlockCfg {
    pub max_txs: usize,
    pub tx: TxCfg,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Example block type agreed on by consensus (via its digest).
pub struct Block {
    pub parent: BlockId,
    pub height: u64,
    pub prevrandao: B256,
    pub state_root: StateRoot,
    pub txs: Vec<Tx>,
}

impl Block {
    pub fn id(&self) -> BlockId {
        block_id(self)
    }
}

pub fn block_id(block: &Block) -> BlockId {
    BlockId(keccak256(block.encode()))
}

fn digest_for_block_id(id: &BlockId) -> crate::ConsensusDigest {
    let mut hasher = Sha256::default();
    hasher.update(id.0.as_slice());
    hasher.finalize()
}

impl Digestible for Block {
    type Digest = crate::ConsensusDigest;

    fn digest(&self) -> Self::Digest {
        digest_for_block_id(&self.id())
    }
}

impl Committable for Block {
    type Commitment = crate::ConsensusDigest;

    fn commitment(&self) -> Self::Commitment {
        digest_for_block_id(&self.id())
    }
}

impl commonware_consensus::Heightable for Block {
    fn height(&self) -> commonware_consensus::types::Height {
        commonware_consensus::types::Height::new(self.height)
    }
}

impl commonware_consensus::Block for Block {
    fn parent(&self) -> Self::Commitment {
        digest_for_block_id(&self.parent)
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.parent.write(buf);
        self.height.write(buf);
        write_b256(&self.prevrandao, buf);
        self.state_root.write(buf);
        self.txs.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.parent.encode_size()
            + self.height.encode_size()
            + 32
            + self.state_root.encode_size()
            + self.txs.encode_size()
    }
}

impl Read for Block {
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let parent = BlockId::read(buf)?;
        let height = u64::read(buf)?;
        let prevrandao = read_b256(buf)?;
        let state_root = StateRoot::read(buf)?;
        let txs = Vec::<Tx>::read_cfg(buf, &(RangeCfg::new(0..=cfg.max_txs), cfg.tx))?;
        Ok(Self {
            parent,
            height,
            prevrandao,
            state_root,
            txs,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::Decode as _;

    fn cfg() -> BlockCfg {
        BlockCfg {
            max_txs: 64,
            tx: TxCfg {
                max_calldata_bytes: 1024,
            },
        }
    }

    #[test]
    fn test_tx_roundtrip_and_id_stable() {
        let tx = Tx {
            from: Address::from([0x11u8; 20]),
            to: Address::from([0x22u8; 20]),
            value: U256::from(1234u64),
            gas_limit: 50_000,
            data: Bytes::from(vec![1, 2, 3]),
        };
        let encoded = tx.encode();
        let decoded = Tx::decode_cfg(
            encoded.clone(),
            &TxCfg {
                max_calldata_bytes: 1024,
            },
        )
        .expect("decode tx");
        assert_eq!(tx, decoded);
        assert_eq!(tx.id(), decoded.id());
        assert_eq!(tx.id(), TxId(keccak256(encoded)));
    }

    #[test]
    fn test_block_roundtrip_and_id_stable() {
        let txs = vec![
            Tx {
                from: Address::from([0x11u8; 20]),
                to: Address::from([0x22u8; 20]),
                value: U256::from(1u64),
                gas_limit: 21_000,
                data: Bytes::new(),
            },
            Tx {
                from: Address::from([0x33u8; 20]),
                to: Address::from([0x44u8; 20]),
                value: U256::from(2u64),
                gas_limit: 50_000,
                data: Bytes::from(vec![9, 9, 9]),
            },
        ];
        let block = Block {
            parent: BlockId(B256::from([0xAAu8; 32])),
            height: 7,
            prevrandao: B256::from([0x55u8; 32]),
            state_root: StateRoot(B256::from([0xBBu8; 32])),
            txs,
        };
        let encoded = block.encode();
        let decoded = Block::decode_cfg(encoded.clone(), &cfg()).expect("decode block");
        assert_eq!(block, decoded);
        assert_eq!(block.id(), decoded.id());
        assert_eq!(block.id(), BlockId(keccak256(encoded)));
    }
}

use super::{
    ids::{read_b256, write_b256, BlockId, StateRoot},
    tx::{Tx, TxCfg},
    BlockContext,
};
use alloy_evm::revm::primitives::{keccak256, B256};
use bytes::{Buf, BufMut};
use commonware_codec::{Encode, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use commonware_consensus::types::{Round, View};
use commonware_cryptography::{ed25519, Committable, Digestible, Hasher as _, Sha256, Signer as _};

#[derive(Clone, Copy, Debug)]
/// Configuration used when decoding blocks and their transactions.
pub struct BlockCfg {
    /// Maximum number of transactions that can be encoded in a block.
    pub max_txs: usize,
    /// Per-transaction codec configuration.
    pub tx: TxCfg,
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// Example block type agreed on by consensus (via its digest).
pub struct Block {
    /// Consensus context used to propose this block.
    pub context: BlockContext,
    /// Identifier of the parent block.
    pub parent: BlockId,
    /// Block height (number of committed ancestors).
    pub height: u64,
    /// Seed-derived randomness used for future prevrandao.
    pub prevrandao: B256,
    /// State commitment resulting from this block (pre-commit QMDB root).
    pub state_root: StateRoot,
    /// Transactions included in the block.
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

pub(crate) fn genesis_context(parent: BlockId) -> BlockContext {
    BlockContext {
        round: Round::zero(),
        leader: ed25519::PrivateKey::from_seed(0).public_key(),
        parent: (View::zero(), digest_for_block_id(&parent)),
    }
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

impl commonware_consensus::CertifiableBlock for Block {
    type Context = BlockContext;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        write_b256(&self.prevrandao, buf);
        self.state_root.write(buf);
        self.txs.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + 32
            + self.state_root.encode_size()
            + self.txs.encode_size()
    }
}

impl Read for Block {
    type Cfg = BlockCfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let context = BlockContext::read(buf)?;
        let parent = BlockId::read(buf)?;
        let height = u64::read(buf)?;
        let prevrandao = read_b256(buf)?;
        let state_root = StateRoot::read(buf)?;
        let txs = Vec::<Tx>::read_cfg(buf, &(RangeCfg::new(0..=cfg.max_txs), cfg.tx))?;
        Ok(Self {
            context,
            parent,
            height,
            prevrandao,
            state_root,
            txs,
        })
    }
}

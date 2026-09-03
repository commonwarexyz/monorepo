//! Block and database types for the glue-based settlement chain.

use crate::chain::{state::Record, tx::SettlementTx, validator::MAX_MESSAGE_SIZE};
use bytes::{Buf, BufMut};
use commonware_codec::{
    Encode as _, EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt as _, Write,
};
use commonware_consensus::{
    Block as ConsensusBlock, CertifiableBlock, Heightable,
    simplex::types::Context,
    types::{Epoch, Height, Round, View},
};
use commonware_cryptography::{Digest as _, Digestible, Hasher, Sha256, ed25519, sha256::Digest};
use commonware_glue::stateful::db::{ManagedDb, Shared};
use commonware_parallel::Sequential;
use commonware_runtime::Clock;
use commonware_storage::{
    mmr,
    qmdb::{
        any::value::VariableEncoding,
        current::ordered::{self, variable},
        sync::Target,
    },
    translator::TwoCap,
};
use commonware_utils::{range::NonEmptyRange, sequence::FixedBytes};

/// Milliseconds since the Unix epoch on the runtime clock.
///
/// The shared reference for block timestamps: proposers stamp blocks with it
/// and clients compare certified timestamps against it for recency. It never
/// feeds a deadline (deadlines are block heights).
pub(crate) fn now(clock: &impl Clock) -> u64 {
    let elapsed = clock
        .current()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the runtime clock is at or after the Unix epoch");
    u64::try_from(elapsed.as_millis()).expect("the runtime clock fits u64 milliseconds")
}

/// Maximum transactions per block.
pub(crate) const MAX_BLOCK_TXS: usize = 128;

/// Maximum encoded bytes for one transaction.
///
/// Sized to cover a full settlement submission at the batch bounds baked into
/// the settlement RPC codecs, with headroom.
pub(crate) const MAX_TX_BYTES: usize = 1 << 20;

/// Maximum aggregate encoded transaction bytes in one block.
///
/// Blocks travel as single p2p messages bounded by [`MAX_MESSAGE_SIZE`], so
/// the transaction budget reserves headroom for the block header and the
/// broadcast framing. Proposals drain the ingress queue under this budget
/// and [`Block`] decoding rejects an encoding over it, so every valid block
/// fits the wire.
pub(crate) const MAX_BLOCK_BYTES: usize = MAX_MESSAGE_SIZE as usize - (64 * 1024);

// A block must always have room for one maximal transaction, or a valid
// submission could never land.
const _: () = assert!(MAX_BLOCK_BYTES >= MAX_TX_BYTES);

/// Bitmap chunk size (bytes) for the current database's activity bitmap.
const CHUNK: usize = 64;

/// Bytes in one state key: 32 entropy bytes then one domain tag byte.
///
/// The translator indexes a key prefix, so the entropy comes first and the
/// tag last (see [`crate::chain::state`] for the key derivation).
pub(crate) const KEY_BYTES: usize = 33;

/// One settlement state key.
pub(crate) type StateKey = FixedBytes<KEY_BYTES>;

/// Ordered current QMDB holding the settlement state.
///
/// Ordered so both presence (key-value proofs) and absence (exclusion proofs)
/// of any state key are provable against the canonical root.
pub(crate) type Qmdb<E> =
    variable::Db<mmr::Family, E, StateKey, Record, Sha256, TwoCap, CHUNK, Sequential>;

/// Shared handle to the settlement QMDB, usable as a glue database set.
pub(crate) type Database<E> = Shared<Qmdb<E>>;

/// State sync target for the settlement QMDB.
pub(crate) type SyncTarget = Target<mmr::Family, Digest>;

/// Presence proof for one state key against the canonical root.
pub(crate) type Proof = variable::KeyValueProof<mmr::Family, StateKey, Digest, CHUNK>;

/// Absence proof for one state key against the canonical root.
pub(crate) type Exclusion =
    ordered::ExclusionProof<mmr::Family, StateKey, VariableEncoding<Record>, Digest, CHUNK>;

/// Unmerkleized settlement batch.
pub(crate) type Batch<E> = <Qmdb<E> as ManagedDb<E>>::Unmerkleized;

/// Merkleized settlement batch.
pub(crate) type Sealed<E> = <Qmdb<E> as ManagedDb<E>>::Merkleized;

/// Chain block carrying settlement transactions and the state commitments.
///
/// The block commits to both roots of the current database: `state_root` is
/// the canonical (bitmap-grafted) root every proof verifies against, and
/// `ops_root` with `range` is the replay-sync target. The stateful wrapper
/// checks only `ops_root` and `range`, so [`crate::chain::app`] verification
/// itself rejects a canonical-root mismatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Block {
    pub(crate) context: Context<Digest, ed25519::PublicKey>,
    pub(crate) parent: Digest,
    pub(crate) height: Height,
    /// Block timestamp in milliseconds since the Unix epoch, covered by the
    /// digest like every other field.
    ///
    /// Strictly greater than the parent's timestamp, and bounded at vote time
    /// against the verifier's clock (see [`crate::chain::app`]). It serves
    /// query recency and display only: block heights remain the only deadline
    /// clock.
    pub(crate) timestamp: u64,
    /// Canonical current-database root.
    pub(crate) state_root: Digest,
    /// Operations-log root used as the state sync target.
    pub(crate) ops_root: Digest,
    /// Operation range backing `ops_root`.
    pub(crate) range: NonEmptyRange<mmr::Location>,
    pub(crate) transactions: Vec<SettlementTx>,
}

impl Block {
    /// Genesis block for one chain.
    ///
    /// The parent field of the genesis block is otherwise unused, so it
    /// carries the chain identity (the digest of the configured deployment
    /// set, [`crate::protocol::chain_id`]): every block digest in the chain
    /// then commits to every hosted deployment. The `timestamp` is the
    /// setup-chosen chain creation time from `genesis.json`
    /// (display/recency-grade, never a deadline input): every later block
    /// timestamp strictly exceeds it. The genesis block is never executed or
    /// verified, so its canonical `state_root` is the empty digest and the
    /// first executed block commits the first canonical root. The embedded
    /// `target` is the initial sync target of an empty database.
    pub(crate) const fn genesis(
        leader: ed25519::PublicKey,
        chain: Digest,
        timestamp: u64,
        target: SyncTarget,
    ) -> Self {
        Self {
            context: Context {
                round: Round::new(Epoch::zero(), View::zero()),
                leader,
                parent: (View::zero(), Digest::EMPTY),
            },
            parent: chain,
            height: Height::zero(),
            timestamp,
            state_root: Digest::EMPTY,
            ops_root: target.root,
            range: target.range,
            transactions: Vec::new(),
        }
    }
}

impl Write for Block {
    fn write(&self, buf: &mut impl BufMut) {
        self.context.write(buf);
        self.parent.write(buf);
        self.height.write(buf);
        self.timestamp.write(buf);
        self.state_root.write(buf);
        self.ops_root.write(buf);
        self.range.write(buf);
        self.transactions.write(buf);
    }
}

impl EncodeSize for Block {
    fn encode_size(&self) -> usize {
        self.context.encode_size()
            + self.parent.encode_size()
            + self.height.encode_size()
            + self.timestamp.encode_size()
            + self.state_root.encode_size()
            + self.ops_root.encode_size()
            + self.range.encode_size()
            + self.transactions.encode_size()
    }
}

impl Read for Block {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let block = Self {
            context: Context::read(buf)?,
            parent: Digest::read(buf)?,
            height: Height::read(buf)?,
            timestamp: u64::read(buf)?,
            state_root: Digest::read(buf)?,
            ops_root: Digest::read(buf)?,
            range: NonEmptyRange::read(buf)?,
            transactions: Vec::<SettlementTx>::read_cfg(
                buf,
                &(RangeCfg::new(0..=MAX_BLOCK_TXS), ()),
            )?,
        };

        // The per-transaction and aggregate byte bounds are enforced on the
        // decoded values: every nested field is already bounded by its own
        // codec, so re-measuring the encoding is exact and cheap at these
        // sizes.
        let mut total = 0_usize;
        for transaction in &block.transactions {
            let size = transaction.encode_size();
            if size > MAX_TX_BYTES {
                return Err(CodecError::Invalid(
                    "clearing_terminal::chain::Block",
                    "transaction exceeds the per-transaction byte bound",
                ));
            }
            total = total.saturating_add(size);
        }
        if total > MAX_BLOCK_BYTES {
            return Err(CodecError::Invalid(
                "clearing_terminal::chain::Block",
                "transactions exceed the block byte budget",
            ));
        }
        Ok(block)
    }
}

impl Digestible for Block {
    type Digest = Digest;

    fn digest(&self) -> Digest {
        Sha256::hash(&[&self.encode()])
    }
}

impl Heightable for Block {
    fn height(&self) -> Height {
        self.height
    }
}

impl ConsensusBlock for Block {
    fn parent(&self) -> Digest {
        self.parent
    }
}

impl CertifiableBlock for Block {
    type Context = Context<Digest, ed25519::PublicKey>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }
}

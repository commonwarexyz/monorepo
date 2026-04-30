//! Shared compact-db state.
//!
//! Both [`crate::qmdb::keyless::CompactDb`] and [`crate::qmdb::immutable::CompactDb`] hold the
//! same set of fields (compact merkle, commit-pointer trio, codec config, persisted witness) and
//! delegate the same set of methods (`init_from_*`, `rewind`, `sync`, `commit`, `destroy`,
//! `current_target`, `compact_state`, all the trivial accessors, and the `WitnessSource` impl).
//! [`Db`] holds those shared fields; the per-variant `Db` types are thin wrappers.
//!
//! Variant-specific bits stay at the wrapper:
//!   * the `MerkleizedBatch` payload (typed `commit_metadata` and any schema-specific fields)
//!   * the `merkleize` body's data-op construction (`Append(value)` vs `Set(key, value)`)
//!   * the `apply_batch` body's metadata cache write
//!
//! The db is parameterized over `Op: CompactCommit` rather than `V`, so it does not need to
//! know the value-encoding shape; metadata flows as `Op::Metadata`.

use crate::{
    merkle::{
        compact as compact_merkle, hasher::Standard as StandardHasher, Family, Location, Proof,
    },
    qmdb::{
        compact::{self, CompactCommit, Witness, WitnessSource},
        sync::compact as compact_sync,
        Error,
    },
    Context,
};
use commonware_codec::{Decode as _, Encode, Read};
use commonware_cryptography::Hasher;
use commonware_utils::sync::RwLock;

/// Shared db state for compact QMDB variants. See module docs.
pub(crate) struct Db<F, E, H, Op, C>
where
    F: Family,
    E: Context,
    H: Hasher,
    Op: CompactCommit<Family = F, CommitCfg = C> + Encode + Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    pub(crate) merkle: compact_merkle::Merkle<F, E, H::Digest>,
    pub(crate) last_commit_loc: Location<F>,
    pub(crate) inactivity_floor_loc: Location<F>,
    pub(crate) last_commit_metadata: Option<Op::Metadata>,
    pub(crate) commit_codec_config: C,
    /// Cache of the last durably servable compact state. Rebuilt from persisted witness bytes
    /// on reopen/rewind and refreshed on `sync`. Intentionally lags behind unsynced in-memory
    /// mutations so compact serving never advertises non-durable state.
    pub(crate) witness: RwLock<Witness<F, H::Digest>>,
}

impl<F, E, H, Op, C> Db<F, E, H, Op, C>
where
    F: Family,
    E: Context,
    H: Hasher,
    Op: CompactCommit<Family = F, CommitCfg = C> + Encode + Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    /// Build a db from already-verified compact state.
    ///
    /// The caller has reconstructed the compact Merkle in memory and authenticated the supplied
    /// witness/root pair. This seeds the in-memory serve cache from that verified witness but
    /// does not itself persist anything; persistence happens only after the caller finishes the
    /// root check for the reconstructed db.
    pub(crate) fn init_from_verified_state(
        merkle: compact_merkle::Merkle<F, E, H::Digest>,
        commit_codec_config: C,
        last_commit_metadata: Option<Op::Metadata>,
        inactivity_floor_loc: Location<F>,
        commit_op_bytes: Vec<u8>,
        commit_proof: Proof<F, H::Digest>,
        pinned_nodes: Vec<H::Digest>,
    ) -> Result<Self, Error<F>> {
        let witness = Witness::new(
            merkle.root(),
            merkle.leaves(),
            inactivity_floor_loc,
            commit_op_bytes,
            commit_proof,
            pinned_nodes,
        )?;
        let last_commit_loc = witness.last_commit_loc();

        Ok(Self {
            merkle,
            last_commit_loc,
            inactivity_floor_loc,
            last_commit_metadata,
            commit_codec_config,
            witness: RwLock::new(witness),
        })
    }

    /// Open a db from persisted compact state and rebuild its serve cache. Bootstraps the
    /// initial commit and witness on first open so every later reopen and rewind can assume "the
    /// active slot has a complete servable compact state."
    pub(crate) async fn init_from_merkle(
        mut merkle: compact_merkle::Merkle<F, E, H::Digest>,
        commit_codec_config: C,
    ) -> Result<Self, Error<F>> {
        let (witness, last_commit_metadata, inactivity_floor_loc) =
            compact::init_compact_witness::<F, E, H, Op>(&mut merkle, &commit_codec_config).await?;
        let last_commit_loc = Location::new(*witness.leaf_count - 1);
        Ok(Self {
            merkle,
            last_commit_loc,
            inactivity_floor_loc,
            last_commit_metadata,
            commit_codec_config,
            witness: RwLock::new(witness),
        })
    }

    pub(crate) fn root(&self) -> H::Digest {
        self.merkle.root()
    }

    pub(crate) const fn last_commit_loc(&self) -> Location<F> {
        self.last_commit_loc
    }

    pub(crate) const fn inactivity_floor_loc(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    pub(crate) fn size(&self) -> Location<F> {
        self.last_commit_loc + 1
    }

    pub(crate) fn get_metadata(&self) -> Option<Op::Metadata> {
        self.last_commit_metadata.clone()
    }

    /// The latest compact-sync target this db can currently serve. Reflects the last durably
    /// captured frontier+witness, which lags live mutations until `sync`.
    pub(crate) fn current_target(&self) -> compact_sync::Target<F, H::Digest> {
        self.cloned_witness().target()
    }

    /// Authenticated state this compact db can serve for `target`. Returns a serve error rather
    /// than panicking on stale targets or corrupted cache bytes.
    #[allow(clippy::type_complexity)]
    pub(crate) fn compact_state(
        &self,
        target: compact_sync::Target<F, H::Digest>,
    ) -> Result<compact_sync::State<F, Op, H::Digest>, compact_sync::ServeError<F, H::Digest>> {
        let witness = self.cloned_witness();
        let current = witness.target();
        if target.root != current.root || target.leaf_count != current.leaf_count {
            return Err(compact_sync::ServeError::StaleTarget {
                requested: target,
                current,
            });
        }
        let op = Op::decode_cfg(witness.commit_op_bytes.as_ref(), &self.commit_codec_config)
            .map_err(|_| {
                compact_sync::ServeError::Database(Error::DataCorrupted(
                    "invalid cached commit operation",
                ))
            })?;
        if op.as_commit().is_none() {
            return Err(compact_sync::ServeError::Database(Error::DataCorrupted(
                "cached last operation was not a commit",
            )));
        }
        Ok(compact_sync::State {
            leaf_count: witness.leaf_count,
            pinned_nodes: witness.pinned_nodes,
            last_commit_op: op,
            last_commit_proof: witness.commit_proof,
        })
    }

    pub(crate) async fn sync(&self) -> Result<(), Error<F>> {
        compact::persist_witness(self).await
    }

    /// Restore the state as of the sync before the most recent one. See the wrapper-level docs
    /// for the full contract.
    pub(crate) async fn rewind(&mut self) -> Result<(), Error<F>> {
        let hasher = StandardHasher::<H>::new();
        self.merkle.rewind(&hasher).await?;
        let (witness, last_commit_metadata, inactivity_floor_loc) =
            compact::load_active_witness::<F, E, H, Op>(&self.merkle, &self.commit_codec_config)
                .await?;
        self.last_commit_metadata = last_commit_metadata;
        self.last_commit_loc = witness.leaf_count - 1;
        self.inactivity_floor_loc = inactivity_floor_loc;
        self.store_witness(witness);
        Ok(())
    }

    pub(crate) async fn destroy(self) -> Result<(), Error<F>> {
        self.merkle.destroy().await.map_err(Into::into)
    }
}

impl<F, E, H, Op, C> WitnessSource<F, E, H> for Db<F, E, H, Op, C>
where
    F: Family,
    E: Context,
    H: Hasher,
    Op: CompactCommit<Family = F, CommitCfg = C> + Encode + Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    fn merkle(&self) -> &compact_merkle::Merkle<F, E, H::Digest> {
        &self.merkle
    }

    fn last_commit_loc(&self) -> Location<F> {
        self.last_commit_loc
    }

    fn encode_current_commit_op(&self) -> Vec<u8> {
        Op::build_commit(self.last_commit_metadata.clone(), self.inactivity_floor_loc)
            .encode()
            .to_vec()
    }

    fn witness_cache(&self) -> &RwLock<Witness<F, H::Digest>> {
        &self.witness
    }
}

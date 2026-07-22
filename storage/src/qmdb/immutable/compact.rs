//! An immutable authenticated db that discards historical operations, retaining only a witness
//! for each synced commit.
//!
//! Mirrors the API of [`crate::qmdb::immutable::Immutable`] (`new_batch -> merkleize ->
//! apply_batch -> sync`, pipelined batch chains, `StaleBatch` validation) but is backed by
//! the peak-only [`crate::merkle::compact`]. Because history is discarded, there are no
//! `get` / `proof` / `bounds` methods; use the full variant if you need them.
//!
//! # Witness journal
//!
//! The witness journal holds a complete snapshot of every synced commit, so [`Db::rewind`] can
//! restore any commit still retained there (history is bounded only by [`Db::prune`]). Reopen
//! and rewind re-verify the persisted snapshot; corruption surfaces as [`Error::DataCorrupted`].
//! The witness (the last-commit operation plus its inclusion proof) is also what lets compact
//! nodes serve compact sync without retaining historical operations.
//!
//! # Inactivity floor
//!
//! Commits carry an inactivity floor for wire-format compatibility with
//! [`crate::qmdb::immutable::Immutable`]: the root is computed over the encoded operation
//! sequence, and that sequence must include the same floor to produce the same root as the
//! full variant. The floor has no effect on pruning or snapshot rebuilding here; all
//! historical in-memory state is discarded on every sync.

use super::operation::Operation;
use crate::{
    Context,
    journal::contiguous::variable::{self, Config as JournalConfig},
    merkle::{Family, Location, batch, compact as compact_merkle},
    qmdb::{
        self, Error,
        any::value::ValueEncoding,
        batch_chain::{self, Bounds},
        compact::{
            batch as compact_batch,
            witness::{self, VerifiedWitness, Witness},
        },
        operation::Key,
        sync::compact as compact_sync,
    },
};
use commonware_codec::{Decode as _, Encode, EncodeShared, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use core::marker::PhantomData;
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};

/// Configuration for a compact immutable authenticated db.
#[derive(Clone)]
pub struct Config<C, S: Strategy> {
    /// Strategy used to parallelize merkleization.
    pub strategy: S,

    /// Configuration for the journal that persists the witness.
    pub witness: JournalConfig<()>,

    /// Codec config used to decode the persisted last commit operation on reopen.
    pub commit_codec_config: C,
}

/// An immutable authenticated db that discards historical operations, retaining only a witness
/// for each synced commit.
pub struct Db<F, E, K, V, H, C, S: Strategy>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    merkle: compact_merkle::Merkle<F, H::Digest, S>,
    last_commit_loc: Location<F>,
    last_commit_metadata: Option<V::Value>,
    inactivity_floor_loc: Location<F>,
    commit_codec_config: C,
    witness: witness::Store<E, F, H::Digest>,
    _key: PhantomData<K>,
}

impl<F, E, K, V, H, C, S: Strategy> std::fmt::Debug for Db<F, E, K, V, H, C, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("size", &self.size())
            .field("inactivity_floor_loc", &self.inactivity_floor_loc())
            .finish_non_exhaustive()
    }
}

type CompactStateResult<F, K, V, D> =
    Result<compact_sync::State<F, Operation<F, K, V>, D>, compact_sync::ServeError<F, D>>;

/// A speculative batch for a compact immutable db.
#[allow(clippy::type_complexity)]
pub struct UnmerkleizedBatch<F, H, K, V, S: Strategy>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared,
{
    merkle_batch: compact_merkle::UnmerkleizedBatch<F, H::Digest, S>,
    mutations: BTreeMap<K, V::Value>,
    parent: Option<Arc<MerkleizedBatch<F, H::Digest, K, V, S>>>,
    base_size: u64,
    db_size: u64,
}

/// A speculative batch whose root digest has been computed.
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, K: Key, V: ValueEncoding, S: Strategy>
where
    Operation<F, K, V>: EncodeShared,
{
    pub(super) merkle_batch: Arc<batch::MerkleizedBatch<F, D, S>>,
    pub(super) root: D,
    pub(super) commit_metadata: Option<V::Value>,
    pub(super) parent: Option<Weak<Self>>,
    pub(super) bounds: batch_chain::Bounds<F>,
    pub(super) _key: PhantomData<K>,
}

impl<F: Family, D: Digest, K: Key, V: ValueEncoding, S: Strategy> MerkleizedBatch<F, D, K, V, S>
where
    Operation<F, K, V>: EncodeShared,
{
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> + use<F, D, K, V, S> {
        batch_chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }

    /// Return the root digest after this batch is applied.
    pub const fn root(&self) -> D {
        self.root
    }

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F> {
        &self.bounds
    }

    /// Create a new speculative batch with this one as its parent.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, K, V, S>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            merkle_batch: compact_merkle::UnmerkleizedBatch::wrap(self.merkle_batch.new_batch()),
            mutations: BTreeMap::new(),
            parent: Some(Arc::clone(self)),
            base_size: self.bounds.total_size,
            db_size: self.bounds.db_size,
        }
    }
}

impl<F, H, K, V, S> UnmerkleizedBatch<F, H, K, V, S>
where
    F: Family,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
{
    pub(super) fn new<E, C>(db: &Db<F, E, K, V, H, C, S>, committed_size: u64) -> Self
    where
        E: Context,
        C: Clone + Send + Sync + 'static,
        Operation<F, K, V>: Read<Cfg = C>,
    {
        Self {
            merkle_batch: db.merkle.new_batch(),
            mutations: BTreeMap::new(),
            parent: None,
            base_size: committed_size,
            db_size: committed_size,
        }
    }

    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.mutations.insert(key, value);
        self
    }

    /// Resolve mutations into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    ///
    /// `inactivity_floor` is threaded through the commit operation for wire-format parity with
    /// [`crate::qmdb::immutable::Immutable`]. It must be >= the database's current floor
    /// (monotonically non-decreasing) and at most the batch's commit location
    /// (`total_size - 1`); these bounds are validated, but the floor does not drive any local
    /// pruning or retention in this variant.
    #[tracing::instrument(
        name = "qmdb.immutable.compact.batch.merkleize",
        level = "info",
        skip_all
    )]
    pub async fn merkleize<E, C>(
        self,
        db: &Db<F, E, K, V, H, C, S>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, K, V, S>>
    where
        F: Family,
        E: Context,
        C: Clone + Send + Sync + 'static,
        Operation<F, K, V>: Read<Cfg = C>,
    {
        let mut ops: Vec<Operation<F, K, V>> = Vec::with_capacity(self.mutations.len() + 1);
        for (key, value) in self.mutations {
            ops.push(Operation::Set(key, value));
        }
        ops.push(Operation::Commit(metadata.clone(), inactivity_floor));

        let total_size = self.base_size + ops.len() as u64;
        let inactive_peaks = F::inactive_peaks(
            F::location_to_position(Location::new(total_size)),
            inactivity_floor,
        );
        let (merkle, root) = compact_batch::merkleize_ops::<F, H, S, _>(
            &db.merkle,
            self.merkle_batch,
            ops,
            inactive_peaks,
        )
        .await
        .expect("inactive_peaks computed from batch size");

        let ancestors =
            batch_chain::parent_and_ancestors(self.parent.as_ref(), |parent| parent.ancestors());
        let ancestors = batch_chain::collect_ancestor_bounds(
            ancestors,
            |batch| batch.bounds.inactivity_floor,
            |batch| batch.bounds.total_size,
        );

        Arc::new(MerkleizedBatch {
            merkle_batch: merkle,
            root,
            commit_metadata: metadata,
            parent: self.parent.as_ref().map(Arc::downgrade),
            bounds: batch_chain::Bounds {
                base_size: self.base_size,
                db_size: self.db_size,
                total_size,
                ancestors,
                inactivity_floor,
            },
            _key: PhantomData,
        })
    }
}

impl<F, E, K, V, H, C, S> Db<F, E, K, V, H, C, S>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, K, V>: EncodeShared,
    Operation<F, K, V>: Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    fn encode_commit_op(metadata: Option<V::Value>, inactivity_floor_loc: Location<F>) -> Vec<u8> {
        Operation::<F, K, V>::Commit(metadata, inactivity_floor_loc)
            .encode()
            .to_vec()
    }

    /// Build a compact db handle from already-validated compact state.
    ///
    /// The caller has reconstructed the compact Merkle in memory and already authenticated the
    /// supplied witness/root pair. The import lives only in memory until the first [`Self::commit`]
    /// or [`Self::sync`], which replaces the journal's contents with it. Until then, dropping the
    /// handle leaves the previous on-disk state untouched, and rewind/prune are rejected.
    pub(crate) fn init_from_validated_state(
        strategy: S,
        journal: witness::Journal<E, F, H::Digest>,
        commit_codec_config: C,
        validated: compact_sync::ValidatedState<F, Operation<F, K, V>, H::Digest>,
    ) -> Result<Self, Error<F>> {
        let compact_sync::ValidatedState {
            state:
                compact_sync::State {
                    leaf_count,
                    pinned_nodes,
                    last_commit_op,
                    last_commit_proof,
                },
            root,
        } = validated;
        let last_commit_loc = Location::new(*leaf_count - 1);
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::UnexpectedData(last_commit_loc));
        };

        let merkle =
            compact_merkle::Merkle::from_compact_state(strategy, leaf_count, pinned_nodes.clone())?;
        let imported = VerifiedWitness {
            witness: Witness {
                op_bytes: Self::encode_commit_op(
                    last_commit_metadata.clone(),
                    inactivity_floor_loc,
                ),
                proof: last_commit_proof,
                pinned_nodes,
            },
            root,
        };

        let witness = witness::Store::from_import(journal, imported);
        Ok(Self {
            merkle,
            last_commit_loc,
            last_commit_metadata,
            inactivity_floor_loc,
            commit_codec_config,
            witness,
            _key: PhantomData,
        })
    }

    /// Open a compact db from persisted compact state and rebuild its witness store.
    ///
    /// On first open, this bootstraps the initial commit and its witness so every later reopen and
    /// rewind can assume the journal tip is a complete compact witness.
    #[boxed]
    pub(crate) async fn init_from_merkle(
        mut merkle: compact_merkle::Merkle<F, H::Digest, S>,
        witness_context: E,
        witness_config: JournalConfig<()>,
        commit_codec_config: C,
    ) -> Result<Self, Error<F>>
    where
        F: Family,
        Operation<F, K, V>: Read<Cfg = C>,
    {
        // Bootstrap: append an initial Commit(None, 0) on first open.
        let journal: witness::Journal<E, F, H::Digest> =
            variable::Journal::init(witness_context, witness_config).await?;
        let (witness, last_commit_op) = witness::init::<E, F, H, S, Operation<F, K, V>>(
            journal,
            &mut merkle,
            &commit_codec_config,
            Operation::<F, K, V>::Commit(None, Location::new(0))
                .encode()
                .to_vec(),
            Operation::has_floor,
        )
        .await?;
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::DataCorrupted("last operation was not a commit"));
        };
        let last_commit_loc = Location::new(*witness.with(|w| w.leaf_count()) - 1);

        Ok(Self {
            merkle,
            last_commit_loc,
            last_commit_metadata,
            inactivity_floor_loc,
            commit_codec_config,
            witness,
            _key: PhantomData,
        })
    }

    /// Return the root of the db.
    pub fn root(&self) -> H::Digest
    where
        F: Family,
    {
        let hasher = qmdb::hasher::<H>();
        let inactive_peaks = F::inactive_peaks(
            F::location_to_position(Location::new(*self.last_commit_loc + 1)),
            self.inactivity_floor_loc,
        );
        self.merkle
            .root(&hasher, inactive_peaks)
            .expect("compact Merkle root should not fail")
    }

    /// Return a reference to the merkleization strategy.
    pub const fn strategy(&self) -> &S {
        self.merkle.strategy()
    }

    /// Return the location of the last commit.
    pub const fn last_commit_loc(&self) -> Location<F> {
        self.last_commit_loc
    }

    /// Return the inactivity floor declared by the last committed batch.
    pub const fn inactivity_floor_loc(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Return the location of the next operation appended to this db.
    pub fn size(&self) -> Location<F> {
        Location::new(*self.last_commit_loc + 1)
    }

    /// Get the metadata associated with the last commit.
    pub fn get_metadata(&self) -> Option<V::Value> {
        self.last_commit_metadata.clone()
    }

    /// Return the compact-sync target described by the current witness.
    ///
    /// This reflects the last durably persisted commit, which may lag behind live in-memory
    /// mutations until [`Self::commit`] or [`Self::sync`] is called.
    pub fn target(&self) -> compact_sync::Target<F, H::Digest> {
        self.witness.with(VerifiedWitness::target)
    }

    /// Return the compact-sync state for `target`, or a stale-target error if the source's
    /// current witness no longer matches.
    pub(crate) fn compact_state(
        &self,
        target: compact_sync::Target<F, H::Digest>,
    ) -> CompactStateResult<F, K, V, H::Digest>
    where
        Operation<F, K, V>: Read<Cfg = C>,
    {
        // Hold the witness lock only long enough to verify the requested target and snapshot the
        // entry; decode outside it so concurrent readers do not contend.
        let (entry, leaf_count) = self.witness.with(|w| {
            if target.root != w.root || target.leaf_count != w.leaf_count() {
                return Err(compact_sync::ServeError::StaleTarget {
                    requested: target.clone(),
                    current: w.target(),
                });
            }
            Ok((w.witness.clone(), w.leaf_count()))
        })?;
        let Witness {
            op_bytes,
            proof: last_commit_proof,
            pinned_nodes,
        } = entry;
        let op = Operation::<F, K, V>::decode_cfg(op_bytes.as_ref(), &self.commit_codec_config)
            .map_err(|_| {
                compact_sync::ServeError::Database(Error::DataCorrupted("invalid commit operation"))
            })?;
        Ok(compact_sync::State {
            leaf_count,
            pinned_nodes,
            last_commit_op: op,
            last_commit_proof,
        })
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, K, V, S> {
        let committed_size = *self.last_commit_loc + 1;
        UnmerkleizedBatch::new(self, committed_size)
    }

    /// Create an owned merkleized batch representing the current applied state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, K, V, S>>
    where
        F: Family,
    {
        let committed_size = *self.last_commit_loc + 1;
        Arc::new(MerkleizedBatch {
            merkle_batch: self.merkle.to_batch(),
            root: self.root(),
            commit_metadata: self.last_commit_metadata.clone(),
            parent: None,
            bounds: batch_chain::Bounds {
                base_size: committed_size,
                db_size: committed_size,
                total_size: committed_size,
                ancestors: Vec::new(),
                inactivity_floor: self.inactivity_floor_loc,
            },
            _key: PhantomData,
        })
    }

    /// Check that `batch` can be applied to the database in its current state, without
    /// applying it.
    ///
    /// [`Self::apply_batch`] runs the same validation but consumes the database when it
    /// fails; callers that want to reject a bad batch and keep the handle can check first.
    pub fn validate_batch(
        &self,
        batch: &MerkleizedBatch<F, H::Digest, K, V, S>,
    ) -> Result<(), Error<F>> {
        batch
            .bounds
            .validate_apply_to(*self.last_commit_loc + 1, self.inactivity_floor_loc)
    }

    /// Apply a merkleized batch to the database.
    ///
    /// Returns the range of locations written. The state is updated in memory only; call
    /// [`Self::commit`] or [`Self::sync`] to persist.
    ///
    /// # Errors
    ///
    /// - [`Error::StaleBatch`] if the batch is detected as stale (see
    ///   [`crate::qmdb::batch_chain`] for more details).
    /// - [`Error::FloorRegressed`] if any commit in the chain declares a floor below the
    ///   previous commit's floor.
    /// - [`Error::FloorBeyondSize`] if any commit in the chain declares a floor beyond its own
    ///   commit location.
    #[tracing::instrument(
        name = "qmdb.immutable.compact.db.apply_batch",
        level = "info",
        skip_all
    )]
    pub fn apply_batch(
        mut self,
        batch: Arc<MerkleizedBatch<F, H::Digest, K, V, S>>,
    ) -> Result<(Self, core::ops::Range<Location<F>>), Error<F>> {
        self.validate_batch(&batch)?;

        let start_loc = self.last_commit_loc + 1;
        self.merkle.apply_batch(&batch.merkle_batch)?;
        self.last_commit_loc = Location::new(batch.bounds.total_size - 1);
        self.last_commit_metadata = batch.commit_metadata.clone();
        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        Ok((self, start_loc..Location::new(batch.bounds.total_size)))
    }

    /// Durably persist the current db state to disk. This is faster than [`Self::sync`] but
    /// reopen may need to replay the witness journal's tail to recover.
    #[tracing::instrument(name = "qmdb.immutable.compact.db.commit", level = "info", skip_all)]
    pub async fn commit(mut self) -> Result<Self, Error<F>> {
        let last_commit_metadata = self.last_commit_metadata.clone();
        let inactivity_floor_loc = self.inactivity_floor_loc;
        self.witness = self
            .witness
            .commit::<H, S>(&self.merkle, inactivity_floor_loc, || {
                Self::encode_commit_op(last_commit_metadata, inactivity_floor_loc)
            })
            .await?;
        Ok(self)
    }

    /// Durably persist the current db state to disk, also persisting journal metadata to
    /// minimize recovery work on reopen.
    #[tracing::instrument(name = "qmdb.immutable.compact.db.sync", level = "info", skip_all)]
    pub async fn sync(mut self) -> Result<Self, Error<F>> {
        let last_commit_metadata = self.last_commit_metadata.clone();
        let inactivity_floor_loc = self.inactivity_floor_loc;
        self.witness = self
            .witness
            .sync::<H, S>(&self.merkle, inactivity_floor_loc, || {
                Self::encode_commit_op(last_commit_metadata, inactivity_floor_loc)
            })
            .await?;
        Ok(self)
    }

    /// Rewind the db to the synced commit with exactly `target` operations, discarding any
    /// uncommitted batches and any later commits. The rewind is made durable before this
    /// method returns.
    ///
    /// # Errors
    ///
    /// Returns [`crate::merkle::Error::RewindBeyondHistory`] (wrapped as [`Error::Merkle`]) if
    /// no retained commit has exactly `target` operations (never synced, or pruned).
    #[tracing::instrument(name = "qmdb.immutable.compact.db.rewind", level = "info", skip_all)]
    pub async fn rewind(mut self, target: Location<F>) -> Result<Self, Error<F>>
    where
        F: Family,
    {
        // Fast path: already durably at `target` with no uncommitted state.
        if self.size() == target
            && self.witness.with(|w| w.leaf_count()) == target
            && !self.witness.import_pending()
        {
            return Ok(self);
        }

        let last_commit_op;
        (self.witness, last_commit_op) = self
            .witness
            .rewind::<H, S, Operation<F, K, V>>(
                &self.merkle,
                target,
                &self.commit_codec_config,
                Operation::has_floor,
            )
            .await?;
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::DataCorrupted("last operation was not a commit"));
        };
        self.last_commit_metadata = last_commit_metadata;
        self.inactivity_floor_loc = inactivity_floor_loc;
        self.last_commit_loc = Location::new(*target - 1);
        Ok(self)
    }

    /// Drop witnesses for commits with fewer than `pruning_boundary` operations. Some witness below
    /// the boundary may survive.
    ///
    /// Pruning bounds how far back [`Self::rewind`] can reach; the current commit's witness always
    /// survives. The prune is made durable before this method returns.
    ///
    /// # Errors
    ///
    /// Fails if a compact-sync import has not yet been persisted by [`Self::commit`] or
    /// [`Self::sync`].
    pub async fn prune(mut self, pruning_boundary: Location<F>) -> Result<Self, Error<F>> {
        self.witness = self.witness.prune(pruning_boundary).await?;
        Ok(self)
    }

    /// Destroy all persisted state associated with this database.
    #[boxed]
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.witness.destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::mmr,
        qmdb::{any::value::FixedEncoding, compact::witness},
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use std::num::{NonZeroU16, NonZeroUsize};

    type TestDb<F> =
        Db<F, deterministic::Context, Digest, FixedEncoding<Digest>, Sha256, (), Sequential>;

    const WITNESS_PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const WITNESS_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    fn witness_config(partition: &str, pooler: &impl BufferPooler) -> JournalConfig<()> {
        JournalConfig {
            partition: format!("{partition}-witness"),
            items_per_section: NZU64!(64),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(pooler, WITNESS_PAGE_SIZE, WITNESS_PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(1024),
        }
    }

    async fn open_db<F: Family>(context: deterministic::Context, partition: &str) -> TestDb<F> {
        let witness_cfg = witness_config(partition, &context);
        let merkle = crate::merkle::compact::Merkle::new(Sequential);
        Db::init_from_merkle(merkle, context.child("witness"), witness_cfg, ())
            .await
            .unwrap()
    }

    /// Open the persisted witness journal directly so tests can corrupt the tip entry.
    async fn open_witness_journal(
        context: deterministic::Context,
        partition: &str,
    ) -> witness::Journal<deterministic::Context, mmr::Family, Digest> {
        let cfg = witness_config(partition, &context);
        witness::Journal::init(context, cfg).await.unwrap()
    }

    #[test_traced("INFO")]
    fn test_compact_stale_batch_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-stale").await;

            let key1 = Sha256::hash(&[&[1]]);
            let key2 = Sha256::hash(&[&[2]]);
            let value1 = Sha256::fill(10u8);
            let value2 = Sha256::fill(20u8);

            let batch_a = db
                .new_batch()
                .set(key1, value1)
                .merkleize(&db, None, Location::new(0))
                .await;
            let batch_b = db
                .new_batch()
                .set(key2, value2)
                .merkleize(&db, None, Location::new(0))
                .await;

            let expected_root = batch_a.root();
            let (db, _) = db.apply_batch(batch_a).unwrap();
            assert_eq!(db.root(), expected_root);
            assert!(matches!(
                db.apply_batch(batch_b),
                Err(Error::StaleBatch { .. })
            ));
        });
    }

    /// Regression: `to_batch()` must snapshot the live in-memory state, not the lagging witness
    /// cache.
    #[test_traced("INFO")]
    fn test_compact_to_batch_reflects_live_state() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-to-batch-live").await;

            let pre_apply_root = db.root();
            let pre_snapshot = db.to_batch();
            assert_eq!(
                pre_snapshot.root(),
                pre_apply_root,
                "snapshot before any mutation should match the live root"
            );

            let key = Sha256::hash(&[&[1]]);
            let value = Sha256::fill(10u8);
            let batch = db
                .new_batch()
                .set(key, value)
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();

            // Leave the witness cache behind the live Merkle state.
            let live_root = db.root();
            assert_ne!(
                live_root, pre_apply_root,
                "applying a non-empty batch must change the live root"
            );

            let snapshot = db.to_batch();
            assert_eq!(
                snapshot.root(),
                live_root,
                "to_batch().root() must match the live db.root() even before sync"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_stale_batch_chained() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-chained-stale").await;

            let parent = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let child_a = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let child_b = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[&[3]]), Sha256::fill(3u8))
                .merkleize(&db, None, Location::new(0))
                .await;

            let (db, _) = db.apply_batch(child_a).unwrap();
            assert!(matches!(
                db.apply_batch(child_b),
                Err(Error::StaleBatch { .. })
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_stale_parent_after_child_applied() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.child("db"), "immutable-child-before-parent").await;

            let parent = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let child = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0))
                .await;

            let (db, _) = db.apply_batch(child).unwrap();
            assert!(matches!(
                db.apply_batch(parent),
                Err(Error::StaleBatch { .. })
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_sequential_commit_parent_then_child() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-parent-child").await;

            let parent = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let child = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let expected_root = child.root();

            let (db, _) = db.apply_batch(parent).unwrap();
            let (db, _) = db.apply_batch(child).unwrap();
            let db = db.sync().await.unwrap();

            assert_eq!(db.root(), expected_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_floor_regressed() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-floor-regressed").await;

            let advance_floor = db.new_batch().set(Sha256::hash(&[&[1]]), Sha256::fill(1u8));
            let advance_floor = advance_floor.merkleize(&db, None, Location::new(1)).await;
            let (db, _) = db.apply_batch(advance_floor).unwrap();
            let db = db.sync().await.unwrap();
            let target = db.target();

            let regressed = db
                .new_batch()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0))
                .await;

            assert!(matches!(
                db.apply_batch(regressed),
                Err(Error::FloorRegressed(new, current))
                    if new == Location::new(0) && current == Location::new(1)
            ));

            // Reopen and verify the rejected batch persisted nothing.
            let db =
                open_db::<mmr::Family>(context.child("reopen"), "immutable-floor-regressed").await;
            assert_eq!(db.target(), target);
        });
    }

    // A chained batch whose tip floor is below its parent's floor must be rejected:
    // the parent's Commit participates in the per-commit monotonicity invariant even
    // before it is applied.
    #[test_traced("INFO")]
    fn test_compact_ancestor_floor_regressed() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.child("db"), "immutable-regressed-ancestor-floor")
                    .await;

            let parent = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(1))
                .await;
            let child = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0))
                .await;

            let target = db.target();
            assert!(matches!(
                db.apply_batch(child),
                Err(Error::FloorRegressed(new, prev))
                    if new == Location::new(0) && prev == Location::new(1)
            ));

            // Reopen and verify the rejected chain persisted nothing.
            let db = open_db::<mmr::Family>(
                context.child("reopen"),
                "immutable-regressed-ancestor-floor",
            )
            .await;
            assert_eq!(db.target(), target);
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_restores_commit_metadata_and_floor() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-rewind-meta").await;

            let k1 = Sha256::hash(&[&[1]]);
            let v1 = Sha256::fill(11u8);
            let meta1 = Sha256::fill(0xaa);
            let floor1 = Location::new(0);
            let batch = db
                .new_batch()
                .set(k1, v1)
                .merkleize(&db, Some(meta1), floor1)
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();
            let size_after_first = db.size();

            let k2 = Sha256::hash(&[&[2]]);
            let v2 = Sha256::fill(22u8);
            let meta2 = Sha256::fill(0xbb);
            // Advance the floor to the commit of the first batch (loc 1).
            let floor2 = Location::new(1);
            let batch = db
                .new_batch()
                .set(k2, v2)
                .merkleize(&db, Some(meta2), floor2)
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            assert_eq!(db.get_metadata(), Some(meta2));
            assert_eq!(db.inactivity_floor_loc(), floor2);

            let db = db.rewind(size_after_first).await.unwrap();
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.get_metadata(), Some(meta1));
            assert_eq!(db.inactivity_floor_loc(), floor1);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_persists_across_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-rewind-reopen";
            let meta1 = Sha256::fill(0xaa);
            let floor1 = Location::new(0);
            let meta2 = Sha256::fill(0xbb);
            let floor2 = Location::new(1);

            let root_after_first = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[1]]), Sha256::fill(11u8))
                    .merkleize(&db, Some(meta1), floor1)
                    .await;
                let (db, _) = db.apply_batch(batch).unwrap();
                let db = db.sync().await.unwrap();
                let root = db.root();
                let size_after_first = db.size();

                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[2]]), Sha256::fill(22u8))
                    .merkleize(&db, Some(meta2), floor2)
                    .await;
                let (db, _) = db.apply_batch(batch).unwrap();
                let db = db.sync().await.unwrap();

                let _db = db.rewind(size_after_first).await.unwrap();
                root
            };

            let db = open_db::<mmr::Family>(context.child("second"), partition).await;
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.get_metadata(), Some(meta1));
            assert_eq!(db.inactivity_floor_loc(), floor1);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_commit_persists_across_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-commit-reopen";
            let meta1 = Sha256::fill(0xaa);
            let meta2 = Sha256::fill(0xbb);

            let root_after_second = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[1]]), Sha256::fill(11u8))
                    .merkleize(&db, Some(meta1), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).unwrap();
                let db = db.commit().await.unwrap();

                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[2]]), Sha256::fill(22u8))
                    .merkleize(&db, Some(meta2), Location::new(1))
                    .await;
                let (db, _) = db.apply_batch(batch).unwrap();
                let db = db.commit().await.unwrap();
                db.root()
            };

            // Reopen recovers the committed tip even though the journal was never synced.
            let db = open_db::<mmr::Family>(context.child("second"), partition).await;
            assert_eq!(db.root(), root_after_second);
            assert_eq!(db.get_metadata(), Some(meta2));
            assert_eq!(db.inactivity_floor_loc(), Location::new(1));
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_to_committed_entry_after_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-commit-rewind-reopen";
            let meta1 = Sha256::fill(0xaa);
            let meta2 = Sha256::fill(0xbb);

            let (root_a, size_a) = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[1]]), Sha256::fill(11u8))
                    .merkleize(&db, Some(meta1), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).unwrap();
                let db = db.commit().await.unwrap();
                let root_a = db.root();
                let size_a = db.size();

                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[2]]), Sha256::fill(22u8))
                    .merkleize(&db, Some(meta2), Location::new(1))
                    .await;
                let (db, _) = db.apply_batch(batch).unwrap();
                let _db = db.commit().await.unwrap();
                (root_a, size_a)
            };

            // Both committed witnesses survive the crash: reopen recovers the tip, and the
            // earlier commit remains a valid rewind target.
            let db = open_db::<mmr::Family>(context.child("second"), partition).await;
            let db = db.rewind(size_a).await.unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.get_metadata(), Some(meta1));
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_sync_after_commit() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-sync-after-commit";
            let meta = Sha256::fill(0xaa);

            let root = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[1]]), Sha256::fill(11u8))
                    .merkleize(&db, Some(meta), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).unwrap();
                let db = db.commit().await.unwrap();
                // The commit already made the state durable, so this is a no-op.
                let db = db.sync().await.unwrap();
                db.root()
            };

            let db = open_db::<mmr::Family>(context.child("second"), partition).await;
            assert_eq!(db.root(), root);
            assert_eq!(db.get_metadata(), Some(meta));
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_reopen_rejects_tampered_witness() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-witness-tamper";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[7]]), Sha256::fill(7u8))
                .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Corrupt the persisted proof so it no longer verifies against the stored root.
            let journal = open_witness_journal(context.child("tamper"), partition).await;
            let (op_bytes, mut proof, pinned_nodes) = witness::tests::tip(&journal).await;
            if let Some(digest) = proof.digests.first_mut() {
                *digest = Sha256::fill(0xff);
            } else {
                proof.leaves = Location::new(*proof.leaves + 1);
            }
            witness::tests::overwrite_tip(journal, op_bytes, proof, pinned_nodes).await;

            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let reopened = TestDb::<mmr::Family>::init_from_merkle(
                merkle,
                context.child("reopen_witness"),
                witness_config(partition, &context),
                (),
            )
            .await;
            assert!(matches!(reopened, Err(Error::DataCorrupted(_))));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_rejects_corrupt_target_entry() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-corrupt-rewind-target";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let rewind_target = db.target().leaf_count;
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let tip_target = db.target();
            drop(db);

            // Corrupt the rewind target's entry (the journal holds bootstrap, target, tip).
            let mut journal = open_witness_journal(context.child("corrupt"), partition).await;
            journal = witness::tests::corrupt_entry(journal, 1, |entry| {
                entry.pinned_nodes[0] = Sha256::fill(0xff);
            })
            .await;
            drop(journal);

            // The tip entry is intact, so reopen succeeds.
            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let reopened = TestDb::<mmr::Family>::init_from_merkle(
                merkle,
                context.child("reopen"),
                witness_config(partition, &context),
                (),
            )
            .await
            .unwrap();
            assert_eq!(reopened.target(), tip_target);

            // The corrupt entry fails the rewind before any truncation.
            assert!(matches!(
                reopened.rewind(rewind_target).await,
                Err(Error::DataCorrupted(_))
            ));

            // The newer history survives: reopen still lands on the original tip.
            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let reopened = TestDb::<mmr::Family>::init_from_merkle(
                merkle,
                context.child("reopen2"),
                witness_config(partition, &context),
                (),
            )
            .await
            .unwrap();
            assert_eq!(reopened.target(), tip_target);
            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_reopen_rejects_interrupted_import() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-interrupted-import";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[7]]), Sha256::fill(7u8))
                .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Simulate a crash between an import's journal clear and its entry append: the
            // journal is empty but its size is nonzero.
            let journal = open_witness_journal(context.child("clear"), partition).await;
            let size = journal.size();
            let journal = journal.clear_to_size(size.max(1)).await.unwrap();
            drop(journal);

            // Reopen must fail rather than bootstrap a fresh db.
            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let reopened = TestDb::<mmr::Family>::init_from_merkle(
                merkle,
                context.child("reopen_witness"),
                witness_config(partition, &context),
                (),
            )
            .await;
            assert!(matches!(reopened, Err(Error::Journal(_))));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_reopen_rejects_commit_floor_beyond_tip() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-invalid-persisted-floor";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[7]]), Sha256::fill(7u8))
                .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            drop(db);
            let oversized_floor = Location::new(10);

            // Overwrite the persisted commit op with a floor beyond its own commit location.
            let journal = open_witness_journal(context.child("tamper"), partition).await;
            let (_, proof, pinned_nodes) = witness::tests::tip(&journal).await;
            let bad_op = Operation::<mmr::Family, Digest, FixedEncoding<Digest>>::Commit(
                Some(Sha256::fill(0xaa)),
                oversized_floor,
            )
            .encode()
            .to_vec();
            witness::tests::overwrite_tip(journal, bad_op, proof, pinned_nodes).await;

            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let reopened = TestDb::<mmr::Family>::init_from_merkle(
                merkle,
                context.child("reopen_witness"),
                witness_config(partition, &context),
                (),
            )
            .await;
            assert!(matches!(
                reopened,
                Err(Error::DataCorrupted("invalid compact witness"))
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_reopen_rejects_tampered_pinned_nodes() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-pins-tamper";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[7]]), Sha256::fill(7u8))
                .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Corrupt one pinned frontier node: the root recomputed from the rebuilt Merkle no
            // longer matches the proof stored in the same entry.
            let journal = open_witness_journal(context.child("tamper"), partition).await;
            let (op_bytes, proof, mut pinned_nodes) = witness::tests::tip(&journal).await;
            pinned_nodes[0] = Sha256::fill(0xff);
            witness::tests::overwrite_tip(journal, op_bytes, proof, pinned_nodes).await;

            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let reopened = TestDb::<mmr::Family>::init_from_merkle(
                merkle,
                context.child("reopen_witness"),
                witness_config(partition, &context),
                (),
            )
            .await;
            assert!(matches!(reopened, Err(Error::DataCorrupted(_))));
        });
    }

    /// A witness entry appended but not synced (a commit interrupted before its journal sync)
    /// must be dropped on reopen, recovering the last synced commit.
    #[test_traced("INFO")]
    fn test_compact_reopen_drops_unsynced_witness() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-witness-unsynced";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;

            // Commit state A.
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, Some(Sha256::fill(0xa1)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let target_a = db.target();
            drop(db);

            // Simulate the crash window: append an entry ahead of the tip without syncing it,
            // then drop the journal. The unsynced tail must not survive reopen.
            let journal = open_witness_journal(context.child("crash"), partition).await;
            let (op_bytes, mut proof, pinned_nodes) = witness::tests::tip(&journal).await;
            proof.leaves = Location::new(*proof.leaves + 2);
            witness::tests::append_unsynced(journal, op_bytes, proof, pinned_nodes).await;

            // Reopen must drop the unsynced entry and recover state A.
            let reopened = open_db::<mmr::Family>(context.child("reopen"), partition).await;
            assert_eq!(reopened.target(), target_a);
            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_beyond_history() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-rewind-beyond").await;
            // The bootstrap commit is the oldest retained state (one leaf); no commit with zero
            // operations exists to rewind to.
            assert!(matches!(
                db.rewind(Location::new(0)).await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));

            let db =
                open_db::<mmr::Family>(context.child("reopen"), "immutable-rewind-beyond").await;
            // A target past the tip is not a commit either.
            let beyond_tip = Location::new(*db.size() + 100);
            assert!(matches!(
                db.rewind(beyond_tip).await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_between_commits() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-rewind-between").await;

            // A multi-op commit jumps the committed size from 1 (bootstrap) to 4.
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, Some(Sha256::fill(0xa1)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let root_a = db.root();
            let size_a = db.size();
            assert_eq!(size_a, Location::new(4));

            // A second commit moves the size to 6.
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[3]]), Sha256::fill(3u8))
                .merkleize(&db, Some(Sha256::fill(0xb1)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let root_b = db.root();

            // Targets inside a commit's span match no entry, even though entries exist on
            // both sides.
            let mut db = db;
            for target in [2u64, 3, 5] {
                assert!(matches!(
                    db.rewind(Location::new(target)).await,
                    Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
                ));
                db = open_db::<mmr::Family>(
                    context.child("reopen").with_attribute("target", target),
                    "immutable-rewind-between",
                )
                .await;
            }
            assert_eq!(db.root(), root_b);

            // The exact commit boundary remains a valid target.
            let db = db.rewind(size_a).await.unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.get_metadata(), Some(Sha256::fill(0xa1)));
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_multiple_commits() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-rewind-multi";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;

            // Commit A, B, C, recording the state after A.
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, Some(Sha256::fill(0xa1)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let root_a = db.root();
            let size_a = db.size();
            let target_a = db.target();

            let mut db = db;
            for i in [2u8, 3] {
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[i]]), Sha256::fill(i))
                    .merkleize(&db, Some(Sha256::fill(i)), Location::new(0))
                    .await;
                (db, _) = db.apply_batch(batch).unwrap();
                db = db.sync().await.unwrap();
            }
            assert_ne!(db.root(), root_a);

            // Rewind two commits in one call.
            let db = db.rewind(size_a).await.unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.size(), size_a);
            assert_eq!(db.get_metadata(), Some(Sha256::fill(0xa1)));
            assert_eq!(db.target(), target_a);
            drop(db);

            // The rewind is durable: reopen recovers state A.
            let db = open_db::<mmr::Family>(context.child("reopen"), partition).await;
            assert_eq!(db.root(), root_a);
            assert_eq!(db.target(), target_a);
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_to_current_is_noop() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-rewind-noop").await;
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, Some(Sha256::fill(0xa1)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let root = db.root();
            let size = db.size();

            let db = db.rewind(size).await.unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.size(), size);
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_prune_then_rewind() {
        deterministic::Runner::default().start(|context| async move {
            // One entry per section so pruning takes effect at entry granularity (pruning is
            // section-aligned and never drops a partial section).
            let mut witness_cfg = witness_config("immutable-prune-rewind", &context);
            witness_cfg.items_per_section = NZU64!(1);
            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let mut db: TestDb<mmr::Family> =
                Db::init_from_merkle(merkle, context.child("witness"), witness_cfg.clone(), ())
                    .await
                    .unwrap();

            // Commit A, B, C.
            let mut sizes = Vec::new();
            for i in [1u8, 2, 3] {
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[i]]), Sha256::fill(i))
                    .merkleize(&db, Some(Sha256::fill(i)), Location::new(0))
                    .await;
                (db, _) = db.apply_batch(batch).unwrap();
                db = db.sync().await.unwrap();
                sizes.push(db.size());
            }

            // Prune history below B: rewinding to B still works, rewinding to A does not.
            let db = db.prune(sizes[1]).await.unwrap();
            assert!(matches!(
                db.rewind(sizes[0]).await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));

            // The prune was durable, so reopen and rewind to B.
            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let db: TestDb<mmr::Family> = Db::init_from_merkle(
                merkle,
                context.child("witness").with_attribute("index", 2),
                witness_cfg,
                (),
            )
            .await
            .unwrap();
            let db = db.rewind(sizes[1]).await.unwrap();
            assert_eq!(db.size(), sizes[1]);
            assert_eq!(db.get_metadata(), Some(Sha256::fill(2)));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_prune_past_tip_keeps_tip() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-prune-past-tip";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, Some(Sha256::fill(0xa1)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let target = db.target();

            // Prune with a boundary beyond the tip: the tip entry must survive.
            let boundary = Location::new(*db.size() + 100);
            let db = db.prune(boundary).await.unwrap();
            assert_eq!(db.target(), target);
            drop(db);

            let reopened = open_db::<mmr::Family>(context.child("reopen"), partition).await;
            assert_eq!(reopened.target(), target);
            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_preserves_pre_advance_batch() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(
                context.child("db"),
                "immutable-rewind-preserves-pre-advance",
            )
            .await;

            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let size_after_first = db.size();

            // Merkleize a batch against the post-commit-A state.
            let held = db
                .new_batch()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0))
                .await;

            // Advance past that state and commit, then rewind back to it.
            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[3]]), Sha256::fill(3u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let db = db.rewind(size_after_first).await.unwrap();

            // The rewind restored the state that `held` was merkleized against, so it still
            // matches the Merkle size and applies cleanly.
            let (db, _) = db.apply_batch(held).unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_commit() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.child("db"), "immutable-noop-after-commit").await;

            let k1 = Sha256::hash(&[&[1]]);
            let v1 = Sha256::fill(11u8);
            let k2 = Sha256::hash(&[&[2]]);
            let v2 = Sha256::fill(22u8);
            let batch = db
                .new_batch()
                .set(k1, v1)
                .set(k2, v2)
                .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();
            let size_after_first = db.size();

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), size_after_first);
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-noop-after-reopen";

            let (root_before_drop, size_before_drop) = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let k1 = Sha256::hash(&[&[1]]);
                let v1 = Sha256::fill(11u8);
                let k2 = Sha256::hash(&[&[2]]);
                let v2 = Sha256::fill(22u8);
                let batch = db
                    .new_batch()
                    .set(k1, v1)
                    .set(k2, v2)
                    .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).unwrap();
                let db = db.sync().await.unwrap();
                (db.root(), db.size())
            };

            let db = open_db::<mmr::Family>(context.child("second"), partition).await;
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.size(), size_before_drop);

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), size_before_drop);
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_rewind() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.child("db"), "immutable-noop-after-rewind").await;

            let k1 = Sha256::hash(&[&[1]]);
            let v1 = Sha256::fill(11u8);
            let k2 = Sha256::hash(&[&[2]]);
            let v2 = Sha256::fill(22u8);
            let batch = db
                .new_batch()
                .set(k1, v1)
                .set(k2, v2)
                .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();
            let size_after_first = db.size();

            let k3 = Sha256::hash(&[&[3]]);
            let v3 = Sha256::fill(33u8);
            let batch = db
                .new_batch()
                .set(k3, v3)
                .merkleize(&db, Some(Sha256::fill(0xbb)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();

            let db = db.rewind(size_after_first).await.unwrap();
            assert_eq!(db.size(), size_after_first);
            assert_eq!(db.root(), root_after_first);

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), size_after_first);
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_makes_post_advance_batch_stale() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.child("db"), "immutable-rewind-makes-stale").await;

            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();
            let size_after_first = db.size();

            let batch = db
                .new_batch()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).unwrap();
            let db = db.sync().await.unwrap();

            // Merkleize a batch against the post-commit-B state, which the rewind will discard.
            let held = db
                .new_batch()
                .set(Sha256::hash(&[&[3]]), Sha256::fill(3u8))
                .merkleize(&db, None, Location::new(0))
                .await;

            let db = db.rewind(size_after_first).await.unwrap();

            // After rewind, mem.size reflects post-commit-A, but the held batch starts after
            // post-commit-B. Apply must be rejected with StaleBatch.
            assert!(matches!(
                db.apply_batch(held),
                Err(Error::StaleBatch { .. })
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_floor_beyond_size() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-floor-beyond").await;

            let batch = db.new_batch().merkleize(&db, None, Location::new(2)).await;

            assert!(matches!(
                db.apply_batch(batch),
                Err(Error::FloorBeyondSize(floor, tip))
                    if floor == Location::new(2) && tip == Location::new(1)
            ));
        });
    }

    // A chained batch whose ancestor's floor exceeds that ancestor's own commit location
    // must be rejected, identifying the ancestor's bound rather than the tip's.
    #[test_traced("INFO")]
    fn test_compact_ancestor_floor_beyond_size() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "immutable-ancestor-floor-beyond")
                .await;

            // parent: set + commit at loc 2, floor=3 (one past parent's commit).
            let parent = db
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(3))
                .await;
            // child: valid on its own (floor=0), but parent's floor is bad.
            let child = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[&[2]]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0))
                .await;

            assert!(matches!(
                db.apply_batch(child),
                Err(Error::FloorBeyondSize(floor, commit))
                    if floor == Location::new(3) && commit == Location::new(2)
            ));
        });
    }
}

//! A keyless authenticated db that discards historical operations, retaining only a witness
//! for each applied batch.
//!
//! Mirrors the API of [`crate::qmdb::keyless::Keyless`] (`new_batch -> merkleize ->
//! apply_batch -> commit / sync / start_sync`, pipelined batch chains, `StaleBatch` validation)
//! but is backed by the peak-only [`crate::merkle::compact`]. Because history is discarded,
//! there are no `get` / `proof` / `bounds` methods. Use the full variant if you need them.
//!
//! # Witness journal
//!
//! The witness journal holds a complete snapshot of every applied batch, so [`Db::rewind`] can
//! restore any retained applied state (history is bounded only by [`Db::prune`]). Reopen
//! and rewind restore the db's in-memory state from an entry. The Merkle is rebuilt from the
//! stored pinned nodes and operation, and the commit fields are decoded from the operation. An
//! entry that cannot rebuild surfaces as [`Error::DataCorrupted`]. The witness is also what lets
//! compact nodes serve compact sync without retaining historical operations.
//!
//! # Inactivity floor
//!
//! Commits carry an inactivity floor for wire-format compatibility with
//! [`crate::qmdb::keyless::Keyless`]: the root is computed over the encoded operation
//! sequence, and that sequence must include the same floor to produce the same root as the
//! full variant. The floor has no effect on pruning or snapshot rebuilding here; all
//! historical in-memory state is discarded whenever a batch is applied.

use super::operation::Operation;
pub use crate::qmdb::compact::Config;
use crate::{
    Context,
    journal::contiguous::variable::{self, Config as JournalConfig},
    merkle::{Family, Location, batch, compact as compact_merkle},
    qmdb::{
        self, Error,
        any::value::ValueEncoding,
        batch_chain::{self, Bounds, Commitment},
        compact::{
            batch as compact_batch,
            witness::{self, VerifiedWitness},
        },
        sync::{CompactTarget, FeedbackTx, Request, Response, Source},
    },
};
use commonware_codec::{Encode, EncodeShared, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use std::sync::{Arc, Weak};

/// A keyless authenticated db that discards historical operations, retaining only a witness
/// for each applied batch.
pub struct Db<F, E, V, H, C, S: Strategy>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    merkle: compact_merkle::Merkle<F, H::Digest, S>,
    root: H::Digest,
    last_commit_loc: Location<F>,
    last_commit_metadata: Option<V::Value>,
    inactivity_floor_loc: Location<F>,
    commit_codec_config: C,
    witness: witness::Store<E, F, H::Digest>,
}

impl<F, E, V, H, C, S: Strategy> std::fmt::Debug for Db<F, E, V, H, C, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Db")
            .field("size", &self.size())
            .field("inactivity_floor_loc", &self.inactivity_floor_loc())
            .finish_non_exhaustive()
    }
}

/// A speculative batch for a compact keyless db.
#[allow(clippy::type_complexity)]
pub struct UnmerkleizedBatch<F, H, V, S: Strategy>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    merkle_batch: compact_merkle::UnmerkleizedBatch<F, H::Digest, S>,
    appends: Vec<V::Value>,
    parent: Option<Arc<MerkleizedBatch<F, H::Digest, V, S>>>,
    base: batch_chain::Commitment<F, H::Digest>,
}

/// A speculative batch whose root digest has been computed.
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, V: ValueEncoding, S: Strategy>
where
    Operation<F, V>: EncodeShared,
{
    pub(super) merkle_batch: Arc<batch::MerkleizedBatch<F, D, S>>,
    pub(super) commit_metadata: Option<V::Value>,
    pub(super) parent: Option<Weak<Self>>,
    pub(super) bounds: batch_chain::Bounds<F, D>,
}

impl<F: Family, D: Digest, V: ValueEncoding, S: Strategy> MerkleizedBatch<F, D, V, S>
where
    Operation<F, V>: EncodeShared,
{
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> + use<F, D, V, S> {
        batch_chain::ancestors(self.parent.clone(), |batch| batch.parent.as_ref())
    }

    /// The [`Commitment`] this batch commits to.
    pub(super) const fn commitment(&self) -> Commitment<F, D> {
        self.bounds.tip
    }

    /// Return the root digest after this batch is applied.
    pub const fn root(&self) -> D {
        self.bounds.tip.root
    }

    /// Return the [`Bounds`] of the batch.
    pub const fn bounds(&self) -> &Bounds<F, D> {
        &self.bounds
    }

    /// Create a new speculative batch with this one as its parent.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, V, S>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            merkle_batch: compact_merkle::UnmerkleizedBatch::wrap(self.merkle_batch.new_batch()),
            appends: Vec::new(),
            parent: Some(Arc::clone(self)),
            base: self.commitment(),
        }
    }
}

impl<F, H, V, S> UnmerkleizedBatch<F, H, V, S>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    pub(super) fn new<E, C>(
        db: &Db<F, E, V, H, C, S>,
        base: batch_chain::Commitment<F, H::Digest>,
    ) -> Self
    where
        E: Context,
        C: Clone + Send + Sync + 'static,
        Operation<F, V>: Read<Cfg = C>,
    {
        Self {
            merkle_batch: db.merkle.new_batch(),
            appends: Vec::new(),
            parent: None,
            base,
        }
    }

    /// The database boundary for this batch chain.
    ///
    /// A batch created from the database uses its base. A child inherits its parent's `db`.
    fn db(&self) -> Commitment<F, H::Digest> {
        self.parent
            .as_ref()
            .map_or(self.base, |parent| parent.bounds.db)
    }

    pub fn append(mut self, value: V::Value) -> Self {
        self.appends.push(value);
        self
    }

    /// Resolve appends into operations, merkleize, and return an `Arc<MerkleizedBatch>`.
    ///
    /// `inactivity_floor` is threaded through the commit operation for wire-format parity with
    /// [`crate::qmdb::keyless::Keyless`]. It must be >= the database's current floor
    /// (monotonically non-decreasing) and at most the batch's commit location
    /// (`total_size - 1`); these bounds are validated, but the floor does not drive any local
    /// pruning or retention in this variant.
    #[tracing::instrument(
        name = "qmdb.keyless.compact.batch.merkleize",
        level = "info",
        skip_all
    )]
    pub async fn merkleize<E, C>(
        self,
        db: &Db<F, E, V, H, C, S>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, V, S>>
    where
        F: Family,
        E: Context,
        C: Clone + Send + Sync + 'static,
        Operation<F, V>: Read<Cfg = C>,
    {
        let live_ancestors: Vec<_> =
            batch_chain::parent_and_ancestors(self.parent.as_ref(), |parent| parent.ancestors())
                .collect();
        let boundary = batch_chain::effective_boundary(
            self.db(),
            live_ancestors.last().map(|oldest| oldest.bounds.base),
        );

        let mut ops: Vec<Operation<F, V>> = Vec::with_capacity(self.appends.len() + 1);
        for value in self.appends {
            ops.push(Operation::Append(value));
        }
        ops.push(Operation::Commit(metadata.clone(), inactivity_floor));

        let total_size = self.base.size + ops.len() as u64;
        let inactive_peaks = F::inactive_peaks(total_size, inactivity_floor);
        let (merkle, root) = compact_batch::merkleize_ops::<F, H, S, _>(
            &db.merkle,
            self.merkle_batch,
            ops,
            inactive_peaks,
        )
        .await
        .expect("inactive_peaks computed from batch size");

        let ancestors = batch_chain::collect_ancestor_bounds(
            live_ancestors,
            |batch| batch.bounds.inactivity_floor,
            |batch| batch.commitment(),
        );

        Arc::new(MerkleizedBatch {
            merkle_batch: merkle,
            commit_metadata: metadata,
            parent: self.parent.as_ref().map(Arc::downgrade),
            bounds: batch_chain::Bounds {
                base: self.base,
                db: boundary,
                tip: Commitment::new(total_size, root),
                ancestors,
                inactivity_floor,
            },
        })
    }
}

impl<F, E, V, H, C, S> Db<F, E, V, H, C, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    fn encode_commit_op(metadata: Option<V::Value>, inactivity_floor_loc: Location<F>) -> Vec<u8> {
        Operation::<F, V>::Commit(metadata, inactivity_floor_loc)
            .encode()
            .to_vec()
    }

    /// Build a compact db from state fetched by the sync engine.
    ///
    /// The imported witness lives only in memory until the first [`Self::apply_batch`],
    /// [`Self::commit`], [`Self::sync`], or [`Self::start_sync`]. Applying a batch replaces it with
    /// the newly applied journal checkpoint; a durability method journals it directly. Until one
    /// of those operations succeeds, rewind and prune are rejected.
    pub(crate) fn init_from_sync(
        strategy: S,
        journal: witness::Journal<E, F, H::Digest>,
        commit_codec_config: C,
        last_commit_loc: Location<F>,
        pinned_nodes: Vec<H::Digest>,
        last_commit_op: Operation<F, V>,
    ) -> Result<Self, Error<F>> {
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::UnexpectedData(last_commit_loc));
        };
        witness::validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;

        let op_bytes = Self::encode_commit_op(last_commit_metadata.clone(), inactivity_floor_loc);
        let merkle =
            compact_merkle::Merkle::from_compact_state(strategy, last_commit_loc, pinned_nodes)?;
        let hasher = qmdb::hasher::<H>();
        merkle.append_leaf(&hasher, &op_bytes)?;
        let imported = witness::build_witness::<F, H, S>(&merkle, inactivity_floor_loc, op_bytes)?;
        merkle.prune_to_frontier();

        let witness = witness::Store::from_import(journal, imported);
        let root = witness.with(|w| w.root);
        Ok(Self {
            merkle,
            root,
            last_commit_loc,
            last_commit_metadata,
            inactivity_floor_loc,
            commit_codec_config,
            witness,
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
        Operation<F, V>: Read<Cfg = C>,
    {
        // Bootstrap: append an initial Commit(None, 0) on first open.
        let journal: witness::Journal<E, F, H::Digest> =
            variable::Journal::init(witness_context, witness_config).await?;
        let (witness, last_commit_op) = witness::init::<E, F, H, S, Operation<F, V>>(
            journal,
            &mut merkle,
            &commit_codec_config,
            Operation::<F, V>::Commit(None, Location::new(0))
                .encode()
                .to_vec(),
        )
        .await?;
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::DataCorrupted("last operation was not a commit"));
        };
        let last_commit_loc = witness.with(|w| w.size()) - 1;
        let root = witness.with(|w| w.root);

        Ok(Self {
            merkle,
            root,
            last_commit_loc,
            last_commit_metadata,
            inactivity_floor_loc,
            commit_codec_config,
            witness,
        })
    }

    /// Return the root of the db.
    pub const fn root(&self) -> H::Digest {
        self.root
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
        self.last_commit_loc + 1
    }

    /// Get the metadata associated with the last commit.
    pub fn get_metadata(&self) -> Option<V::Value> {
        self.last_commit_metadata.clone()
    }

    /// Return the compact-sync target described by the current witness.
    ///
    /// This reflects the most recently applied batch. The target remains non-durable until a
    /// covering [`Self::commit`], [`Self::sync`], or [`Self::start_sync`] completes.
    pub fn target(&self) -> CompactTarget<F, H::Digest> {
        self.witness.with(VerifiedWitness::target)
    }

    /// The [`Commitment`] for the database's current state.
    pub(crate) fn commitment(&self) -> batch_chain::Commitment<F, H::Digest> {
        batch_chain::Commitment::new(self.last_commit_loc + 1, self.root())
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, V, S> {
        UnmerkleizedBatch::new(self, self.commitment())
    }

    /// Create an owned merkleized batch representing the current applied state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, V, S>>
    where
        F: Family,
    {
        Arc::new(MerkleizedBatch {
            merkle_batch: self.merkle.to_batch(),
            commit_metadata: self.last_commit_metadata.clone(),
            parent: None,
            bounds: batch_chain::Bounds::from_db(self.commitment(), self.inactivity_floor_loc),
        })
    }

    /// Check that `batch` can be applied to the database in its current state, without
    /// applying it.
    ///
    /// [`Self::apply_batch`] runs the same validation but consumes the database when it
    /// fails; callers that want to reject a bad batch and keep the handle can check first.
    pub fn validate_batch(
        &self,
        batch: &MerkleizedBatch<F, H::Digest, V, S>,
    ) -> Result<(), Error<F>> {
        batch
            .bounds
            .validate_apply_to(self.commitment(), self.inactivity_floor_loc)
    }

    /// Apply a merkleized batch to the database.
    ///
    /// Returns the range of locations written. The state is updated in memory and appended to the
    /// witness journal. Call [`Self::commit`] or [`Self::sync`], or await the handle returned by
    /// [`Self::start_sync`], to make the applied state durable.
    ///
    /// # Errors
    ///
    /// - [`Error::StaleBatch`] if the batch is detected as stale (see
    ///   [`crate::qmdb::batch_chain`] for more details).
    /// - [`Error::FloorRegressed`] if any commit in the chain declares a floor below the
    ///   previous commit's floor.
    /// - [`Error::FloorBeyondSize`] if any commit in the chain declares a floor beyond its own
    ///   commit location.
    #[tracing::instrument(name = "qmdb.keyless.compact.db.apply_batch", level = "info", skip_all)]
    pub async fn apply_batch(
        mut self,
        batch: Arc<MerkleizedBatch<F, H::Digest, V, S>>,
    ) -> Result<(Self, core::ops::Range<Location<F>>), Error<F>> {
        self.validate_batch(&batch)?;

        let start_loc = self.last_commit_loc + 1;
        self.merkle.apply_batch(&batch.merkle_batch)?;
        self.root = batch.root();
        self.last_commit_loc = batch.bounds.tip.size - 1;
        self.last_commit_metadata = batch.commit_metadata.clone();
        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        let last_commit_metadata = self.last_commit_metadata.clone();
        let inactivity_floor_loc = self.inactivity_floor_loc;
        self.witness = self
            .witness
            .apply::<H, S>(&self.merkle, inactivity_floor_loc, || {
                Self::encode_commit_op(last_commit_metadata, inactivity_floor_loc)
            })
            .await?;
        Ok((self, start_loc..batch.bounds.tip.size))
    }

    /// Begin durably persisting the current db state to disk.
    ///
    /// Awaiting the returned [Handle] provides the same durability guarantee as [Self::commit],
    /// plus a best-effort attempt to bound the recovery needed on reopen. Use [Self::sync] to
    /// guarantee none is needed. A new sync waits for the prior sync before starting. Failures
    /// of the deferred durability work surface on the returned handle and the next durability
    /// operation.
    #[tracing::instrument(name = "qmdb.keyless.compact.db.start_sync", level = "info", skip_all)]
    pub async fn start_sync(mut self) -> Result<(Self, Handle<()>), Error<F>> {
        let last_commit_metadata = self.last_commit_metadata.clone();
        let inactivity_floor_loc = self.inactivity_floor_loc;
        let handle;
        (self.witness, handle) = self
            .witness
            .start_sync::<H, S>(&self.merkle, inactivity_floor_loc, || {
                Self::encode_commit_op(last_commit_metadata, inactivity_floor_loc)
            })
            .await?;
        Ok((self, handle))
    }

    /// Durably persist the current db state to disk. This is faster than [`Self::sync`] but
    /// reopen may need to replay the witness journal's tail to recover.
    #[tracing::instrument(name = "qmdb.keyless.compact.db.commit", level = "info", skip_all)]
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
    #[tracing::instrument(name = "qmdb.keyless.compact.db.sync", level = "info", skip_all)]
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

    /// Rewind the db to the applied state with exactly `target` operations, discarding any
    /// uncommitted batches and any later states. The rewind is made durable before this
    /// method returns.
    ///
    /// # Errors
    ///
    /// Returns [`crate::merkle::Error::RewindBeyondHistory`] (wrapped as [`Error::Merkle`]) if
    /// no retained applied state has exactly `target` operations (never applied, or pruned).
    #[tracing::instrument(name = "qmdb.keyless.compact.db.rewind", level = "info", skip_all)]
    pub async fn rewind(mut self, target: Location<F>) -> Result<Self, Error<F>>
    where
        F: Family,
    {
        // A clean current target only needs to settle its pipelined sync. An uncommitted target
        // takes the regular rewind path so the witness journal becomes durable before return.
        if self.size() == target
            && self.witness.with(|w| w.size()) == target
            && !self.witness.has_uncommitted_state()
        {
            self.witness.wait_for_sync().await?;
            return Ok(self);
        }

        let last_commit_op;
        (self.witness, last_commit_op) = self
            .witness
            .rewind::<H, S, Operation<F, V>>(&self.merkle, target, &self.commit_codec_config)
            .await?;
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::DataCorrupted("last operation was not a commit"));
        };
        self.last_commit_metadata = last_commit_metadata;
        self.inactivity_floor_loc = inactivity_floor_loc;
        self.last_commit_loc = target - 1;
        self.root = self.witness.with(|w| w.root);
        Ok(self)
    }

    /// Drop witnesses for commits with fewer than `pruning_boundary` operations. Some witness
    /// below the boundary may survive.
    ///
    /// Pruning bounds how far back [`Self::rewind`] can reach; the current commit's witness
    /// always survives. The prune is made durable before this method returns.
    ///
    /// # Errors
    ///
    /// Fails if a compact-sync import has not yet been applied to the witness journal.
    #[tracing::instrument(name = "qmdb.keyless.compact.db.prune", level = "info", skip_all)]
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

impl<F, E, V, H, C, S> Source for Db<F, E, V, H, C, S>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared + Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Family = F;
    type Digest = H::Digest;
    type Op = Operation<F, V>;
    type Error = qmdb::Error<F>;

    async fn serve(
        &self,
        request: Request<F>,
    ) -> Result<(Response<F, Self::Op, H::Digest>, FeedbackTx), Self::Error> {
        Ok((
            self.witness
                .compact_state(&self.commit_codec_config, request)?,
            None,
        ))
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
        BufferPooler, Runner as _, Spawner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, fail_pending_syncs},
        reschedule,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, sequence::U64};
    use core::future::Future;
    use futures::FutureExt as _;
    use std::num::{NonZeroU16, NonZeroUsize};

    type TestDb<F> = Db<F, deterministic::Context, FixedEncoding<U64>, Sha256, (), Sequential>;

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
            replay_buffer: NZUsize!(1024),
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

    /// The witness serves only the request matching its single committed state. Each mismatch
    /// reports the same error a pruned operation log would.
    #[test_traced("INFO")]
    fn test_serve_refuses_requests_outside_witness() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-serve-refusal").await;
            let floor = db.inactivity_floor_loc();
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let n = db.target().size;
            let boundary = |size: Location<mmr::Family>, start: Location<mmr::Family>| {
                Request::Boundary { size, start }
            };
            let operations =
                |size: Location<mmr::Family>, start: Location<mmr::Family>| Request::Operations {
                    size,
                    start,
                    max_ops: NZU64!(1),
                };

            let beyond = n + 1;
            assert!(matches!(
                db.serve(boundary(beyond, n)).await,
                Err(Error::Merkle(crate::merkle::Error::RangeOutOfBounds(_)))
            ));
            assert!(matches!(
                db.serve(operations(Location::new(0), Location::new(0)))
                    .await,
                Err(Error::Merkle(crate::merkle::Error::RangeOutOfBounds(_)))
            ));
            assert!(matches!(
                db.serve(operations(n - 1, n - 2)).await,
                Err(Error::Journal(crate::journal::Error::ItemPruned(_)))
            ));
            assert!(matches!(
                db.serve(boundary(n, n)).await,
                Err(Error::Merkle(crate::merkle::Error::RangeOutOfBounds(_)))
            ));
            assert!(matches!(
                db.serve(boundary(n, n - 2)).await,
                Err(Error::Journal(crate::journal::Error::ItemPruned(_)))
            ));

            // Requests without pinned nodes are also served, even when they ask for more operations
            // than the witness holds.
            let (response, feedback_tx) = db
                .serve(Request::Operations {
                    size: n,
                    start: n - 1,
                    max_ops: NZU64!(5),
                })
                .await
                .unwrap();
            assert!(feedback_tx.is_none());
            let Response::Operations { operations, .. } = response else {
                panic!("operations request should get an operations response");
            };
            assert_eq!(operations.len(), 1);
            let (response, _) = db.serve(boundary(n, n - 1)).await.unwrap();
            assert!(matches!(response, Response::Boundary { .. }));
        });
    }

    /// A compact db over a delayed-sync storage backend.
    type DelayedDb = Db<
        mmr::Family,
        DelayedSyncContext<deterministic::Context>,
        FixedEncoding<U64>,
        Sha256,
        (),
        Sequential,
    >;

    /// Open a [DelayedDb] whose blob syncs park on `pending`.
    ///
    /// Init durably persists the bootstrap witness, so while syncs park the returned future
    /// must be driven with [drive_pending_syncs] (or the mock unblocked first).
    fn open_delayed_db(
        context: &deterministic::Context,
        label: &'static str,
        partition: &str,
        pending: &PendingSyncs,
    ) -> impl Future<Output = Result<DelayedDb, Error<mmr::Family>>> {
        let witness_cfg = witness_config(partition, context);
        let merkle = crate::merkle::compact::Merkle::new(Sequential);
        let context = DelayedSyncContext {
            inner: context.child(label),
            pending: pending.clone(),
        };
        DelayedDb::init_from_merkle(merkle, context.child("witness"), witness_cfg, ())
    }

    /// Apply a single-append batch carrying `seed` as both value and metadata.
    async fn apply_append(db: DelayedDb, seed: u64) -> DelayedDb {
        let floor = db.inactivity_floor_loc();
        let batch = db
            .new_batch()
            .append(U64::new(seed))
            .merkleize(&db, Some(U64::new(seed)), floor)
            .await;
        let (db, _) = db.apply_batch(batch).await.unwrap();
        db
    }

    /// Leave a failed recovery-watermark sync retained after dropping its public handle.
    async fn fail_dropped_watermark_sync(mut db: DelayedDb, pending: &PendingSyncs) -> DelayedDb {
        // Prove the data durable so the next call only advances recovery metadata.
        let first;
        (db, first) = db.start_sync().await.unwrap();
        drive_pending_syncs(pending, first).await.unwrap();

        let dropped;
        (db, dropped) = db.start_sync().await.unwrap();
        assert_eq!(
            pending.lock().len(),
            1,
            "expected only the recovery-watermark sync"
        );
        fail_pending_syncs(pending);
        drop(dropped);
        db
    }

    /// Applying a successor does not wait for the witness sync already in flight.
    #[test_traced]
    fn test_compact_apply_overlaps_start_sync() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "keyless-start-sync-overlap";
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", partition, &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_append(db, 1).await;

            let starts_before = pending.starts();
            let entered_before = pending.entered();
            let completions_before = pending.completions();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(pending.starts() > starts_before);
            assert_eq!(pending.completions(), completions_before);
            let first_target = db.target();

            let waiter = ctx
                .child("await_sync")
                .spawn(|_| async move { handle.await.unwrap() });
            while pending.entered() == entered_before {
                reschedule().await;
            }

            db = apply_append(db, 2).await;
            assert_ne!(db.root(), first_target.root);
            let second_target = db.target();
            assert_ne!(second_target, first_target);
            assert_eq!(
                pending.completions(),
                completions_before,
                "the database made progress while the sync was still in flight"
            );

            pending.unblock();
            waiter.await.unwrap();

            // The successor becomes durable after the next start_sync handle completes.
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            drop(db);

            let db = open_delayed_db(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.target(), second_target);
            assert_eq!(db.get_metadata(), Some(U64::new(2)));
            let db = db.rewind(first_target.size).await.unwrap();
            assert_eq!(db.target(), first_target);
            db.destroy().await.unwrap();
        });
    }

    /// State persisted via an awaited start_sync handle is recovered on reopen.
    #[test_traced]
    fn test_compact_start_sync_recovery() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "keyless-start-sync-recovery";
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db(&ctx, "delayed", partition, &pending)
                .await
                .unwrap();
            db = apply_append(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();
            let root = db.root();
            drop(db);

            let db = open_delayed_db(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.get_metadata(), Some(U64::new(1)));
            db.destroy().await.unwrap();
        });
    }

    /// A sync begun by `start_sync` that fails in flight surfaces the error through both the
    /// returned handle and the next durability operation, even when that operation has nothing
    /// new to persist.
    #[test_traced]
    fn test_compact_start_sync_failure_propagates() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db(&ctx, "delayed", "keyless-start-sync-fail", &pending)
                .await
                .unwrap();
            db = apply_append(db, 1).await;

            // Arm all future syncs to resolve to an injected error.
            pending.arm_fail();

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(
                handle.await.is_err(),
                "the sync handle surfaces the failure"
            );
            let starts_before = pending.starts();

            // The witness entry was already appended, so this commit has nothing to stage.
            // It must still observe the retained failure rather than no-op.
            assert!(
                db.commit().await.is_err(),
                "the next durability op surfaces the failed in-flight sync"
            );
            assert_eq!(
                pending.starts(),
                starts_before,
                "the surfaced error is the retained failure, not a fresh sync's"
            );
        });
    }

    /// A `sync` with nothing new to persist still drains (and proves) the sync started by a
    /// prior `start_sync`.
    #[test_traced]
    fn test_compact_start_sync_then_noop_sync_drains() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "keyless-start-sync-noop-drain";
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", partition, &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_append(db, 1).await;

            let starts_before = pending.starts();
            let completions_before = pending.completions();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(pending.starts() > starts_before);
            assert_eq!(pending.completions(), completions_before);
            let root = db.root();

            let db = {
                let mut sync = std::pin::pin!(db.sync());
                assert!(
                    sync.as_mut().now_or_never().is_none(),
                    "sync proceeded while the started sync was pending"
                );
                pending.unblock();
                sync.await.unwrap()
            };
            handle.await.unwrap();
            assert!(pending.completions() > completions_before);
            drop(db);

            let db = open_delayed_db(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            db.destroy().await.unwrap();
        });
    }

    /// A no-op `sync` returns a retained metadata failure before starting new journal work.
    #[test_traced]
    fn test_compact_start_sync_then_noop_sync_fails_without_new_work() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(
                &ctx,
                "delayed",
                "keyless-start-sync-noop-sync-fail",
                &pending,
            );
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_append(db, 1).await;
            db = fail_dropped_watermark_sync(db, &pending).await;

            let starts_before = pending.starts();
            assert!(
                drive_pending_syncs(&pending, db.sync()).await.is_err(),
                "sync absorbed the retained metadata failure"
            );
            assert_eq!(
                pending.starts(),
                starts_before,
                "sync started new journal work before returning the retained failure"
            );
        });
    }

    /// A `commit` with nothing new to persist still waits for the sync started by a prior
    /// `start_sync` before reporting the tip durable, and starts no journal work when that
    /// sync succeeds.
    #[test_traced]
    fn test_compact_start_sync_then_noop_commit_waits() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", "keyless-start-sync-noop-commit", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_append(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            let starts_before = pending.starts();

            let db = {
                let mut commit = std::pin::pin!(db.commit());
                assert!(
                    commit.as_mut().now_or_never().is_none(),
                    "commit proceeded while the started sync was pending"
                );
                pending.unblock();
                commit.await.unwrap()
            };
            handle.await.unwrap();
            assert_eq!(
                pending.starts(),
                starts_before,
                "a successful pipelined sync still triggered journal work"
            );
            db.destroy().await.unwrap();
        });
    }

    /// A `start_sync` with nothing new to persist returns a working handle and appends no
    /// duplicate witness entry.
    #[test_traced]
    fn test_compact_start_sync_noop_second_call() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "keyless-start-sync-noop-second";
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", partition, &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_append(db, 1).await;

            let h1;
            (db, h1) = db.start_sync().await.unwrap();
            // Release the parked sync: a second start_sync waits for the prior sync before
            // starting, so back-to-back calls under a parked mock would deadlock.
            pending.unblock();
            h1.await.unwrap();

            let h2;
            (db, h2) = db.start_sync().await.unwrap();
            h2.await.unwrap();
            let root = db.root();
            drop(db);

            // The journal holds exactly the bootstrap entry and the one durable witness.
            let journal = open_witness_journal(ctx.child("probe"), partition).await;
            assert_eq!(journal.size(), 2);
            drop(journal);

            let db = open_delayed_db(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            db.destroy().await.unwrap();
        });
    }

    /// A rewind to the current size waits for the in-flight sync and adopts its proof of
    /// durability instead of starting new journal work.
    #[test_traced]
    fn test_compact_start_sync_rewind_fast_path_drains() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "keyless-start-sync-rewind-drain";
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", partition, &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_append(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            let root = db.root();
            let size = db.size();

            let starts_before = pending.starts();
            let db = {
                let mut rewind = std::pin::pin!(db.rewind(size));
                assert!(
                    rewind.as_mut().now_or_never().is_none(),
                    "rewind proceeded while the started sync was pending"
                );
                pending.unblock();
                rewind.await.unwrap()
            };
            handle.await.unwrap();
            assert_eq!(
                pending.starts(),
                starts_before,
                "the fast path started journal work instead of adopting the proven sync"
            );
            assert_eq!(db.root(), root);
            drop(db);

            // The awaited pipelined sync made the witness entry durable.
            let db = open_delayed_db(&ctx, "reopen", partition, &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            db.destroy().await.unwrap();
        });
    }

    /// A rewind to the current size fails when the sync started for the tip witness has
    /// already failed, rather than reporting the unproven tip as durable.
    #[test_traced]
    fn test_compact_start_sync_rewind_fast_path_fails() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db =
                open_delayed_db(&ctx, "delayed", "keyless-start-sync-rewind-fail", &pending)
                    .await
                    .unwrap();
            db = apply_append(db, 1).await;

            pending.arm_fail();
            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            assert!(handle.await.is_err());
            let size = db.size();
            assert!(
                db.rewind(size).await.is_err(),
                "rewind reported an unproven tip as durable"
            );
        });
    }

    /// A metadata sync failure from `start_sync` resurfaces on the next `commit`, even when
    /// that commit has new state to persist.
    #[test_traced]
    fn test_compact_start_sync_metadata_failure_resurfaces_on_commit() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&ctx, "delayed", "keyless-start-sync-meta-fail", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_append(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();

            // start_sync parks the data sync and then the offsets sync. Complete the data
            // sync and fail the offsets sync.
            {
                let mut parked = pending.lock();
                assert_eq!(
                    parked.len(),
                    2,
                    "expected the data and offsets syncs parked"
                );
                let offsets = parked.pop().unwrap();
                let data = parked.pop().unwrap();
                data.release.send(Ok(())).unwrap();
                offsets
                    .release
                    .send(Err(commonware_runtime::Error::Io(
                        std::io::Error::other("injected sync failure").into(),
                    )))
                    .unwrap();
            }
            assert!(
                handle.await.is_err(),
                "the sync handle surfaces the failure"
            );

            // Later syncs pass; only the retained offsets failure remains.
            pending.unblock();

            // Apply another batch to prove commit checks the prior sync before persisting a new
            // witness.
            let db = apply_append(db, 2).await;
            assert!(
                db.commit().await.is_err(),
                "commit absorbed the retained metadata failure"
            );
        });
    }

    /// A later `start_sync` cannot replace an unobserved failure from the prior handle.
    #[test_traced]
    fn test_compact_start_sync_retains_dropped_metadata_failure() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(
                &ctx,
                "delayed",
                "keyless-start-sync-dropped-meta-fail",
                &pending,
            );
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            db = apply_append(db, 1).await;
            // Leave only the failed recovery-watermark completion for the next call to observe.
            db = fail_dropped_watermark_sync(db, &pending).await;

            // The store retains the dropped handle's completion. Deferred failures stay on the
            // handle channel, so this call succeeds but its handle must fail.
            let next;
            (db, next) = db.start_sync().await.unwrap();
            assert!(
                drive_pending_syncs(&pending, next).await.is_err(),
                "a later start_sync masked the retained metadata failure"
            );
            drop(db);
        });
    }

    /// Once a start_sync handle completes successfully, a commit and a rewind to the current
    /// size have nothing left to prove and touch no storage.
    #[test_traced]
    fn test_compact_start_sync_proven_skips_journal() {
        deterministic::Runner::default().start(|ctx| async move {
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db(&ctx, "delayed", "keyless-start-sync-proven", &pending)
                .await
                .unwrap();
            db = apply_append(db, 1).await;

            let handle;
            (db, handle) = db.start_sync().await.unwrap();
            handle.await.unwrap();

            let starts_before = pending.starts();
            let db = db.commit().await.unwrap();
            let size = db.size();
            let db = db.rewind(size).await.unwrap();
            assert_eq!(
                pending.starts(),
                starts_before,
                "a proven pipelined sync still triggered journal work"
            );
            db.destroy().await.unwrap();
        });
    }

    /// The first persist after a compact-sync import can be pipelined: awaiting the handle
    /// makes the imported witness durable.
    #[test_traced("INFO")]
    fn test_compact_start_sync_persists_import() {
        deterministic::Runner::default().start(|context| async move {
            let dst = "keyless-import-start-sync-dst";
            let src = "keyless-import-start-sync-src";
            let meta_a = U64::new(11);
            let meta_b = U64::new(22);

            // Build state B in a separate source partition and capture its validated state.
            let target_b = {
                let source = open_db::<mmr::Family>(context.child("src"), src).await;
                let batch = source
                    .new_batch()
                    .append(U64::new(2))
                    .merkleize(&source, Some(meta_b.clone()), Location::new(0))
                    .await;
                let (source, _) = source.apply_batch(batch).await.unwrap();
                let source = source.sync().await.unwrap();
                source.target()
            };
            let (_, size_b, pinned_b) = {
                let journal = open_witness_journal(context.child("src_tip"), src).await;
                witness::tests::tip(&journal).await
            };
            assert_eq!(size_b, target_b.size);

            // Seed the destination partition with a different committed state A.
            {
                let seeded = open_db::<mmr::Family>(context.child("seed"), dst).await;
                let batch = seeded
                    .new_batch()
                    .append(U64::new(1))
                    .merkleize(&seeded, Some(meta_a), Location::new(0))
                    .await;
                let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                let seeded = seeded.sync().await.unwrap();
                assert_ne!(seeded.target(), target_b);
            }

            // Import state B over the destination and make it durable through a pipelined sync.
            {
                let journal = open_witness_journal(context.child("import"), dst).await;
                let imported = TestDb::<mmr::Family>::init_from_sync(
                    Sequential,
                    journal,
                    (),
                    size_b - 1,
                    pinned_b,
                    Operation::Commit(Some(meta_b.clone()), Location::new(0)),
                )
                .unwrap();
                assert_eq!(imported.target(), target_b);
                let (_imported, handle) = imported.start_sync().await.unwrap();
                handle.await.unwrap();
            }

            // Reopen recovers the imported state, replacing state A.
            let db = open_db::<mmr::Family>(context.child("reopen"), dst).await;
            assert_eq!(db.target(), target_b);
            assert_eq!(db.root(), target_b.root);
            assert_eq!(db.get_metadata(), Some(meta_b));
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_stale_batch_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-stale").await;
            let floor = db.inactivity_floor_loc();

            let batch_a = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), floor)
                .await;
            let batch_b = db
                .new_batch()
                .append(U64::new(2))
                .merkleize(&db, Some(U64::new(22)), floor)
                .await;

            let expected_root = batch_a.root();
            let (db, _) = db.apply_batch(batch_a).await.unwrap();
            assert_eq!(db.root(), expected_root);
            assert!(matches!(
                db.apply_batch(batch_b).await,
                Err(Error::StaleBatch)
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_delayed_merkleize_after_ancestor_apply() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-delayed-child").await;
            let floor = db.inactivity_floor_loc();

            let a = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, None, floor)
                .await;
            let b = a
                .new_batch::<Sha256>()
                .append(U64::new(2))
                .merkleize(&db, None, floor)
                .await;
            let c = b.new_batch::<Sha256>().append(U64::new(3));

            let (db, _) = db.apply_batch(a).await.unwrap();
            let c = c.merkleize(&db, None, floor).await;
            let expected_root = c.root();
            let (db, _) = db.apply_batch(c).await.unwrap();

            assert_eq!(db.root(), expected_root);
        });
    }

    /// `to_batch()` reflects the current applied state before it becomes durable.
    #[test_traced("INFO")]
    fn test_compact_to_batch_reflects_live_state() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-to-batch-live").await;
            let floor = db.inactivity_floor_loc();

            let pre_apply_root = db.root();
            let pre_snapshot = db.to_batch();
            assert_eq!(
                pre_snapshot.root(),
                pre_apply_root,
                "snapshot before any mutation should match the live root"
            );

            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();

            // Observe the applied state before making it durable.
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
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-chained-stale").await;
            let floor = db.inactivity_floor_loc();

            let common_parent = db
                .new_batch()
                .append(U64::new(10))
                .merkleize(&db, Some(U64::new(110)), floor)
                .await;
            let sibling_a = common_parent
                .new_batch::<Sha256>()
                .append(U64::new(11))
                .merkleize(&db, Some(U64::new(111)), floor)
                .await;
            let sibling_b = common_parent
                .new_batch::<Sha256>()
                .append(U64::new(12))
                .merkleize(&db, Some(U64::new(112)), floor)
                .await;
            let (db, _) = db.apply_batch(sibling_a).await.unwrap();
            assert!(matches!(
                db.validate_batch(&sibling_b),
                Err(Error::StaleBatch)
            ));

            let parent_a = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), floor)
                .await;
            let parent_b = db
                .new_batch()
                .append(U64::new(2))
                .merkleize(&db, Some(U64::new(22)), floor)
                .await;
            let child_b = parent_b
                .new_batch::<Sha256>()
                .append(U64::new(3))
                .merkleize(&db, Some(U64::new(33)), floor)
                .await;

            let (db, _) = db.apply_batch(parent_a).await.unwrap();
            assert!(matches!(
                db.validate_batch(&child_b),
                Err(Error::StaleBatch)
            ));
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_stale_parent_after_child_applied() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.child("db"), "keyless-child-before-parent").await;
            let floor = db.inactivity_floor_loc();

            let parent = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), floor)
                .await;
            let child = parent
                .new_batch::<Sha256>()
                .append(U64::new(2))
                .merkleize(&db, Some(U64::new(22)), floor)
                .await;

            let (db, _) = db.apply_batch(child).await.unwrap();
            assert!(matches!(
                db.apply_batch(parent).await,
                Err(Error::StaleBatch)
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_sequential_commit_parent_then_child() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-parent-child").await;
            let floor = db.inactivity_floor_loc();

            let parent = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), floor)
                .await;
            let child = parent
                .new_batch::<Sha256>()
                .append(U64::new(2))
                .merkleize(&db, Some(U64::new(22)), floor)
                .await;
            let expected_root = child.root();

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let (db, _) = db.apply_batch(child).await.unwrap();
            let db = db.sync().await.unwrap();

            assert_eq!(db.root(), expected_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_floor_regressed() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-floor-regressed").await;

            let advance_floor = db.new_batch().append(U64::new(1));
            let advance_floor = advance_floor.merkleize(&db, None, Location::new(1)).await;
            let (db, _) = db.apply_batch(advance_floor).await.unwrap();
            let db = db.sync().await.unwrap();
            let target = db.target();

            let regressed = db
                .new_batch()
                .append(U64::new(2))
                .merkleize(&db, None, Location::new(0))
                .await;

            assert!(matches!(
                db.apply_batch(regressed).await,
                Err(Error::FloorRegressed(new, current))
                    if new == Location::new(0) && current == Location::new(1)
            ));

            // Reopen and verify the rejected batch persisted nothing.
            let db =
                open_db::<mmr::Family>(context.child("reopen"), "keyless-floor-regressed").await;
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
                open_db::<mmr::Family>(context.child("db"), "keyless-ancestor-floor-regressed")
                    .await;

            // parent: append + commit at loc 2 with floor=2.
            let parent = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, None, Location::new(2))
                .await;
            // child: append + commit at loc 4 with floor=1 (regressed from parent's floor=2).
            let child = parent
                .new_batch::<Sha256>()
                .append(U64::new(2))
                .merkleize(&db, None, Location::new(1))
                .await;

            let target = db.target();
            assert!(matches!(
                db.apply_batch(child).await,
                Err(Error::FloorRegressed(new, prev))
                    if new == Location::new(1) && prev == Location::new(2)
            ));

            // Reopen and verify the rejected chain persisted nothing.
            let db =
                open_db::<mmr::Family>(context.child("reopen"), "keyless-ancestor-floor-regressed")
                    .await;
            assert_eq!(db.target(), target);
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_restores_commit_metadata_and_floor() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-rewind-meta").await;

            let v1 = U64::new(1);
            let meta1 = U64::new(11);
            let floor1 = Location::new(0);
            let batch = db
                .new_batch()
                .append(v1)
                .merkleize(&db, Some(meta1.clone()), floor1)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();
            let size_after_first = db.size();

            let v2 = U64::new(2);
            let meta2 = U64::new(22);
            let floor2 = Location::new(1);
            let batch = db
                .new_batch()
                .append(v2)
                .merkleize(&db, Some(meta2.clone()), floor2)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
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
            let partition = "keyless-rewind-reopen";
            let meta1 = U64::new(11);
            let floor1 = Location::new(0);
            let meta2 = U64::new(22);
            let floor2 = Location::new(1);

            let root_after_first = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .append(U64::new(1))
                    .merkleize(&db, Some(meta1.clone()), floor1)
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.sync().await.unwrap();
                let root = db.root();
                let size_after_first = db.size();

                let batch = db
                    .new_batch()
                    .append(U64::new(2))
                    .merkleize(&db, Some(meta2), floor2)
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
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
            let partition = "keyless-commit-reopen";
            let meta1 = U64::new(11);
            let meta2 = U64::new(22);

            let root_after_second = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .append(U64::new(1))
                    .merkleize(&db, Some(meta1), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();

                let batch = db
                    .new_batch()
                    .append(U64::new(2))
                    .merkleize(&db, Some(meta2.clone()), Location::new(1))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
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
            let partition = "keyless-commit-rewind-reopen";
            let meta1 = U64::new(11);
            let meta2 = U64::new(22);

            let (root_a, size_a) = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .append(U64::new(1))
                    .merkleize(&db, Some(meta1.clone()), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.commit().await.unwrap();
                let root_a = db.root();
                let size_a = db.size();

                let batch = db
                    .new_batch()
                    .append(U64::new(2))
                    .merkleize(&db, Some(meta2), Location::new(1))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
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
            let partition = "keyless-sync-after-commit";
            let meta = U64::new(11);

            let root = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .append(U64::new(1))
                    .merkleize(&db, Some(meta.clone()), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
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
    fn test_compact_import_persists_with_commit() {
        deterministic::Runner::default().start(|context| async move {
            let dst = "keyless-import-commit-dst";
            let src = "keyless-import-commit-src";
            let meta_a = U64::new(11);
            let meta_b = U64::new(22);

            // Build state B in a separate source partition and fetch its state the way a sync
            // client would.
            let (target_b, pinned_b) = {
                let source = open_db::<mmr::Family>(context.child("src"), src).await;
                let batch = source
                    .new_batch()
                    .append(U64::new(2))
                    .merkleize(&source, Some(meta_b.clone()), Location::new(0))
                    .await;
                let (source, _) = source.apply_batch(batch).await.unwrap();
                let source = source.sync().await.unwrap();
                let target = source.target();
                let (response, _) = source
                    .serve(Request::Boundary {
                        size: target.size,
                        start: target.size - 1,
                    })
                    .await
                    .unwrap();
                let Response::Boundary { pinned_nodes, .. } = response else {
                    panic!("boundary request should get a boundary response");
                };
                (target, pinned_nodes)
            };

            // Seed the destination partition with a different committed state A.
            {
                let seeded = open_db::<mmr::Family>(context.child("seed"), dst).await;
                let batch = seeded
                    .new_batch()
                    .append(U64::new(1))
                    .merkleize(&seeded, Some(meta_a), Location::new(0))
                    .await;
                let (seeded, _) = seeded.apply_batch(batch).await.unwrap();
                let seeded = seeded.sync().await.unwrap();
                assert_ne!(seeded.target(), target_b);
            }

            // Import state B over the destination and make it durable with commit (not sync).
            {
                let journal = open_witness_journal(context.child("import"), dst).await;
                let imported = TestDb::<mmr::Family>::init_from_sync(
                    Sequential,
                    journal,
                    (),
                    target_b.size - 1,
                    pinned_b,
                    Operation::Commit(Some(meta_b.clone()), Location::new(0)),
                )
                .unwrap();
                assert_eq!(imported.target(), target_b);
                let _imported = imported.commit().await.unwrap();
            }

            // Reopen recovers the committed import, replacing state A even though the journal was
            // never synced.
            let db = open_db::<mmr::Family>(context.child("reopen"), dst).await;
            assert_eq!(db.target(), target_b);
            assert_eq!(db.root(), target_b.root);
            assert_eq!(db.get_metadata(), Some(meta_b));
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_reopen_rejects_tampered_witness() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-witness-tamper";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .append(U64::new(7))
                .merkleize(&db, Some(U64::new(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Corrupt the entry structurally. An extra pinned node cannot rebuild the Merkle.
            let journal = open_witness_journal(context.child("tamper"), partition).await;
            let (op_bytes, size, mut pinned_nodes) = witness::tests::tip(&journal).await;
            pinned_nodes.push(Sha256::fill(0xff));
            witness::tests::overwrite_tip(journal, op_bytes, size, pinned_nodes).await;

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
            let partition = "keyless-corrupt-rewind-target";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, None, Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let rewind_target = db.target().size;
            let batch = db
                .new_batch()
                .append(U64::new(2))
                .merkleize(&db, None, Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let tip_target = db.target();
            drop(db);

            // Corrupt the rewind target's entry (the journal holds bootstrap, target, tip).
            let mut journal = open_witness_journal(context.child("corrupt"), partition).await;
            journal = witness::tests::corrupt_entry(journal, 1, |entry| {
                entry.pinned_nodes.push(Sha256::fill(0xff));
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
            let partition = "keyless-interrupted-import";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .append(U64::new(7))
                .merkleize(&db, Some(U64::new(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
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
            let partition = "keyless-invalid-persisted-floor";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .append(U64::new(7))
                .merkleize(&db, Some(U64::new(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);
            let oversized_floor = Location::new(10);

            // Overwrite the persisted commit op with a floor beyond its own commit location.
            let journal = open_witness_journal(context.child("tamper"), partition).await;
            let (_, size, pinned_nodes) = witness::tests::tip(&journal).await;
            let bad_op = Operation::<mmr::Family, FixedEncoding<U64>>::Commit(
                Some(U64::new(11)),
                oversized_floor,
            )
            .encode()
            .to_vec();
            witness::tests::overwrite_tip(journal, bad_op, size, pinned_nodes).await;

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
            let partition = "keyless-pinned-nodes-tamper";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .append(U64::new(7))
                .merkleize(&db, Some(U64::new(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let tampered_target = db.target();
            drop(db);

            // Flip one pinned-node digest. There is no stored proof to cross-check against, so the
            // rebuild succeeds and yields a different root, the same way a bit-flipped replay
            // journal reopens with a different root.
            let journal = open_witness_journal(context.child("tamper"), partition).await;
            let (op_bytes, size, mut pinned_nodes) = witness::tests::tip(&journal).await;
            pinned_nodes[0] = Sha256::fill(0xff);
            witness::tests::overwrite_tip(journal, op_bytes, size, pinned_nodes).await;

            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let reopened = TestDb::<mmr::Family>::init_from_merkle(
                merkle,
                context.child("reopen_witness"),
                witness_config(partition, &context),
                (),
            )
            .await
            .unwrap();
            assert_ne!(reopened.target(), tampered_target);
            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_to_current_is_noop() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-rewind-noop").await;
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
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
    fn test_compact_prune_past_tip_keeps_tip() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-prune-past-tip";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let target = db.target();

            // Prune with a boundary beyond the tip: the tip entry must survive.
            let boundary = db.size() + 100;
            let db = db.prune(boundary).await.unwrap();
            assert_eq!(db.target(), target);
            drop(db);

            let reopened = open_db::<mmr::Family>(context.child("reopen"), partition).await;
            assert_eq!(reopened.target(), target);
            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_beyond_history() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-rewind-beyond").await;
            // The bootstrap commit is the oldest retained state (one leaf); no commit with zero
            // operations exists to rewind to.
            assert!(matches!(
                db.rewind(Location::new(0)).await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));

            let db = open_db::<mmr::Family>(context.child("reopen"), "keyless-rewind-beyond").await;
            // A target past the tip is not a commit either.
            let beyond_tip = db.size() + 100;
            assert!(matches!(
                db.rewind(beyond_tip).await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_between_commits() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-rewind-between").await;
            let floor = db.inactivity_floor_loc();

            // A multi-op commit jumps the committed size from 1 (bootstrap) to 4.
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .append(U64::new(2))
                .merkleize(&db, Some(U64::new(11)), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_a = db.root();
            let size_a = db.size();
            assert_eq!(size_a, Location::new(4));

            // A second commit moves the size to 6.
            let batch = db
                .new_batch()
                .append(U64::new(3))
                .merkleize(&db, Some(U64::new(22)), floor)
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
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
                    "keyless-rewind-between",
                )
                .await;
            }
            assert_eq!(db.root(), root_b);

            // The exact commit boundary remains a valid target.
            let db = db.rewind(size_a).await.unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.get_metadata(), Some(U64::new(11)));
            db.destroy().await.unwrap();
        });
    }

    /// A witness entry appended but not synced (a commit interrupted before its journal sync)
    /// must be dropped on reopen, recovering the last synced commit.
    #[test_traced("INFO")]
    fn test_compact_reopen_drops_unsynced_witness() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-witness-unsynced";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;

            // Commit state A.
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let target_a = db.target();
            drop(db);

            // Simulate the crash window: append an entry ahead of the tip without syncing it,
            // then drop the journal. The unsynced tail must not survive reopen.
            let journal = open_witness_journal(context.child("crash"), partition).await;
            let (op_bytes, mut size, pinned_nodes) = witness::tests::tip(&journal).await;
            size += 2;
            witness::tests::append_unsynced(journal, op_bytes, size, pinned_nodes).await;

            // Reopen must drop the unsynced entry and recover state A.
            let reopened = open_db::<mmr::Family>(context.child("reopen"), partition).await;
            assert_eq!(reopened.target(), target_a);
            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_multiple_commits() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-rewind-multi";
            let db = open_db::<mmr::Family>(context.child("db"), partition).await;

            // Commit A, B, C, recording the state after A.
            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, Some(U64::new(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_a = db.root();
            let size_a = db.size();
            let target_a = db.target();

            let mut db = db;
            for i in [2u64, 3] {
                let batch = db
                    .new_batch()
                    .append(U64::new(i))
                    .merkleize(&db, Some(U64::new(i * 11)), Location::new(0))
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
            }
            assert_ne!(db.root(), root_a);

            // Rewind two commits in one call.
            let db = db.rewind(size_a).await.unwrap();
            assert_eq!(db.root(), root_a);
            assert_eq!(db.size(), size_a);
            assert_eq!(db.get_metadata(), Some(U64::new(11)));
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
    fn test_compact_prune_then_rewind() {
        deterministic::Runner::default().start(|context| async move {
            // One entry per section so pruning takes effect at entry granularity (pruning is
            // section-aligned and never drops a partial section).
            let mut witness_cfg = witness_config("keyless-prune-rewind", &context);
            witness_cfg.items_per_section = NZU64!(1);
            let merkle = crate::merkle::compact::Merkle::new(Sequential);
            let mut db: TestDb<mmr::Family> =
                Db::init_from_merkle(merkle, context.child("witness"), witness_cfg.clone(), ())
                    .await
                    .unwrap();

            // Commit A, B, C.
            let mut sizes = Vec::new();
            for i in [1u64, 2, 3] {
                let batch = db
                    .new_batch()
                    .append(U64::new(i))
                    .merkleize(&db, Some(U64::new(i * 11)), Location::new(0))
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
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
            assert_eq!(db.get_metadata(), Some(U64::new(22)));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_preserves_pre_advance_batch() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.child("db"), "keyless-rewind-preserves-pre-advance")
                    .await;

            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let size_after_first = db.size();

            // Merkleize a batch against the post-commit-A state.
            let held = db
                .new_batch()
                .append(U64::new(2))
                .merkleize(&db, None, Location::new(0))
                .await;

            // Advance past that state and commit, then rewind back to it.
            let batch = db
                .new_batch()
                .append(U64::new(3))
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let db = db.rewind(size_after_first).await.unwrap();

            // The rewind restored the state that `held` was merkleized against, so it still
            // matches the Merkle size and applies cleanly.
            let (db, _) = db.apply_batch(held).await.unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_commit() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-noop-after-commit").await;

            let batch = db
                .new_batch()
                .append(U64::new(1))
                .append(U64::new(2))
                .merkleize(&db, Some(U64::new(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();
            assert_eq!(db.size(), Location::new(4));

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-noop-after-reopen";

            let root_before_drop = {
                let db = open_db::<mmr::Family>(context.child("first"), partition).await;
                let batch = db
                    .new_batch()
                    .append(U64::new(1))
                    .append(U64::new(2))
                    .merkleize(&db, Some(U64::new(11)), Location::new(0))
                    .await;
                let (db, _) = db.apply_batch(batch).await.unwrap();
                let db = db.sync().await.unwrap();
                let root = db.root();
                assert_eq!(db.size(), Location::new(4));
                root
            };

            let db = open_db::<mmr::Family>(context.child("second"), partition).await;
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.size(), Location::new(4));

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_rewind() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-noop-after-rewind").await;

            let batch = db
                .new_batch()
                .append(U64::new(1))
                .append(U64::new(2))
                .merkleize(&db, Some(U64::new(11)), Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let root_after_first = db.root();

            let batch = db
                .new_batch()
                .append(U64::new(3))
                .merkleize(&db, Some(U64::new(22)), Location::new(1))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();

            let db = db.rewind(Location::new(4)).await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);

            let db = db.sync().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_makes_post_advance_batch_stale() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.child("db"), "keyless-rewind-makes-stale").await;

            let batch = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();
            let size_after_first = db.size();

            let batch = db
                .new_batch()
                .append(U64::new(2))
                .merkleize(&db, None, Location::new(0))
                .await;
            let (db, _) = db.apply_batch(batch).await.unwrap();
            let db = db.sync().await.unwrap();

            // Merkleize a batch against the post-commit-B state, which the rewind will discard.
            let held = db
                .new_batch()
                .append(U64::new(3))
                .merkleize(&db, None, Location::new(0))
                .await;

            let db = db.rewind(size_after_first).await.unwrap();

            // After rewind, mem.size reflects post-commit-A, but the held batch starts after
            // post-commit-B. Apply must be rejected with StaleBatch.
            assert!(matches!(db.apply_batch(held).await, Err(Error::StaleBatch)));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_floor_beyond_size() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-floor-beyond").await;

            let batch = db.new_batch().merkleize(&db, None, Location::new(2)).await;

            assert!(matches!(
                db.apply_batch(batch).await,
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
            let db =
                open_db::<mmr::Family>(context.child("db"), "keyless-ancestor-floor-beyond").await;

            // parent: append + commit at loc 2, floor=3 (one past parent's commit).
            let parent = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, None, Location::new(3))
                .await;
            // child: valid on its own (floor=0), but parent's floor is bad.
            let child = parent
                .new_batch::<Sha256>()
                .append(U64::new(2))
                .merkleize(&db, None, Location::new(0))
                .await;

            assert!(matches!(
                db.apply_batch(child).await,
                Err(Error::FloorBeyondSize(floor, commit))
                    if floor == Location::new(3) && commit == Location::new(2)
            ));
        });
    }
}

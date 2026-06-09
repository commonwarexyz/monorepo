//! A keyless authenticated db that does not retain historical operations after sync.
//!
//! Mirrors the API of [`crate::qmdb::keyless::Keyless`] (`new_batch -> merkleize ->
//! apply_batch -> sync`, pipelined batch chains, `StaleBatch` validation) but is backed by
//! the peak-only [`crate::merkle::compact`]. Because history is discarded, there are no
//! `get` / `proof` / `bounds` methods; use the full variant if you need them.
//!
//! # Compact serving witness
//!
//! On every durable sync, this db persists the encoded last-commit operation together with its
//! inclusion proof against the current root. Reopen and rewind re-verify that proof; corruption
//! surfaces as [`Error::DataCorrupted`]. This authenticated witness is what lets compact nodes
//! serve compact sync without retaining historical operations.
//!
//! # Inactivity floor
//!
//! Commits still carry an inactivity floor, but only for wire-format compatibility with
//! [`crate::qmdb::keyless::Keyless`]: the root is computed over the encoded operation
//! sequence, and that sequence must include the same floor to produce the same root as the
//! full variant. Here the floor has no effect on pruning or snapshot rebuilding. All
//! historical in-memory state is discarded on every `sync`.

use super::operation::Operation;
use crate::{
    journal::contiguous::variable::Config as WitnessJournalConfig,
    merkle::{batch, compact as compact_merkle, Family, Location, Proof},
    qmdb::{
        self,
        any::value::ValueEncoding,
        batch_chain::{self, Bounds},
        compact::{
            batch as compact_batch,
            witness::{self, ServeState},
        },
        sync::compact as compact_sync,
        Error,
    },
    Context,
};
use commonware_codec::{Decode as _, Encode, EncodeShared, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::Strategy;
use std::sync::{Arc, Weak};

/// Configuration for a compact keyless authenticated db.
#[derive(Clone)]
pub struct Config<C, S: Strategy> {
    /// Configuration for the backing compact Merkle structure.
    pub merkle: compact_merkle::Config<S>,

    /// Configuration for the journal that persists the compact-sync witness. Its `codec_config` is
    /// ignored; the witness entry codec configuration is supplied internally.
    pub witness: WitnessJournalConfig<()>,

    /// Codec config used to decode the persisted last commit operation on reopen.
    pub commit_codec_config: C,
}

/// A keyless authenticated db that does not retain historical operations after sync.
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
    merkle: compact_merkle::Merkle<F, E, H::Digest, S>,
    last_commit_loc: Location<F>,
    last_commit_metadata: Option<V::Value>,
    inactivity_floor_loc: Location<F>,
    commit_codec_config: C,
    /// Durable store for the last persisted compact witness, backed by a contiguous journal plus an
    /// in-memory cache.
    ///
    /// The cache is rebuilt from the persisted journal on reopen/rewind and refreshed on
    /// [`Self::sync`]. It intentionally does not track unsynced in-memory mutations, so compact
    /// serving never advertises state that has not been durably persisted.
    witness: witness::Store<E, F, H::Digest>,
}

type CompactStateResult<F, V, D> =
    Result<compact_sync::State<F, Operation<F, V>, D>, compact_sync::ServeError<F, D>>;

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
    base_size: u64,
    db_size: u64,
}

/// A speculative batch whose root digest has been computed.
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, V: ValueEncoding, S: Strategy>
where
    Operation<F, V>: EncodeShared,
{
    pub(super) merkle_batch: Arc<batch::MerkleizedBatch<F, D, S>>,
    pub(super) root: D,
    pub(super) commit_metadata: Option<V::Value>,
    pub(super) parent: Option<Weak<Self>>,
    pub(super) bounds: batch_chain::Bounds<F>,
}

impl<F: Family, D: Digest, V: ValueEncoding, S: Strategy> MerkleizedBatch<F, D, V, S>
where
    Operation<F, V>: EncodeShared,
{
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> {
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
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, V, S>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            merkle_batch: compact_merkle::UnmerkleizedBatch::wrap(self.merkle_batch.new_batch()),
            appends: Vec::new(),
            parent: Some(Arc::clone(self)),
            base_size: self.bounds.total_size,
            db_size: self.bounds.db_size,
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
    pub(super) fn new<E, C>(db: &Db<F, E, V, H, C, S>, committed_size: u64) -> Self
    where
        E: Context,
        C: Clone + Send + Sync + 'static,
        Operation<F, V>: Read<Cfg = C>,
    {
        Self {
            merkle_batch: db.merkle.new_batch(),
            appends: Vec::new(),
            parent: None,
            base_size: committed_size,
            db_size: committed_size,
        }
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
    pub fn merkleize<E, C>(
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
        let mut ops: Vec<Operation<F, V>> = Vec::with_capacity(self.appends.len() + 1);
        for value in self.appends {
            ops.push(Operation::Append(value));
        }
        ops.push(Operation::Commit(metadata.clone(), inactivity_floor));

        let total_size = self.base_size + ops.len() as u64;
        let merkle = compact_batch::merkleize_ops::<F, E, H, S, _>(
            &db.merkle,
            self.merkle_batch,
            ops.as_slice(),
        );

        let inactive_peaks = F::inactive_peaks(
            F::location_to_position(Location::new(total_size)),
            inactivity_floor,
        );
        let hasher = qmdb::hasher::<H>();
        let root = db
            .merkle
            .with_mem(|mem| merkle.root(mem, &hasher, inactive_peaks))
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

    /// Build a compact db handle from already-verified compact state.
    ///
    /// The caller has reconstructed the compact Merkle in memory and already authenticated the
    /// supplied witness/root pair. This seeds the witness store from that verified witness but does
    /// not itself persist anything; persistence happens only after the caller finishes the root
    /// check for the reconstructed db. The supplied journal is reset so the first persist starts
    /// from a clean witness log.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn init_from_verified_state(
        merkle: compact_merkle::Merkle<F, E, H::Digest, S>,
        journal: witness::WitnessJournal<E, F, H::Digest>,
        commit_codec_config: C,
        last_commit_metadata: Option<V::Value>,
        inactivity_floor_loc: Location<F>,
        root: H::Digest,
        last_commit_op_bytes: Vec<u8>,
        last_commit_proof: Proof<F, H::Digest>,
        pinned_nodes: Vec<H::Digest>,
    ) -> Result<Self, Error<F>> {
        let (last_commit_loc, serve_state) = witness::witness_from_authenticated_state(
            merkle.leaves(),
            root,
            inactivity_floor_loc,
            last_commit_op_bytes,
            last_commit_proof,
            pinned_nodes,
        )?;

        let witness = witness::Store::new(journal, serve_state);
        witness.reset().await?;
        Ok(Self {
            merkle,
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
    /// rewind can assume "the journal tip is a complete compact witness".
    pub(crate) async fn init_from_merkle(
        mut merkle: compact_merkle::Merkle<F, E, H::Digest, S>,
        witness_context: E,
        witness_config: WitnessJournalConfig<()>,
        commit_codec_config: C,
    ) -> Result<Self, Error<F>>
    where
        F: Family,
        Operation<F, V>: Read<Cfg = C>,
    {
        // Bootstrap: append an initial Commit(None, 0) on first open. This establishes the
        // invariant that every merkleized batch ends with a Commit op, so `last_commit_loc =
        // leaves - 1` is always correct without replaying the log (which we can't, since we
        // don't retain it).
        let journal =
            witness::open_journal::<E, F, H::Digest>(witness_context, witness_config).await?;
        let (witness, last_commit_op) = witness::open::<E, F, H, S, _, Operation<F, V>>(
            journal,
            &mut merkle,
            &commit_codec_config,
            Operation::<F, V>::Commit(None, Location::new(0))
                .encode()
                .to_vec(),
            Operation::has_floor,
        )
        .await?;
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::DataCorrupted("last operation was not a commit"));
        };
        let last_commit_loc = Location::new(*witness.with(|w| w.leaf_count) - 1);

        Ok(Self {
            merkle,
            last_commit_loc,
            last_commit_metadata,
            inactivity_floor_loc,
            commit_codec_config,
            witness,
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
    /// This reflects the last state for which both frontier and witness were durably captured,
    /// which may lag behind live in-memory mutations until [`Self::sync`] is called.
    pub fn current_target(&self) -> compact_sync::Target<F, H::Digest> {
        self.witness.with(ServeState::target)
    }

    /// Return the compact-sync state for `target`, or a stale-target error if the source's
    /// current witness no longer matches.
    ///
    /// The witness lock is held only long enough to verify the requested target and snapshot
    /// the bytes, proof, and pinned nodes needed for [`compact_sync::State`]. Decoding the
    /// commit operation runs outside the lock so concurrent readers do not contend on it.
    pub(crate) fn compact_state(
        &self,
        target: compact_sync::Target<F, H::Digest>,
    ) -> CompactStateResult<F, V, H::Digest>
    where
        Operation<F, V>: Read<Cfg = C>,
    {
        let (op_bytes, last_commit_proof, pinned_nodes, leaf_count) = self.witness.with(|w| {
            if target.root != w.root || target.leaf_count != w.leaf_count {
                return Err(compact_sync::ServeError::StaleTarget {
                    requested: target.clone(),
                    current: w.target(),
                });
            }
            Ok((
                w.last_commit_op_bytes.clone(),
                w.last_commit_proof.clone(),
                w.pinned_nodes.clone(),
                w.leaf_count,
            ))
        })?;
        let op = Operation::<F, V>::decode_cfg(op_bytes.as_ref(), &self.commit_codec_config)
            .map_err(|_| {
                compact_sync::ServeError::Database(Error::DataCorrupted("invalid commit operation"))
            })?;
        if !matches!(&op, Operation::Commit(_, _)) {
            return Err(compact_sync::ServeError::Database(Error::DataCorrupted(
                "last operation was not a commit",
            )));
        }
        Ok(compact_sync::State {
            leaf_count,
            pinned_nodes,
            last_commit_op: op,
            last_commit_proof,
        })
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, V, S> {
        let committed_size = *self.last_commit_loc + 1;
        UnmerkleizedBatch::new(self, committed_size)
    }

    /// Create an owned merkleized batch representing the current committed state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, V, S>>
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
        })
    }

    /// Apply a merkleized batch to the database.
    ///
    /// Returns the range of locations written. The state is updated in memory only; call
    /// [`Self::sync`] or [`Self::commit`] to persist.
    ///
    /// # Errors
    ///
    /// - [`Error::StaleBatch`] if the batch was created from a stale DB state.
    /// - [`Error::FloorRegressed`] if any unapplied commit's floor is below the running floor
    ///   (walking ancestors oldest-first, then the tip).
    /// - [`Error::FloorBeyondSize`] if any unapplied commit's floor exceeds its own commit
    ///   location.
    pub fn apply_batch(
        &mut self,
        batch: Arc<MerkleizedBatch<F, H::Digest, V, S>>,
    ) -> Result<core::ops::Range<Location<F>>, Error<F>> {
        let db_size = *self.last_commit_loc + 1;
        batch
            .bounds
            .validate_apply_to(db_size, self.inactivity_floor_loc)?;

        let start_loc = self.last_commit_loc + 1;
        self.merkle.apply_batch(&batch.merkle_batch)?;
        self.last_commit_loc = Location::new(batch.bounds.total_size - 1);
        self.last_commit_metadata = batch.commit_metadata.clone();
        self.inactivity_floor_loc = batch.bounds.inactivity_floor;
        Ok(start_loc..Location::new(batch.bounds.total_size))
    }

    /// Durably persist the current db state to disk.
    ///
    /// This is the point at which in-memory mutations become servable via compact sync: the witness
    /// is appended and synced, then the compact Merkle frontier flips in lockstep.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        self.witness
            .persist::<H, S>(
                &self.merkle,
                self.last_commit_loc,
                self.inactivity_floor_loc,
                Self::encode_commit_op(
                    self.last_commit_metadata.clone(),
                    self.inactivity_floor_loc,
                ),
            )
            .await
    }

    /// Durably persist the current db state to disk (alias for [`Self::sync`]).
    pub async fn commit(&self) -> Result<(), Error<F>>
    where
        F: Family,
    {
        self.sync().await
    }

    /// Restore the state as of the sync before the most recent one.
    ///
    /// Discards any uncommitted batches, flips the db back to the previous persisted state,
    /// and reloads the cached commit metadata and inactivity floor from that slot.
    ///
    /// Callers must drop any [`Arc<MerkleizedBatch>`] merkleized against state that this rewind
    /// discards. [`Self::apply_batch`] validates batches by size only: a discarded-branch batch
    /// will usually trip the size-mismatch check, but if the db later regrows to the same size
    /// along an alternate branch, the stale batch becomes admissible again and applying it will
    /// corrupt the committed root. Batches merkleized against the state this rewind restores to
    /// (for example, a batch built before an advance that is then discarded by the rewind)
    /// remain compatible and apply cleanly.
    ///
    /// # Errors
    ///
    /// Returns [`crate::merkle::Error::RewindBeyondHistory`] (wrapped as [`Error::Merkle`]) if
    /// no prior state exists — either no sync has occurred yet, or the previous state was
    /// already consumed by a rewind with no intervening sync.
    ///
    /// Any error from this method is fatal for this handle. The Merkle layer may have already
    /// flipped its generation pointer and rebuilt its in-memory state before a later step (e.g.
    /// reloading the cached commit metadata or inactivity floor) fails, leaving this `Db`'s
    /// in-memory fields out of sync with the persisted slot. Callers must drop this handle
    /// after any `Err` from `rewind` and reopen from storage.
    pub async fn rewind(&mut self) -> Result<(), Error<F>>
    where
        F: Family,
    {
        self.merkle.rewind().await?;
        // Reload the witness for the state the rewind restored, so compact serving stays aligned
        // with the same frontier/root.
        let (witness, last_commit_op) = self
            .witness
            .reload_after_rewind::<H, S, _, Operation<F, V>>(
                &self.merkle,
                &self.commit_codec_config,
                Operation::has_floor,
            )
            .await?;
        let Operation::Commit(last_commit_metadata, inactivity_floor_loc) = last_commit_op else {
            return Err(Error::DataCorrupted("last operation was not a commit"));
        };
        self.last_commit_metadata = last_commit_metadata;
        self.inactivity_floor_loc = inactivity_floor_loc;
        self.last_commit_loc = Location::new(*witness.leaf_count - 1);
        Ok(())
    }

    /// Destroy all persisted state associated with this database.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.merkle.destroy().await?;
        self.witness.destroy().await?;
        Ok(())
    }

    pub(crate) async fn persist_cached_witness(&self) -> Result<(), Error<F>> {
        self.witness.persist_cached::<S>(&self.merkle).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        journal::contiguous::variable,
        merkle::mmr,
        qmdb::{any::value::FixedEncoding, compact::witness},
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Runner as _, Supervisor as _,
    };
    use commonware_utils::{sequence::U64, NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    type TestDb<F> = Db<F, deterministic::Context, FixedEncoding<U64>, Sha256, (), Sequential>;

    const WITNESS_PAGE_SIZE: NonZeroU16 = NZU16!(77);
    const WITNESS_PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(9);

    fn witness_config(partition: &str, pooler: &impl BufferPooler) -> variable::Config<()> {
        variable::Config {
            partition: format!("{partition}-witness"),
            items_per_section: NZU64!(64),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(pooler, WITNESS_PAGE_SIZE, WITNESS_PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(1024),
        }
    }

    async fn open_merkle<F: Family>(
        context: deterministic::Context,
        partition: &str,
    ) -> crate::merkle::compact::Merkle<F, deterministic::Context, Digest, Sequential> {
        crate::merkle::compact::Merkle::init(
            context,
            crate::merkle::compact::Config {
                partition: partition.into(),
                strategy: Sequential,
            },
        )
        .await
        .unwrap()
    }

    async fn open_db<F: Family>(context: deterministic::Context, partition: &str) -> TestDb<F> {
        let witness_cfg = witness_config(partition, &context);
        let witness_ctx = context.child("witness");
        let merkle = open_merkle::<F>(context, partition).await;
        Db::init_from_merkle(merkle, witness_ctx, witness_cfg, ())
            .await
            .unwrap()
    }

    /// Open the persisted witness journal directly so tests can corrupt the tip entry.
    async fn open_witness_journal(
        context: deterministic::Context,
        partition: &str,
    ) -> witness::WitnessJournal<deterministic::Context, mmr::Family, Digest> {
        let cfg = witness_config(partition, &context);
        witness::open_journal::<_, mmr::Family, Digest>(context, cfg)
            .await
            .unwrap()
    }

    #[test_traced("INFO")]
    fn test_compact_stale_batch_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db::<mmr::Family>(context.child("db"), "keyless-stale").await;
            let floor = db.inactivity_floor_loc();

            let batch_a =
                db.new_batch()
                    .append(U64::new(1))
                    .merkleize(&db, Some(U64::new(11)), floor);
            let batch_b =
                db.new_batch()
                    .append(U64::new(2))
                    .merkleize(&db, Some(U64::new(22)), floor);

            let expected_root = batch_a.root();
            db.apply_batch(batch_a).unwrap();
            assert_eq!(db.root(), expected_root);
            assert!(matches!(
                db.apply_batch(batch_b),
                Err(Error::StaleBatch { .. })
            ));

            db.destroy().await.unwrap();
        });
    }

    /// Regression: `to_batch()` must snapshot the live in-memory state, not the durable serve
    /// cache.
    #[test_traced("INFO")]
    fn test_compact_to_batch_reflects_live_state() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db::<mmr::Family>(context.child("db"), "keyless-to-batch-live").await;
            let floor = db.inactivity_floor_loc();

            let pre_apply_root = db.root();
            let pre_snapshot = db.to_batch();
            assert_eq!(
                pre_snapshot.root(),
                pre_apply_root,
                "snapshot before any mutation should match the live root"
            );

            db.apply_batch(db.new_batch().append(U64::new(1)).merkleize(
                &db,
                Some(U64::new(11)),
                floor,
            ))
            .unwrap();

            // Leave the durable serve cache behind the live Merkle state.
            let live_root = db.root();
            assert_ne!(
                live_root, pre_apply_root,
                "applying a non-empty batch must change the live root"
            );

            let snapshot = db.to_batch();
            assert_eq!(
                snapshot.root(),
                live_root,
                "to_batch().root() must match the live db.root() even before sync/commit"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_stale_batch_chained() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db::<mmr::Family>(context.child("db"), "keyless-chained-stale").await;
            let floor = db.inactivity_floor_loc();

            let parent =
                db.new_batch()
                    .append(U64::new(1))
                    .merkleize(&db, Some(U64::new(11)), floor);
            let child_a = parent.new_batch::<Sha256>().append(U64::new(2)).merkleize(
                &db,
                Some(U64::new(22)),
                floor,
            );
            let child_b = parent.new_batch::<Sha256>().append(U64::new(3)).merkleize(
                &db,
                Some(U64::new(33)),
                floor,
            );

            db.apply_batch(child_a).unwrap();
            assert!(matches!(
                db.apply_batch(child_b),
                Err(Error::StaleBatch { .. })
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_stale_parent_after_child_applied() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.child("db"), "keyless-child-before-parent").await;
            let floor = db.inactivity_floor_loc();

            let parent =
                db.new_batch()
                    .append(U64::new(1))
                    .merkleize(&db, Some(U64::new(11)), floor);
            let child = parent.new_batch::<Sha256>().append(U64::new(2)).merkleize(
                &db,
                Some(U64::new(22)),
                floor,
            );

            db.apply_batch(child).unwrap();
            assert!(matches!(
                db.apply_batch(parent),
                Err(Error::StaleBatch { .. })
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_sequential_commit_parent_then_child() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db::<mmr::Family>(context.child("db"), "keyless-parent-child").await;
            let floor = db.inactivity_floor_loc();

            let parent =
                db.new_batch()
                    .append(U64::new(1))
                    .merkleize(&db, Some(U64::new(11)), floor);
            let child = parent.new_batch::<Sha256>().append(U64::new(2)).merkleize(
                &db,
                Some(U64::new(22)),
                floor,
            );
            let expected_root = child.root();

            db.apply_batch(parent).unwrap();
            db.apply_batch(child).unwrap();
            db.commit().await.unwrap();

            assert_eq!(db.root(), expected_root);

            db.destroy().await.unwrap();
        });
    }

    // A chained batch whose tip floor is below its parent's floor must be rejected:
    // the parent's Commit participates in the per-commit monotonicity invariant even
    // before it is applied.
    #[test_traced("INFO")]
    fn test_compact_ancestor_floor_regression_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.child("db"), "keyless-ancestor-floor-regressed")
                    .await;

            // parent: append + commit at loc 2 with floor=2.
            let parent = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, None, Location::new(2));
            // child: append + commit at loc 4 with floor=1 (regressed from parent's floor=2).
            let child = parent.new_batch::<Sha256>().append(U64::new(2)).merkleize(
                &db,
                None,
                Location::new(1),
            );

            assert!(matches!(
                db.apply_batch(child),
                Err(Error::FloorRegressed(new, prev))
                    if new == Location::new(1) && prev == Location::new(2)
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_restores_commit_metadata_and_floor() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db::<mmr::Family>(context.child("db"), "keyless-rewind-meta").await;

            let v1 = U64::new(1);
            let meta1 = U64::new(11);
            let floor1 = Location::new(0);
            db.apply_batch(
                db.new_batch()
                    .append(v1)
                    .merkleize(&db, Some(meta1.clone()), floor1),
            )
            .unwrap();
            db.commit().await.unwrap();
            let root_after_first = db.root();

            let v2 = U64::new(2);
            let meta2 = U64::new(22);
            let floor2 = Location::new(1);
            db.apply_batch(
                db.new_batch()
                    .append(v2)
                    .merkleize(&db, Some(meta2.clone()), floor2),
            )
            .unwrap();
            db.commit().await.unwrap();
            assert_eq!(db.get_metadata(), Some(meta2));
            assert_eq!(db.inactivity_floor_loc(), floor2);

            db.rewind().await.unwrap();
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
                let mut db = open_db::<mmr::Family>(context.child("first"), partition).await;
                db.apply_batch(db.new_batch().append(U64::new(1)).merkleize(
                    &db,
                    Some(meta1.clone()),
                    floor1,
                ))
                .unwrap();
                db.commit().await.unwrap();
                let root = db.root();

                db.apply_batch(db.new_batch().append(U64::new(2)).merkleize(
                    &db,
                    Some(meta2),
                    floor2,
                ))
                .unwrap();
                db.commit().await.unwrap();

                db.rewind().await.unwrap();
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
    fn test_compact_reopen_rejects_tampered_witness() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-witness-tamper";
            let mut db = open_db::<mmr::Family>(context.child("db"), partition).await;
            db.apply_batch(db.new_batch().append(U64::new(7)).merkleize(
                &db,
                Some(U64::new(11)),
                Location::new(1),
            ))
            .unwrap();
            db.commit().await.unwrap();
            drop(db);

            // Corrupt the persisted proof so it no longer verifies against the stored root.
            let journal = open_witness_journal(context.child("tamper"), partition).await;
            let (op_bytes, mut proof) = witness::tip_for_test(&journal).await;
            if let Some(digest) = proof.digests.first_mut() {
                *digest = Sha256::fill(0xff);
            } else {
                proof.leaves = Location::new(*proof.leaves + 1);
            }
            witness::overwrite_tip_for_test(&journal, op_bytes, proof).await;
            drop(journal);

            let merkle = open_merkle::<mmr::Family>(context.child("reopen"), partition).await;
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
    fn test_compact_reopen_rejects_commit_floor_beyond_tip() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-invalid-persisted-floor";
            let mut db = open_db::<mmr::Family>(context.child("db"), partition).await;
            db.apply_batch(db.new_batch().append(U64::new(7)).merkleize(
                &db,
                Some(U64::new(11)),
                Location::new(1),
            ))
            .unwrap();
            db.commit().await.unwrap();
            drop(db);
            let oversized_floor = Location::new(10);

            // Overwrite the persisted commit op with a floor beyond its own commit location.
            let journal = open_witness_journal(context.child("tamper"), partition).await;
            let (_, proof) = witness::tip_for_test(&journal).await;
            let bad_op = Operation::<mmr::Family, FixedEncoding<U64>>::Commit(
                Some(U64::new(11)),
                oversized_floor,
            )
            .encode()
            .to_vec();
            witness::overwrite_tip_for_test(&journal, bad_op, proof).await;
            drop(journal);

            let merkle = open_merkle::<mmr::Family>(context.child("reopen"), partition).await;
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

    /// Reopen must reconcile a witness journal whose tip is one commit ahead of the Merkle, the
    /// state left by a crash after the witness synced but before the Merkle flipped.
    #[test_traced("INFO")]
    fn test_compact_reopen_truncates_witness_ahead_of_merkle() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-witness-ahead";
            let mut db = open_db::<mmr::Family>(context.child("db"), partition).await;

            // Commit state A.
            db.apply_batch(db.new_batch().append(U64::new(1)).merkleize(
                &db,
                Some(U64::new(0xa1)),
                Location::new(1),
            ))
            .unwrap();
            db.commit().await.unwrap();
            let target_a = db.current_target();

            // Commit state B, advancing both the Merkle and the witness journal.
            db.apply_batch(db.new_batch().append(U64::new(2)).merkleize(
                &db,
                Some(U64::new(0xb2)),
                Location::new(3),
            ))
            .unwrap();
            db.commit().await.unwrap();
            drop(db);

            // Rewind the Merkle alone, leaving the witness journal tip one commit ahead of it.
            let mut merkle =
                open_merkle::<mmr::Family>(context.child("merkle_rewind"), partition).await;
            merkle.rewind().await.unwrap();
            drop(merkle);

            // Reopen must drop the ahead-by-one witness and recover state A.
            let reopened = open_db::<mmr::Family>(context.child("reopen"), partition).await;
            assert_eq!(reopened.current_target(), target_a);
            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_beyond_history() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db::<mmr::Family>(context.child("db"), "keyless-rewind-beyond").await;
            assert!(matches!(
                db.rewind().await,
                Err(Error::Merkle(crate::merkle::Error::RewindBeyondHistory))
            ));
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_preserves_pre_advance_batch() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.child("db"), "keyless-rewind-preserves-pre-advance")
                    .await;

            db.apply_batch(db.new_batch().append(U64::new(1)).merkleize(
                &db,
                None,
                Location::new(0),
            ))
            .unwrap();
            db.commit().await.unwrap();

            // Merkleize a batch against the post-commit-A state.
            let held = db
                .new_batch()
                .append(U64::new(2))
                .merkleize(&db, None, Location::new(0));

            // Advance past that state and commit, then rewind back to it.
            db.apply_batch(db.new_batch().append(U64::new(3)).merkleize(
                &db,
                None,
                Location::new(0),
            ))
            .unwrap();
            db.commit().await.unwrap();
            db.rewind().await.unwrap();

            // The rewind restored the state that `held` was merkleized against, so it still
            // matches the Merkle size and applies cleanly.
            db.apply_batch(held).unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_commit() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.child("db"), "keyless-noop-after-commit").await;

            db.apply_batch(
                db.new_batch()
                    .append(U64::new(1))
                    .append(U64::new(2))
                    .merkleize(&db, Some(U64::new(11)), Location::new(0)),
            )
            .unwrap();
            db.commit().await.unwrap();
            let root_after_first = db.root();
            assert_eq!(db.size(), Location::new(4));

            db.commit().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.current_target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-noop-after-reopen";

            let root_before_drop = {
                let mut db = open_db::<mmr::Family>(context.child("first"), partition).await;
                db.apply_batch(
                    db.new_batch()
                        .append(U64::new(1))
                        .append(U64::new(2))
                        .merkleize(&db, Some(U64::new(11)), Location::new(0)),
                )
                .unwrap();
                db.commit().await.unwrap();
                let root = db.root();
                assert_eq!(db.size(), Location::new(4));
                root
            };

            let db = open_db::<mmr::Family>(context.child("second"), partition).await;
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.size(), Location::new(4));

            db.commit().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.current_target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_rewind() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.child("db"), "keyless-noop-after-rewind").await;

            db.apply_batch(
                db.new_batch()
                    .append(U64::new(1))
                    .append(U64::new(2))
                    .merkleize(&db, Some(U64::new(11)), Location::new(0)),
            )
            .unwrap();
            db.commit().await.unwrap();
            let root_after_first = db.root();

            db.apply_batch(db.new_batch().append(U64::new(3)).merkleize(
                &db,
                Some(U64::new(22)),
                Location::new(1),
            ))
            .unwrap();
            db.commit().await.unwrap();

            db.rewind().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);

            db.commit().await.unwrap();
            assert_eq!(db.size(), Location::new(4));
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.current_target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_makes_post_advance_batch_stale() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.child("db"), "keyless-rewind-makes-stale").await;

            db.apply_batch(db.new_batch().append(U64::new(1)).merkleize(
                &db,
                None,
                Location::new(0),
            ))
            .unwrap();
            db.commit().await.unwrap();

            db.apply_batch(db.new_batch().append(U64::new(2)).merkleize(
                &db,
                None,
                Location::new(0),
            ))
            .unwrap();
            db.commit().await.unwrap();

            // Merkleize a batch against the post-commit-B state, which the rewind will discard.
            let held = db
                .new_batch()
                .append(U64::new(3))
                .merkleize(&db, None, Location::new(0));

            db.rewind().await.unwrap();

            // After rewind, mem.size reflects post-commit-A, but the held batch starts after
            // post-commit-B. Apply must be rejected with StaleBatch.
            assert!(matches!(
                db.apply_batch(held),
                Err(Error::StaleBatch { .. })
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_witness_state_reports_cached_commit_corruption() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db::<mmr::Family>(context.child("db"), "keyless-serve-corruption").await;
            let target = db.current_target();
            db.witness
                .mutate(|witness| witness.last_commit_op_bytes.clear());

            assert!(matches!(
                db.compact_state(target),
                Err(compact_sync::ServeError::Database(Error::DataCorrupted(
                    "invalid commit operation"
                )))
            ));

            db.destroy().await.unwrap();
        });
    }

    // A chained batch whose ancestor's floor exceeds that ancestor's own commit location
    // must be rejected, identifying the ancestor's bound rather than the tip's.
    #[test_traced("INFO")]
    fn test_compact_ancestor_floor_beyond_commit_loc_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.child("db"), "keyless-ancestor-floor-beyond").await;

            // parent: append + commit at loc 2, floor=3 (one past parent's commit).
            let parent = db
                .new_batch()
                .append(U64::new(1))
                .merkleize(&db, None, Location::new(3));
            // child: valid on its own (floor=0), but parent's floor is bad.
            let child = parent.new_batch::<Sha256>().append(U64::new(2)).merkleize(
                &db,
                None,
                Location::new(0),
            );

            assert!(matches!(
                db.apply_batch(child),
                Err(Error::FloorBeyondSize(floor, commit))
                    if floor == Location::new(3) && commit == Location::new(2)
            ));

            db.destroy().await.unwrap();
        });
    }
}

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
//! Commits still carry an inactivity floor so compact and full variants derive the same encoded
//! leaf for each commit. Here the floor has no effect on pruning or snapshot rebuilding. All
//! historical in-memory state is discarded on every `sync`.

use super::operation::Operation;
use crate::{
    merkle::{
        compact as compact_merkle, hasher::Standard as StandardHasher, Family, Location, Proof,
    },
    qmdb::{
        any::value::ValueEncoding,
        append_batch::{
            AppendBatchChain, AppendBatchCore, AppendBatchView, BatchBase, BatchSpan, ResolvedBase,
        },
        compact_db::CompactDbInner,
        compact_witness::CompactCommit,
        sync::compact as compact_sync,
        Error,
    },
    Context,
};
use commonware_codec::{EncodeShared, Read};
use commonware_cryptography::{Digest, Hasher};
use std::sync::Arc;

/// Configuration for a compact keyless authenticated db.
#[derive(Clone)]
pub struct Config<C> {
    /// Configuration for the backing compact Merkle structure.
    pub merkle: compact_merkle::Config,

    /// Codec config used to decode the persisted last commit operation on reopen.
    pub commit_codec_config: C,
}

/// A keyless authenticated db that does not retain historical operations after sync.
pub struct Db<F, E, V, H, C = ()>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    inner: CompactDbInner<F, E, H, Operation<F, V>, C>,
}

impl<F, V> CompactCommit for Operation<F, V>
where
    F: Family,
    V: ValueEncoding,
    Self: Read,
    <Self as Read>::Cfg: Clone + Send + Sync + 'static,
{
    type Family = F;
    type Metadata = V::Value;
    type CommitCfg = <Self as Read>::Cfg;

    fn build_commit(metadata: Option<Self::Metadata>, floor: Location<Self::Family>) -> Self {
        Self::Commit(metadata, floor)
    }

    fn is_commit(&self) -> bool {
        matches!(self, Self::Commit(_, _))
    }

    fn into_commit_fields(self) -> Option<(Option<Self::Metadata>, Location<Self::Family>)> {
        let Self::Commit(metadata, floor) = self else {
            return None;
        };
        Some((metadata, floor))
    }
}

/// A speculative batch for a compact keyless db.
pub struct UnmerkleizedBatch<F, H, V>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    base: BatchBase<F, H::Digest, MerkleizedBatch<F, H::Digest, V>>,
    appends: Vec<V::Value>,
}

/// A merkleized batch for a compact keyless db.
pub struct MerkleizedBatch<F: Family, D: Digest, V: ValueEncoding>
where
    Operation<F, V>: EncodeShared,
{
    pub(super) core: AppendBatchCore<F, D>,
    pub(super) commit_metadata: Option<V::Value>,
    /// Strong refs to uncommitted ancestors, newest-to-oldest.
    ///
    /// This is a wrapper-level chain for validation and may include itemless `to_batch` markers.
    pub(super) ancestors: Vec<Arc<Self>>,
}

impl<F: Family, D: Digest, V: ValueEncoding> AppendBatchView<F, D> for MerkleizedBatch<F, D, V>
where
    Operation<F, V>: EncodeShared,
{
    fn merkle(&self) -> &Arc<crate::merkle::batch::MerkleizedBatch<F, D>> {
        &self.core.merkle
    }

    fn span(&self) -> &BatchSpan<F> {
        &self.core.span
    }
}

impl<F: Family, D: Digest, V: ValueEncoding> AppendBatchChain<F, D> for MerkleizedBatch<F, D, V>
where
    Operation<F, V>: EncodeShared,
{
    fn ancestors(&self) -> &[Arc<Self>] {
        &self.ancestors
    }
}

impl<F: Family, D: Digest, V: ValueEncoding> MerkleizedBatch<F, D, V>
where
    Operation<F, V>: EncodeShared,
{
    /// Return the root digest after this batch is applied.
    pub fn root(&self) -> D {
        self.core.root()
    }

    /// Create a new speculative batch with this one as its parent.
    pub fn new_batch<H>(self: &Arc<Self>) -> UnmerkleizedBatch<F, H, V>
    where
        H: Hasher<Digest = D>,
    {
        UnmerkleizedBatch {
            base: BatchBase::Child(Arc::clone(self)),
            appends: Vec::new(),
        }
    }
}

impl<F, H, V> UnmerkleizedBatch<F, H, V>
where
    F: Family,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
{
    pub(super) fn new<E, C>(db: &Db<F, E, V, H, C>, committed_size: u64) -> Self
    where
        E: Context,
        C: Clone + Send + Sync + 'static,
        Operation<F, V>: Read<Cfg = C>,
    {
        Self {
            base: BatchBase::Db {
                db_size: committed_size,
                merkle_parent: db.inner.merkle.to_batch(),
            },
            appends: Vec::new(),
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
        db: &Db<F, E, V, H, C>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, V>>
    where
        E: Context,
        C: Clone + Send + Sync + 'static,
        Operation<F, V>: Read<Cfg = C>,
    {
        let hasher = StandardHasher::<H>::new();
        let ResolvedBase {
            base_size,
            db_size,
            merkle_parent,
            ancestors,
        } = self.base.resolve();
        let commit_op = Operation::Commit(metadata.clone(), inactivity_floor);
        let core = db.inner.merkle.with_mem(|mem| {
            AppendBatchCore::from_encoded_ops(
                merkle_parent,
                mem,
                &hasher,
                base_size,
                db_size,
                inactivity_floor,
                self.appends.into_iter().map(Operation::Append),
                commit_op,
            )
        });

        Arc::new(MerkleizedBatch {
            core,
            commit_metadata: metadata,
            ancestors,
        })
    }
}

impl<F, E, V, H, C> Db<F, E, V, H, C>
where
    F: Family,
    E: Context,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, V>: EncodeShared,
    Operation<F, V>: Read<Cfg = C>,
    C: Clone + Send + Sync + 'static,
{
    /// Borrow the shared compact-db inner state. Used by sync-engine plumbing that needs to
    /// reach the witness machinery directly.
    pub(crate) const fn inner(&self) -> &CompactDbInner<F, E, H, Operation<F, V>, C> {
        &self.inner
    }

    /// Build a compact db handle from already-verified compact state.
    ///
    /// The caller has reconstructed the compact Merkle in memory and already authenticated the
    /// supplied witness/root pair. This seeds the in-memory serve cache from that verified witness
    /// but does not itself persist anything; persistence happens only after the caller finishes the
    /// root check for the reconstructed db.
    pub(crate) fn init_from_verified_state(
        merkle: compact_merkle::Merkle<F, E, H::Digest>,
        commit_codec_config: C,
        last_commit_metadata: Option<V::Value>,
        inactivity_floor_loc: Location<F>,
        commit_op_bytes: Vec<u8>,
        commit_proof: Proof<F, H::Digest>,
        pinned_nodes: Vec<H::Digest>,
    ) -> Result<Self, Error<F>> {
        let inner = CompactDbInner::init_from_verified_state(
            merkle,
            commit_codec_config,
            last_commit_metadata,
            inactivity_floor_loc,
            commit_op_bytes,
            commit_proof,
            pinned_nodes,
        )?;
        Ok(Self { inner })
    }

    /// Open a compact db from persisted compact state and rebuild its serve cache.
    ///
    /// On first open, this bootstraps the initial commit and its witness so every later reopen and
    /// rewind can assume "the active slot has a complete servable compact state".
    pub(crate) async fn init_from_merkle(
        merkle: compact_merkle::Merkle<F, E, H::Digest>,
        commit_codec_config: C,
    ) -> Result<Self, Error<F>> {
        let inner = CompactDbInner::init_from_merkle(merkle, commit_codec_config).await?;
        Ok(Self { inner })
    }

    /// Return the root of the db.
    pub fn root(&self) -> H::Digest {
        self.inner.root()
    }

    /// Return the location of the last commit.
    pub const fn last_commit_loc(&self) -> Location<F> {
        self.inner.last_commit_loc()
    }

    /// Return the inactivity floor declared by the last committed batch.
    pub const fn inactivity_floor_loc(&self) -> Location<F> {
        self.inner.inactivity_floor_loc()
    }

    /// Return the location of the next operation appended to this db.
    pub fn size(&self) -> Location<F> {
        self.inner.size()
    }

    /// Get the metadata associated with the last commit.
    pub fn get_metadata(&self) -> Option<V::Value> {
        self.inner.get_metadata()
    }

    /// Return the latest compact-sync target this compact db can currently serve.
    ///
    /// This reflects the last state for which both commit_bounds and witness were durably captured,
    /// which may lag behind live in-memory mutations until [`Self::sync`] is called.
    pub fn current_target(&self) -> compact_sync::Target<F, H::Digest> {
        self.inner.current_target()
    }

    /// Return the authenticated state this compact db can serve for `target`.
    ///
    /// Compact sync only authenticates the requested `root` and `leaf_count`. If the target does
    /// not match the current servable tip, or if the cached witness is corrupted, this returns a
    /// serve error instead of panicking.
    #[allow(clippy::type_complexity)]
    pub(crate) fn compact_state(
        &self,
        target: compact_sync::Target<F, H::Digest>,
    ) -> Result<
        compact_sync::State<F, Operation<F, V>, H::Digest>,
        compact_sync::ServeError<F, H::Digest>,
    > {
        self.inner.compact_state(target)
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, V> {
        let committed_size = *self.inner.size();
        UnmerkleizedBatch::new(self, committed_size)
    }

    /// Create an owned merkleized batch representing the current committed state.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, V>> {
        let committed_size = *self.inner.size();
        let span = BatchSpan::quiescent(committed_size, self.inner.inactivity_floor_loc());
        Arc::new(MerkleizedBatch {
            core: AppendBatchCore {
                merkle: self.inner.merkle.to_batch(),
                span,
            },
            commit_metadata: self.inner.get_metadata(),
            ancestors: Vec::new(),
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
        batch: Arc<MerkleizedBatch<F, H::Digest, V>>,
    ) -> Result<core::ops::Range<Location<F>>, Error<F>> {
        let validated = self
            .inner
            .commit_bounds
            .validate(&batch.core, &batch.ancestors)?;
        self.inner.merkle.apply_batch(&batch.core.merkle)?;
        self.inner.last_commit_metadata = batch.commit_metadata.clone();
        Ok(validated.commit(&mut self.inner.commit_bounds))
    }

    /// Durably persist the current db state to disk.
    ///
    /// This is the point at which in-memory mutations become servable via compact sync. The compact
    /// Merkle frontier and last-commit witness are written into the same slot, reusing the cached
    /// witness when the current state has already been persisted.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        self.inner.sync().await
    }

    /// Durably persist the current db state to disk (alias for [`Self::sync`]).
    pub async fn commit(&self) -> Result<(), Error<F>> {
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
    pub async fn rewind(&mut self) -> Result<(), Error<F>> {
        self.inner.rewind().await
    }

    /// Destroy all persisted state associated with this database.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.inner.destroy().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{hasher::Standard as StandardHasher, mmr},
        metadata::{Config as MConfig, Metadata},
        qmdb::any::value::FixedEncoding,
    };
    use commonware_codec::Encode;
    use commonware_cryptography::Sha256;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics, Runner as _};
    use commonware_utils::sequence::{prefixed_u64::U64 as MetadataKey, U64};

    type TestDb<F> = Db<F, deterministic::Context, FixedEncoding<U64>, Sha256>;

    async fn open_db<F: Family>(context: deterministic::Context, partition: &str) -> TestDb<F> {
        let merkle = crate::merkle::compact::Merkle::init(
            context,
            &StandardHasher::<Sha256>::new(),
            crate::merkle::compact::Config {
                partition: partition.into(),
                thread_pool: None,
            },
        )
        .await
        .unwrap();
        Db::init_from_merkle(merkle, ()).await.unwrap()
    }

    async fn tamper_metadata_key(
        context: deterministic::Context,
        partition: &str,
        key: MetadataKey,
    ) {
        let mut metadata = open_metadata(context, partition).await;
        let mut bytes = metadata.get(&key).cloned().expect("metadata entry missing");
        *bytes.last_mut().expect("metadata entry empty") ^= 0x01;
        metadata.put(key, bytes);
        metadata.sync().await.unwrap();
    }

    async fn open_metadata(
        context: deterministic::Context,
        partition: &str,
    ) -> Metadata<deterministic::Context, MetadataKey, Vec<u8>> {
        Metadata::<_, MetadataKey, Vec<u8>>::init(
            context.with_label("meta_write"),
            MConfig {
                partition: partition.into(),
                codec_config: ((0..).into(), ()),
            },
        )
        .await
        .unwrap()
    }

    async fn overwrite_metadata_key(
        context: deterministic::Context,
        partition: &str,
        key: MetadataKey,
        bytes: Vec<u8>,
    ) {
        let mut metadata = open_metadata(context, partition).await;
        metadata.put(key, bytes);
        metadata.sync().await.unwrap();
    }

    #[test_traced("INFO")]
    fn test_compact_stale_batch_rejected() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db::<mmr::Family>(context.with_label("db"), "keyless-stale").await;
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

    #[test_traced("INFO")]
    fn test_compact_stale_batch_chained() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "keyless-chained-stale").await;
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
                open_db::<mmr::Family>(context.with_label("db"), "keyless-child-before-parent")
                    .await;
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
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "keyless-parent-child").await;
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
            let mut db = open_db::<mmr::Family>(
                context.with_label("db"),
                "keyless-ancestor-floor-regressed",
            )
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
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "keyless-rewind-meta").await;

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
                let mut db = open_db::<mmr::Family>(context.with_label("first"), partition).await;
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

            let db = open_db::<mmr::Family>(context.with_label("second"), partition).await;
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
            let mut db = open_db::<mmr::Family>(context.with_label("db"), partition).await;
            db.apply_batch(db.new_batch().append(U64::new(7)).merkleize(
                &db,
                Some(U64::new(11)),
                Location::new(1),
            ))
            .unwrap();
            db.commit().await.unwrap();
            let slot = db.inner().merkle.active_slot();
            drop(db);

            tamper_metadata_key(
                context.with_label("tamper"),
                partition,
                crate::qmdb::compact_witness::proof_key(slot),
            )
            .await;

            let merkle: crate::merkle::compact::Merkle<mmr::Family, _, _> =
                crate::merkle::compact::Merkle::init(
                    context.with_label("reopen"),
                    &StandardHasher::<Sha256>::new(),
                    crate::merkle::compact::Config {
                        partition: partition.into(),
                        thread_pool: None,
                    },
                )
                .await
                .unwrap();
            let reopened = TestDb::<mmr::Family>::init_from_merkle(merkle, ()).await;
            assert!(matches!(reopened, Err(Error::DataCorrupted(_))));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_reopen_rejects_commit_floor_beyond_tip() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "keyless-invalid-persisted-floor";
            let mut db = open_db::<mmr::Family>(context.with_label("db"), partition).await;
            db.apply_batch(db.new_batch().append(U64::new(7)).merkleize(
                &db,
                Some(U64::new(11)),
                Location::new(1),
            ))
            .unwrap();
            db.commit().await.unwrap();
            let slot = db.inner().merkle.active_slot();
            drop(db);
            let oversized_floor = Location::new(10);

            overwrite_metadata_key(
                context.with_label("tamper"),
                partition,
                crate::qmdb::compact_witness::commit_op_key(slot),
                Operation::<mmr::Family, FixedEncoding<U64>>::Commit(
                    Some(U64::new(11)),
                    oversized_floor,
                )
                .encode()
                .to_vec(),
            )
            .await;

            let merkle: crate::merkle::compact::Merkle<mmr::Family, _, _> =
                crate::merkle::compact::Merkle::init(
                    context.with_label("reopen"),
                    &StandardHasher::<Sha256>::new(),
                    crate::merkle::compact::Config {
                        partition: partition.into(),
                        thread_pool: None,
                    },
                )
                .await
                .unwrap();
            let reopened = TestDb::<mmr::Family>::init_from_merkle(merkle, ()).await;
            assert!(matches!(
                reopened,
                Err(Error::DataCorrupted("invalid compact witness"))
            ));
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_beyond_history() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "keyless-rewind-beyond").await;
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
            let mut db = open_db::<mmr::Family>(
                context.with_label("db"),
                "keyless-rewind-preserves-pre-advance",
            )
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

            // The rewind restored the state that `held` was merkleized against, so its
            // base_size matches mem.size and it applies cleanly.
            db.apply_batch(held).unwrap();

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_commit() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "keyless-noop-after-commit").await;

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
                let mut db = open_db::<mmr::Family>(context.with_label("first"), partition).await;
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

            let db = open_db::<mmr::Family>(context.with_label("second"), partition).await;
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
                open_db::<mmr::Family>(context.with_label("db"), "keyless-noop-after-rewind").await;

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
                open_db::<mmr::Family>(context.with_label("db"), "keyless-rewind-makes-stale")
                    .await;

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

            // After rewind, mem.size reflects post-commit-A, but held.base_size reflects
            // post-commit-B. Apply must be rejected with StaleBatch.
            assert!(matches!(
                db.apply_batch(held),
                Err(Error::StaleBatch { .. })
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_state_reports_cached_commit_corruption() {
        deterministic::Runner::default().start(|context| async move {
            let db =
                open_db::<mmr::Family>(context.with_label("db"), "keyless-serve-corruption").await;
            let target = db.current_target();
            db.inner().witness.write().commit_op_bytes.clear();

            assert!(matches!(
                db.compact_state(target),
                Err(compact_sync::ServeError::Database(Error::DataCorrupted(
                    "invalid cached commit operation"
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
                open_db::<mmr::Family>(context.with_label("db"), "keyless-ancestor-floor-beyond")
                    .await;

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

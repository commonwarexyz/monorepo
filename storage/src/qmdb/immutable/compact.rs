//! An immutable authenticated db that does not retain historical operations after sync.
//!
//! Mirrors the API of [`crate::qmdb::immutable::Immutable`] (`new_batch -> merkleize ->
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
//! [`crate::qmdb::immutable::Immutable`]: the root is computed over the encoded operation
//! sequence, and that sequence must include the same floor to produce the same root as the
//! full variant. Here the floor has no effect on pruning or snapshot rebuilding. All
//! historical in-memory state is discarded on every `sync`.

use super::operation::Operation;
use crate::{
    merkle::{batch, compact as compact_merkle, Family, Location, Proof},
    qmdb::{
        any::value::ValueEncoding,
        compact_witness::{self, CachedServeState, WitnessSource},
        operation::Key,
        sync::compact as compact_sync,
        Bagging, Error,
    },
    Context,
};
use commonware_codec::{Decode as _, Encode, EncodeShared, Read};
use commonware_cryptography::{Digest, Hasher};
use commonware_parallel::{Sequential, Strategy};
use commonware_utils::sync::RwLock;
use core::{iter, marker::PhantomData};
use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
};

/// Configuration for a compact immutable authenticated db.
#[derive(Clone)]
pub struct Config<C, S: Strategy = Sequential> {
    /// Configuration for the backing compact Merkle structure.
    pub merkle: compact_merkle::Config<S>,

    /// Codec config used to decode the persisted last commit operation on reopen.
    pub commit_codec_config: C,
}

/// An immutable authenticated db that does not retain historical operations after sync.
pub struct Db<F, E, K, V, H, C = (), S: Strategy = Sequential>
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
    merkle: compact_merkle::Merkle<F, E, H::Digest, S>,
    last_commit_loc: Location<F>,
    last_commit_metadata: Option<V::Value>,
    inactivity_floor_loc: Location<F>,
    commit_codec_config: C,
    /// Cache of the last durably servable compact state.
    ///
    /// This cache is rebuilt from persisted witness bytes on reopen/rewind and refreshed on
    /// [`Self::sync`]. It intentionally does not track unsynced in-memory mutations, so compact
    /// serving never advertises state that has not been durably persisted.
    serve_state: RwLock<CachedServeState<F, H::Digest>>,
    _key: PhantomData<K>,
}

type CommitFields<F, V> = (Option<<V as ValueEncoding>::Value>, Location<F>);
type ServeStateResult<F, K, V, D> =
    Result<compact_sync::State<F, Operation<F, K, V>, D>, compact_sync::ServeError<F, D>>;

/// A speculative batch for a compact immutable db.
#[allow(clippy::type_complexity)]
pub struct UnmerkleizedBatch<F, H, K, V, S: Strategy = Sequential>
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

/// A merkleized batch for a compact immutable db.
#[derive(Clone)]
pub struct MerkleizedBatch<F: Family, D: Digest, K: Key, V: ValueEncoding, S: Strategy = Sequential>
where
    Operation<F, K, V>: EncodeShared,
{
    pub(super) merkle_batch: Arc<batch::MerkleizedBatch<F, D, S>>,
    pub(super) root: D,
    pub(super) commit_metadata: Option<V::Value>,
    pub(super) parent: Option<Weak<Self>>,
    pub(super) base_size: u64,
    pub(super) total_size: u64,
    pub(super) db_size: u64,
    /// Ancestor totals in newest-first order. Pair with `ancestor_floors[i]`.
    pub(super) ancestor_batch_ends: Vec<u64>,
    /// Floor each ancestor committed to; `[i]` matches `ancestor_batch_ends[i]`.
    pub(super) ancestor_floors: Vec<Location<F>>,
    pub(super) new_inactivity_floor_loc: Location<F>,
    pub(super) _key: PhantomData<K>,
}

impl<F: Family, D: Digest, K: Key, V: ValueEncoding, S: Strategy> MerkleizedBatch<F, D, K, V, S>
where
    Operation<F, K, V>: EncodeShared,
{
    pub(super) fn ancestors(&self) -> impl Iterator<Item = Arc<Self>> {
        let mut next = self.parent.as_ref().and_then(Weak::upgrade);
        iter::from_fn(move || {
            let batch = next.take()?;
            next = batch.parent.as_ref().and_then(Weak::upgrade);
            Some(batch)
        })
    }

    /// Return the root digest after this batch is applied.
    pub const fn root(&self) -> D {
        self.root
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
            base_size: self.total_size,
            db_size: self.db_size,
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
    pub fn merkleize<E, C>(
        self,
        db: &Db<F, E, K, V, H, C, S>,
        metadata: Option<V::Value>,
        inactivity_floor: Location<F>,
    ) -> Arc<MerkleizedBatch<F, H::Digest, K, V, S>>
    where
        F: Bagging,
        E: Context,
        C: Clone + Send + Sync + 'static,
        Operation<F, K, V>: Read<Cfg = C>,
    {
        let hasher = F::default_hasher::<H>();
        let mut ops: Vec<Operation<F, K, V>> = Vec::with_capacity(self.mutations.len() + 1);
        for (key, value) in self.mutations {
            ops.push(Operation::Set(key, value));
        }
        ops.push(Operation::Commit(metadata.clone(), inactivity_floor));

        let total_size = self.base_size + ops.len() as u64;
        let mut merkle_batch = self.merkle_batch;
        for op in &ops {
            merkle_batch = merkle_batch.add(&hasher, &op.encode());
        }
        let merkle = db
            .merkle
            .with_mem(|mem| merkle_batch.merkleize(mem, &hasher));

        let inactive_peaks = F::inactive_peaks(
            F::location_to_position(Location::new(total_size)),
            inactivity_floor,
        );
        let root = db
            .merkle
            .with_mem(|mem| merkle.root(mem, &hasher, inactive_peaks))
            .expect("inactive_peaks computed from batch size");

        let mut ancestor_batch_ends = Vec::new();
        let mut ancestor_floors = Vec::new();
        if let Some(parent) = &self.parent {
            ancestor_batch_ends.push(parent.total_size);
            ancestor_floors.push(parent.new_inactivity_floor_loc);
            for batch in parent.ancestors() {
                ancestor_batch_ends.push(batch.total_size);
                ancestor_floors.push(batch.new_inactivity_floor_loc);
            }
        }

        Arc::new(MerkleizedBatch {
            merkle_batch: merkle,
            root,
            commit_metadata: metadata,
            parent: self.parent.as_ref().map(Arc::downgrade),
            base_size: self.base_size,
            total_size,
            db_size: self.db_size,
            ancestor_batch_ends,
            ancestor_floors,
            new_inactivity_floor_loc: inactivity_floor,
            _key: PhantomData,
        })
    }
}

impl<F, E, K, V, H, C, S: Strategy> Db<F, E, K, V, H, C, S>
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
    fn encode_commit_op(metadata: Option<V::Value>, inactivity_floor_loc: Location<F>) -> Vec<u8> {
        Operation::<F, K, V>::Commit(metadata, inactivity_floor_loc)
            .encode()
            .to_vec()
    }

    fn decode_commit_op(
        bytes: &[u8],
        commit_codec_config: &C,
    ) -> Result<CommitFields<F, V>, Error<F>>
    where
        Operation<F, K, V>: Read<Cfg = C>,
    {
        let op = Operation::<F, K, V>::decode_cfg(bytes, commit_codec_config)
            .map_err(|_| Error::DataCorrupted("invalid persisted commit operation"))?;
        let Operation::Commit(metadata, inactivity_floor_loc) = op else {
            return Err(Error::DataCorrupted(
                "persisted last operation was not a commit",
            ));
        };
        Ok((metadata, inactivity_floor_loc))
    }

    async fn load_active_serve_state(
        merkle: &compact_merkle::Merkle<F, E, H::Digest, S>,
        commit_codec_config: &C,
    ) -> Result<
        (
            CachedServeState<F, H::Digest>,
            Option<V::Value>,
            Location<F>,
        ),
        Error<F>,
    >
    where
        F: Bagging,
    {
        compact_witness::load_serve_state::<F, E, H, S, _, _, _>(
            merkle,
            commit_codec_config,
            Self::decode_commit_op,
        )
        .await
    }

    /// Build a compact db handle from already-verified compact state.
    ///
    /// The caller has reconstructed the compact Merkle in memory and already authenticated the
    /// supplied witness/root pair. This seeds the in-memory serve cache from that verified witness
    /// but does not itself persist anything; persistence happens only after the caller finishes the
    /// root check for the reconstructed db.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn init_from_verified_state(
        merkle: compact_merkle::Merkle<F, E, H::Digest, S>,
        commit_codec_config: C,
        last_commit_metadata: Option<V::Value>,
        inactivity_floor_loc: Location<F>,
        root: H::Digest,
        commit_op_bytes: Vec<u8>,
        commit_proof: Proof<F, H::Digest>,
        pinned_nodes: Vec<H::Digest>,
    ) -> Result<Self, Error<F>> {
        if merkle.leaves() == 0 {
            return Err(Error::DataCorrupted("missing final commit"));
        }
        let leaf_count = merkle.leaves();
        let last_commit_loc = Location::<F>::new(*leaf_count - 1);
        compact_witness::validate_inactivity_floor(inactivity_floor_loc, last_commit_loc)?;
        let serve_state = CachedServeState {
            root,
            leaf_count,
            pinned_nodes,
            commit_op_bytes,
            commit_proof,
        };

        Ok(Self {
            merkle,
            last_commit_loc,
            last_commit_metadata,
            inactivity_floor_loc,
            commit_codec_config,
            serve_state: RwLock::new(serve_state),
            _key: PhantomData,
        })
    }

    /// Open a compact db from persisted compact state and rebuild its serve cache.
    ///
    /// On first open, this bootstraps the initial commit and its witness so every later reopen and
    /// rewind can assume "the active slot has a complete servable compact state".
    pub(crate) async fn init_from_merkle(
        mut merkle: compact_merkle::Merkle<F, E, H::Digest, S>,
        commit_codec_config: C,
    ) -> Result<Self, Error<F>>
    where
        F: Bagging,
        Operation<F, K, V>: Read<Cfg = C>,
    {
        // Bootstrap: append an initial Commit(None, 0) on first open. This establishes the
        // invariant that every merkleized batch ends with a Commit op, so `last_commit_loc =
        // leaves - 1` is always correct without replaying the log (which we can't, since we
        // don't retain it).
        //
        // We also persist that initial commit's witness immediately so every later reopen or
        // rewind can uniformly assume "the active slot has a servable tip witness".
        if merkle.leaves() == 0 {
            compact_witness::bootstrap_initial_commit::<F, E, H, S>(
                &mut merkle,
                Operation::<F, K, V>::Commit(None, Location::new(0))
                    .encode()
                    .to_vec(),
            )
            .await?;
        }

        let (serve_state, last_commit_metadata, inactivity_floor_loc) =
            Self::load_active_serve_state(&merkle, &commit_codec_config).await?;

        Self::init_from_verified_state(
            merkle,
            commit_codec_config,
            last_commit_metadata,
            inactivity_floor_loc,
            serve_state.root,
            serve_state.commit_op_bytes,
            serve_state.commit_proof,
            serve_state.pinned_nodes,
        )
    }

    /// Return the root of the db.
    pub fn root(&self) -> H::Digest
    where
        F: Bagging,
    {
        let hasher = F::default_hasher::<H>();
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

    /// Return the latest compact-sync target this compact db can currently serve.
    ///
    /// This reflects the last state for which both frontier and witness were durably captured,
    /// which may lag behind live in-memory mutations until [`Self::sync`] is called.
    pub fn current_target(&self) -> compact_sync::Target<F, H::Digest> {
        self.cloned_serve_state().target()
    }

    /// Return the authenticated state this compact db can serve for `target`.
    ///
    /// Compact sync only authenticates the requested `root` and `leaf_count`. If the target does
    /// not match the current servable tip, or if the cached witness is corrupted, this returns a
    /// serve error instead of panicking.
    pub(crate) fn compact_state(
        &self,
        target: compact_sync::Target<F, H::Digest>,
    ) -> ServeStateResult<F, K, V, H::Digest>
    where
        Operation<F, K, V>: Read<Cfg = C>,
    {
        let serve_state = self.cloned_serve_state();
        let current = serve_state.target();
        if target.root != current.root || target.leaf_count != current.leaf_count {
            return Err(compact_sync::ServeError::StaleTarget {
                requested: target,
                current,
            });
        }
        let op = Operation::<F, K, V>::decode_cfg(
            serve_state.commit_op_bytes.as_ref(),
            &self.commit_codec_config,
        )
        .map_err(|_| {
            compact_sync::ServeError::Database(Error::DataCorrupted(
                "invalid cached commit operation",
            ))
        })?;
        if !matches!(&op, Operation::Commit(_, _)) {
            return Err(compact_sync::ServeError::Database(Error::DataCorrupted(
                "cached last operation was not a commit",
            )));
        }
        Ok(compact_sync::State {
            leaf_count: serve_state.leaf_count,
            pinned_nodes: serve_state.pinned_nodes,
            last_commit_op: op,
            last_commit_proof: serve_state.commit_proof,
        })
    }

    /// Create a new speculative batch of operations with this database as its parent.
    pub fn new_batch(&self) -> UnmerkleizedBatch<F, H, K, V, S> {
        let committed_size = *self.last_commit_loc + 1;
        UnmerkleizedBatch::new(self, committed_size)
    }

    /// Create an owned merkleized batch representing the current committed state.
    ///
    /// The returned batch's cached root reflects the live in-memory state and matches
    /// [`Self::root`]; the durable serve-state cache (which can lag unsynced mutations) is
    /// intentionally not consulted here.
    pub fn to_batch(&self) -> Arc<MerkleizedBatch<F, H::Digest, K, V, S>>
    where
        F: Bagging,
    {
        let committed_size = *self.last_commit_loc + 1;
        Arc::new(MerkleizedBatch {
            merkle_batch: self.merkle.to_batch(),
            root: self.root(),
            commit_metadata: self.last_commit_metadata.clone(),
            parent: None,
            base_size: committed_size,
            total_size: committed_size,
            db_size: committed_size,
            ancestor_batch_ends: Vec::new(),
            ancestor_floors: Vec::new(),
            new_inactivity_floor_loc: self.inactivity_floor_loc,
            _key: PhantomData,
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
        batch: Arc<MerkleizedBatch<F, H::Digest, K, V, S>>,
    ) -> Result<core::ops::Range<Location<F>>, Error<F>> {
        let db_size = *self.last_commit_loc + 1;
        let valid = db_size == batch.db_size
            || db_size == batch.base_size
            || batch.ancestor_batch_ends.contains(&db_size);
        if !valid {
            return Err(Error::StaleBatch {
                db_size,
                batch_db_size: batch.db_size,
                batch_base_size: batch.base_size,
            });
        }

        let tip_commit_loc = Location::new(batch.total_size - 1);
        // Per-commit floor validation; see `compact_witness::validate_ancestor_floors`.
        compact_witness::validate_ancestor_floors(
            self.inactivity_floor_loc,
            db_size,
            &batch.ancestor_batch_ends,
            &batch.ancestor_floors,
            batch.new_inactivity_floor_loc,
            tip_commit_loc,
        )?;

        let start_loc = self.last_commit_loc + 1;
        self.merkle.apply_batch(&batch.merkle_batch)?;
        self.last_commit_loc = Location::new(batch.total_size - 1);
        self.last_commit_metadata = batch.commit_metadata.clone();
        self.inactivity_floor_loc = batch.new_inactivity_floor_loc;
        Ok(start_loc..Location::new(batch.total_size))
    }

    /// Durably persist the current db state to disk.
    ///
    /// This is the point at which in-memory mutations become servable via compact sync. The compact
    /// Merkle frontier and last-commit witness are written into the same slot, reusing the cached
    /// witness when the current state has already been persisted.
    pub async fn sync(&self) -> Result<(), Error<F>>
    where
        F: Bagging,
    {
        compact_witness::persist_witness(self).await
    }

    /// Durably persist the current db state to disk (alias for [`Self::sync`]).
    pub async fn commit(&self) -> Result<(), Error<F>>
    where
        F: Bagging,
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
        F: Bagging,
    {
        self.merkle.rewind().await?;
        // Reload the witness from the reverted slot as well, so compact serving stays aligned with
        // the same frontier/root that `rewind` restored.
        let (serve_state, last_commit_metadata, inactivity_floor_loc) =
            Self::load_active_serve_state(&self.merkle, &self.commit_codec_config).await?;
        self.last_commit_metadata = last_commit_metadata;
        self.inactivity_floor_loc = inactivity_floor_loc;
        self.last_commit_loc = Location::new(*serve_state.leaf_count - 1);
        self.store_serve_state(serve_state);
        Ok(())
    }

    /// Destroy all persisted state associated with this database.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        self.merkle.destroy().await.map_err(Into::into)
    }
}

impl<F, E, K, V, H, C, S> WitnessSource<F, E, H, S> for Db<F, E, K, V, H, C, S>
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
    fn merkle(&self) -> &compact_merkle::Merkle<F, E, H::Digest, S> {
        &self.merkle
    }

    fn last_commit_loc(&self) -> Location<F> {
        self.last_commit_loc
    }

    fn inactivity_floor_loc(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    fn encode_current_commit_op(&self) -> Vec<u8> {
        Self::encode_commit_op(self.last_commit_metadata.clone(), self.inactivity_floor_loc)
    }

    fn serve_state_cache(&self) -> &RwLock<CachedServeState<F, H::Digest>> {
        &self.serve_state
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::mmr,
        metadata::{Config as MConfig, Metadata},
        qmdb::{any::value::FixedEncoding, Bagging},
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{deterministic, Metrics, Runner as _};
    use commonware_utils::sequence::prefixed_u64::U64 as MetadataKey;

    type TestDb<F> = Db<F, deterministic::Context, Digest, FixedEncoding<Digest>, Sha256>;

    async fn open_db<F: Family + Bagging>(
        context: deterministic::Context,
        partition: &str,
    ) -> TestDb<F> {
        let merkle = crate::merkle::compact::Merkle::init(
            context,
            crate::merkle::compact::Config {
                partition: partition.into(),
                strategy: Sequential,
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
            let mut db = open_db::<mmr::Family>(context.with_label("db"), "immutable-stale").await;

            let key1 = Sha256::hash(&[1]);
            let key2 = Sha256::hash(&[2]);
            let value1 = Sha256::fill(10u8);
            let value2 = Sha256::fill(20u8);

            let batch_a = db
                .new_batch()
                .set(key1, value1)
                .merkleize(&db, None, Location::new(0));
            let batch_b = db
                .new_batch()
                .set(key2, value2)
                .merkleize(&db, None, Location::new(0));

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

    /// Regression: `to_batch()` must reflect the live in-memory state, not the lagging durable
    /// serve-state cache. Compact dbs intentionally keep the serve-state cache behind unsynced
    /// mutations, so a snapshot built without `sync()` / `commit()` between
    /// `apply_batch()` and `to_batch()` previously bound its cached root to the stale serve
    /// state.
    #[test_traced("INFO")]
    fn test_compact_to_batch_reflects_live_state() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "immutable-to-batch-live").await;

            let pre_apply_root = db.root();
            let pre_snapshot = db.to_batch();
            assert_eq!(
                pre_snapshot.root(),
                pre_apply_root,
                "snapshot before any mutation should match the live root"
            );

            let key = Sha256::hash(&[1]);
            let value = Sha256::fill(10u8);
            db.apply_batch(
                db.new_batch()
                    .set(key, value)
                    .merkleize(&db, None, Location::new(0)),
            )
            .unwrap();

            // Deliberately skip `sync()` / `commit()` so the durable serve-state cache lags the
            // live merkle state.
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
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "immutable-chained-stale").await;

            let parent = db
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0));
            let child_a = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[2]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0));
            let child_b = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[3]), Sha256::fill(3u8))
                .merkleize(&db, None, Location::new(0));

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
                open_db::<mmr::Family>(context.with_label("db"), "immutable-child-before-parent")
                    .await;

            let parent = db
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0));
            let child = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[2]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0));

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
                open_db::<mmr::Family>(context.with_label("db"), "immutable-parent-child").await;

            let parent = db
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0));
            let child = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[2]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0));
            let expected_root = child.root();

            db.apply_batch(parent).unwrap();
            db.apply_batch(child).unwrap();
            db.commit().await.unwrap();

            assert_eq!(db.root(), expected_root);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_floor_regressed() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "immutable-floor-regressed").await;

            let advance_floor = db.new_batch().set(Sha256::hash(&[1]), Sha256::fill(1u8));
            let advance_floor = advance_floor.merkleize(&db, None, Location::new(1));
            db.apply_batch(advance_floor).unwrap();

            let regressed = db
                .new_batch()
                .set(Sha256::hash(&[2]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0));

            assert!(matches!(
                db.apply_batch(regressed),
                Err(Error::FloorRegressed(new, current))
                    if new == Location::new(0) && current == Location::new(1)
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rejects_regressed_ancestor_floor() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db::<mmr::Family>(
                context.with_label("db"),
                "immutable-regressed-ancestor-floor",
            )
            .await;

            let parent = db
                .new_batch()
                .set(Sha256::hash(&[1]), Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(1));
            let child = parent
                .new_batch::<Sha256>()
                .set(Sha256::hash(&[2]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0));

            assert!(matches!(
                db.apply_batch(child),
                Err(Error::FloorRegressed(new, prev))
                    if new == Location::new(0) && prev == Location::new(1)
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_restores_commit_metadata_and_floor() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "immutable-rewind-meta").await;

            let k1 = Sha256::hash(&[1]);
            let v1 = Sha256::fill(11u8);
            let meta1 = Sha256::fill(0xaa);
            let floor1 = Location::new(0);
            db.apply_batch(
                db.new_batch()
                    .set(k1, v1)
                    .merkleize(&db, Some(meta1), floor1),
            )
            .unwrap();
            db.commit().await.unwrap();
            let root_after_first = db.root();

            let k2 = Sha256::hash(&[2]);
            let v2 = Sha256::fill(22u8);
            let meta2 = Sha256::fill(0xbb);
            // Advance the floor to the commit of the first batch (loc 1).
            let floor2 = Location::new(1);
            db.apply_batch(
                db.new_batch()
                    .set(k2, v2)
                    .merkleize(&db, Some(meta2), floor2),
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
            let partition = "immutable-rewind-reopen";
            let meta1 = Sha256::fill(0xaa);
            let floor1 = Location::new(0);
            let meta2 = Sha256::fill(0xbb);
            let floor2 = Location::new(1);

            let root_after_first = {
                let mut db = open_db::<mmr::Family>(context.with_label("first"), partition).await;
                db.apply_batch(
                    db.new_batch()
                        .set(Sha256::hash(&[1]), Sha256::fill(11u8))
                        .merkleize(&db, Some(meta1), floor1),
                )
                .unwrap();
                db.commit().await.unwrap();
                let root = db.root();

                db.apply_batch(
                    db.new_batch()
                        .set(Sha256::hash(&[2]), Sha256::fill(22u8))
                        .merkleize(&db, Some(meta2), floor2),
                )
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
            let partition = "immutable-witness-tamper";
            let mut db = open_db::<mmr::Family>(context.with_label("db"), partition).await;
            db.apply_batch(
                db.new_batch()
                    .set(Sha256::hash(&[7]), Sha256::fill(7u8))
                    .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(1)),
            )
            .unwrap();
            db.commit().await.unwrap();
            let slot = db.merkle.active_slot();
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
                    crate::merkle::compact::Config {
                        partition: partition.into(),
                        strategy: Sequential,
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
            let partition = "immutable-invalid-persisted-floor";
            let mut db = open_db::<mmr::Family>(context.with_label("db"), partition).await;
            db.apply_batch(
                db.new_batch()
                    .set(Sha256::hash(&[7]), Sha256::fill(7u8))
                    .merkleize(&db, Some(Sha256::fill(0xaa)), Location::new(1)),
            )
            .unwrap();
            db.commit().await.unwrap();
            let slot = db.merkle.active_slot();
            drop(db);
            let oversized_floor = Location::new(10);

            overwrite_metadata_key(
                context.with_label("tamper"),
                partition,
                crate::qmdb::compact_witness::commit_op_key(slot),
                Operation::<mmr::Family, Digest, FixedEncoding<Digest>>::Commit(
                    Some(Sha256::fill(0xaa)),
                    oversized_floor,
                )
                .encode()
                .to_vec(),
            )
            .await;

            let merkle: crate::merkle::compact::Merkle<mmr::Family, _, _> =
                crate::merkle::compact::Merkle::init(
                    context.with_label("reopen"),
                    crate::merkle::compact::Config {
                        partition: partition.into(),
                        strategy: Sequential,
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
                open_db::<mmr::Family>(context.with_label("db"), "immutable-rewind-beyond").await;
            // Bootstrap sync flipped the pointer from the default slot 0 to slot 1; slot 0 is
            // still empty, so there is no prior state to rewind to.
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
                "immutable-rewind-preserves-pre-advance",
            )
            .await;

            db.apply_batch(
                db.new_batch()
                    .set(Sha256::hash(&[1]), Sha256::fill(1u8))
                    .merkleize(&db, None, Location::new(0)),
            )
            .unwrap();
            db.commit().await.unwrap();

            // Merkleize a batch against the post-commit-A state.
            let held = db
                .new_batch()
                .set(Sha256::hash(&[2]), Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0));

            // Advance past that state and commit, then rewind back to it.
            db.apply_batch(
                db.new_batch()
                    .set(Sha256::hash(&[3]), Sha256::fill(3u8))
                    .merkleize(&db, None, Location::new(0)),
            )
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
                open_db::<mmr::Family>(context.with_label("db"), "immutable-noop-after-commit")
                    .await;

            let k1 = Sha256::hash(&[1]);
            let v1 = Sha256::fill(11u8);
            let k2 = Sha256::hash(&[2]);
            let v2 = Sha256::fill(22u8);
            db.apply_batch(db.new_batch().set(k1, v1).set(k2, v2).merkleize(
                &db,
                Some(Sha256::fill(0xaa)),
                Location::new(0),
            ))
            .unwrap();
            db.commit().await.unwrap();
            let root_after_first = db.root();
            let size_after_first = db.size();

            db.commit().await.unwrap();
            assert_eq!(db.size(), size_after_first);
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.current_target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let partition = "immutable-noop-after-reopen";

            let (root_before_drop, size_before_drop) = {
                let mut db = open_db::<mmr::Family>(context.with_label("first"), partition).await;
                let k1 = Sha256::hash(&[1]);
                let v1 = Sha256::fill(11u8);
                let k2 = Sha256::hash(&[2]);
                let v2 = Sha256::fill(22u8);
                db.apply_batch(db.new_batch().set(k1, v1).set(k2, v2).merkleize(
                    &db,
                    Some(Sha256::fill(0xaa)),
                    Location::new(0),
                ))
                .unwrap();
                db.commit().await.unwrap();
                (db.root(), db.size())
            };

            let db = open_db::<mmr::Family>(context.with_label("second"), partition).await;
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.size(), size_before_drop);

            db.commit().await.unwrap();
            assert_eq!(db.size(), size_before_drop);
            assert_eq!(db.root(), root_before_drop);
            assert_eq!(db.current_target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_noop_commit_after_rewind() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "immutable-noop-after-rewind")
                    .await;

            let k1 = Sha256::hash(&[1]);
            let v1 = Sha256::fill(11u8);
            let k2 = Sha256::hash(&[2]);
            let v2 = Sha256::fill(22u8);
            db.apply_batch(db.new_batch().set(k1, v1).set(k2, v2).merkleize(
                &db,
                Some(Sha256::fill(0xaa)),
                Location::new(0),
            ))
            .unwrap();
            db.commit().await.unwrap();
            let root_after_first = db.root();
            let size_after_first = db.size();

            let k3 = Sha256::hash(&[3]);
            let v3 = Sha256::fill(33u8);
            db.apply_batch(db.new_batch().set(k3, v3).merkleize(
                &db,
                Some(Sha256::fill(0xbb)),
                Location::new(1),
            ))
            .unwrap();
            db.commit().await.unwrap();

            db.rewind().await.unwrap();
            assert_eq!(db.size(), size_after_first);
            assert_eq!(db.root(), root_after_first);

            db.commit().await.unwrap();
            assert_eq!(db.size(), size_after_first);
            assert_eq!(db.root(), root_after_first);
            assert_eq!(db.current_target().root, db.root());

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_rewind_makes_post_advance_batch_stale() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "immutable-rewind-makes-stale")
                    .await;

            db.apply_batch(
                db.new_batch()
                    .set(Sha256::hash(&[1]), Sha256::fill(1u8))
                    .merkleize(&db, None, Location::new(0)),
            )
            .unwrap();
            db.commit().await.unwrap();

            db.apply_batch(
                db.new_batch()
                    .set(Sha256::hash(&[2]), Sha256::fill(2u8))
                    .merkleize(&db, None, Location::new(0)),
            )
            .unwrap();
            db.commit().await.unwrap();

            // Merkleize a batch against the post-commit-B state, which the rewind will discard.
            let held = db
                .new_batch()
                .set(Sha256::hash(&[3]), Sha256::fill(3u8))
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
            let db = open_db::<mmr::Family>(context.with_label("db"), "immutable-serve-corruption")
                .await;
            let target = db.current_target();
            db.serve_state.write().commit_op_bytes.clear();

            assert!(matches!(
                db.compact_state(target),
                Err(compact_sync::ServeError::Database(Error::DataCorrupted(
                    "invalid cached commit operation"
                )))
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_compact_floor_beyond_size() {
        deterministic::Runner::default().start(|context| async move {
            let mut db =
                open_db::<mmr::Family>(context.with_label("db"), "immutable-floor-beyond").await;

            let batch = db.new_batch().merkleize(&db, None, Location::new(2));

            assert!(matches!(
                db.apply_batch(batch),
                Err(Error::FloorBeyondSize(floor, tip))
                    if floor == Location::new(2) && tip == Location::new(1)
            ));

            db.destroy().await.unwrap();
        });
    }
}

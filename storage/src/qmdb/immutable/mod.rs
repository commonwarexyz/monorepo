//! An authenticated database that only supports adding new keyed values (no updates or
//! deletions).
//!
//! Two variants are available based on value encoding:
//! - [fixed]: For fixed-size values.
//! - [variable]: For variable-size values.
//!
//! # Inactivity floor
//!
//! Each commit carries an inactivity floor: a location before which the application
//! declares operations are no longer needed. The floor is embedded in the operation
//! log and included in the Merkle root, so all replicas processing the same operations
//! arrive at the same floor.
//!
//! The floor controls two things:
//! - **Pruning**: [`Immutable::prune`] only allows pruning up to the floor.
//! - **Reconstruction**: on restart or sync, the snapshot is rebuilt from the floor
//!   onward. Keys set before the floor are not loaded into memory.
//!
//! The floor must be monotonically non-decreasing across commits and must not exceed
//! the batch's total operation count. Pass `db.inactivity_floor_loc()` to keep the
//! floor unchanged, or a higher value to advance it.
//!
//! # Examples
//!
//! ```ignore
//! // Simple mode: apply a batch, then durably commit it.
//! // The third argument to merkleize is the inactivity floor -- operations
//! // before this location are declared inactive by the application.
//! let floor = db.inactivity_floor_loc();
//! let merkleized = db.new_batch()
//!     .set(key, value)
//!     .merkleize(&db, None, floor);
//! db.apply_batch(merkleized).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Batches can still fork before you apply them.
//! let floor = db.inactivity_floor_loc();
//! let parent = db.new_batch()
//!     .set(key_a, value_a)
//!     .merkleize(&db, None, floor);
//!
//! let child_a = parent.new_batch::<Sha256>()
//!     .set(key_b, value_b)
//!     .merkleize(&db, None, floor);
//!
//! let child_b = parent.new_batch::<Sha256>()
//!     .set(key_c, value_c)
//!     .merkleize(&db, None, floor);
//!
//! db.apply_batch(child_a).await?;
//! db.commit().await?;
//! ```
//!
//! ```ignore
//! // Advanced mode: while the previous batch is being committed, build exactly
//! // one child batch from the newly published state.
//! let floor = db.inactivity_floor_loc();
//! let parent = db.new_batch()
//!     .set(key_a, value_a)
//!     .merkleize(&db, None, floor);
//! db.apply_batch(parent).await?;
//!
//! let (child, commit_result) = futures::join!(
//!     async {
//!         db.new_batch()
//!             .set(key_b, value_b)
//!             .merkleize(&db, None, floor)
//!     },
//!     db.commit(),
//! );
//! commit_result?;
//!
//! db.apply_batch(child).await?;
//! db.commit().await?;
//! ```

use crate::{
    index::{unordered::Index, Unordered as _},
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable, Reader},
        Error as JournalError,
    },
    merkle::{journaled::Config as MmrConfig, Family, Location, Proof},
    qmdb::{
        any::ValueEncoding,
        build_snapshot_from_log,
        operation::{Key, Operation as _},
        Error,
    },
    translator::Translator,
    Context, Persistable,
};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher as CHasher;
use std::{collections::HashSet, num::NonZeroU64, ops::Range, sync::Arc};
use tracing::warn;

pub mod batch;
pub mod fixed;
mod operation;
pub mod sync;
pub mod variable;

pub use operation::Operation;

/// Configuration for an [Immutable] authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, J> {
    /// Configuration for the Merkle structure backing the authenticated journal.
    pub merkle_config: MmrConfig,

    /// Configuration for the operations log journal.
    pub log: J,

    /// The translator used by the compressed index.
    pub translator: T,
}

/// An authenticated database that only supports adding new keyed values (no updates or
/// deletions).
///
/// # Invariant
///
/// A key must be set at most once across the database history. Writing the same key more than
/// once is undefined behavior.
///
/// Use [fixed::Db] or [variable::Db] for concrete instantiations.
pub struct Immutable<
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    H: CHasher,
    T: Translator,
> where
    C::Item: EncodeShared,
{
    /// Authenticated journal of operations.
    pub(crate) journal: authenticated::Journal<F, E, C, H>,

    /// A map from each active key to the location of the operation that set its value.
    ///
    /// # Invariant
    ///
    /// Only references operations of type [Operation::Set].
    pub(crate) snapshot: Index<T, Location<F>>,

    /// The location of the last commit operation.
    pub(crate) last_commit_loc: Location<F>,

    /// The inactivity floor declared by the last committed batch.
    /// Operations before this location are considered inactive by the application.
    pub(crate) inactivity_floor_loc: Location<F>,
}

// Shared read-only functionality.
impl<F, E, K, V, C, H, T> Immutable<F, E, K, V, C, H, T>
where
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, K, V>> + Persistable<Error = JournalError>,
    C::Item: EncodeShared,
    H: CHasher,
    T: Translator,
{
    /// Initialize from a pre-constructed authenticated journal.
    ///
    /// Seeds an initial commit if the journal is empty, builds the in-memory snapshot,
    /// and returns the initialized database.
    pub(crate) async fn init_from_journal(
        mut journal: authenticated::Journal<F, E, C, H>,
        context: E,
        translator: T,
    ) -> Result<Self, Error<F>> {
        if journal.size().await == 0 {
            warn!("Authenticated log is empty, initialized new db.");
            journal
                .append(&Operation::Commit(None, Location::new(0)))
                .await?;
            journal.sync().await?;
        }

        let mut snapshot = Index::new(context.with_label("snapshot"), translator);

        let (last_commit_loc, inactivity_floor_loc) = {
            let reader = journal.journal.reader().await;
            let bounds = reader.bounds();
            let last_commit_loc =
                Location::new(bounds.end.checked_sub(1).expect("commit should exist"));

            // Read the floor from the last commit operation.
            let last_op = reader.read(*last_commit_loc).await?;
            let inactivity_floor_loc = last_op
                .has_floor()
                .expect("last operation should be a commit with floor");

            // Replay the log from the inactivity floor to build the snapshot.
            build_snapshot_from_log::<F, _, _, _>(
                inactivity_floor_loc,
                &reader,
                &mut snapshot,
                |_, _| {},
            )
            .await?;

            (last_commit_loc, inactivity_floor_loc)
        };

        Ok(Self {
            journal,
            snapshot,
            last_commit_loc,
            inactivity_floor_loc,
        })
    }

    /// Return the inactivity floor location declared by the last committed batch.
    pub const fn inactivity_floor_loc(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Return the Location of the next operation appended to this db.
    pub async fn size(&self) -> Location<F> {
        self.bounds().await.end
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> Range<Location<F>> {
        let bounds = self.journal.reader().await.bounds();
        Location::new(bounds.start)..Location::new(bounds.end)
    }

    /// Return the most recent location from which this database can safely be synced, and the
    /// upper bound on [`Self::prune`]'s `loc`. For immutable databases, this equals the
    /// inactivity floor declared by the last committed batch.
    pub const fn sync_boundary(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Get the value of `key` in the db, or None if it has no value or its corresponding operation
    /// has been pruned.
    pub async fn get(&self, key: &K) -> Result<Option<V::Value>, Error<F>> {
        let iter = self.snapshot.get(key);
        let reader = self.journal.reader().await;
        let oldest = reader.bounds().start;
        for &loc in iter {
            if loc < oldest {
                continue;
            }
            if let Some(v) = Self::get_from_loc(&reader, key, loc).await? {
                return Ok(Some(v));
            }
        }

        Ok(None)
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&K]) -> Result<Vec<Option<V::Value>>, Error<F>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        let mut candidates: Vec<(usize, u64)> = Vec::with_capacity(keys.len());
        let mut results: Vec<Option<V::Value>> = vec![None; keys.len()];

        let reader = self.journal.reader().await;
        let oldest = reader.bounds().start;

        for (key_idx, key) in keys.iter().enumerate() {
            for &loc in self.snapshot.get(key) {
                if loc < oldest {
                    continue;
                }
                candidates.push((key_idx, *loc));
            }
        }

        if candidates.is_empty() {
            return Ok(results);
        }

        candidates.sort_unstable_by_key(|&(_, pos)| pos);

        let mut positions: Vec<u64> = Vec::with_capacity(candidates.len());
        for &(_, pos) in &candidates {
            if positions.last() != Some(&pos) {
                positions.push(pos);
            }
        }

        let ops = reader.read_many(&positions).await?;

        for &(key_idx, pos) in &candidates {
            if results[key_idx].is_some() {
                continue;
            }
            let op_idx = positions
                .binary_search(&pos)
                .expect("position was deduped from candidates");
            let Operation::Set(k, v) = &ops[op_idx] else {
                continue;
            };
            if k == keys[key_idx] {
                results[key_idx] = Some(v.clone());
            }
        }

        Ok(results)
    }

    /// Get the value of the operation with location `loc` in the db if it matches `key`. Returns
    /// [`crate::qmdb::Error::OperationPruned`] if loc precedes the oldest retained location. The
    /// location is otherwise assumed valid.
    async fn get_from_loc(
        reader: &impl Reader<Item = Operation<F, K, V>>,
        key: &K,
        loc: Location<F>,
    ) -> Result<Option<V::Value>, Error<F>> {
        if loc < reader.bounds().start {
            return Err(Error::OperationPruned(loc));
        }

        let Operation::Set(k, v) = reader.read(*loc).await? else {
            return Err(Error::UnexpectedData(loc));
        };

        if k != *key {
            Ok(None)
        } else {
            Ok(Some(v))
        }
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error<F>> {
        let last_commit_loc = self.last_commit_loc;
        let Operation::Commit(metadata, _floor) = self
            .journal
            .journal
            .reader()
            .await
            .read(*last_commit_loc)
            .await?
        else {
            unreachable!("no commit operation at location of last commit {last_commit_loc}");
        };

        Ok(metadata)
    }

    /// Analogous to proof but with respect to the state of the database when it had `op_count`
    /// operations.
    ///
    /// # Errors
    ///
    /// Returns [crate::merkle::Error::LocationOverflow] if `op_count` or `start_loc` >
    /// [crate::merkle::Family::MAX_LEAVES].
    /// Returns [crate::merkle::Error::RangeOutOfBounds] if `op_count` > number of operations, or
    /// if `start_loc` >= `op_count`.
    /// Returns [`Error::OperationPruned`] if `start_loc` has been pruned.
    pub async fn historical_proof(
        &self,
        op_count: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, K, V>>), Error<F>> {
        Ok(self
            .journal
            .historical_proof(op_count, start_loc, max_ops)
            .await?)
    }

    /// Generate and return:
    ///  1. a proof of all operations applied to the db in the range starting at (and including)
    ///     location `start_loc`, and ending at the first of either:
    ///     - the last operation performed, or
    ///     - the operation `max_ops` from the start.
    ///  2. the operations corresponding to the leaves in this range.
    pub async fn proof(
        &self,
        start_index: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, K, V>>), Error<F>> {
        let op_count = self.bounds().await.end;
        self.historical_proof(op_count, start_index, max_ops).await
    }

    /// Prune operations prior to `prune_loc`. This does not affect the db's root, but it will
    /// affect retrieval of any keys that were set prior to `prune_loc`.
    ///
    /// Pruning is irreversible. Callers must ensure any floor-raising batch has been durably
    /// committed (via [`Immutable::commit`] or [`Immutable::sync`]) before pruning. The
    /// inactivity floor used to gate pruning is updated by [`Immutable::apply_batch`] before
    /// the batch is durable. If the batch is lost on crash, recovery replays from the prior
    /// durable floor, which may reference data that has already been pruned.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::merkle::Error::LocationOverflow] if `prune_loc` > [crate::merkle::Family::MAX_LEAVES].
    pub async fn prune(&mut self, loc: Location<F>) -> Result<(), Error<F>> {
        if loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                loc,
                self.inactivity_floor_loc,
            ));
        }
        self.journal.prune(loc).await?;

        Ok(())
    }

    /// Rewind the database to `size` operations, where `size` is the location of the next append.
    ///
    /// This rewinds both the operations journal and its Merkle structure to the historical
    /// state at `size`, and removes rewound set operations from the in-memory snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - `size` is not a valid rewind target
    /// - the target's required logical range is not fully retained (for immutable, this means the
    ///   oldest retained location is already beyond the rewind boundary)
    /// - `size - 1` is not a commit operation
    ///
    /// Any error from this method is fatal for this handle. Rewind may mutate journal state
    /// before this method finishes rebuilding in-memory rewind state. Callers must drop this
    /// database handle after any `Err` from `rewind` and reopen from storage.
    ///
    /// A successful rewind is not restart-stable until a subsequent [`Immutable::commit`] or
    /// [`Immutable::sync`].
    pub async fn rewind(&mut self, size: Location<F>) -> Result<(), Error<F>> {
        let rewind_size = *size;
        let current_size = *self.last_commit_loc + 1;
        if rewind_size == current_size {
            return Ok(());
        }
        if rewind_size == 0 || rewind_size > current_size {
            return Err(Error::Journal(crate::journal::Error::InvalidRewind(
                rewind_size,
            )));
        }

        let (rewind_last_loc, rewind_floor, rewound_keys) = {
            let reader = self.journal.reader().await;
            let bounds = reader.bounds();
            let rewind_last_loc = Location::new(rewind_size - 1);
            if rewind_size <= bounds.start {
                return Err(Error::Journal(crate::journal::Error::ItemPruned(
                    *rewind_last_loc,
                )));
            }
            let rewind_last_op = reader.read(*rewind_last_loc).await?;
            let Operation::Commit(_, rewind_floor) = &rewind_last_op else {
                return Err(Error::UnexpectedData(rewind_last_loc));
            };
            let rewind_floor = *rewind_floor;
            if *rewind_floor < bounds.start {
                return Err(Error::Journal(crate::journal::Error::ItemPruned(
                    *rewind_floor,
                )));
            }

            let mut rewound_keys = Vec::new();
            for loc in rewind_size..current_size {
                if let Operation::Set(key, _) = reader.read(loc).await? {
                    rewound_keys.push(key);
                }
            }

            (rewind_last_loc, rewind_floor, rewound_keys)
        };

        let old_floor = self.inactivity_floor_loc;

        // Journal rewind happens before in-memory snapshot updates. If a later step fails, this
        // handle may be internally diverged and must be dropped by the caller.
        self.journal.rewind(rewind_size).await?;

        // Remove suffix keys from the snapshot. After reopen, the snapshot may
        // have been rebuilt from a higher floor, so some suffix keys might not
        // be present -- use remove() which is tolerant of missing keys.
        for key in &rewound_keys {
            self.snapshot.remove(key);
        }

        // If the rewind target has a lower floor than the current snapshot was
        // built from, insert keys from the gap [rewind_floor, old_floor) that
        // were excluded by the higher-floor reconstruction.
        if rewind_floor < old_floor {
            let reader = self.journal.journal.reader().await;
            let gap_end = core::cmp::min(*old_floor, rewind_size);
            for loc in *rewind_floor..gap_end {
                if let Operation::Set(key, _) = reader.read(loc).await? {
                    self.snapshot.insert(&key, Location::new(loc));
                }
            }
        }

        self.last_commit_loc = rewind_last_loc;
        self.inactivity_floor_loc = rewind_floor;

        Ok(())
    }

    /// Return the root of the db.
    pub fn root(&self) -> H::Digest {
        self.journal.root()
    }

    /// Return the pinned Merkle nodes at the given location.
    pub async fn pinned_nodes_at(&self, loc: Location<F>) -> Result<Vec<H::Digest>, Error<F>> {
        if !loc.is_valid() {
            return Err(crate::merkle::Error::LocationOverflow(loc).into());
        }
        let futs: Vec<_> = F::nodes_to_pin(loc)
            .map(|p| async move {
                self.journal
                    .merkle
                    .get_node(p)
                    .await?
                    .ok_or(crate::merkle::Error::ElementPruned(p).into())
            })
            .collect();
        futures::future::try_join_all(futs).await
    }

    /// Sync all database state to disk. While this isn't necessary to ensure durability of
    /// committed operations, periodic invocation may reduce memory usage and the time required to
    /// recover the database on restart.
    pub async fn sync(&self) -> Result<(), Error<F>> {
        Ok(self.journal.sync().await?)
    }

    /// Durably commit the journal state published by prior [`Immutable::apply_batch`] calls.
    pub async fn commit(&self) -> Result<(), Error<F>> {
        Ok(self.journal.commit().await?)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error<F>> {
        Ok(self.journal.destroy().await?)
    }

    /// Create a new speculative batch of operations with this database as its parent.
    #[allow(clippy::type_complexity)]
    pub fn new_batch(&self) -> batch::UnmerkleizedBatch<F, H, K, V> {
        let journal_size = *self.last_commit_loc + 1;
        batch::UnmerkleizedBatch::new(self, journal_size)
    }

    /// Apply a [`batch::MerkleizedBatch`] to the database.
    ///
    /// A batch is valid only if every batch applied to the database since this batch's
    /// ancestor chain was created is an ancestor of this batch. Applying a batch from a
    /// different fork returns [`Error::StaleBatch`].
    ///
    /// Returns the range of locations written.
    ///
    /// # Errors
    ///
    /// - [`Error::StaleBatch`] if the batch was created from a stale DB state.
    /// - [`Error::FloorRegressed`] if the batch's inactivity floor is below the
    ///   database's current floor.
    /// - [`Error::FloorBeyondSize`] if the batch's inactivity floor exceeds its
    ///   commit operation's location. The maximum valid floor is
    ///   `total_size - 1` (the commit operation's location); a floor past the
    ///   commit would permit pruning the commit itself.
    ///
    /// This publishes the batch to the in-memory database state and appends it to the
    /// journal, but does not durably commit it. Call [`Immutable::commit`] or
    /// [`Immutable::sync`] to guarantee durability.
    pub async fn apply_batch(
        &mut self,
        batch: Arc<batch::MerkleizedBatch<F, H::Digest, K, V>>,
    ) -> Result<Range<Location<F>>, Error<F>> {
        let db_size = *self.last_commit_loc + 1;
        let valid = db_size == batch.db_size
            || db_size == batch.base_size
            || batch.ancestor_diff_ends.contains(&db_size);
        if !valid {
            return Err(Error::StaleBatch {
                db_size,
                batch_db_size: batch.db_size,
                batch_base_size: batch.base_size,
            });
        }
        if batch.new_inactivity_floor_loc < self.inactivity_floor_loc {
            return Err(Error::FloorRegressed(
                batch.new_inactivity_floor_loc,
                self.inactivity_floor_loc,
            ));
        }
        let tip_commit_loc = Location::new(batch.total_size - 1);
        if batch.new_inactivity_floor_loc > tip_commit_loc {
            return Err(Error::FloorBeyondSize(
                batch.new_inactivity_floor_loc,
                tip_commit_loc,
            ));
        }
        let start_loc = Location::new(db_size);

        // Apply journal.
        self.journal.apply_batch(&batch.journal_batch).await?;

        // Apply snapshot inserts. Child first (child wins via `seen`), then
        // uncommitted ancestor batches.
        let bounds = self.journal.reader().await.bounds();
        let mut seen = HashSet::new();
        for (key, entry) in batch.diff.iter() {
            seen.insert(key.clone());
            self.snapshot
                .insert_and_prune(key, entry.loc, |v| *v < bounds.start);
        }
        for (i, ancestor_diff) in batch.ancestor_diffs.iter().enumerate() {
            if batch.ancestor_diff_ends[i] <= db_size {
                continue;
            }
            for (key, entry) in ancestor_diff.iter() {
                if seen.insert(key.clone()) {
                    self.snapshot
                        .insert_and_prune(key, entry.loc, |v| *v < bounds.start);
                }
            }
        }

        // Update state.
        self.last_commit_loc = Location::new(batch.total_size - 1);
        self.inactivity_floor_loc = batch.new_inactivity_floor_loc;
        Ok(start_loc..Location::new(batch.total_size))
    }
}

#[cfg(test)]
pub(super) mod test {
    use super::*;
    use crate::{
        merkle::{Family, Location},
        qmdb::verify_proof,
        translator::TwoCap,
    };
    use commonware_codec::EncodeShared;
    use commonware_cryptography::{sha256, sha256::Digest, Sha256};
    use commonware_runtime::{deterministic, Metrics};
    use commonware_utils::NZU64;
    use core::{future::Future, pin::Pin};
    use std::ops::Range;

    type StandardHasher<H> = crate::merkle::hasher::Standard<H>;

    const ITEMS_PER_SECTION: u64 = 5;

    type TestDb<F, V, C> = Immutable<F, deterministic::Context, Digest, V, C, Sha256, TwoCap>;

    pub(crate) async fn test_immutable_empty<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let db = open_db(context.with_label("first")).await;
        let bounds = db.bounds().await;
        assert_eq!(bounds.end, 1);
        assert_eq!(bounds.start, Location::new(0));
        assert_eq!(db.inactivity_floor_loc(), Location::new(0));
        assert!(db.get_metadata().await.unwrap().is_none());

        // Make sure closing/reopening gets us back to the same state, even after adding an uncommitted op.
        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);
        let root = db.root();
        {
            let _batch = db.new_batch().set(k1, v1);
            // Don't merkleize/apply -- simulate failed commit
        }
        drop(db);
        let mut db = open_db(context.with_label("second")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.bounds().await.end, 1);

        // Test calling commit on an empty db which should make it (durably) non-empty.
        db.apply_batch(db.new_batch().merkleize(&db, None, Location::new(0)))
            .await
            .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.bounds().await.end, 2); // commit op added
        let root = db.root();
        drop(db);

        let db = open_db(context.with_label("third")).await;
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_build_basic<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        // Build a db with 2 keys.
        let mut db = open_db(context.with_label("first")).await;

        let k1 = Sha256::fill(1u8);
        let k2 = Sha256::fill(2u8);
        let v1 = Sha256::fill(3u8);
        let v2 = Sha256::fill(4u8);

        assert!(db.get(&k1).await.unwrap().is_none());
        assert!(db.get(&k2).await.unwrap().is_none());

        // Set and commit the first key.
        let metadata = Some(Sha256::fill(99u8));
        db.apply_batch(
            db.new_batch()
                .set(k1, v1)
                .merkleize(&db, metadata, Location::new(0)),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
        assert!(db.get(&k2).await.unwrap().is_none());
        assert_eq!(db.bounds().await.end, 3);
        assert_eq!(db.get_metadata().await.unwrap(), Some(Sha256::fill(99u8)));

        // Set and commit the second key.
        db.apply_batch(
            db.new_batch()
                .set(k2, v2)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
        assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);
        assert_eq!(db.bounds().await.end, 5);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        // Capture state.
        let root = db.root();

        // Add an uncommitted op then simulate failure.
        let k3 = Sha256::fill(5u8);
        let v3 = Sha256::fill(6u8);
        {
            let _batch = db.new_batch().set(k3, v3);
            // Don't merkleize/apply -- simulate failed commit
        }

        // Reopen, make sure state is restored to last commit point.
        drop(db); // Simulate failed commit
        let db = open_db(context.with_label("second")).await;
        assert!(db.get(&k3).await.unwrap().is_none());
        assert_eq!(db.root(), root);
        assert_eq!(db.get(&k1).await.unwrap().unwrap(), v1);
        assert_eq!(db.get(&k2).await.unwrap().unwrap(), v2);
        assert_eq!(db.bounds().await.end, 5);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        // Cleanup.
        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_proof_verify<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("first")).await;

        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(10u8);
        db.apply_batch(
            db.new_batch()
                .set(k1, v1)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();

        let (proof, ops) = db.proof(Location::new(0), NZU64!(100)).await.unwrap();
        let root = db.root();
        let hasher = StandardHasher::<Sha256>::new();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_prune<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("first")).await;

        for i in 0..20u8 {
            let key = Sha256::fill(i);
            let value = Sha256::fill(i.wrapping_add(100));
            let floor = db.bounds().await.end;
            db.apply_batch(db.new_batch().set(key, value).merkleize(&db, None, floor))
                .await
                .unwrap();
            db.commit().await.unwrap();
        }

        let root_before = db.root();
        let bounds_before = db.bounds().await;

        let prune_loc = Location::new(*bounds_before.end - 5);
        db.prune(prune_loc).await.unwrap();

        assert_eq!(db.root(), root_before);

        let key_0 = Sha256::fill(0u8);
        assert!(db.get(&key_0).await.unwrap().is_none());

        let key_19 = Sha256::fill(19u8);
        assert_eq!(
            db.get(&key_19).await.unwrap(),
            Some(Sha256::fill(19u8.wrapping_add(100)))
        );

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_batch_chain<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("first")).await;

        let k1 = Sha256::fill(1u8);
        let k2 = Sha256::fill(2u8);
        let k3 = Sha256::fill(3u8);
        let v1 = Sha256::fill(11u8);
        let v2 = Sha256::fill(12u8);
        let v3 = Sha256::fill(13u8);

        let parent = db
            .new_batch()
            .set(k1, v1)
            .merkleize(&db, None, Location::new(0));
        let child = parent
            .new_batch::<Sha256>()
            .set(k2, v2)
            .merkleize(&db, None, Location::new(0));

        assert_eq!(child.get(&k1, &db).await.unwrap(), Some(v1));
        assert_eq!(child.get(&k2, &db).await.unwrap(), Some(v2));
        assert!(child.get(&k3, &db).await.unwrap().is_none());

        db.apply_batch(child).await.unwrap();
        db.commit().await.unwrap();

        assert_eq!(db.get(&k1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&k2).await.unwrap(), Some(v2));

        db.apply_batch(
            db.new_batch()
                .set(k3, v3)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.get(&k3).await.unwrap(), Some(v3));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_build_and_authenticate<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        // Build a db with `ELEMENTS` key/value pairs and prove ranges over them.
        let hasher = StandardHasher::<Sha256>::new();
        let mut db = open_db(context.with_label("first")).await;

        let mut batch = db.new_batch();
        for i in 0u64..2_000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::fill(i as u8);
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&db, None, Location::new(0));
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.bounds().await.end, 2_000 + 2);

        // Drop & reopen the db, making sure it has exactly the same state.
        let root = db.root();
        drop(db);

        let db = open_db(context.with_label("second")).await;
        assert_eq!(root, db.root());
        assert_eq!(db.bounds().await.end, 2_000 + 2);
        for i in 0u64..2_000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::fill(i as u8);
            assert_eq!(db.get(&k).await.unwrap().unwrap(), v);
        }

        // Make sure all ranges of 5 operations are provable, including truncated ranges at the
        // end.
        let max_ops = NZU64!(5);
        for i in 0..*db.bounds().await.end {
            let (proof, log) = db.proof(Location::new(i), max_ops).await.unwrap();
            assert!(verify_proof(&hasher, &proof, Location::new(i), &log, &root));
        }

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_recovery_from_failed_merkle_sync<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        // Insert 1000 keys then sync.
        const ELEMENTS: u64 = 1000;
        let mut db = open_db(context.with_label("first")).await;

        let mut batch = db.new_batch();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::fill(i as u8);
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&db, None, Location::new(0));
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.bounds().await.end, ELEMENTS + 2);
        db.sync().await.unwrap();
        let halfway_root = db.root();

        // Insert another 1000 keys (different from the first batch) then commit.
        let mut batch = db.new_batch();
        for i in ELEMENTS..ELEMENTS * 2 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::fill(i as u8);
            batch = batch.set(k, v);
        }
        let merkleized = batch.merkleize(&db, None, Location::new(0));
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        drop(db); // Drop before syncing

        // Recovery should replay the log to regenerate the merkle structure.
        // op_count = 1002 (first batch + commit) + 1000 (second batch) + 1 (second commit) = 2003
        let db = open_db(context.with_label("second")).await;
        assert_eq!(db.bounds().await.end, 2003);
        let root = db.root();
        assert_ne!(root, halfway_root);

        // Drop & reopen could preserve the final commit.
        drop(db);
        let db = open_db(context.with_label("third")).await;
        assert_eq!(db.bounds().await.end, 2003);
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_recovery_from_failed_log_sync<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("first")).await;

        // Insert a single key and then commit to create a first commit point.
        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(3u8);
        db.apply_batch(
            db.new_batch()
                .set(k1, v1)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        let first_commit_root = db.root();

        // Simulate failure. Sets that are never merkleized/applied are lost.
        // Recovery should restore the last commit point.
        drop(db);

        // Recovery should back up to previous commit point.
        let db = open_db(context.with_label("second")).await;
        assert_eq!(db.bounds().await.end, 3);
        let root = db.root();
        assert_eq!(root, first_commit_root);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_pruning<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        // Build a db with `ELEMENTS` key/value pairs then prune some of them.
        const ELEMENTS: u64 = 2_000;
        let mut db = open_db(context.with_label("first")).await;

        // Batch writes keys in BTreeMap-sorted order, so build the sorted key
        // list to map between journal locations and keys.
        let mut sorted_keys: Vec<sha256::Digest> = (1u64..ELEMENTS + 1)
            .map(|i| Sha256::hash(&i.to_be_bytes()))
            .collect();
        sorted_keys.sort();
        // Location 0: initial commit; locations 1..=ELEMENTS: Set ops in sorted
        // key order; location ELEMENTS+1: batch commit.
        // key_at_loc(L) = sorted_keys[L - 1] for 1 <= L <= ELEMENTS.

        let mut batch = db.new_batch();
        for i in 1u64..ELEMENTS + 1 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::fill(i as u8);
            batch = batch.set(k, v);
        }
        // The inactivity floor must cover both prune targets in this test.
        // Second prune request is at ELEMENTS / 2 + ITEMS_PER_SECTION * 2 - 1.
        let inactivity_floor = Location::new(ELEMENTS / 2 + ITEMS_PER_SECTION * 2 - 1);
        let merkleized = batch.merkleize(&db, None, inactivity_floor);
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.bounds().await.end, ELEMENTS + 2);

        // Prune the db to the first half of the operations.
        db.prune(Location::new((ELEMENTS + 2) / 2)).await.unwrap();
        let bounds = db.bounds().await;
        assert_eq!(bounds.end, ELEMENTS + 2);

        // items_per_section is 5, so half should be exactly at a blob boundary, in which case
        // the actual pruning location should match the requested.
        let oldest_retained_loc = bounds.start;
        assert_eq!(oldest_retained_loc, Location::new(ELEMENTS / 2));

        // Try to fetch a pruned key (at location oldest_retained - 1).
        let pruned_key = sorted_keys[*oldest_retained_loc as usize - 2];
        assert!(db.get(&pruned_key).await.unwrap().is_none());

        // Try to fetch unpruned key (at location oldest_retained).
        let unpruned_key = sorted_keys[*oldest_retained_loc as usize - 1];
        assert!(db.get(&unpruned_key).await.unwrap().is_some());

        // Drop & reopen the db, making sure it has exactly the same state.
        let root = db.root();
        db.sync().await.unwrap();
        drop(db);

        let mut db = open_db(context.with_label("second")).await;
        assert_eq!(root, db.root());
        let bounds = db.bounds().await;
        assert_eq!(bounds.end, ELEMENTS + 2);
        let oldest_retained_loc = bounds.start;
        assert_eq!(oldest_retained_loc, Location::new(ELEMENTS / 2));

        // Prune to a non-blob boundary.
        let loc = Location::new(ELEMENTS / 2 + (ITEMS_PER_SECTION * 2 - 1));
        db.prune(loc).await.unwrap();
        // Actual boundary should be a multiple of 5.
        let oldest_retained_loc = db.bounds().await.start;
        assert_eq!(
            oldest_retained_loc,
            Location::new(ELEMENTS / 2 + ITEMS_PER_SECTION)
        );

        // Confirm boundary persists across restart.
        db.sync().await.unwrap();
        drop(db);
        let db = open_db(context.with_label("third")).await;
        let oldest_retained_loc = db.bounds().await.start;
        assert_eq!(
            oldest_retained_loc,
            Location::new(ELEMENTS / 2 + ITEMS_PER_SECTION)
        );

        // Try to fetch a key before the inactivity floor (not in snapshot after reopen).
        let floor_val = ELEMENTS / 2 + ITEMS_PER_SECTION * 2 - 1;
        let inactive_key = sorted_keys[floor_val as usize - 2];
        assert!(db.get(&inactive_key).await.unwrap().is_none());

        // Try to fetch a key at the inactivity floor (in snapshot after reopen).
        let active_key = sorted_keys[floor_val as usize - 1];
        assert!(db.get(&active_key).await.unwrap().is_some());

        // Confirm behavior of trying to create a proof of pruned items is as expected.
        let pruned_pos = ELEMENTS / 2;
        let proof_result = db
            .proof(Location::new(pruned_pos), NZU64!(pruned_pos + 100))
            .await;
        assert!(
            matches!(proof_result, Err(Error::Journal(crate::journal::Error::ItemPruned(pos))) if pos == pruned_pos)
        );

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_prune_beyond_floor<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("test")).await;

        // Test pruning empty database (floor=0, so prune(1) fails)
        let result = db.prune(Location::new(1)).await;
        assert!(
            matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, floor))
                if prune_loc == Location::new(1) && floor == Location::new(0))
        );

        // Add key-value pairs and commit
        let k1 = Digest::from(*b"12345678901234567890123456789012");
        let k2 = Digest::from(*b"abcdefghijklmnopqrstuvwxyz123456");
        let k3 = Digest::from(*b"99999999999999999999999999999999");
        let v1 = Sha256::fill(1u8);
        let v2 = Sha256::fill(2u8);
        let v3 = Sha256::fill(3u8);

        // First batch with floor=3 (the commit location).
        db.apply_batch(db.new_batch().set(k1, v1).set(k2, v2).merkleize(
            &db,
            None,
            Location::new(3),
        ))
        .await
        .unwrap();

        // op_count is 4 (initial_commit, k1, k2, commit), last_commit is at location 3
        assert_eq!(*db.last_commit_loc, 3);

        // Second batch with floor=5 (the new commit location).
        db.apply_batch(
            db.new_batch()
                .set(k3, v3)
                .merkleize(&db, None, Location::new(5)),
        )
        .await
        .unwrap();

        // Test valid prune (3 <= floor of 5)
        assert!(db.prune(Location::new(3)).await.is_ok());

        // Test pruning beyond inactivity floor
        let floor = db.inactivity_floor_loc();
        let beyond = floor + 1;
        let result = db.prune(beyond).await;
        assert!(
            matches!(result, Err(Error::PruneBeyondMinRequired(prune_loc, f))
                if prune_loc == beyond && f == floor)
        );

        db.destroy().await.unwrap();
    }

    async fn commit_sets<F: Family, V, C>(
        db: &mut TestDb<F, V, C>,
        sets: impl IntoIterator<Item = (Digest, V::Value)>,
        metadata: Option<V::Value>,
    ) -> Range<Location<F>>
    where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        commit_sets_with_floor(db, sets, metadata, Location::new(0)).await
    }

    async fn commit_sets_with_floor<F: Family, V, C>(
        db: &mut TestDb<F, V, C>,
        sets: impl IntoIterator<Item = (Digest, V::Value)>,
        metadata: Option<V::Value>,
        floor: Location<F>,
    ) -> Range<Location<F>>
    where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut batch = db.new_batch();
        for (key, value) in sets {
            batch = batch.set(key, value);
        }
        let range = db
            .apply_batch(batch.merkleize(db, metadata, floor))
            .await
            .unwrap();
        db.commit().await.unwrap();
        range
    }

    pub(crate) async fn test_immutable_rewind_recovery<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key1 = Sha256::hash(&1u64.to_be_bytes());
        let key2 = Sha256::hash(&2u64.to_be_bytes());
        let key3 = Sha256::hash(&3u64.to_be_bytes());
        let key4 = Sha256::hash(&4u64.to_be_bytes());

        let value1 = Sha256::fill(11u8);
        let value2 = Sha256::fill(22u8);
        let value3 = Sha256::fill(33u8);
        let value4 = Sha256::fill(66u8);

        let metadata_a = Sha256::fill(44u8);
        let first_range =
            commit_sets(&mut db, [(key1, value1), (key2, value2)], Some(metadata_a)).await;
        let size_before = db.bounds().await.end;
        let root_before = db.root();
        let last_commit_before = db.last_commit_loc;
        assert_eq!(size_before, first_range.end);

        let metadata_b = Sha256::fill(55u8);
        let second_range =
            commit_sets(&mut db, [(key3, value3), (key4, value4)], Some(metadata_b)).await;
        assert_eq!(second_range.start, size_before);
        assert_ne!(db.root(), root_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_b));
        assert_eq!(db.get(&key3).await.unwrap(), Some(value3));
        assert_eq!(db.get(&key4).await.unwrap(), Some(value4));

        db.rewind(size_before).await.unwrap();
        assert_eq!(db.root(), root_before);
        assert_eq!(db.bounds().await.end, size_before);
        assert_eq!(db.last_commit_loc, last_commit_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a));
        assert_eq!(db.get(&key1).await.unwrap(), Some(value1));
        assert_eq!(db.get(&key2).await.unwrap(), Some(value2));
        assert_eq!(db.get(&key3).await.unwrap(), None);
        assert_eq!(db.get(&key4).await.unwrap(), None);

        db.commit().await.unwrap();
        drop(db);
        let db = open_db(context.with_label("reopen")).await;
        assert_eq!(db.root(), root_before);
        assert_eq!(db.bounds().await.end, size_before);
        assert_eq!(db.last_commit_loc, last_commit_before);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a));
        assert_eq!(db.get(&key1).await.unwrap(), Some(value1));
        assert_eq!(db.get(&key2).await.unwrap(), Some(value2));
        assert_eq!(db.get(&key3).await.unwrap(), None);
        assert_eq!(db.get(&key4).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_rewind_pruned_target_errors<F: Family, V, C>(
        context: deterministic::Context,
        open_small_sections_db: impl Fn(
            deterministic::Context,
        )
            -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_small_sections_db(context.with_label("db")).await;

        let first_range = commit_sets(
            &mut db,
            (0u64..16).map(|i| (Sha256::hash(&i.to_be_bytes()), Sha256::fill(i as u8))),
            None,
        )
        .await;

        let mut round = 0u64;
        loop {
            round += 1;
            assert!(
                round <= 64,
                "failed to prune enough history for rewind test"
            );

            // Floor must be >= last_commit_loc for prune to succeed.
            // With 16 sets, commit is at current end + 16.
            let floor = Location::new(*db.bounds().await.end + 16);
            commit_sets_with_floor(
                &mut db,
                (0u64..16).map(|i| {
                    let seed = round * 100 + i;
                    (Sha256::hash(&seed.to_be_bytes()), Sha256::fill(seed as u8))
                }),
                None,
                floor,
            )
            .await;
            db.prune(db.last_commit_loc).await.unwrap();

            if db.bounds().await.start > first_range.start {
                break;
            }
        }

        let oldest_retained = db.bounds().await.start;
        let boundary_err = db.rewind(oldest_retained).await.unwrap_err();
        assert!(
            matches!(
                boundary_err,
                Error::Journal(crate::journal::Error::ItemPruned(_))
            ),
            "unexpected rewind error at retained boundary: {boundary_err:?}"
        );

        let err = db.rewind(first_range.start).await.unwrap_err();
        assert!(
            matches!(err, Error::Journal(crate::journal::Error::ItemPruned(_))),
            "unexpected rewind error: {err:?}"
        );

        db.destroy().await.unwrap();
    }

    /// batch.get() reads pending mutations and falls through to base DB.
    pub(crate) async fn test_immutable_batch_get_read_through<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        // Pre-populate with key A.
        let key_a = Sha256::hash(&0u64.to_be_bytes());
        let val_a = Sha256::fill(1u8);
        db.apply_batch(
            db.new_batch()
                .set(key_a, val_a)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();

        // batch.get(&A) should return DB value.
        let mut batch = db.new_batch();
        assert_eq!(batch.get(&key_a, &db).await.unwrap(), Some(val_a));

        // Set B in batch, batch.get(&B) returns the value.
        let key_b = Sha256::hash(&1u64.to_be_bytes());
        let val_b = Sha256::fill(2u8);
        batch = batch.set(key_b, val_b);
        assert_eq!(batch.get(&key_b, &db).await.unwrap(), Some(val_b));

        // Nonexistent key.
        let key_c = Sha256::hash(&2u64.to_be_bytes());
        assert_eq!(batch.get(&key_c, &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    /// Child batch reads parent diff and adds its own mutations.
    pub(crate) async fn test_immutable_batch_stacked_get<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let db = open_db(context.with_label("db")).await;

        // Parent batch: set A.
        let key_a = Sha256::hash(&0u64.to_be_bytes());
        let val_a = Sha256::fill(10u8);
        let parent = db.new_batch().set(key_a, val_a);
        let parent_m = parent.merkleize(&db, None, Location::new(0));

        // Child reads parent's A.
        let mut child = parent_m.new_batch::<Sha256>();
        assert_eq!(child.get(&key_a, &db).await.unwrap(), Some(val_a));

        // Child sets B.
        let key_b = Sha256::hash(&1u64.to_be_bytes());
        let val_b = Sha256::fill(20u8);
        child = child.set(key_b, val_b);
        assert_eq!(child.get(&key_b, &db).await.unwrap(), Some(val_b));

        // Nonexistent key.
        let key_c = Sha256::hash(&2u64.to_be_bytes());
        assert_eq!(child.get(&key_c, &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    /// Two-level stacked batch apply works end-to-end.
    pub(crate) async fn test_immutable_batch_stacked_apply<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        // Sort keys so operations are in BTreeMap order (same as merkleize writes).
        let mut kvs_first: Vec<(Digest, Digest)> = (0u64..5)
            .map(|i| (Sha256::hash(&i.to_be_bytes()), Sha256::fill(i as u8)))
            .collect();
        kvs_first.sort_by_key(|a| a.0);

        let mut kvs_second: Vec<(Digest, Digest)> = (5u64..10)
            .map(|i| (Sha256::hash(&i.to_be_bytes()), Sha256::fill(i as u8)))
            .collect();
        kvs_second.sort_by_key(|a| a.0);

        // Parent batch: set keys 0..5.
        let mut parent = db.new_batch();
        for (k, v) in &kvs_first {
            parent = parent.set(*k, *v);
        }
        let parent_m = parent.merkleize(&db, None, Location::new(0));

        // Child batch: set keys 5..10.
        let mut child = parent_m.new_batch::<Sha256>();
        for (k, v) in &kvs_second {
            child = child.set(*k, *v);
        }
        let child_m = child.merkleize(&db, None, Location::new(0));
        let expected_root = child_m.root();
        db.apply_batch(child_m).await.unwrap();

        assert_eq!(db.root(), expected_root);

        // All 10 keys should be accessible.
        for (k, v) in kvs_first.iter().chain(kvs_second.iter()) {
            assert_eq!(db.get(k).await.unwrap(), Some(*v));
        }

        db.destroy().await.unwrap();
    }

    /// MerkleizedBatch::root() matches db.root() after apply_batch().
    pub(crate) async fn test_immutable_batch_speculative_root<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let mut batch = db.new_batch();
        for i in 0u8..10 {
            let k = Sha256::hash(&[i]);
            batch = batch.set(k, Sha256::fill(i));
        }
        let merkleized = batch.merkleize(&db, None, Location::new(0));

        let speculative = merkleized.root();
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.root(), speculative);

        // Second batch with metadata.
        let metadata = Some(Sha256::fill(55u8));
        let mut batch = db.new_batch();
        let k = Sha256::hash(&[0xAA]);
        batch = batch.set(k, Sha256::fill(0xAA));
        let merkleized = batch.merkleize(&db, metadata, Location::new(0));
        let speculative = merkleized.root();
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.root(), speculative);

        db.destroy().await.unwrap();
    }

    /// MerkleizedBatch::get() reads from diff and base DB.
    pub(crate) async fn test_immutable_merkleized_batch_get<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        // Pre-populate base DB.
        let key_a = Sha256::hash(&0u64.to_be_bytes());
        let val_a = Sha256::fill(10u8);
        db.apply_batch(
            db.new_batch()
                .set(key_a, val_a)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();

        // Create a merkleized batch with a new key.
        let key_b = Sha256::hash(&1u64.to_be_bytes());
        let val_b = Sha256::fill(20u8);
        let merkleized = db
            .new_batch()
            .set(key_b, val_b)
            .merkleize(&db, None, Location::new(0));

        // Read base DB value through merkleized batch.
        assert_eq!(merkleized.get(&key_a, &db).await.unwrap(), Some(val_a));

        // Read this batch's key from the diff.
        assert_eq!(merkleized.get(&key_b, &db).await.unwrap(), Some(val_b));

        // Nonexistent key.
        let key_c = Sha256::hash(&2u64.to_be_bytes());
        assert_eq!(merkleized.get(&key_c, &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    /// Independent sequential batches applied one at a time.
    pub(crate) async fn test_immutable_batch_sequential_apply<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key_a = Sha256::hash(&0u64.to_be_bytes());
        let val_a = Sha256::fill(1u8);

        // First batch.
        let m = db
            .new_batch()
            .set(key_a, val_a)
            .merkleize(&db, None, Location::new(0));
        let root1 = m.root();
        db.apply_batch(m).await.unwrap();
        assert_eq!(db.root(), root1);
        assert_eq!(db.get(&key_a).await.unwrap(), Some(val_a));

        // Second independent batch.
        let key_b = Sha256::hash(&1u64.to_be_bytes());
        let val_b = Sha256::fill(2u8);
        let m = db
            .new_batch()
            .set(key_b, val_b)
            .merkleize(&db, None, Location::new(0));
        let root2 = m.root();
        db.apply_batch(m).await.unwrap();
        assert_eq!(db.root(), root2);
        assert_eq!(db.get(&key_b).await.unwrap(), Some(val_b));

        db.destroy().await.unwrap();
    }

    /// Many sequential batches accumulate correctly.
    pub(crate) async fn test_immutable_batch_many_sequential<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;
        let hasher = StandardHasher::<Sha256>::new();

        const BATCHES: u64 = 20;
        const KEYS_PER_BATCH: u64 = 5;

        let mut all_kvs: Vec<(Digest, Digest)> = Vec::new();

        for batch_idx in 0..BATCHES {
            let mut batch = db.new_batch();
            for j in 0..KEYS_PER_BATCH {
                let seed = batch_idx * 100 + j;
                let k = Sha256::hash(&seed.to_be_bytes());
                let v = Sha256::fill(seed as u8);
                batch = batch.set(k, v);
                all_kvs.push((k, v));
            }
            let merkleized = batch.merkleize(&db, None, Location::new(0));
            db.apply_batch(merkleized).await.unwrap();
        }

        // Verify all key-values are readable.
        for (k, v) in &all_kvs {
            assert_eq!(db.get(k).await.unwrap(), Some(*v));
        }

        // Verify proof over the full range.
        let root = db.root();
        let (proof, ops) = db.proof(Location::new(0), NZU64!(10000)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root));

        // Expected: 1 initial commit + BATCHES * (KEYS_PER_BATCH + 1 commit).
        let expected = 1 + BATCHES * (KEYS_PER_BATCH + 1);
        assert_eq!(db.bounds().await.end, expected);

        db.destroy().await.unwrap();
    }

    /// Empty batch (zero mutations) produces correct speculative root.
    pub(crate) async fn test_immutable_batch_empty_batch<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        // Apply a non-empty batch first.
        let k = Sha256::hash(&[1u8]);
        db.apply_batch(db.new_batch().set(k, Sha256::fill(1u8)).merkleize(
            &db,
            None,
            Location::new(0),
        ))
        .await
        .unwrap();
        let root_before = db.root();
        let size_before = db.bounds().await.end;

        // Empty batch with no mutations.
        let merkleized = db.new_batch().merkleize(&db, None, Location::new(0));
        let speculative = merkleized.root();
        db.apply_batch(merkleized).await.unwrap();

        // Root changed (a new Commit op was appended).
        assert_ne!(db.root(), root_before);
        assert_eq!(db.root(), speculative);
        // Size grew by exactly 1 (the Commit op).
        assert_eq!(db.bounds().await.end, size_before + 1);

        db.destroy().await.unwrap();
    }

    /// MerkleizedBatch::get() works on a chained child's merkleized batch.
    pub(crate) async fn test_immutable_batch_chained_merkleized_get<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        // Pre-populate base DB.
        let key_a = Sha256::hash(&0u64.to_be_bytes());
        let val_a = Sha256::fill(10u8);
        db.apply_batch(
            db.new_batch()
                .set(key_a, val_a)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();

        // Parent batch sets key B.
        let key_b = Sha256::hash(&1u64.to_be_bytes());
        let val_b = Sha256::fill(1u8);
        let parent_m = db
            .new_batch()
            .set(key_b, val_b)
            .merkleize(&db, None, Location::new(0));

        // Child batch sets key C.
        let key_c = Sha256::hash(&2u64.to_be_bytes());
        let val_c = Sha256::fill(2u8);
        let child_m =
            parent_m
                .new_batch::<Sha256>()
                .set(key_c, val_c)
                .merkleize(&db, None, Location::new(0));

        // Child's MerkleizedBatch can read all three layers:
        // base DB value
        assert_eq!(child_m.get(&key_a, &db).await.unwrap(), Some(val_a));
        // parent diff value
        assert_eq!(child_m.get(&key_b, &db).await.unwrap(), Some(val_b));
        // child's own value
        assert_eq!(child_m.get(&key_c, &db).await.unwrap(), Some(val_c));
        // nonexistent key
        let key_d = Sha256::hash(&3u64.to_be_bytes());
        assert_eq!(child_m.get(&key_d, &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    /// Large single batch, verifying all values and proof.
    pub(crate) async fn test_immutable_batch_large<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;
        let hasher = StandardHasher::<Sha256>::new();

        const N: u64 = 500;
        let mut kvs: Vec<(Digest, Digest)> = Vec::new();

        let mut batch = db.new_batch();
        for i in 0..N {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::fill((i % 256) as u8);
            batch = batch.set(k, v);
            kvs.push((k, v));
        }
        let merkleized = batch.merkleize(&db, None, Location::new(0));
        db.apply_batch(merkleized).await.unwrap();

        // Verify every value.
        for (k, v) in &kvs {
            assert_eq!(db.get(k).await.unwrap(), Some(*v));
        }

        // Verify proof over the full range.
        let root = db.root();
        let (proof, ops) = db.proof(Location::new(0), NZU64!(1000)).await.unwrap();
        assert!(verify_proof(&hasher, &proof, Location::new(0), &ops, &root));

        // Expected: 1 initial commit + N sets + 1 commit.
        assert_eq!(db.bounds().await.end, 1 + N + 1);

        db.destroy().await.unwrap();
    }

    /// Child batch overrides same key set by parent.
    pub(crate) async fn test_immutable_batch_chained_key_override<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key = Sha256::hash(&0u64.to_be_bytes());
        let val_parent = Sha256::fill(1u8);
        let val_child = Sha256::fill(2u8);

        // Parent sets key.
        let parent_m = db
            .new_batch()
            .set(key, val_parent)
            .merkleize(&db, None, Location::new(0));

        // Child overrides same key.
        let mut child = parent_m.new_batch::<Sha256>();
        child = child.set(key, val_child);

        // Child's pending mutation wins over parent diff.
        assert_eq!(child.get(&key, &db).await.unwrap(), Some(val_child));

        let child_m = child.merkleize(&db, None, Location::new(0));

        // After merkleize, child's diff wins.
        assert_eq!(child_m.get(&key, &db).await.unwrap(), Some(val_child));

        // Apply and verify.
        db.apply_batch(child_m).await.unwrap();
        assert_eq!(db.get(&key).await.unwrap(), Some(val_child));

        db.destroy().await.unwrap();
    }

    /// Same key set across two sequential applied batches. The immutable DB
    /// keeps all versions -- `get()` returns the earliest non-pruned value.
    /// After pruning the first version, `get()` returns the second.
    ///
    /// `open_db_small_sections` must return a DB whose log has `items_per_section=1`
    /// so pruning is per-item.
    pub(crate) async fn test_immutable_batch_sequential_key_override<F: Family, V, C>(
        context: deterministic::Context,
        open_db_small_sections: impl Fn(
            deterministic::Context,
        )
            -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db_small_sections(context.with_label("db")).await;

        let key = Sha256::hash(&0u64.to_be_bytes());
        let v1 = Sha256::fill(1u8);
        let v2 = Sha256::fill(2u8);

        // First batch sets key.
        // Layout: 0=initial commit, 1=Set(key,v1), 2=Commit
        db.apply_batch(
            db.new_batch()
                .set(key, v1)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();
        assert_eq!(db.get(&key).await.unwrap(), Some(v1));

        // Second batch sets same key to different value.
        // Layout continues: 3=Set(key,v2), 4=Commit
        // Floor=4 so that prune(2) succeeds (2 <= 4).
        db.apply_batch(
            db.new_batch()
                .set(key, v2)
                .merkleize(&db, None, Location::new(4)),
        )
        .await
        .unwrap();

        // Immutable DB returns the earliest non-pruned value.
        assert_eq!(db.get(&key).await.unwrap(), Some(v1));

        // Prune past the first Set (loc 1). With items_per_section=1,
        // pruning to loc 2 should remove the blob containing loc 1.
        db.prune(Location::new(2)).await.unwrap();
        assert_eq!(db.get(&key).await.unwrap(), Some(v2));

        db.destroy().await.unwrap();
    }

    /// Metadata propagates through merkleize and clears with None.
    pub(crate) async fn test_immutable_batch_metadata<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        // Batch with metadata.
        let metadata = Sha256::fill(42u8);
        let k = Sha256::hash(&[1u8]);
        db.apply_batch(db.new_batch().set(k, Sha256::fill(1u8)).merkleize(
            &db,
            Some(metadata),
            Location::new(0),
        ))
        .await
        .unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

        // Second batch clears metadata.
        db.apply_batch(db.new_batch().merkleize(&db, None, Location::new(0)))
            .await
            .unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_stale_batch_rejected<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key1 = Sha256::hash(&[1]);
        let key2 = Sha256::hash(&[2]);
        let v1 = Sha256::fill(10u8);
        let v2 = Sha256::fill(20u8);

        // Create two batches from the same DB state.
        let batch_a = db
            .new_batch()
            .set(key1, v1)
            .merkleize(&db, None, Location::new(0));
        let batch_b = db
            .new_batch()
            .set(key2, v2)
            .merkleize(&db, None, Location::new(0));

        // Apply the first -- should succeed.
        db.apply_batch(batch_a).await.unwrap();
        let expected_root = db.root();
        let expected_bounds = db.bounds().await;
        assert_eq!(db.get(&key1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&key2).await.unwrap(), None);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        // Apply the second -- should fail because the DB was modified.
        let result = db.apply_batch(batch_b).await;
        assert!(
            matches!(result, Err(Error::StaleBatch { .. })),
            "expected StaleBatch error, got {result:?}"
        );
        assert_eq!(db.root(), expected_root);
        assert_eq!(db.bounds().await, expected_bounds);
        assert_eq!(db.get(&key1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&key2).await.unwrap(), None);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_stale_batch_chained<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key1 = Sha256::hash(&[1]);
        let key2 = Sha256::hash(&[2]);
        let key3 = Sha256::hash(&[3]);

        // Parent batch.
        let parent_m =
            db.new_batch()
                .set(key1, Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0));

        // Fork two children from the same parent.
        let child_a = parent_m
            .new_batch::<Sha256>()
            .set(key2, Sha256::fill(2u8))
            .merkleize(&db, None, Location::new(0));
        let child_b = parent_m
            .new_batch::<Sha256>()
            .set(key3, Sha256::fill(3u8))
            .merkleize(&db, None, Location::new(0));

        // Apply child A.
        db.apply_batch(child_a).await.unwrap();

        // Child B is stale.
        let result = db.apply_batch(child_b).await;
        assert!(
            matches!(result, Err(Error::StaleBatch { .. })),
            "expected StaleBatch error, got {result:?}"
        );

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_partial_ancestor_commit<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key1 = Sha256::hash(&[1]);
        let key2 = Sha256::hash(&[2]);
        let key3 = Sha256::hash(&[3]);
        let v1 = Sha256::fill(1u8);
        let v2 = Sha256::fill(2u8);
        let v3 = Sha256::fill(3u8);

        // Chain: DB <- A <- B <- C
        let a = db
            .new_batch()
            .set(key1, v1)
            .merkleize(&db, None, Location::new(0));
        let b = a
            .new_batch::<Sha256>()
            .set(key2, v2)
            .merkleize(&db, None, Location::new(0));
        let c = b
            .new_batch::<Sha256>()
            .set(key3, v3)
            .merkleize(&db, None, Location::new(0));

        let expected_root = c.root();

        // Apply only A, then apply C directly (B uncommitted).
        db.apply_batch(a).await.unwrap();
        db.apply_batch(c).await.unwrap();

        assert_eq!(db.root(), expected_root);
        assert_eq!(db.get(&key1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&key2).await.unwrap(), Some(v2));
        assert_eq!(db.get(&key3).await.unwrap(), Some(v3));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_sequential_commit_parent_then_child<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key1 = Sha256::hash(&[1]);
        let key2 = Sha256::hash(&[2]);
        let v1 = Sha256::fill(1u8);
        let v2 = Sha256::fill(2u8);

        // Parent batch.
        let parent_m = db
            .new_batch()
            .set(key1, v1)
            .merkleize(&db, None, Location::new(0));

        // Child batch built on parent.
        let child_m =
            parent_m
                .new_batch::<Sha256>()
                .set(key2, v2)
                .merkleize(&db, None, Location::new(0));

        // Apply parent first, then child. This is a valid sequential commit.
        db.apply_batch(parent_m).await.unwrap();
        db.apply_batch(child_m).await.unwrap();

        // Both keys present.
        assert_eq!(db.get(&key1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&key2).await.unwrap(), Some(v2));

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_child_root_matches_pending_and_committed<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key1 = Sha256::hash(&[1]);
        let key2 = Sha256::hash(&[2]);

        // Build the child while the parent is still pending.
        let parent =
            db.new_batch()
                .set(key1, Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0));
        let pending_child = parent
            .new_batch::<Sha256>()
            .set(key2, Sha256::fill(2u8))
            .merkleize(&db, None, Location::new(0));

        // Commit the parent, then rebuild the same logical child from the
        // committed DB state and compare roots.
        db.apply_batch(parent).await.unwrap();
        db.commit().await.unwrap();

        let committed_child =
            db.new_batch()
                .set(key2, Sha256::fill(2u8))
                .merkleize(&db, None, Location::new(0));

        assert_eq!(pending_child.root(), committed_child.root());

        db.destroy().await.unwrap();
    }

    pub(crate) async fn test_immutable_stale_batch_child_applied_before_parent<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key1 = Sha256::hash(&[1]);
        let key2 = Sha256::hash(&[2]);

        // Parent batch.
        let parent_m =
            db.new_batch()
                .set(key1, Sha256::fill(1u8))
                .merkleize(&db, None, Location::new(0));

        // Child batch.
        let child_m = parent_m
            .new_batch::<Sha256>()
            .set(key2, Sha256::fill(2u8))
            .merkleize(&db, None, Location::new(0));

        // Apply child first (it carries all parent ops too).
        db.apply_batch(child_m).await.unwrap();

        // Parent is stale.
        let result = db.apply_batch(parent_m).await;
        assert!(
            matches!(result, Err(Error::StaleBatch { .. })),
            "expected StaleBatch error, got {result:?}"
        );

        db.destroy().await.unwrap();
    }

    /// to_batch() creates an owned snapshot whose root matches the committed DB.
    /// A child batch chained from it can be applied.
    pub(crate) async fn test_immutable_to_batch<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        // Populate.
        let key1 = Sha256::hash(&[1]);
        let v1 = Sha256::fill(10u8);
        db.apply_batch(
            db.new_batch()
                .set(key1, v1)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();

        // to_batch root matches committed root.
        let snapshot = db.to_batch();
        assert_eq!(snapshot.root(), db.root());

        // Chain a child from the snapshot, apply it.
        let key2 = Sha256::hash(&[2]);
        let v2 = Sha256::fill(20u8);
        let child =
            snapshot
                .new_batch::<Sha256>()
                .set(key2, v2)
                .merkleize(&db, None, Location::new(0));
        db.apply_batch(child).await.unwrap();

        assert_eq!(db.get(&key1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&key2).await.unwrap(), Some(v2));

        db.destroy().await.unwrap();
    }

    /// Regression: applying a batch after its ancestor Arc is dropped (without
    /// committing) must still apply the ancestor's snapshot diffs.
    pub(crate) async fn test_immutable_apply_after_ancestor_dropped<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let key1 = Sha256::hash(&[1]);
        let key2 = Sha256::hash(&[2]);
        let key3 = Sha256::hash(&[3]);
        let v1 = Sha256::fill(1u8);
        let v2 = Sha256::fill(2u8);
        let v3 = Sha256::fill(3u8);

        // Chain: DB <- A <- B <- C
        let a = db
            .new_batch()
            .set(key1, v1)
            .merkleize(&db, None, Location::new(0));
        let b = a
            .new_batch::<Sha256>()
            .set(key2, v2)
            .merkleize(&db, None, Location::new(0));
        let c = b
            .new_batch::<Sha256>()
            .set(key3, v3)
            .merkleize(&db, None, Location::new(0));

        // Drop A and B without committing. Their Weak refs in C are now dead.
        drop(a);
        drop(b);

        // Apply only the tip. This is !skip_ancestors (DB hasn't changed).
        db.apply_batch(c).await.unwrap();

        // All three keys must be in the snapshot.
        assert_eq!(db.get(&key1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&key2).await.unwrap(), Some(v2));
        assert_eq!(db.get(&key3).await.unwrap(), Some(v3));

        db.destroy().await.unwrap();
    }

    /// Verify the inactivity floor is zero for a fresh empty database and is
    /// correctly set after applying batches with specific floor values.
    pub(crate) async fn test_immutable_inactivity_floor_tracking<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("test")).await;

        // Empty DB has floor=0.
        assert_eq!(db.inactivity_floor_loc(), Location::new(0));

        // Apply batch with floor=0, floor stays 0.
        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);
        db.apply_batch(
            db.new_batch()
                .set(k1, v1)
                .merkleize(&db, None, Location::new(0)),
        )
        .await
        .unwrap();
        assert_eq!(db.inactivity_floor_loc(), Location::new(0));

        // Apply batch with floor=3, floor advances.
        let k2 = Sha256::fill(3u8);
        let v2 = Sha256::fill(4u8);
        db.apply_batch(
            db.new_batch()
                .set(k2, v2)
                .merkleize(&db, None, Location::new(3)),
        )
        .await
        .unwrap();
        assert_eq!(db.inactivity_floor_loc(), Location::new(3));

        // Floor persists across restart.
        db.commit().await.unwrap();
        db.sync().await.unwrap();
        drop(db);
        let db = open_db(context.with_label("reopen")).await;
        assert_eq!(db.inactivity_floor_loc(), Location::new(3));

        db.destroy().await.unwrap();
    }

    /// Verify that applying a batch with a floor equal to the current floor succeeds,
    /// and that a higher floor also succeeds.
    pub(crate) async fn test_immutable_floor_monotonicity<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("test")).await;

        // DB starts with 1 op (initial commit).
        // First batch: 1 set + 1 commit = total_size 3. Use floor=2 (the commit loc).
        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);
        db.apply_batch(
            db.new_batch()
                .set(k1, v1)
                .merkleize(&db, None, Location::new(2)),
        )
        .await
        .unwrap();
        assert_eq!(db.inactivity_floor_loc(), Location::new(2));

        // Same floor is OK. Second batch: 1 set + 1 commit = total_size 5. floor=2 < 5.
        let k2 = Sha256::fill(3u8);
        let v2 = Sha256::fill(4u8);
        db.apply_batch(
            db.new_batch()
                .set(k2, v2)
                .merkleize(&db, None, Location::new(2)),
        )
        .await
        .unwrap();
        assert_eq!(db.inactivity_floor_loc(), Location::new(2));

        // Higher floor also succeeds. Third batch: 1 set + 1 commit = total_size 7. floor=5 < 7.
        let k3 = Sha256::fill(5u8);
        let v3 = Sha256::fill(6u8);
        db.apply_batch(
            db.new_batch()
                .set(k3, v3)
                .merkleize(&db, None, Location::new(5)),
        )
        .await
        .unwrap();
        assert_eq!(db.inactivity_floor_loc(), Location::new(5));

        db.destroy().await.unwrap();
    }

    /// Verify that the inactivity floor is correctly restored after a rewind.
    pub(crate) async fn test_immutable_rewind_restores_floor<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("test")).await;

        // Apply first batch with floor=2.
        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);
        db.apply_batch(
            db.new_batch()
                .set(k1, v1)
                .merkleize(&db, None, Location::new(2)),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        let first_size = db.bounds().await.end;
        assert_eq!(db.inactivity_floor_loc(), Location::new(2));

        // Apply second batch with floor=4 (the new commit's location).
        let k2 = Sha256::fill(3u8);
        let v2 = Sha256::fill(4u8);
        db.apply_batch(
            db.new_batch()
                .set(k2, v2)
                .merkleize(&db, None, Location::new(4)),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), Location::new(4));

        // Rewind to the first batch.
        db.rewind(first_size).await.unwrap();
        assert_eq!(db.inactivity_floor_loc(), Location::new(2));

        db.destroy().await.unwrap();
    }

    /// Verify that applying a batch with a floor lower than the current floor
    /// returns an error.
    pub(crate) async fn test_immutable_floor_monotonicity_violation<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("test")).await;

        // DB starts with 1 op. First batch: 1 set + 1 commit = total_size 3. floor=2.
        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);
        db.apply_batch(
            db.new_batch()
                .set(k1, v1)
                .merkleize(&db, None, Location::new(2)),
        )
        .await
        .unwrap();

        // Apply batch with floor=1 (regression). Should return an error.
        let k2 = Sha256::fill(3u8);
        let v2 = Sha256::fill(4u8);
        let result = db
            .apply_batch(
                db.new_batch()
                    .set(k2, v2)
                    .merkleize(&db, None, Location::new(1)),
            )
            .await;
        assert!(matches!(result, Err(Error::FloorRegressed(new, current))
                if new == Location::new(1) && current == Location::new(2)));

        db.destroy().await.unwrap();
    }

    /// Verify that applying a batch with a floor beyond the total operation
    /// count returns an error.
    pub(crate) async fn test_immutable_floor_beyond_size<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("test")).await;

        // DB has 1 op (initial commit). A batch with 1 set + 1 commit = total_size 3.
        // Setting floor=100 exceeds total_size.
        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(2u8);
        let result = db
            .apply_batch(
                db.new_batch()
                    .set(k1, v1)
                    .merkleize(&db, None, Location::new(100)),
            )
            .await;
        assert!(matches!(result, Err(Error::FloorBeyondSize(floor, commit))
                if floor == Location::new(100) && commit == Location::new(2)));

        // Boundary: floor == total_size must also be rejected. The commit op is
        // at total_size - 1, so a floor equal to total_size would allow a later
        // prune to remove the commit and leave the db unrecoverable.
        let k2 = Sha256::fill(3u8);
        let v2 = Sha256::fill(4u8);
        let result = db
            .apply_batch(
                db.new_batch()
                    .set(k2, v2)
                    .merkleize(&db, None, Location::new(3)),
            )
            .await;
        assert!(matches!(result, Err(Error::FloorBeyondSize(floor, commit))
                if floor == Location::new(3) && commit == Location::new(2)));

        // Floor == total_size - 1 (the commit location) is the maximum valid.
        db.apply_batch(
            db.new_batch()
                .set(k2, v2)
                .merkleize(&db, None, Location::new(2)),
        )
        .await
        .unwrap();

        db.destroy().await.unwrap();
    }

    /// Regression test for rewind-after-reopen with floor change.
    ///
    /// After reopening a database (which rebuilds the snapshot from the latest
    /// floor), rewinding to an earlier commit with a lower floor must restore
    /// all keys that were live at the rewind target -- not just the ones that
    /// happened to be in the rebuilt snapshot.
    pub(crate) async fn test_immutable_rewind_after_reopen_with_floor_change<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("first")).await;

        let k1 = Sha256::fill(1u8);
        let k2 = Sha256::fill(2u8);
        let k3 = Sha256::fill(3u8);
        let v1 = Sha256::fill(11u8);
        let v2 = Sha256::fill(12u8);
        let v3 = Sha256::fill(13u8);

        // Commit A: 3 keys with floor=0.
        commit_sets(&mut db, [(k1, v1), (k2, v2), (k3, v3)], None).await;
        let first_size = db.bounds().await.end;
        let first_root = db.root();

        // Commit B: 3 more keys with floor=first_size (declares batch A inactive).
        let k4 = Sha256::fill(4u8);
        let k5 = Sha256::fill(5u8);
        let k6 = Sha256::fill(6u8);
        let v4 = Sha256::fill(14u8);
        let v5 = Sha256::fill(15u8);
        let v6 = Sha256::fill(16u8);
        commit_sets_with_floor(&mut db, [(k4, v4), (k5, v5), (k6, v6)], None, first_size).await;
        db.sync().await.unwrap();

        // Reopen: snapshot rebuilt from floor=first_size, batch A keys excluded.
        drop(db);
        let mut db = open_db(context.with_label("second")).await;

        // Verify batch A keys are NOT in the reopened snapshot (expected).
        assert!(db.get(&k1).await.unwrap().is_none());

        // Rewind to commit A.
        db.rewind(first_size).await.unwrap();

        // All batch A keys must be accessible after rewind.
        assert_eq!(db.get(&k1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&k2).await.unwrap(), Some(v2));
        assert_eq!(db.get(&k3).await.unwrap(), Some(v3));
        assert_eq!(db.root(), first_root);
        assert_eq!(db.inactivity_floor_loc(), Location::new(0));

        // Batch B keys must NOT be accessible.
        assert!(db.get(&k4).await.unwrap().is_none());

        db.destroy().await.unwrap();
    }

    /// Regression test: rewind-after-reopen where the rewind target is NOT the
    /// immediate predecessor. This ensures the snapshot gap fill only covers
    /// [rewind_floor, old_floor) and does not re-insert keys already present.
    pub(crate) async fn test_immutable_rewind_after_reopen_partial_floor_gap<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("first")).await;

        let k1 = Sha256::fill(1u8);
        let v1 = Sha256::fill(11u8);

        // Commit A: 1 key, floor=0.
        commit_sets(&mut db, [(k1, v1)], None).await;
        let first_size = db.bounds().await.end;
        let first_root = db.root();

        // Commit B: 1 key, floor=first_size.
        let k2 = Sha256::fill(2u8);
        let v2 = Sha256::fill(12u8);
        commit_sets_with_floor(&mut db, [(k2, v2)], None, first_size).await;
        let second_size = db.bounds().await.end;

        // Commit C: 1 key, floor=second_size. This raises the floor
        // above commit B's keys, so reopen excludes both A and B keys.
        let k3 = Sha256::fill(3u8);
        let v3 = Sha256::fill(13u8);
        commit_sets_with_floor(&mut db, [(k3, v3)], None, second_size).await;
        db.sync().await.unwrap();

        // Reopen: snapshot rebuilt from floor=second_size. Only k3 is in snapshot.
        drop(db);
        let mut db = open_db(context.with_label("second")).await;
        assert!(db.get(&k1).await.unwrap().is_none());
        assert!(db.get(&k2).await.unwrap().is_none());
        assert_eq!(db.get(&k3).await.unwrap(), Some(v3));

        // Rewind to commit B (not A). The gap fill should add keys from
        // [first_size, second_size) -- which includes k2 but not k1.
        // k3 is in the suffix and gets removed. k2 from the gap gets inserted.
        db.rewind(second_size).await.unwrap();
        assert!(db.get(&k1).await.unwrap().is_none()); // below B's floor
        assert_eq!(db.get(&k2).await.unwrap(), Some(v2));
        assert!(db.get(&k3).await.unwrap().is_none()); // in suffix, removed

        // Now rewind further to commit A.
        db.rewind(first_size).await.unwrap();
        assert_eq!(db.get(&k1).await.unwrap(), Some(v1));
        assert!(db.get(&k2).await.unwrap().is_none()); // above first_size, truncated
        assert_eq!(db.root(), first_root);
        assert_eq!(db.inactivity_floor_loc(), Location::new(0));

        db.destroy().await.unwrap();
    }

    /// After committing with `floor = commit_loc` and pruning down to it, the live set is
    /// exactly one operation — the commit itself. This is the minimum non-empty live set
    /// achievable under the per-commit bound. The DB must remain fully usable:
    ///
    /// - `prune(commit_loc + 1)` is rejected (the floor is a hard ceiling).
    /// - `prune` does not affect the root (documented invariant).
    /// - Reopen reconstructs `inactivity_floor_loc` from the sole surviving commit op, and the
    ///   in-memory snapshot is empty (all Sets were below the floor).
    /// - A follow-on batch applies cleanly on top from the floor-at-max state.
    pub(crate) async fn test_immutable_single_commit_live_set<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("test")).await;

        // Initial commit is at loc 0. 3 sets + 1 commit → commit lands at loc 4.
        // Declare floor = 4 (= commit_loc), the tight maximum.
        let metadata = Sha256::fill(42u8);
        let commit_loc = Location::<F>::new(4);
        let k1 = Sha256::fill(1u8);
        let k2 = Sha256::fill(2u8);
        let k3 = Sha256::fill(3u8);
        let v1 = Sha256::fill(11u8);
        let v2 = Sha256::fill(12u8);
        let v3 = Sha256::fill(13u8);
        db.apply_batch(
            db.new_batch()
                .set(k1, v1)
                .set(k2, v2)
                .set(k3, v3)
                .merkleize(&db, Some(metadata), commit_loc),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.last_commit_loc, commit_loc);
        assert_eq!(db.inactivity_floor_loc(), commit_loc);
        let root_after_commit = db.root();

        // All three keys are in the in-memory snapshot pre-prune.
        assert_eq!(db.get(&k1).await.unwrap(), Some(v1));
        assert_eq!(db.get(&k2).await.unwrap(), Some(v2));
        assert_eq!(db.get(&k3).await.unwrap(), Some(v3));

        // Prune at the floor — the maximum prune allowed.
        // Pruning is blob-aligned, so `bounds.start` may not physically advance all the way
        // to `commit_loc`; what matters semantically is that the floor authorizes pruning
        // of everything below the commit and that any further prune is rejected.
        db.prune(commit_loc).await.unwrap();
        let bounds = db.bounds().await;
        assert!(
            bounds.start <= commit_loc,
            "prune must not advance bounds.start past the floor"
        );
        assert_eq!(bounds.end, Location::new(*commit_loc + 1));

        // Pruning one past the floor must be rejected — the floor is the hard ceiling.
        let err = db.prune(Location::new(*commit_loc + 1)).await.unwrap_err();
        assert!(matches!(err, Error::PruneBeyondMinRequired(p, f)
                if *p == *commit_loc + 1 && *f == *commit_loc));

        // State preserved across the prune; root unchanged; commit metadata still readable.
        assert_eq!(db.last_commit_loc, commit_loc);
        assert_eq!(db.inactivity_floor_loc(), commit_loc);
        assert_eq!(db.root(), root_after_commit);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

        // Persist and reopen. `init_from_journal` rebuilds the snapshot by replaying from
        // the floor (= commit_loc). The only op at/above the floor is the commit, which
        // contributes no keys — so the rebuilt snapshot is empty.
        db.sync().await.unwrap();
        drop(db);
        let mut db = open_db(context.with_label("reopened")).await;
        assert_eq!(db.last_commit_loc, commit_loc);
        assert_eq!(db.inactivity_floor_loc(), commit_loc);
        assert_eq!(db.root(), root_after_commit);
        // The commit op at `commit_loc` is the anchor that survived pruning — its metadata
        // must come back through `get_metadata` after the snapshot rebuild.
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

        // Keys set below the floor are excluded from the rebuilt snapshot.
        assert!(db.get(&k1).await.unwrap().is_none());
        assert!(db.get(&k2).await.unwrap().is_none());
        assert!(db.get(&k3).await.unwrap().is_none());

        // A follow-on batch applies on top. Monotonicity requires the new floor to be at
        // least `commit_loc` (= 4); advancing to the new tight max (= 6) exercises the
        // floor-at-max → new-batch transition.
        let k4 = Sha256::fill(4u8);
        let v4 = Sha256::fill(14u8);
        let next_commit_loc = Location::<F>::new(6);
        db.apply_batch(
            db.new_batch()
                .set(k4, v4)
                .merkleize(&db, None, next_commit_loc),
        )
        .await
        .unwrap();
        db.commit().await.unwrap();
        assert_eq!(db.last_commit_loc, next_commit_loc);
        assert_eq!(db.inactivity_floor_loc(), next_commit_loc);

        // New key readable; keys from the pre-prune batch remain excluded.
        assert_eq!(db.get(&k4).await.unwrap(), Some(v4));
        assert!(db.get(&k1).await.unwrap().is_none());
        // Follow-on commit replaced the anchor: its metadata was `None`, so `get_metadata`
        // should no longer return the original metadata.
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    /// `get_many` on the DB and on unmerkleized/merkleized batches returns results
    /// that match individual `get` calls.
    pub(crate) async fn test_immutable_get_many<F: Family, V, C>(
        context: deterministic::Context,
        open_db: impl Fn(
            deterministic::Context,
        ) -> Pin<Box<dyn Future<Output = TestDb<F, V, C>> + Send>>,
    ) where
        V: ValueEncoding<Value = Digest>,
        C: Mutable<Item = Operation<F, Digest, V>> + Persistable<Error = JournalError>,
        C::Item: EncodeShared,
    {
        let mut db = open_db(context.with_label("db")).await;

        let k1 = Sha256::fill(1u8);
        let k2 = Sha256::fill(2u8);
        let k3 = Sha256::fill(3u8);
        let k_missing = Sha256::fill(99u8);

        let v1 = Sha256::fill(11u8);
        let v2 = Sha256::fill(12u8);
        let v3 = Sha256::fill(13u8);

        // Commit k1 and k2 to disk.
        db.apply_batch(db.new_batch().set(k1, v1).set(k2, v2).merkleize(
            &db,
            None,
            Location::new(0),
        ))
        .await
        .unwrap();
        db.commit().await.unwrap();

        // DB-level get_many.
        let results = db.get_many(&[&k1, &k2, &k_missing]).await.unwrap();
        assert_eq!(results, vec![Some(v1), Some(v2), None]);

        // Empty input.
        let results = db.get_many(&([] as [&Digest; 0])).await.unwrap();
        assert!(results.is_empty());

        // Unmerkleized batch: mutations + DB fallthrough.
        let batch = db.new_batch().set(k3, v3);
        let results = batch.get_many(&[&k3, &k1, &k_missing], &db).await.unwrap();
        assert_eq!(results, vec![Some(v3), Some(v1), None]);

        // Merkleized batch: diff + parent chain + DB fallthrough.
        let parent = db
            .new_batch()
            .set(k3, v3)
            .merkleize(&db, None, Location::new(0));
        let results = parent.get_many(&[&k1, &k3, &k_missing], &db).await.unwrap();
        assert_eq!(results, vec![Some(v1), Some(v3), None]);

        // Child of merkleized parent reads parent diff.
        let v3_new = Sha256::fill(30u8);
        let child = parent.new_batch::<Sha256>().set(k3, v3_new);
        let results = child.get_many(&[&k1, &k3, &k_missing], &db).await.unwrap();
        assert_eq!(results, vec![Some(v1), Some(v3_new), None]);

        db.destroy().await.unwrap();
    }
}

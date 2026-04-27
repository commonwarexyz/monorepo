//! A shared, generic implementation of the _Any_ QMDB.
//!
//! The impl blocks in this file define shared functionality across all Any QMDB variants.

use super::operation::{update::Update, Operation};
use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        authenticated,
        contiguous::{Contiguous, Mutable, Reader},
        Error as JournalError,
    },
    merkle::{Bagging, Family, Location, Proof, RootSpec},
    qmdb::{
        build_snapshot_from_log, delete_known_loc, operation::Operation as OperationTrait,
        update_known_loc, Error,
    },
    Context, Persistable,
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::Hasher;
use core::num::NonZeroU64;
use std::collections::HashMap;

/// Type alias for the authenticated journal used by [Db].
pub(crate) type AuthenticatedLog<F, E, C, H> = authenticated::Journal<F, E, C, H>;

/// Snapshot mutation needed to undo one operation while rewinding.
enum SnapshotUndo<F: Family, K> {
    Replace {
        key: K,
        old_loc: Location<F>,
        new_loc: Location<F>,
    },
    Remove {
        key: K,
        old_loc: Location<F>,
    },
    Insert {
        key: K,
        new_loc: Location<F>,
    },
}

/// An "Any" QMDB implementation generic over ordered/unordered keys and variable/fixed values.
/// Consider using one of the following specialized variants instead, which may be more ergonomic:
/// - [crate::qmdb::any::ordered::fixed::Db]
/// - [crate::qmdb::any::ordered::variable::Db]
/// - [crate::qmdb::any::unordered::fixed::Db]
/// - [crate::qmdb::any::unordered::variable::Db]
pub struct Db<
    F: Family,
    E: Context,
    C: Contiguous<Item: CodecShared>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    U: Send + Sync,
> {
    /// A (pruned) log of all operations in order of their application. The index of each
    /// operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - The log is never pruned beyond the inactivity floor.
    /// - There is always at least one commit operation in the log.
    pub(crate) log: AuthenticatedLog<F, E, C, H>,

    /// Cached operations root for this database.
    pub(crate) root: H::Digest,

    /// Whether the operations root uses inactive-prefix split semantics.
    pub(crate) split_root: bool,

    /// Bagging used by the operations root.
    pub(crate) root_bagging: Bagging,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(crate) inactivity_floor_loc: Location<F>,

    /// The location of the last commit operation.
    pub(crate) last_commit_loc: Location<F>,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariant
    ///
    /// - Only references `Operation::Update`s.
    pub(crate) snapshot: I,

    /// The number of active keys in the snapshot.
    pub(crate) active_keys: usize,

    /// Marker for the update type parameter.
    pub(crate) _update: core::marker::PhantomData<U>,
}

// Shared read-only functionality.
impl<F, E, U, C, I, H> Db<F, E, C, I, H, U>
where
    F: Family,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    #[cfg(any(test, feature = "test-traits"))]
    pub(crate) const fn inactivity_floor_loc(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Return the most recent location from which this database can safely be synced, and the
    /// upper bound on [`Self::prune`]'s `loc`. For `any`, this equals the inactivity floor.
    pub const fn sync_boundary(&self) -> Location<F> {
        self.inactivity_floor_loc
    }

    /// Whether the snapshot currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<U::Value>, crate::qmdb::Error<F>> {
        match self.log.reader().await.read(*self.last_commit_loc).await? {
            Operation::CommitFloor(metadata, _) => Ok(metadata),
            _ => unreachable!("last commit is not a CommitFloor operation"),
        }
    }

    /// Return the canonical QMDB operations root.
    pub const fn root(&self) -> H::Digest {
        self.root
    }

    /// Return the operations-root spec for the given leaf count and inactivity floor.
    pub(crate) fn root_spec(&self, leaves: Location<F>, inactivity_floor: Location<F>) -> RootSpec {
        if self.split_root {
            RootSpec::Split {
                inactive_peaks: F::inactive_peaks(
                    F::location_to_position(leaves),
                    inactivity_floor,
                ),
                bagging: self.root_bagging,
            }
        } else {
            RootSpec::Full {
                bagging: self.root_bagging,
            }
        }
    }

    /// Get the value of `key` in the db, or None if it has no value.
    pub async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, crate::qmdb::Error<F>> {
        // Collect to avoid holding a borrow across await points (rust-lang/rust#100013).
        let locs: Vec<Location<F>> = self.snapshot.get(key).copied().collect();
        let reader = self.log.reader().await;
        for loc in locs {
            let op = reader.read(*loc).await?;
            let Operation::Update(data) = op else {
                panic!("location does not reference update operation. loc={loc}");
            };
            if data.key() == key {
                return Ok(Some(data.value().clone()));
            }
        }
        Ok(None)
    }

    /// Batch read multiple keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(
        &self,
        keys: &[&U::Key],
    ) -> Result<Vec<Option<U::Value>>, crate::qmdb::Error<F>> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }

        // Phase 1: Collect candidate locations from the in-memory index.
        // Each key may map to multiple locations due to hash collisions.
        let mut candidates: Vec<(usize, u64)> = Vec::with_capacity(keys.len());
        let mut results: Vec<Option<U::Value>> = vec![None; keys.len()];

        for (key_idx, key) in keys.iter().enumerate() {
            for &loc in self.snapshot.get(key) {
                candidates.push((key_idx, *loc));
            }
        }

        if candidates.is_empty() {
            return Ok(results);
        }

        // Phase 2: Sort by position for batched journal reads, then deduplicate.
        candidates.sort_unstable_by_key(|&(_, pos)| pos);

        let mut positions: Vec<u64> = Vec::with_capacity(candidates.len());
        for &(_, pos) in &candidates {
            if positions.last() != Some(&pos) {
                positions.push(pos);
            }
        }

        // Phase 3: Batch-read from the journal (one reader acquisition, one I/O batch).
        let reader = self.log.reader().await;
        let ops = reader.read_many(&positions).await?;

        // Phase 4: Match operations back to keys via binary search (no HashMap).
        for &(key_idx, pos) in &candidates {
            if results[key_idx].is_some() {
                continue;
            }
            let op_idx = positions
                .binary_search(&pos)
                .expect("position was deduped from candidates");
            let Operation::Update(data) = &ops[op_idx] else {
                panic!("location does not reference update operation. loc={pos}");
            };
            if data.key() == keys[key_idx] {
                results[key_idx] = Some(data.value().clone());
            }
        }

        Ok(results)
    }

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> std::ops::Range<Location<F>> {
        let bounds = self.log.reader().await.bounds();
        Location::new(bounds.start)..Location::new(bounds.end)
    }

    /// Return the pinned Merkle nodes for a lower operation boundary of `loc`.
    pub async fn pinned_nodes_at(
        &self,
        loc: Location<F>,
    ) -> Result<Vec<H::Digest>, crate::qmdb::Error<F>> {
        if !loc.is_valid() {
            return Err(crate::merkle::Error::LocationOverflow(loc).into());
        }
        let futs: Vec<_> = F::nodes_to_pin(loc)
            .map(|p| async move {
                self.log
                    .merkle
                    .get_node(p)
                    .await?
                    .ok_or(crate::merkle::Error::ElementPruned(p).into())
            })
            .collect();
        futures::future::try_join_all(futs).await
    }
}

// Functionality requiring Mutable journal.
impl<F, E, U, C, I, H> Db<F, E, C, I, H, U>
where
    F: Family,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [crate::qmdb::Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [`crate::merkle::Error::LocationOverflow`] if `prune_loc` > [`crate::merkle::Family::MAX_LEAVES`].
    pub async fn prune(&mut self, prune_loc: Location<F>) -> Result<(), crate::qmdb::Error<F>> {
        if prune_loc > self.inactivity_floor_loc {
            return Err(crate::qmdb::Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }

        self.log.prune(prune_loc).await?;

        Ok(())
    }

    /// Returns a historical proof for `historical_size` operations, anchored at `start_loc`
    /// and bounded by `max_ops`.
    ///
    /// # Contract
    ///
    /// When this database is configured with `split_root: true`, `historical_size` must be a
    /// commit-boundary size: the operation at `historical_size - 1` must itself be a commit
    /// op declaring the governing inactivity floor. With `split_root: false` the spec does
    /// not depend on the floor and any retained `historical_size` works.
    ///
    /// # Errors
    ///
    /// Returns [`crate::qmdb::Error::HistoricalFloorPruned`] (split_root only) if
    /// `historical_size - 1` is retained but is not a commit op, either because the caller
    /// passed a non-commit-boundary size or because pruning removed the commit that would
    /// have governed it.
    pub async fn historical_proof(
        &self,
        historical_size: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, U>>), crate::qmdb::Error<F>> {
        if historical_size > self.log.size().await {
            return Err(crate::qmdb::Error::Merkle(
                crate::merkle::Error::RangeOutOfBounds(historical_size),
            ));
        }

        let inactivity_floor = if self.split_root {
            let reader = self.log.reader().await;
            crate::qmdb::find_inactivity_floor_at::<F, _>(&reader, historical_size, |op| {
                op.has_floor()
            })
            .await?
        } else {
            // Unused by `root_spec` when `split_root` is false.
            Location::new(0)
        };
        let spec = self.root_spec(historical_size, inactivity_floor);
        self.log
            .historical_proof(historical_size, start_loc, max_ops, spec)
            .await
            .map_err(Into::into)
    }

    pub async fn proof(
        &self,
        loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<F, U>>), crate::qmdb::Error<F>> {
        self.historical_proof(self.log.size().await, loc, max_ops)
            .await
    }

    /// Rewind the database to `size` operations, where `size` is the location of the next append.
    ///
    /// This rewinds both the authenticated log and the in-memory snapshot, then restores metadata
    /// (`last_commit_loc`, `inactivity_floor_loc`, `active_keys`) for the new tip commit.
    ///
    /// # Errors
    ///
    /// Returns an error when:
    /// - `size` is not a valid rewind target
    /// - the target's required logical range is not fully retained (for example, the target
    ///   inactivity floor is pruned)
    /// - `size - 1` is not a commit operation
    ///
    /// Any error from this method is fatal for this handle. Rewind may mutate journal state before
    /// all in-memory structures are rebuilt. Callers must drop this database handle after any `Err`
    /// from `rewind` and reopen from storage.
    ///
    /// Returns the list of locations restored to active state in the snapshot.
    ///
    /// A successful rewind is not restart-stable until a subsequent [`Db::commit`] or
    /// [`Db::sync`].
    pub async fn rewind(&mut self, size: Location<F>) -> Result<Vec<Location<F>>, Error<F>> {
        let rewind_size = *size;
        let current_size = *self.last_commit_loc + 1;

        if rewind_size == current_size {
            return Ok(Vec::new());
        }
        if rewind_size == 0 || rewind_size > current_size {
            return Err(Error::Journal(JournalError::InvalidRewind(rewind_size)));
        }

        // Read everything needed for rewind before mutating storage.
        let (rewind_floor, undos, active_keys_delta) = {
            let reader = self.log.reader().await;
            let bounds = reader.bounds();
            let rewind_last_loc = Location::new(rewind_size - 1);
            if rewind_size <= bounds.start {
                return Err(Error::<F>::Journal(JournalError::ItemPruned(
                    *rewind_last_loc,
                )));
            }
            let rewind_last_op = reader.read(*rewind_last_loc).await?;
            let Some(rewind_floor) = rewind_last_op.has_floor() else {
                return Err(Error::UnexpectedData(rewind_last_loc));
            };
            if *rewind_floor < bounds.start {
                return Err(Error::<F>::Journal(JournalError::ItemPruned(*rewind_floor)));
            }

            let mut undos = Vec::with_capacity((current_size - rewind_size) as usize);
            let mut active_keys_delta = 0isize;
            let mut prior_state_by_key: HashMap<U::Key, Option<Location<F>>> = HashMap::new();

            // Reconstruct key state once in a single pass from the rewind floor.
            for loc in *rewind_floor..current_size {
                let op = reader.read(loc).await?;
                let op_loc = Location::new(loc);
                match op {
                    Operation::CommitFloor(_, _) => {}
                    Operation::Update(update) => {
                        let key = update.key().clone();
                        let previous_loc = prior_state_by_key.get(&key).copied().flatten();

                        if loc >= rewind_size {
                            if let Some(previous_loc) = previous_loc {
                                undos.push(SnapshotUndo::Replace {
                                    key: key.clone(),
                                    old_loc: op_loc,
                                    new_loc: previous_loc,
                                });
                            } else {
                                active_keys_delta -= 1;
                                undos.push(SnapshotUndo::Remove {
                                    key: key.clone(),
                                    old_loc: op_loc,
                                });
                            }
                        }

                        prior_state_by_key.insert(key, Some(op_loc));
                    }
                    Operation::Delete(key) => {
                        let previous_loc = prior_state_by_key.get(&key).copied().flatten();

                        if loc >= rewind_size {
                            if let Some(previous_loc) = previous_loc {
                                active_keys_delta += 1;
                                undos.push(SnapshotUndo::Insert {
                                    key: key.clone(),
                                    new_loc: previous_loc,
                                });
                            }
                        }

                        prior_state_by_key.insert(key, None);
                    }
                }
            }

            // Undo operations must run from newest to oldest removed operation.
            undos.reverse();

            (rewind_floor, undos, active_keys_delta)
        };

        // Journal rewind happens before in-memory undo application. If any later step fails, this
        // handle may be internally diverged and must be dropped by the caller. This step is not
        // restart-stable until a later commit/sync boundary.
        self.log.rewind(rewind_size).await?;

        let mut restored_locs = Vec::new();
        for undo in undos {
            match undo {
                SnapshotUndo::Replace {
                    key,
                    old_loc,
                    new_loc,
                } => {
                    if new_loc < rewind_size {
                        restored_locs.push(new_loc);
                    }
                    update_known_loc(&mut self.snapshot, &key, old_loc, new_loc);
                }
                SnapshotUndo::Remove { key, old_loc } => {
                    delete_known_loc(&mut self.snapshot, &key, old_loc)
                }
                SnapshotUndo::Insert { key, new_loc } => {
                    if new_loc < rewind_size {
                        restored_locs.push(new_loc);
                    }
                    self.snapshot.insert(&key, new_loc);
                }
            }
        }

        self.active_keys = self
            .active_keys
            .checked_add_signed(active_keys_delta)
            .ok_or(Error::DataCorrupted(
                "active_keys underflow while rewinding",
            ))?;
        self.last_commit_loc = Location::new(rewind_size - 1);
        self.inactivity_floor_loc = rewind_floor;
        self.root = self
            .log
            .root(self.root_spec(Location::new(rewind_size), rewind_floor))?;

        Ok(restored_locs)
    }
}

// Functionality requiring Mutable + Persistable journal.
impl<F, E, U, C, I, H> Db<F, E, C, I, H, U>
where
    F: Family,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    /// Returns a [Db] initialized from `log`, using `callback` to report snapshot
    /// building events.
    ///
    /// # Panics
    ///
    /// Panics if the log is empty or the last operation is not a commit floor operation.
    pub async fn init_from_log<Cb>(
        mut index: I,
        log: AuthenticatedLog<F, E, C, H>,
        known_inactivity_floor: Option<Location<F>>,
        split_root: bool,
        root_bagging: Bagging,
        mut callback: Cb,
    ) -> Result<Self, crate::qmdb::Error<F>>
    where
        Cb: FnMut(bool, Option<Location<F>>),
    {
        // If the last-known inactivity floor is behind the current floor, then invoke the callback
        // appropriately to report the inactive bits.
        let (last_commit_loc, inactivity_floor_loc, active_keys) = {
            let reader = log.reader().await;
            let last_commit_loc = reader
                .bounds()
                .end
                .checked_sub(1)
                .expect("commit should exist");
            let last_commit = reader.read(last_commit_loc).await?;
            let inactivity_floor_loc = last_commit.has_floor().expect("should be a commit");
            if let Some(known_inactivity_floor) = known_inactivity_floor {
                (*known_inactivity_floor..*inactivity_floor_loc)
                    .for_each(|_| callback(false, None));
            }

            let active_keys =
                build_snapshot_from_log(inactivity_floor_loc, &reader, &mut index, callback)
                    .await?;
            (
                Location::new(last_commit_loc),
                inactivity_floor_loc,
                active_keys,
            )
        };
        let root_spec = if split_root {
            RootSpec::Split {
                inactive_peaks: F::inactive_peaks(
                    F::location_to_position(log.merkle.leaves()),
                    inactivity_floor_loc,
                ),
                bagging: root_bagging,
            }
        } else {
            RootSpec::Full {
                bagging: root_bagging,
            }
        };
        let root = log.root(root_spec)?;

        Ok(Self {
            log,
            root,
            split_root,
            root_bagging,
            inactivity_floor_loc,
            snapshot: index,
            last_commit_loc,
            active_keys,
            _update: core::marker::PhantomData,
        })
    }

    /// Sync all database state to disk.
    pub async fn sync(&self) -> Result<(), crate::qmdb::Error<F>> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Durably commit the journal state published by prior [`Db::apply_batch`]
    /// calls.
    pub async fn commit(&self) -> Result<(), crate::qmdb::Error<F>> {
        self.log.commit().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), crate::qmdb::Error<F>> {
        self.log.destroy().await.map_err(Into::into)
    }
}

impl<F, E, U, C, I, H> Persistable for Db<F, E, C, I, H, U>
where
    F: Family,
    E: Context,
    U: Update,
    C: Mutable<Item = Operation<F, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<F, U>: Codec,
{
    type Error = crate::qmdb::Error<F>;

    async fn commit(&self) -> Result<(), crate::qmdb::Error<F>> {
        Self::commit(self).await
    }

    async fn sync(&self) -> Result<(), crate::qmdb::Error<F>> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), crate::qmdb::Error<F>> {
        self.destroy().await
    }
}

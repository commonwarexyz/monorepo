//! A shared, generic implementation of the _Any_ QMDB.
//!
//! The impl blocks in this file defines shared functionality across all Any QMDB variants.

use super::operation::{update::Update, Operation};
use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        authenticated,
        contiguous::{Contiguous, MutableContiguous},
        Error as JournalError,
    },
    mmr::{Location, Proof},
    qmdb::{
        any::ValueEncoding,
        build_snapshot_from_log,
        operation::{Committable, Operation as OperationTrait},
        store::{self, LogStore, MerkleizedStore, PrunableStore},
        DurabilityState, Durable, Error, FloorHelper, MerkleizationState, Merkleized, NonDurable,
        Unmerkleized,
    },
    AuthenticatedBitMap, Persistable,
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use core::{num::NonZeroU64, ops::Range};
use tracing::debug;

/// Type alias for the authenticated journal used by [Db].
pub(crate) type AuthenticatedLog<E, C, H, M = Merkleized<H>> = authenticated::Journal<E, C, H, M>;

/// An "Any" QMDB implementation generic over ordered/unordered keys and variable/fixed values.
/// Consider using one of the following specialized variants instead, which may be more ergonomic:
/// - [crate::qmdb::any::ordered::fixed::Db]
/// - [crate::qmdb::any::ordered::variable::Db]
/// - [crate::qmdb::any::unordered::fixed::Db]
/// - [crate::qmdb::any::unordered::variable::Db]
pub struct Db<
    E: Storage + Clock + Metrics,
    C: Contiguous<Item: CodecShared>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
    M: MerkleizationState<DigestOf<H>> = Merkleized<H>,
    D: DurabilityState = Durable,
> {
    /// A (pruned) log of all operations in order of their application. The index of each
    /// operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - The log is never pruned beyond the inactivity floor.
    /// - There is always at least one commit operation in the log.
    pub(crate) log: AuthenticatedLog<E, C, H, M>,

    /// A location before which all operations are "inactive" (that is, operations before this point
    /// are over keys that have been updated by some operation at or after this point).
    pub(crate) inactivity_floor_loc: Location,

    /// The location of the last commit operation.
    pub(crate) last_commit_loc: Location,

    /// A snapshot of all currently active operations in the form of a map from each key to the
    /// location in the log containing its most recent update.
    ///
    /// # Invariant
    ///
    /// - Only references `Operation::Update`s.
    pub(crate) snapshot: I,

    /// The number of active keys in the snapshot.
    pub(crate) active_keys: usize,

    /// Whether the database is in the durable or non-durable state.
    pub(crate) durable_state: D,

    /// Marker for the update type parameter.
    pub(crate) _update: core::marker::PhantomData<U>,
}

// Functionality shared across all DB states, such as most non-mutating operations.
impl<E, K, V, U, C, I, H, M, D> Db<E, C, I, H, U, M, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    M: MerkleizationState<DigestOf<H>>,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    /// The number of operations that have been applied to this db, including those that have been
    /// pruned and those that are not yet committed.
    pub fn op_count(&self) -> Location {
        self.log.size()
    }

    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc
    }

    /// Whether the snapshot currently has no active keys.
    pub const fn is_empty(&self) -> bool {
        self.active_keys == 0
    }

    /// Returns the location of the oldest operation that remains retrievable.
    pub fn oldest_retained_loc(&self) -> Location {
        self.log
            .oldest_retained_loc()
            .expect("at least one operation should exist")
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        match self.log.read(self.last_commit_loc).await? {
            Operation::CommitFloor(metadata, _) => Ok(metadata),
            _ => unreachable!("last commit is not a CommitFloor operation"),
        }
    }
}

// Functionality shared across Merkleized states, such as the ability to prune the log, retrieve the
// state root, and compute proofs.
impl<E, K, V, U, C, I, H, D> Db<E, C, I, H, U, Merkleized<H>, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    pub const fn root(&self) -> H::Digest {
        self.log.root()
    }

    pub async fn proof(
        &self,
        loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V, U>>), Error> {
        self.historical_proof(self.op_count(), loc, max_ops).await
    }

    pub async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V, U>>), Error> {
        self.log
            .historical_proof(historical_size, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }

    /// Prunes historical operations prior to `prune_loc`. This does not affect the db's root or
    /// snapshot.
    ///
    /// # Errors
    ///
    /// - Returns [Error::PruneBeyondMinRequired] if `prune_loc` > inactivity floor.
    /// - Returns [crate::mmr::Error::LocationOverflow] if `prune_loc` > [crate::mmr::MAX_LOCATION].
    pub async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        if prune_loc > self.inactivity_floor_loc {
            return Err(Error::PruneBeyondMinRequired(
                prune_loc,
                self.inactivity_floor_loc,
            ));
        }

        self.log.prune(prune_loc).await?;

        Ok(())
    }
}

// Functionality specific to (Merkleized,Durable) state, such as ability to initialize and persist.
impl<E, K, V, U, C, I, H> Db<E, C, I, H, U, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Returns a [Db] initialized from `log`, using `callback` to report snapshot
    /// building events.
    ///
    /// # Panics
    ///
    /// Panics if the log is empty or the last operation is not a commit floor operation.
    pub async fn init_from_log<F>(
        mut index: I,
        log: AuthenticatedLog<E, C, H>,
        known_inactivity_floor: Option<Location>,
        mut callback: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        // If the last-known inactivity floor is behind the current floor, then invoke the callback
        // appropriately to report the inactive bits.
        let last_commit_loc = log.size().checked_sub(1).expect("commit should exist");
        let last_commit = log.read(last_commit_loc).await?;
        let inactivity_floor_loc = last_commit.has_floor().expect("should be a commit");
        if let Some(known_inactivity_floor) = known_inactivity_floor {
            (*known_inactivity_floor..*inactivity_floor_loc).for_each(|_| callback(false, None));
        }

        // Build snapshot from the log
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut index, callback).await?;

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot: index,
            last_commit_loc,
            active_keys,
            durable_state: store::Durable,
            _update: core::marker::PhantomData,
        })
    }

    /// Sync all database state to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }

    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, Unmerkleized, NonDurable> {
        Db {
            log: self.log.into_dirty(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
            snapshot: self.snapshot,
            active_keys: self.active_keys,
            durable_state: NonDurable { steps: 0 },
            _update: core::marker::PhantomData,
        }
    }
}

// Functionality shared across Unmerkleized states.
impl<E, K, V, U, C, I, H, D> Db<E, C, I, H, U, Unmerkleized, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    pub fn into_merkleized(self) -> Db<E, C, I, H, U, Merkleized<H>, D> {
        Db {
            log: self.log.merkleize(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
            snapshot: self.snapshot,
            active_keys: self.active_keys,
            durable_state: self.durable_state,
            _update: core::marker::PhantomData,
        }
    }
}

// Functionality specific to (Unmerkleized,Durable) state.
impl<E, K, V, U, C, I, H> Db<E, C, I, H, U, Unmerkleized, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, Unmerkleized, NonDurable> {
        Db {
            log: self.log,
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
            snapshot: self.snapshot,
            active_keys: self.active_keys,
            durable_state: store::NonDurable { steps: 0 },
            _update: core::marker::PhantomData,
        }
    }
}

// Functionality specific to (Merkleized,NonDurable) state.
impl<E, K, V, U, C, I, H> Db<E, C, I, H, U, Merkleized<H>, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Convert this database into a mutable state.
    pub fn into_mutable(self) -> Db<E, C, I, H, U, Unmerkleized, NonDurable> {
        Db {
            log: self.log.into_dirty(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
            snapshot: self.snapshot,
            active_keys: self.active_keys,
            durable_state: self.durable_state,
            _update: core::marker::PhantomData,
        }
    }
}

// Funtionality shared across NonDurable states.
impl<E, K, V, U, C, I, H, M> Db<E, C, I, H, U, M, NonDurable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    M: MerkleizationState<DigestOf<H>>,
    Operation<K, V, U>: Codec,
    AuthenticatedLog<E, C, H, M>: MutableContiguous<Item = Operation<K, V, U>>,
{
    /// Applies the given commit operation to the log and commits it to disk. Does not raise the
    /// inactivity floor.
    ///
    /// # Panics
    ///
    /// Panics if the given operation is not a commit operation.
    pub(crate) async fn apply_commit_op(&mut self, op: Operation<K, V, U>) -> Result<(), Error> {
        assert!(op.is_commit(), "commit operation expected");
        self.last_commit_loc = self.op_count();
        self.log.append(op).await?;

        self.log.commit().await.map_err(Into::into)
    }

    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Returns the
    /// `[start_loc, end_loc)` location range of committed operations.
    pub async fn commit(
        mut self,
        metadata: Option<V::Value>,
    ) -> Result<(Db<E, C, I, H, U, M, Durable>, Range<Location>), Error> {
        let start_loc = self.last_commit_loc + 1;

        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.raise_floor().await?;

        // Append the commit operation with the new inactivity floor.
        self.apply_commit_op(Operation::CommitFloor(metadata, inactivity_floor_loc))
            .await?;

        let range = start_loc..self.op_count();

        let db = Db {
            log: self.log,
            inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
            snapshot: self.snapshot,
            active_keys: self.active_keys,
            durable_state: store::Durable,
            _update: core::marker::PhantomData,
        };

        Ok((db, range))
    }

    /// Raises the inactivity floor by exactly one step, moving the first active operation to tip.
    /// Raises the floor to the tip if the db is empty.
    pub(crate) async fn raise_floor(&mut self) -> Result<Location, Error> {
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.durable_state.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self.as_floor_helper().raise_floor(loc).await?;
            }
        }
        self.durable_state.steps = 0;

        Ok(self.inactivity_floor_loc)
    }

    /// Same as `raise_floor` but uses the status bitmap to more efficiently find the first active
    /// operation above the inactivity floor.
    pub(crate) async fn raise_floor_with_bitmap<
        F: Storage + Clock + Metrics,
        D: Digest,
        const N: usize,
    >(
        &mut self,
        status: &mut AuthenticatedBitMap<F, D, N, Unmerkleized>,
    ) -> Result<Location, Error> {
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.durable_state.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self
                    .as_floor_helper()
                    .raise_floor_with_bitmap(status, loc)
                    .await?;
            }
        }
        self.durable_state.steps = 0;

        Ok(self.inactivity_floor_loc)
    }

    /// Returns a FloorHelper wrapping the current state of the log.
    pub(crate) const fn as_floor_helper(
        &mut self,
    ) -> FloorHelper<'_, I, AuthenticatedLog<E, C, H, M>> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
        }
    }
}

impl<E, K, V, U, C, I, H> Persistable for Db<E, C, I, H, U, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    type Error = Error;

    async fn commit(&mut self) -> Result<(), Error> {
        // No-op, DB already in recoverable state.
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), Error> {
        self.sync().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
    }
}

impl<E, K, V, U, C, I, H, D> MerkleizedStore for Db<E, C, I, H, U, Merkleized<H>, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V, U>;

    fn root(&self) -> H::Digest {
        self.root()
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V, U>>), Error> {
        self.historical_proof(historical_size, start_loc, max_ops)
            .await
    }
}

impl<E, K, V, U, C, I, H, M, D> LogStore for Db<E, C, I, H, U, M, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    M: MerkleizationState<DigestOf<H>>,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    type Value = V::Value;

    fn op_count(&self) -> Location {
        self.op_count()
    }

    fn inactivity_floor_loc(&self) -> Location {
        self.inactivity_floor_loc()
    }

    async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        self.get_metadata().await
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }
}

impl<E, K, V, U, C, I, H, D> PrunableStore for Db<E, C, I, H, U, Merkleized<H>, D>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: MutableContiguous<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    D: DurabilityState,
    Operation<K, V, U>: Codec,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

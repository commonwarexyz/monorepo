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
    merkle::{Family, Location, Proof},
    qmdb::{build_snapshot_from_log, operation::Operation as OperationTrait},
    Persistable,
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use core::num::NonZeroU64;

/// Type alias for the authenticated journal used by [Db].
pub(crate) type AuthenticatedLog<F, E, C, H> = authenticated::Journal<F, E, C, H>;

/// An "Any" QMDB implementation generic over ordered/unordered keys and variable/fixed values.
/// Consider using one of the following specialized variants instead, which may be more ergonomic:
/// - [crate::qmdb::any::ordered::fixed::Db]
/// - [crate::qmdb::any::ordered::variable::Db]
/// - [crate::qmdb::any::unordered::fixed::Db]
/// - [crate::qmdb::any::unordered::variable::Db]
pub struct Db<
    F: Family,
    E: Storage + Clock + Metrics,
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
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Return the inactivity floor location. This is the location before which all operations are
    /// known to be inactive. Operations before this point can be safely pruned.
    pub const fn inactivity_floor_loc(&self) -> Location<F> {
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

    pub fn root(&self) -> H::Digest {
        self.log.root()
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

    /// Return [start, end) where `start` and `end - 1` are the Locations of the oldest and newest
    /// retained operations respectively.
    pub async fn bounds(&self) -> std::ops::Range<Location<F>> {
        let bounds = self.log.reader().await.bounds();
        Location::new(bounds.start)..Location::new(bounds.end)
    }
}

// MMR-specific functionality (pinned nodes).
impl<E, U, C, I, H> Db<crate::merkle::mmr::Family, E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Contiguous<Item = Operation<U>>,
    I: UnorderedIndex<Value = crate::mmr::Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Return the pinned MMR nodes for a lower operation boundary of `loc`.
    pub async fn pinned_nodes_at(
        &self,
        loc: crate::mmr::Location,
    ) -> Result<Vec<H::Digest>, crate::qmdb::Error<crate::merkle::mmr::Family>> {
        let pos = crate::mmr::Position::try_from(loc)?;
        let futs: Vec<_> = crate::mmr::iterator::nodes_to_pin(pos)
            .map(|p| async move {
                self.log
                    .mmr
                    .get_node(p)
                    .await?
                    .ok_or(crate::mmr::Error::ElementPruned(p).into())
            })
            .collect();
        futures::future::try_join_all(futs).await
    }
}

// Functionality requiring Mutable journal.
impl<F, E, U, C, I, H> Db<F, E, C, I, H, U>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<U>: Codec,
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

    pub async fn historical_proof(
        &self,
        historical_size: Location<F>,
        start_loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<U>>), crate::qmdb::Error<F>> {
        self.log
            .historical_proof(historical_size, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }

    pub async fn proof(
        &self,
        loc: Location<F>,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<F, H::Digest>, Vec<Operation<U>>), crate::qmdb::Error<F>> {
        self.historical_proof(self.log.size().await, loc, max_ops)
            .await
    }
}

// Functionality requiring Mutable + Persistable journal (MMR-specific: init_from_log).
impl<E, U, C, I, H> Db<crate::merkle::mmr::Family, E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = crate::mmr::Location>,
    H: Hasher,
    Operation<U>: Codec,
{
    /// Returns a [Db] initialized from `log`, using `callback` to report snapshot
    /// building events.
    ///
    /// # Panics
    ///
    /// Panics if the log is empty or the last operation is not a commit floor operation.
    pub async fn init_from_log<Cb>(
        mut index: I,
        log: AuthenticatedLog<crate::merkle::mmr::Family, E, C, H>,
        known_inactivity_floor: Option<crate::mmr::Location>,
        mut callback: Cb,
    ) -> Result<Self, crate::qmdb::Error<crate::merkle::mmr::Family>>
    where
        Cb: FnMut(bool, Option<crate::mmr::Location>),
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
                crate::mmr::Location::new(last_commit_loc),
                inactivity_floor_loc,
                active_keys,
            )
        };

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot: index,
            last_commit_loc,
            active_keys,
            _update: core::marker::PhantomData,
        })
    }
}

// Functionality requiring Mutable + Persistable journal.
impl<F, E, U, C, I, H> Db<F, E, C, I, H, U>
where
    F: Family,
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<U>: Codec,
{
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
    E: Storage + Clock + Metrics,
    U: Update,
    C: Mutable<Item = Operation<U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    Operation<U>: Codec,
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

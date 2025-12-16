//! Authenticated databases that provides succinct proofs of _any_ value ever associated with
//! a key. The submodules provide two classes of variants, one specialized for ordered keys and
//! the other for unordered keys.

use crate::{
    index::Unordered as UnorderedIndex,
    journal::{
        authenticated,
        contiguous::{
            fixed::{Config as FixedJournalConfig, Journal as FixedJournal},
            variable::{Config as VariableJournalConfig, Journal as VariableJournal},
            Contiguous, MutableContiguous, PersistableContiguous,
        },
    },
    mmr::{
        journaled::Config as MmrConfig,
        mem::{Clean, Dirty, State},
        Location, Proof,
    },
    qmdb::{
        build_snapshot_from_log,
        operation::Committable,
        store::{CleanStore, DirtyStore, LogStore},
        Error, FloorHelper,
    },
    translator::Translator,
    AuthenticatedBitMap,
};
use commonware_codec::{Codec, CodecFixed, Read};
use commonware_cryptography::{Digest, DigestOf, Hasher};
use commonware_runtime::{buffer::PoolRef, Clock, Metrics, Storage, ThreadPool};
use commonware_utils::Array;
use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
};
use tracing::debug;

mod operation;
use operation::Update;
pub use operation::{
    Operation, OrderedOperation, OrderedUpdate, UnorderedOperation, UnorderedUpdate,
};

mod value;
use value::ValueEncoding;
pub use value::{FixedEncoding, FixedValue, VariableEncoding, VariableValue};

mod ext;
pub mod ordered;
pub mod unordered;

pub use ext::AnyExt;
pub(crate) use ordered::span_contains;

/// Extension trait for "Any" QMDBs in a clean (merkleized) state.
pub trait CleanAny:
    CleanStore<Dirty: DirtyAny<Key = Self::Key, Value = Self::Value, Clean = Self>>
{
    /// The key type for this database.
    type Key: Array;

    /// Get the value for a given key, or None if it has no value.
    fn get(&self, key: &Self::Key) -> impl Future<Output = Result<Option<Self::Value>, Error>>;

    /// Commit pending operations to the database, ensuring durability.
    /// Returns the location range of committed operations.
    fn commit(
        &mut self,
        metadata: Option<Self::Value>,
    ) -> impl Future<Output = Result<Range<Location>, Error>>;

    /// Sync all database state to disk.
    fn sync(&mut self) -> impl Future<Output = Result<(), Error>>;

    /// Prune historical operations prior to `prune_loc`.
    fn prune(&mut self, prune_loc: Location) -> impl Future<Output = Result<(), Error>>;

    /// Close the db. Uncommitted operations will be lost or rolled back on restart.
    fn close(self) -> impl Future<Output = Result<(), Error>>;

    /// Destroy the db, removing all data from disk.
    fn destroy(self) -> impl Future<Output = Result<(), Error>>;
}

/// Extension trait for "Any" QMDBs in a dirty (deferred merkleization) state.
pub trait DirtyAny: DirtyStore {
    /// The key type for this database.
    type Key: Array;

    /// Get the value for a given key, or None if it has no value.
    fn get(&self, key: &Self::Key) -> impl Future<Output = Result<Option<Self::Value>, Error>>;

    /// Update `key` to have value `value`. Subject to rollback until next `commit`.
    fn update(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<(), Error>>;

    /// Create a new key-value pair. Returns true if created, false if key already existed.
    /// Subject to rollback until next `commit`.
    fn create(
        &mut self,
        key: Self::Key,
        value: Self::Value,
    ) -> impl Future<Output = Result<bool, Error>>;

    /// Delete `key` and its value. Returns true if deleted, false if already inactive.
    /// Subject to rollback until next `commit`.
    fn delete(&mut self, key: Self::Key) -> impl Future<Output = Result<bool, Error>>;
}

/// Configuration for an `Any` authenticated db with fixed-size values.
#[derive(Clone)]
pub struct FixedConfig<T: Translator> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the (pruned) log of operations.
    pub log_journal_partition: String,

    /// The items per blob configuration value used by the log journal.
    pub log_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

/// Configuration for an `Any` authenticated db with variable-sized values.
#[derive(Clone)]
pub struct VariableConfig<T: Translator, C> {
    /// The name of the [Storage] partition used for the MMR's backing journal.
    pub mmr_journal_partition: String,

    /// The items per blob configuration value used by the MMR journal.
    pub mmr_items_per_blob: NonZeroU64,

    /// The size of the write buffer to use for each blob in the MMR journal.
    pub mmr_write_buffer: NonZeroUsize,

    /// The name of the [Storage] partition used for the MMR's metadata.
    pub mmr_metadata_partition: String,

    /// The name of the [Storage] partition used to persist the log of operations.
    pub log_partition: String,

    /// The size of the write buffer to use for each blob in the log journal.
    pub log_write_buffer: NonZeroUsize,

    /// Optional compression level (using `zstd`) to apply to log data before storing.
    pub log_compression: Option<u8>,

    /// The codec configuration to use for encoding and decoding log items.
    pub log_codec_config: C,

    /// The number of items to put in each blob of the journal.
    pub log_items_per_blob: NonZeroU64,

    /// The translator used by the compressed index.
    pub translator: T,

    /// An optional thread pool to use for parallelizing batch operations.
    pub thread_pool: Option<ThreadPool>,

    /// The buffer pool to use for caching data.
    pub buffer_pool: PoolRef,
}

type FixedAuthenticatedLog<E, O, H, S = Clean<DigestOf<H>>> =
    authenticated::Journal<E, FixedJournal<E, O>, H, S>;

/// Initialize the authenticated log from the given config, returning it along with the inactivity
/// floor specified by the last commit.
pub(crate) async fn init_fixed_authenticated_log<
    E: Storage + Clock + Metrics,
    O: Committable + CodecFixed<Cfg = ()>,
    H: Hasher,
    T: Translator,
>(
    context: E,
    cfg: FixedConfig<T>,
) -> Result<FixedAuthenticatedLog<E, O, H>, Error> {
    let mmr_config = MmrConfig {
        journal_partition: cfg.mmr_journal_partition,
        metadata_partition: cfg.mmr_metadata_partition,
        items_per_blob: cfg.mmr_items_per_blob,
        write_buffer: cfg.mmr_write_buffer,
        thread_pool: cfg.thread_pool,
        buffer_pool: cfg.buffer_pool.clone(),
    };

    let journal_config = FixedJournalConfig {
        partition: cfg.log_journal_partition,
        items_per_blob: cfg.log_items_per_blob,
        write_buffer: cfg.log_write_buffer,
        buffer_pool: cfg.buffer_pool,
    };

    let log = FixedAuthenticatedLog::new(
        context.with_label("log"),
        mmr_config,
        journal_config,
        O::is_commit,
    )
    .await?;

    Ok(log)
}

type VariableAuthenticatedLog<E, O, H, S = Clean<DigestOf<H>>> =
    authenticated::Journal<E, VariableJournal<E, O>, H, S>;

/// Initialize a variable-size authenticated log from the given config.
pub(crate) async fn init_variable_authenticated_log<
    E: Storage + Clock + Metrics,
    O: Committable + Codec + Read,
    H: Hasher,
    T: Translator,
>(
    context: E,
    cfg: VariableConfig<T, <O as Read>::Cfg>,
) -> Result<VariableAuthenticatedLog<E, O, H>, Error> {
    let mmr_config = MmrConfig {
        journal_partition: cfg.mmr_journal_partition,
        metadata_partition: cfg.mmr_metadata_partition,
        items_per_blob: cfg.mmr_items_per_blob,
        write_buffer: cfg.mmr_write_buffer,
        thread_pool: cfg.thread_pool,
        buffer_pool: cfg.buffer_pool.clone(),
    };

    let journal_config = VariableJournalConfig {
        partition: cfg.log_partition,
        items_per_section: cfg.log_items_per_blob,
        compression: cfg.log_compression,
        codec_config: cfg.log_codec_config,
        buffer_pool: cfg.buffer_pool,
        write_buffer: cfg.log_write_buffer,
    };

    let log = VariableAuthenticatedLog::new(
        context.with_label("log"),
        mmr_config,
        journal_config,
        O::is_commit,
    )
    .await?;

    Ok(log)
}

/// A QMDB implementation that can prove a key held a value at some point.
/// This type is generic over ordered/unordered keys and fixed/variable-length values.
/// Consider using one of the following, which provide concrete types for some of the generic
/// parameters of this type:
/// - [ordered::Fixed] for ordered keys and fixed-length values
/// - [ordered::Variable] for ordered keys and variable-length values
/// - [unordered::Fixed] for unordered keys and fixed-length values
/// - [unordered::Variable] for unordered keys and variable-length values
pub struct Db<
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Contiguous<Item = Operation<K, V, U>>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    S: State<DigestOf<H>> = Clean<DigestOf<H>>,
> where
    Operation<K, V, U>: Codec,
{
    /// A (pruned) log of all operations in order of their application. The index of each
    /// operation in the log is called its _location_, which is a stable identifier.
    ///
    /// # Invariants
    ///
    /// - The log is never pruned beyond the inactivity floor.
    /// - There is always at least one commit operation in the log.
    pub(crate) log: authenticated::Journal<E, C, H, S>,

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
    /// - Only references update operations.
    pub(crate) snapshot: I,

    /// The number of _steps_ to raise the inactivity floor. Each step involves moving exactly one
    /// active operation to tip.
    pub(crate) steps: u64,

    /// The number of active keys in the snapshot.
    pub(crate) active_keys: usize,
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: Contiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > Db<E, K, V, U, C, I, H, S>
where
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
    pub fn oldest_retained_loc(&self) -> Option<Location> {
        self.log.oldest_retained_loc()
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: Contiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > Db<E, K, V, U, C, I, H, S>
where
    Operation<K, V, U>: Codec,
{
    /// Returns the inactivity floor from an authenticated log known to be in a consistent state by
    /// reading it from the last commit, which is assumed to be the last operation in the log.
    ///
    /// # Panics
    ///
    /// Panics if the log is not empty and the last operation is not a commit floor operation.
    pub(crate) async fn recover_inactivity_floor(
        log: &authenticated::Journal<E, C, H, S>,
    ) -> Result<Location, Error> {
        let last_commit_loc = log.size().checked_sub(1).expect("commit should exist");
        let last_commit = log.read(last_commit_loc).await?;
        let inactivity_floor = match last_commit {
            Operation::CommitFloor(_, loc) => loc,
            _ => unreachable!("last commit is not a CommitFloor operation"),
        };

        Ok(inactivity_floor)
    }

    /// Get the metadata associated with the last commit.
    pub async fn get_metadata(&self) -> Result<Option<V::Value>, Error> {
        match self.log.read(self.last_commit_loc).await? {
            Operation::CommitFloor(metadata, _) => Ok(metadata),
            _ => unreachable!("last commit is not a CommitFloor operation"),
        }
    }

    /// Get the update operation at the given location.
    ///
    /// # Panics
    ///
    /// Panics if the operation at the given location is not an update operation.
    async fn get_update(
        log: &authenticated::Journal<E, C, H, S>,
        loc: Location,
    ) -> Result<U, Error> {
        match log.read(loc).await? {
            Operation::Update(update) => Ok(update),
            _ => unreachable!("expected update operation at location {}", loc),
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: MutableContiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > Db<E, K, V, U, C, I, H>
where
    Operation<K, V, U>: Codec,
{
    /// Returns a [Db] initialized from `log`, using `callback` to report snapshot
    /// building events.
    ///
    /// # Panics
    ///
    /// Panics if the last operation is not a commit.
    pub async fn init_from_log<F>(
        mut index: I,
        log: authenticated::Journal<E, C, H, Clean<H::Digest>>,
        known_inactivity_floor: Option<Location>,
        mut callback: F,
    ) -> Result<Self, Error>
    where
        F: FnMut(bool, Option<Location>),
    {
        // If the last-known inactivity floor is behind the current floor, then invoke the callback
        // appropriately to report the inactive bits.
        let inactivity_floor_loc = Self::recover_inactivity_floor(&log).await?;
        if let Some(mut known_inactivity_floor) = known_inactivity_floor {
            while known_inactivity_floor < inactivity_floor_loc {
                callback(false, None);
                known_inactivity_floor += 1;
            }
        }

        // Build snapshot from the log
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut index, callback).await?;

        let last_commit_loc = log.size().checked_sub(1).expect("commit should exist");

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot: index,
            last_commit_loc,
            steps: 0,
            active_keys,
        })
    }

    /// Returns an [Db] initialized directly from the given components. The log is
    /// replayed from `inactivity_floor_loc` to build the snapshot, and that value is used as the
    /// inactivity floor. The last operation is assumed to be a commit.
    pub(crate) async fn from_components(
        inactivity_floor_loc: Location,
        log: authenticated::Journal<E, C, H, Clean<H::Digest>>,
        mut snapshot: I,
    ) -> Result<Self, Error> {
        let active_keys =
            build_snapshot_from_log(inactivity_floor_loc, &log, &mut snapshot, |_, _| {}).await?;
        let last_commit_loc = log.size().checked_sub(1).expect("commit should exist");
        assert!(matches!(
            log.read(last_commit_loc).await?,
            Operation::CommitFloor(_, _)
        ));

        Ok(Self {
            log,
            inactivity_floor_loc,
            snapshot,
            last_commit_loc,
            steps: 0,
            active_keys,
        })
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: Contiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > Db<E, K, V, U, C, I, H>
where
    Operation<K, V, U>: Codec,
{
    /// Convert this database into its dirty counterpart for batched updates.
    pub fn into_dirty(self) -> Db<E, K, V, U, C, I, H, Dirty> {
        Db {
            log: self.log.into_dirty(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
            snapshot: self.snapshot,
            steps: self.steps,
            active_keys: self.active_keys,
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: MutableContiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > Db<E, K, V, U, C, I, H>
where
    Operation<K, V, U>: Codec,
{
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

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: PersistableContiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > Db<E, K, V, U, C, I, H>
where
    Operation<K, V, U>: Codec,
{
    /// Commit any pending operations to the database, ensuring their durability upon return from
    /// this function. Also raises the inactivity floor according to the schedule. Returns the
    /// `(start_loc, end_loc]` location range of committed operations.
    pub async fn commit(&mut self, metadata: Option<V::Value>) -> Result<Range<Location>, Error> {
        let start_loc = self.last_commit_loc + 1;

        let inactivity_floor_loc = self.raise_floor().await?;

        // Append the commit operation with the new inactivity floor.
        self.apply_commit_op(Operation::CommitFloor(metadata, inactivity_floor_loc))
            .await?;

        Ok(start_loc..self.op_count())
    }

    /// Applies the given commit operation to the log and commits it to disk. Does not raise the
    /// inactivity floor.
    ///
    /// # Panics
    ///
    /// Panics if the given operation is not a commit operation.
    pub(crate) async fn apply_commit_op(&mut self, op: C::Item) -> Result<(), Error> {
        self.last_commit_loc = self.op_count();
        self.log.append(op).await?;

        self.log.commit().await.map_err(Into::into)
    }

    /// Simulate an unclean shutdown by consuming the db. If commit_log is true, the underlying
    /// authenticated log will be be committed before consuming.
    #[cfg(any(test, feature = "fuzzing"))]
    pub async fn simulate_failure(mut self, commit_log: bool) -> Result<(), Error> {
        if commit_log {
            self.log.commit().await?;
        }

        Ok(())
    }

    /// Sync all database state to disk.
    pub async fn sync(&mut self) -> Result<(), Error> {
        self.log.sync().await.map_err(Into::into)
    }

    /// Close the db. Operations that have not been committed will be lost or rolled back on
    /// restart.
    pub async fn close(self) -> Result<(), Error> {
        self.log.close().await.map_err(Into::into)
    }

    /// Destroy the db, removing all data from disk.
    pub async fn destroy(self) -> Result<(), Error> {
        self.log.destroy().await.map_err(Into::into)
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: MutableContiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > Db<E, K, V, U, C, I, H>
where
    Operation<K, V, U>: Codec,
{
    /// Returns a FloorHelper wrapping the current state of the log.
    #[allow(clippy::type_complexity)]
    pub(crate) const fn as_floor_helper(
        &mut self,
    ) -> FloorHelper<'_, I, authenticated::Journal<E, C, H, Clean<H::Digest>>> {
        FloorHelper {
            snapshot: &mut self.snapshot,
            log: &mut self.log,
        }
    }

    /// Raises the inactivity floor by exactly one step, moving the first active operation to tip.
    /// Raises the floor to the tip if the db is empty.
    pub(crate) async fn raise_floor(&mut self) -> Result<Location, Error> {
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self.as_floor_helper().raise_floor(loc).await?;
            }
        }
        self.steps = 0;

        Ok(self.inactivity_floor_loc)
    }

    /// Same as `raise_floor` but uses the status bitmap to more efficiently find the first active
    /// operation above the inactivity floor.
    pub(crate) async fn raise_floor_with_bitmap<D: Digest, const N: usize>(
        &mut self,
        status: &mut AuthenticatedBitMap<D, N, Dirty>,
    ) -> Result<Location, Error> {
        if self.is_empty() {
            self.inactivity_floor_loc = self.op_count();
            debug!(tip = ?self.inactivity_floor_loc, "db is empty, raising floor to tip");
        } else {
            let steps_to_take = self.steps + 1;
            for _ in 0..steps_to_take {
                let loc = self.inactivity_floor_loc;
                self.inactivity_floor_loc = self
                    .as_floor_helper()
                    .raise_floor_with_bitmap(status, loc)
                    .await?;
            }
        }
        self.steps = 0;

        Ok(self.inactivity_floor_loc)
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: Contiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > Db<E, K, V, U, C, I, H, Dirty>
where
    Operation<K, V, U>: Codec,
{
    /// Merkleize the database and compute the root digest.
    pub fn merkleize(self) -> Db<E, K, V, U, C, I, H, Clean<H::Digest>> {
        Db {
            log: self.log.merkleize(),
            inactivity_floor_loc: self.inactivity_floor_loc,
            last_commit_loc: self.last_commit_loc,
            snapshot: self.snapshot,
            steps: self.steps,
            active_keys: self.active_keys,
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: MutableContiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::LogStorePrunable for Db<E, K, V, U, C, I, H>
where
    Operation<K, V, U>: Codec,
{
    async fn prune(&mut self, prune_loc: Location) -> Result<(), Error> {
        self.prune(prune_loc).await
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: Contiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::CleanStore for Db<E, K, V, U, C, I, H>
where
    Operation<K, V, U>: Codec,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V, U>;
    type Dirty = Db<E, K, V, U, C, I, H, Dirty>;

    fn into_dirty(self) -> Self::Dirty {
        self.into_dirty()
    }

    fn root(&self) -> H::Digest {
        self.log.root()
    }

    async fn proof(
        &self,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Self::Operation>), Error> {
        let size = self.op_count();
        self.historical_proof(size, start_loc, max_ops).await
    }

    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Self::Operation>), Error> {
        self.log
            .historical_proof(historical_size, start_loc, max_ops)
            .await
            .map_err(Into::into)
    }
}

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: Contiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        S: State<DigestOf<H>>,
    > LogStore for Db<E, K, V, U, C, I, H, S>
where
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

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: ValueEncoding,
        U: Update<K, V>,
        C: Contiguous<Item = Operation<K, V, U>>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
    > crate::qmdb::store::DirtyStore for Db<E, K, V, U, C, I, H, Dirty>
where
    Operation<K, V, U>: Codec,
{
    type Digest = H::Digest;
    type Operation = Operation<K, V, U>;
    type Clean = Db<E, K, V, U, C, I, H>;

    async fn merkleize(self) -> Result<Self::Clean, Error> {
        Ok(self.merkleize())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        qmdb::any::{FixedConfig, VariableConfig},
        translator::TwoCap,
    };
    use commonware_utils::{NZUsize, NZU64};

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: usize = 101;
    const PAGE_CACHE_SIZE: usize = 11;

    pub(super) fn fixed_db_config(suffix: &str) -> FixedConfig<TwoCap> {
        FixedConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_journal_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }

    pub(super) fn variable_db_config(suffix: &str) -> VariableConfig<TwoCap, ()> {
        VariableConfig {
            mmr_journal_partition: format!("journal_{suffix}"),
            mmr_metadata_partition: format!("metadata_{suffix}"),
            mmr_items_per_blob: NZU64!(11),
            mmr_write_buffer: NZUsize!(1024),
            log_partition: format!("log_journal_{suffix}"),
            log_items_per_blob: NZU64!(7),
            log_write_buffer: NZUsize!(1024),
            log_compression: None,
            log_codec_config: (),
            translator: TwoCap,
            thread_pool: None,
            buffer_pool: PoolRef::new(NZUsize!(PAGE_SIZE), NZUsize!(PAGE_CACHE_SIZE)),
        }
    }
}

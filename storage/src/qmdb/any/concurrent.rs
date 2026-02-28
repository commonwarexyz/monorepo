//! Facade for an Any QMDB supporting a single-writer, multi-reader access pattern where concurrent
//! readers are not blocked by any fsync calls or merkleization.
//!
//! Multiple concurrent readers can read the database and/or generate proofs, and multiple
//! concurrent threads can each construct their own [Batch] of updates (e.g. for parallel tx
//! execution). A single [Writer] applies batches and commits them.
//!
//! # Example: Parallel execution with concurrent RPC request serving.
//!
//! ```ignore
//! use futures::StreamExt as _;
//!
//! let (mut writer, shared) = db.into_concurrent(context.clone(), SyncPolicy::Never);
//!
//! // --- RPC thread: serves root and proof requests concurrently with everything else. ---
//! let rpc_shared = shared.clone();
//! context.spawn(|_| async move {
//!     loop {
//!         let req = rpc_recv.next().await;
//!         match req {
//!             RpcRequest::Root(resp) => {
//!                 resp.send(rpc_shared.root());
//!             }
//!             RpcRequest::Proof { loc, max_ops, resp } => {
//!                 let (_, leaves) = rpc_shared.root();
//!                 let result = rpc_shared.historical_proof(leaves, loc, max_ops).await;
//!                 resp.send(result);
//!             }
//!         }
//!     }
//! });
//!
//! // --- Execution threads: build batches concurrently (assumes no conflicts). ---
//! let (tx, mut rx) = futures::channel::mpsc::channel(num_workers);
//! for partition in work_partitions {
//!     let shared = shared.clone();
//!     let mut tx = tx.clone();
//!     context.spawn(|_| async move {
//!         let mut batch = shared.start_batch().await;
//!         for key in partition {
//!             let current = batch.get(&key).await.unwrap();
//!             batch.update(key, compute_new_value(current)).await.unwrap();
//!         }
//!         tx.send(batch.into_iter().collect::<Vec<_>>()).await.unwrap();
//!     });
//! }
//! drop(tx);
//!
//! // --- Writer thread: applies batches and commits. ---
//! while let Some(entries) = rx.next().await {
//!     writer.write_batch(entries).await.unwrap();
//! }
//! let (_root, _range) = writer.commit_and_compute_root(None).await.unwrap();
//! ```

use super::{
    db::Db,
    operation::{update::Update, Operation},
    ValueEncoding,
};
use crate::{
    index::Unordered as UnorderedIndex,
    journal::{contiguous::Mutable, Error as JournalError},
    kv,
    mmr::{Location, Position, Proof, StandardHasher},
    qmdb::{store, Durable, Error, Merkleized, NonDurable, Unmerkleized},
    Persistable,
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{
    sync::{AsyncRwLockReadGuard, Mutex, UpgradableAsyncRwLock},
    Array,
};
use core::{num::NonZeroU64, ops::Range};
use std::{
    collections::BTreeMap,
    sync::Arc,
    time::{Duration, SystemTime},
};

/// Runtime state for a shared Any DB facade.
enum DbState<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    Clean(Db<E, C, I, H, U, Merkleized<H>, Durable>),
    UnmerkleizedDurable(Db<E, C, I, H, U, Unmerkleized, Durable>),
    Mutable(Db<E, C, I, H, U, Unmerkleized, NonDurable>),
}

/// Policy that controls when a full `sync()` is performed after `commit()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyncPolicy {
    /// Never perform automatic full sync after commit.
    Never,
    /// Always perform full sync after every commit.
    Always,
    /// Perform full sync if at least this much time has elapsed since the last full sync.
    Interval(Duration),
}

type StateOption<E, C, I, H, U> = Option<DbState<E, C, I, H, U>>;
type Handles<E, C, I, H, U> = (Writer<E, C, I, H, U>, Shared<E, C, I, H, U>);
type ReadGuard<'a, E, C, I, H, U> = AsyncRwLockReadGuard<'a, StateOption<E, C, I, H, U>>;

struct SharedInner<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    db: UpgradableAsyncRwLock<StateOption<E, C, I, H, U>>,
    merkleize_hasher: Mutex<StandardHasher<H>>,
    /// Cached root digest and leaf count from the last computed root.
    last_root: Mutex<(H::Digest, Location)>,
}

impl<E, K, V, U, C, I, H> SharedInner<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    fn merkleize_to(
        &self,
        state: &DbState<E, C, I, H, U>,
        target_size: Position,
    ) -> Result<(), Error> {
        let mut hasher = self.merkleize_hasher.lock();
        match state {
            DbState::UnmerkleizedDurable(db) => db.merkleize_to(&mut *hasher, target_size),
            DbState::Mutable(db) => db.merkleize_to(&mut *hasher, target_size),
            DbState::Clean(_) => Ok(()),
        }
    }

    fn mmr_size(&self, state: &DbState<E, C, I, H, U>) -> Position {
        match state {
            DbState::Clean(db) => db.log.mmr.size(),
            DbState::UnmerkleizedDurable(db) => db.log.mmr.size(),
            DbState::Mutable(db) => db.log.mmr.size(),
        }
    }

    /// Return the cached root digest and leaf count.
    fn last_root(&self) -> (H::Digest, Location) {
        *self.last_root.lock()
    }

    /// Update the cached root.
    fn set_last_root(&self, root: H::Digest, leaves: Location) {
        *self.last_root.lock() = (root, leaves);
    }

    /// Generate a historical proof.
    ///
    /// Returns [Error::Unmerkleized] when `historical_size` is greater than the size represented
    /// by the last cached root.
    async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V, U>>), Error> {
        let (_, root_leaves) = self.last_root();
        if historical_size > root_leaves {
            return Err(Error::Unmerkleized);
        }

        let guard = self.db.read().await;
        let state = guard.as_ref().ok_or(Error::Shutdown)?;
        match state {
            DbState::Clean(db) => {
                return db
                    .historical_proof(historical_size, start_loc, max_ops)
                    .await;
            }
            DbState::UnmerkleizedDurable(db) => {
                db.historical_proof(historical_size, start_loc, max_ops)
                    .await
            }
            DbState::Mutable(db) => {
                db.historical_proof(historical_size, start_loc, max_ops)
                    .await
            }
        }
    }
}

pub struct Writer<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    inner: Arc<SharedInner<E, C, I, H, U>>,
    context: E,
    sync_policy: SyncPolicy,
    last_full_sync: Option<SystemTime>,
}

pub struct Shared<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    inner: Arc<SharedInner<E, C, I, H, U>>,
}

impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > Clone for Shared<E, C, I, H, U>
{
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

pub struct Reader<
    'a,
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    guard: ReadGuard<'a, E, C, I, H, U>,
}

impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > Writer<E, C, I, H, U>
{
    pub const fn sync_policy(&self) -> SyncPolicy {
        self.sync_policy
    }

    fn should_auto_full_sync(&self, now: SystemTime) -> bool {
        match self.sync_policy {
            SyncPolicy::Never => false,
            SyncPolicy::Always => true,
            SyncPolicy::Interval(interval) => self.last_full_sync.is_none_or(|last| {
                now.duration_since(last)
                    .map(|elapsed| elapsed >= interval)
                    .unwrap_or(true)
            }),
        }
    }
}

impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > Shared<E, C, I, H, U>
{
    pub async fn reader(&self) -> Reader<'_, E, C, I, H, U> {
        Reader {
            guard: self.inner.db.read().await,
        }
    }
}

impl<
        'a,
        E: Storage + Clock + Metrics,
        C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > Reader<'a, E, C, I, H, U>
{
    fn state(&self) -> Result<&DbState<E, C, I, H, U>, Error> {
        self.guard.as_ref().ok_or(Error::Shutdown)
    }
}

impl<'a, E, K, V, U, C, I, H> Reader<'a, E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Convert this reader into a [Batch], transferring the read lock.
    ///
    /// This is useful when reads are needed before deciding what to write, without
    /// releasing the lock in between.
    pub fn into_batch(self) -> Batch<'a, E, C, I, H, K, V::Value, U> {
        Batch {
            guard: self.guard,
            diff: BTreeMap::new(),
        }
    }
}

impl<'a, E, K, V, U, C, I, H> kv::Gettable for Reader<'a, E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    K: Array + Send + Sync,
    V: ValueEncoding,
    V::Value: Send + Sync,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V, U>: Codec,
    Db<E, C, I, H, U, Merkleized<H>, Durable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
    Db<E, C, I, H, U, Unmerkleized, Durable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
    Db<E, C, I, H, U, Unmerkleized, NonDurable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
{
    type Key = K;
    type Value = V::Value;
    type Error = Error;

    async fn get(&self, key: &Self::Key) -> Result<Option<Self::Value>, Self::Error> {
        match self.state()? {
            DbState::Clean(db) => kv::Gettable::get(db, key).await,
            DbState::UnmerkleizedDurable(db) => kv::Gettable::get(db, key).await,
            DbState::Mutable(db) => kv::Gettable::get(db, key).await,
        }
    }
}

/// A batch of changes that owns a read lock on the shared db state.
///
/// Created by [Shared::start_batch]. Reads fall through to the underlying db when a key is not
/// in the diff. Consuming the batch (via [IntoIterator] or passing to [Writer::write_batch])
/// releases the read lock.
pub struct Batch<
    'a,
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    K: Array,
    V: CodecShared + Clone,
    U: Send + Sync,
> {
    guard: ReadGuard<'a, E, C, I, H, U>,
    diff: BTreeMap<K, Option<V>>,
}

impl<'a, E, K, V, U, C, I, H> kv::Gettable for Batch<'a, E, C, I, H, K, V::Value, U>
where
    E: Storage + Clock + Metrics,
    K: Array + Send + Sync,
    V: ValueEncoding,
    V::Value: Send + Sync,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V, U>: Codec,
    Db<E, C, I, H, U, Merkleized<H>, Durable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
    Db<E, C, I, H, U, Unmerkleized, Durable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
    Db<E, C, I, H, U, Unmerkleized, NonDurable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
{
    type Key = K;
    type Value = V::Value;
    type Error = Error;

    async fn get(&self, key: &K) -> Result<Option<V::Value>, Error> {
        if let Some(value) = self.diff.get(key) {
            return Ok(value.clone());
        }
        let state = self.guard.as_ref().ok_or(Error::Shutdown)?;
        match state {
            DbState::Clean(db) => kv::Gettable::get(db, key).await,
            DbState::UnmerkleizedDurable(db) => kv::Gettable::get(db, key).await,
            DbState::Mutable(db) => kv::Gettable::get(db, key).await,
        }
    }
}

impl<'a, E, K, V, U, C, I, H> kv::Updatable for Batch<'a, E, C, I, H, K, V::Value, U>
where
    E: Storage + Clock + Metrics,
    K: Array + Send + Sync,
    V: ValueEncoding,
    V::Value: Send + Sync,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V, U>: Codec,
    Db<E, C, I, H, U, Merkleized<H>, Durable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
    Db<E, C, I, H, U, Unmerkleized, Durable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
    Db<E, C, I, H, U, Unmerkleized, NonDurable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
{
    async fn update(&mut self, key: K, value: V::Value) -> Result<(), Error> {
        self.diff.insert(key, Some(value));
        Ok(())
    }
}

impl<'a, E, K, V, U, C, I, H> kv::Deletable for Batch<'a, E, C, I, H, K, V::Value, U>
where
    E: Storage + Clock + Metrics,
    K: Array + Send + Sync,
    V: ValueEncoding,
    V::Value: Send + Sync,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location> + Send + Sync + 'static,
    H: Hasher,
    Operation<K, V, U>: Codec,
    Db<E, C, I, H, U, Merkleized<H>, Durable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
    Db<E, C, I, H, U, Unmerkleized, Durable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
    Db<E, C, I, H, U, Unmerkleized, NonDurable>:
        kv::Gettable<Key = K, Value = V::Value, Error = Error>,
{
    async fn delete(&mut self, key: K) -> Result<bool, Error> {
        if let Some(entry) = self.diff.get_mut(&key) {
            match entry {
                Some(_) => {
                    *entry = None;
                    return Ok(true);
                }
                None => return Ok(false),
            }
        }
        if kv::Gettable::get(self, &key).await?.is_some() {
            self.diff.insert(key, None);
            return Ok(true);
        }
        Ok(false)
    }
}

impl<'a, E, C, I, H, K, V, U> IntoIterator for Batch<'a, E, C, I, H, K, V, U>
where
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    K: Array,
    V: CodecShared + Clone,
    U: Send + Sync,
{
    type Item = (K, Option<V>);
    type IntoIter = std::collections::btree_map::IntoIter<K, Option<V>>;

    fn into_iter(self) -> Self::IntoIter {
        self.diff.into_iter()
    }
}

impl<E, K, V, U, C, I, H> Db<E, C, I, H, U, Merkleized<H>, Durable>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Convert the database into a writer and a shared handle for concurrent use.
    pub fn into_concurrent(self, context: E, sync_policy: SyncPolicy) -> Handles<E, C, I, H, U> {
        let root = self.root();
        let leaves = self.log.mmr.leaves();
        let inner = Arc::new(SharedInner {
            db: UpgradableAsyncRwLock::new(Some(DbState::Clean(self))),
            merkleize_hasher: Mutex::new(StandardHasher::<H>::new()),
            last_root: Mutex::new((root, leaves)),
        });
        (
            Writer {
                inner: inner.clone(),
                context,
                sync_policy,
                last_full_sync: None,
            },
            Shared { inner },
        )
    }
}

impl<E, K, V, U, C, I, H> Writer<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Write a batch of operations to the database.
    pub async fn write_batch<Iter>(&self, iter: Iter) -> Result<(), Error>
    where
        Db<E, C, I, H, U, Unmerkleized, NonDurable>:
            kv::Batchable<Key = K, Value = V::Value, Error = Error> + Send,
        V::Value: Clone,
        Iter: IntoIterator<Item = (K, Option<V::Value>)> + Send,
        Iter::IntoIter: Send,
    {
        // Collect before acquiring the write lock so that any read guard held by the
        // iterator (e.g. from a WriterBatch / kv::Batch backed by a Reader) is released.
        let entries: Vec<_> = iter.into_iter().collect();
        let mut guard = self.inner.db.write().await;
        let state = guard.take().expect("state missing");
        let mut db = match state {
            DbState::Clean(db) => db.into_mutable(),
            DbState::UnmerkleizedDurable(db) => db.into_mutable(),
            DbState::Mutable(db) => db,
        };

        if let Err(err) = kv::Batchable::write_batch(&mut db, entries).await {
            panic!("shared write_batch failed; state is unrecoverable: {err}");
        }

        *guard = Some(DbState::Mutable(db));
        Ok(())
    }

    /// Commit the database, ensuring durability of all preceeding writes. Also syncs the database
    /// according to the [SyncPolicy].
    pub async fn commit(&mut self, metadata: Option<V::Value>) -> Result<Range<Location>, Error> {
        let mut write_guard = self.inner.db.write().await;
        let state = write_guard.take().expect("state missing");
        let mut db = match state {
            DbState::Clean(db) => db.into_mutable(),
            DbState::UnmerkleizedDurable(db) => db.into_mutable(),
            DbState::Mutable(db) => db,
        };
        let range = match db.commit_no_sync(metadata).await {
            Ok(range) => range,
            Err(err) => {
                panic!("shared commit failed after mutable update; state is unrecoverable: {err}")
            }
        };
        *write_guard = Some(DbState::Mutable(db));

        // Keep writer serialization while allowing concurrent readers during fsync.
        let upgradable_guard = write_guard.downgrade_to_upgradable();

        if let Err(err) = {
            let state = upgradable_guard.as_ref().expect("state missing");
            match state {
                DbState::Mutable(db) => db.log.commit().await.map_err(Error::from),
                _ => panic!("shared commit invariant violated: expected non-durable state"),
            }
        } {
            panic!("shared commit fsync failed; state is unrecoverable: {err}");
        }

        let now = self.context.current();
        if self.should_auto_full_sync(now) {
            // Pre-compute merkleization under upgradable read (allows concurrent kv reads).
            let state = upgradable_guard.as_ref().expect("state missing");
            let size = self.inner.mmr_size(state);
            if let Err(err) = self.inner.merkleize_to(state, size) {
                panic!("shared merkleize_to failed; state is unrecoverable: {err}");
            }

            let mut write_guard = upgradable_guard.upgrade().await;
            let state = write_guard.take().expect("state missing");
            *write_guard = Some(match state {
                DbState::Mutable(db) => {
                    let db = db.into_merkleized();
                    DbState::Clean(Db {
                        log: db.log,
                        inactivity_floor_loc: db.inactivity_floor_loc,
                        last_commit_loc: db.last_commit_loc,
                        snapshot: db.snapshot,
                        active_keys: db.active_keys,
                        durable_state: store::Durable,
                        _update: core::marker::PhantomData,
                    })
                }
                _ => panic!("shared commit invariant violated: expected non-durable state"),
            });

            let upgradable_guard = write_guard.downgrade_to_upgradable();
            if let Err(err) = {
                let state = upgradable_guard.as_ref().expect("state missing");
                match state {
                    DbState::Clean(db) => db.sync().await,
                    _ => panic!("shared commit invariant violated: expected merkleized durable"),
                }
            } {
                panic!("shared full sync after commit failed; state is unrecoverable: {err}");
            }

            let (root, leaves) = {
                let state = upgradable_guard.as_ref().expect("state missing");
                match state {
                    DbState::Clean(db) => (db.root(), db.log.mmr.leaves()),
                    _ => panic!("shared commit invariant violated: expected merkleized durable"),
                }
            };
            self.inner.set_last_root(root, leaves);

            let finished_at = self.context.current();
            self.last_full_sync = Some(finished_at);
        } else {
            let mut write_guard = upgradable_guard.upgrade().await;
            let state = write_guard.take().expect("state missing");
            *write_guard = Some(match state {
                DbState::Mutable(db) => DbState::UnmerkleizedDurable(Db {
                    log: db.log,
                    inactivity_floor_loc: db.inactivity_floor_loc,
                    last_commit_loc: db.last_commit_loc,
                    snapshot: db.snapshot,
                    active_keys: db.active_keys,
                    durable_state: store::Durable,
                    _update: core::marker::PhantomData,
                }),
                _ => panic!("shared commit invariant violated: expected non-durable state"),
            });
        }

        Ok(range)
    }

    /// Commit pending operations, merkleize (if needed), compute the root, and cache it.
    ///
    /// This is like [Self::commit] but additionally merkleizes the db after committing, computes
    /// the root on the resulting durable state, and caches it so that subsequent calls to
    /// [Shared::root] return the updated value.
    pub async fn commit_and_compute_root(
        &mut self,
        metadata: Option<V::Value>,
    ) -> Result<(H::Digest, Range<Location>), Error> {
        let range = self.commit(metadata).await?;

        // After commit(), the db is either Clean (full sync path) or UnmerkleizedDurable.
        let guard = self.inner.db.upgradable_read().await;
        let state = guard.as_ref().expect("state missing");

        // Fast path: already clean from commit()'s full sync.
        if let DbState::Clean(db) = state {
            let root = db.root();
            let leaves = db.log.mmr.leaves();
            self.inner.set_last_root(root, leaves);
            return Ok((root, range));
        }

        // Merkleize under upgradable read (allows concurrent KV reads).
        let size = self.inner.mmr_size(state);
        self.inner.merkleize_to(state, size)?;

        // Upgrade to write and transition to Clean.
        let mut write_guard = guard.upgrade().await;
        let state = write_guard.take().expect("state missing");
        let DbState::UnmerkleizedDurable(db) = state else {
            panic!("expected UnmerkleizedDurable after commit");
        };
        let db = db.into_merkleized();
        let root = db.root();
        let leaves = db.log.mmr.leaves();
        *write_guard = Some(DbState::Clean(db));

        self.inner.set_last_root(root, leaves);
        Ok((root, range))
    }

    /// Shut down the shared facade, returning the underlying database in a clean state.
    ///
    /// Any pending operations are committed and merkleized. After this call, outstanding
    /// [Shared] and [Reader] handles will return [Error::Shutdown].
    pub async fn into_db(
        mut self,
        metadata: Option<V::Value>,
    ) -> Result<Db<E, C, I, H, U, Merkleized<H>, Durable>, Error> {
        // Commit to reach a durable state, then merkleize to reach Clean.
        let _ = self.commit_and_compute_root(metadata).await?;

        // Take the db out of the shared state.
        let mut guard = self.inner.db.write().await;
        let state = guard.take().expect("state missing");
        match state {
            DbState::Clean(db) => Ok(db),
            _ => unreachable!("commit_and_compute_root leaves db in Clean state"),
        }
    }
}

impl<E, K, V, U, C, I, H> Shared<E, C, I, H, U>
where
    E: Storage + Clock + Metrics,
    K: Array,
    V: ValueEncoding,
    U: Update<K, V>,
    C: Mutable<Item = Operation<K, V, U>> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    Operation<K, V, U>: Codec,
{
    /// Return the cached root digest and leaf count from the last computed root.
    pub fn root(&self) -> (H::Digest, Location) {
        self.inner.last_root()
    }

    /// Start a new batch of changes, acquiring a read lock on the current db state.
    ///
    /// The read lock is held for the lifetime of the returned [Batch], so reads during batch
    /// construction resolve without per-call lock acquisition. Pass the batch to
    /// [Writer::write_batch] to apply the changes.
    pub async fn start_batch(&self) -> Batch<'_, E, C, I, H, K, V::Value, U> {
        Batch {
            guard: self.inner.db.read().await,
            diff: BTreeMap::new(),
        }
    }

    /// Generate a historical proof.
    ///
    /// Returns [Error::Unmerkleized] if `historical_size` is greater than the size represented
    /// by the last cached root.
    pub async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V, U>>), Error> {
        self.inner
            .historical_proof(historical_size, start_loc, max_ops)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::SyncPolicy;
    use crate::{
        kv::{Deletable as _, Gettable as _, Updatable as _},
        mmr::{Location, StandardHasher},
        qmdb::{
            any::{ordered::fixed::Db, test::fixed_db_config},
            verify_proof, Error,
        },
        translator::OneCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _};
    use commonware_utils::{sequence::U64, NZU64};

    type TestDb = Db<deterministic::Context, Digest, U64, Sha256, OneCap>;

    #[test_traced("WARN")]
    fn test_concurrent_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed_db_config::<OneCap>("concurrent_empty", &context);
            let db = TestDb::init(context.clone(), cfg).await.unwrap();
            let (writer, shared) = db.into_concurrent(context, SyncPolicy::Never);

            // Read a key via the reader, expect None.
            let reader = shared.reader().await;
            let result = reader.get(&Sha256::hash(b"missing")).await.unwrap();
            assert!(result.is_none());
            drop(reader);

            // Get the cached root and leaf count.
            let (root, leaves) = shared.root();

            // Generate a historical proof for the full range [0, leaves).
            let mut hasher = StandardHasher::<Sha256>::new();
            let (proof, ops) = shared
                .historical_proof(leaves, Location::new_unchecked(0), NZU64!(u64::MAX))
                .await
                .unwrap();
            assert!(verify_proof(
                &mut hasher,
                &proof,
                Location::new_unchecked(0),
                &ops,
                &root,
            ));

            // Requesting a proof beyond the root's leaves returns Unmerkleized.
            assert!(matches!(
                shared
                    .historical_proof(leaves + 1, Location::new_unchecked(0), NZU64!(u64::MAX),)
                    .await,
                Err(Error::Unmerkleized)
            ));

            // Shut down and destroy.
            let db = writer.into_db(None).await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_concurrent_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed_db_config::<OneCap>("concurrent_basic", &context);
            let db = TestDb::init(context.clone(), cfg).await.unwrap();
            let (mut writer, shared) = db.into_concurrent(context, SyncPolicy::Never);

            let key1 = Sha256::hash(b"key1");
            let key2 = Sha256::hash(b"key2");
            let key3 = Sha256::hash(b"key3");
            let val1 = U64::new(1);
            let val2 = U64::new(2);
            let val3 = U64::new(3);

            // Read keys (not yet present), then upgrade to a batch and write them.
            let reader = shared.reader().await;
            assert!(reader.get(&key1).await.unwrap().is_none());
            assert!(reader.get(&key2).await.unwrap().is_none());
            assert!(reader.get(&key3).await.unwrap().is_none());
            let mut batch = reader.into_batch();
            batch.update(key1, val1.clone()).await.unwrap();
            batch.update(key2, val2.clone()).await.unwrap();
            batch.update(key3, val3.clone()).await.unwrap();
            writer.write_batch(batch).await.unwrap();

            // Keys are now visible.
            let reader = shared.reader().await;
            assert_eq!(reader.get(&key1).await.unwrap().unwrap(), val1);
            assert_eq!(reader.get(&key2).await.unwrap().unwrap(), val2);
            assert_eq!(reader.get(&key3).await.unwrap().unwrap(), val3);
            drop(reader);

            // Root still reflects the initial state (leaves == 1 from the init commit).
            let (_, leaves) = shared.root();
            assert_eq!(*leaves, 1);

            // Commit (without computing root).
            writer.commit(None).await.unwrap();

            // Keys still readable after commit.
            let reader = shared.reader().await;
            assert_eq!(reader.get(&key1).await.unwrap().unwrap(), val1);
            assert_eq!(reader.get(&key2).await.unwrap().unwrap(), val2);
            assert_eq!(reader.get(&key3).await.unwrap().unwrap(), val3);
            drop(reader);

            // Root still at leaves == 1 since we didn't call commit_and_compute_root.
            let (_, leaves) = shared.root();
            assert_eq!(*leaves, 1);

            // Delete all three keys via batch, write, commit, and compute root.
            let mut batch = shared.start_batch().await;
            batch.delete(key1).await.unwrap();
            batch.delete(key2).await.unwrap();
            batch.delete(key3).await.unwrap();
            writer.write_batch(batch).await.unwrap();
            let (_, range) = writer.commit_and_compute_root(None).await.unwrap();

            // Keys are now deleted.
            let reader = shared.reader().await;
            assert!(reader.get(&key1).await.unwrap().is_none());
            assert!(reader.get(&key2).await.unwrap().is_none());
            assert!(reader.get(&key3).await.unwrap().is_none());
            drop(reader);

            // Root now reflects more leaves than the initial commit.
            let (_, leaves) = shared.root();
            assert!(leaves > Location::new_unchecked(1));
            assert_eq!(leaves, range.end);

            // Shut down and destroy.
            let db = writer.into_db(None).await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_concurrent_shutdown() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed_db_config::<OneCap>("concurrent_shutdown", &context);
            let db = TestDb::init(context.clone(), cfg).await.unwrap();
            let (writer, shared) = db.into_concurrent(context, SyncPolicy::Never);
            let shared2 = shared.clone();

            // Shut down.
            let db = writer.into_db(None).await.unwrap();

            // Reader get returns Shutdown.
            let reader = shared.reader().await;
            assert!(matches!(
                reader.get(&Sha256::hash(b"key")).await,
                Err(Error::Shutdown)
            ));
            drop(reader);

            // Historical proof returns Shutdown.
            assert!(matches!(
                shared
                    .historical_proof(
                        Location::new_unchecked(1),
                        Location::new_unchecked(0),
                        NZU64!(1),
                    )
                    .await,
                Err(Error::Shutdown)
            ));

            // Cloned handle also returns Shutdown.
            let reader = shared2.reader().await;
            assert!(matches!(
                reader.get(&Sha256::hash(b"key")).await,
                Err(Error::Shutdown)
            ));
            drop(reader);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_concurrent_sync_policy_always() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = fixed_db_config::<OneCap>("concurrent_sync_always", &context);
            let db = TestDb::init(context.clone(), cfg).await.unwrap();
            let (mut writer, shared) = db.into_concurrent(context, SyncPolicy::Always);

            assert_eq!(writer.sync_policy(), SyncPolicy::Always);

            let key = Sha256::hash(b"key");
            let val = U64::new(42);

            // Root before any writes.
            let (root_before, leaves_before) = shared.root();

            // Write a key and commit. With SyncPolicy::Always, commit performs a full
            // sync which merkleizes and transitions to Clean, updating the cached root.
            let mut batch = shared.start_batch().await;
            batch.update(key, val.clone()).await.unwrap();
            writer.write_batch(batch).await.unwrap();
            writer.commit(None).await.unwrap();

            // Root should have advanced (unlike SyncPolicy::Never).
            let (root_after, leaves_after) = shared.root();
            assert!(leaves_after > leaves_before);
            assert_ne!(root_before, root_after);

            // commit_and_compute_root hits the fast path (already Clean from full sync).
            let mut batch = shared.start_batch().await;
            batch
                .create(Sha256::hash(b"key2"), U64::new(99))
                .await
                .unwrap();
            writer.write_batch(batch).await.unwrap();
            let (root_ccr, range) = writer.commit_and_compute_root(None).await.unwrap();
            let (root_cached, leaves_cached) = shared.root();
            assert_eq!(root_ccr, root_cached);
            assert_eq!(leaves_cached, range.end);
            assert!(leaves_cached > leaves_after);

            // Shut down and destroy.
            let db = writer.into_db(None).await.unwrap();
            db.destroy().await.unwrap();
        });
    }
}

//! Shared facade for Any QMDB.
//!
//! This facade provides a single-writer, multi-reader access pattern over Any QMDB while preserving
//! typestate transitions internally.
//!
//! # Examples
//!
//! ```ignore
//! use commonware_storage::kv::{Batchable as _, Gettable as _};
//! use commonware_storage::mmr::Location;
//! use commonware_storage::qmdb::any::{SharedDb, SyncPolicy};
//! use std::num::NonZeroU64;
//! use std::time::{Duration, SystemTime};
//!
//! # async fn demo(mut db: impl Sized) -> Result<(), Box<dyn std::error::Error>> {
//! // Start from a clean Any Db and convert to shared handles.
//! let (writer, shared) = db.into_shared(
//!     SyncPolicy::Interval(Duration::from_secs(5)),
//!     SystemTime::now,
//! );
//!
//! // Read path.
//! let reader = shared.reader().await;
//! let _value = reader.get(&key).await?;
//!
//! // Write path.
//! writer.write_batch(vec![(key.clone(), Some(new_value))]).await?;
//! let _committed = writer.commit(None).await?;
//!
//! // Prover path (forces transition to merkleized state if needed).
//! let prover = shared.prover().await?;
//! let _root = prover.root()?;
//! let (_proof, _ops) = prover
//!     .proof(Location::new_unchecked(0), NonZeroU64::new(1).unwrap())
//!     .await?;
//! # Ok(())
//! # }
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
    mmr::{Location, Proof, StandardHasher},
    qmdb::{store, Durable, Error, Merkleized, NonDurable, Unmerkleized},
    Persistable,
};
use commonware_codec::{Codec, CodecShared};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::{
    sync::{AsyncRwLockReadGuard, UpgradableAsyncRwLock, UpgradableAsyncRwLockUpgradableReadGuard},
    Array,
};
use core::{num::NonZeroU64, ops::Range};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

/// Runtime state for a shared Any DB facade.
pub enum SharedStateDb<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    Clean(Db<E, C, I, H, U, Merkleized<H>, Durable>),
    MerkleizedNonDurable(Db<E, C, I, H, U, Merkleized<H>, NonDurable>),
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

pub(crate) struct SharedInner<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    pub(crate) db: UpgradableAsyncRwLock<Option<SharedStateDb<E, C, I, H, U>>>,
    sync_policy: SyncPolicy,
    merkleize_hasher: Mutex<StandardHasher<H>>,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    last_full_sync: Mutex<Option<SystemTime>>,
}

impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > SharedInner<E, C, I, H, U>
{
    fn sync_policy(&self) -> SyncPolicy {
        self.sync_policy
    }

    fn should_auto_full_sync(&self, now: SystemTime) -> bool {
        match self.sync_policy {
            SyncPolicy::Never => false,
            SyncPolicy::Always => true,
            SyncPolicy::Interval(interval) => {
                let last = self
                    .last_full_sync
                    .lock()
                    .expect("last_full_sync lock poisoned");
                match *last {
                    None => true,
                    Some(last) => now
                        .duration_since(last)
                        .map(|elapsed| elapsed >= interval)
                        .unwrap_or(true),
                }
            }
        }
    }

    fn mark_full_sync(&self, now: SystemTime) {
        *self
            .last_full_sync
            .lock()
            .expect("last_full_sync lock poisoned") = Some(now);
    }
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
    fn prepare_merkleized(&self, state: &SharedStateDb<E, C, I, H, U>) {
        let mut hasher = self
            .merkleize_hasher
            .lock()
            .expect("shared merkleization hasher lock poisoned");
        match state {
            SharedStateDb::UnmerkleizedDurable(db) => db.prepare_merkleized(&mut *hasher),
            SharedStateDb::Mutable(db) => db.prepare_merkleized(&mut *hasher),
            SharedStateDb::Clean(_) | SharedStateDb::MerkleizedNonDurable(_) => {}
        }
    }

    async fn prover(&self) -> Result<SharedProver<'_, E, C, I, H, U>, Error> {
        let mut guard = self.db.upgradable_read().await;
        if !matches!(
            guard.as_ref().expect("state missing"),
            SharedStateDb::Clean(_) | SharedStateDb::MerkleizedNonDurable(_)
        ) {
            self.prepare_merkleized(guard.as_ref().expect("state missing"));

            let mut write_guard = guard.upgrade().await;
            let state = write_guard.take().expect("state missing");
            *write_guard = Some(match state {
                SharedStateDb::Clean(db) => SharedStateDb::Clean(db),
                SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::MerkleizedNonDurable(db),
                SharedStateDb::UnmerkleizedDurable(db) => {
                    SharedStateDb::Clean(db.into_merkleized())
                }
                SharedStateDb::Mutable(db) => {
                    SharedStateDb::MerkleizedNonDurable(db.into_merkleized())
                }
            });
            guard = write_guard.downgrade_to_upgradable();
        }

        match guard.as_ref().expect("state missing") {
            SharedStateDb::Clean(_) | SharedStateDb::MerkleizedNonDurable(_) => {
                Ok(SharedProver { guard })
            }
            _ => panic!("shared prover invariant violated: expected merkleized state"),
        }
    }
}

pub struct SharedWriter<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    pub(crate) inner: Arc<SharedInner<E, C, I, H, U>>,
}

#[derive(Clone)]
pub struct Shared<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    pub(crate) inner: Arc<SharedInner<E, C, I, H, U>>,
}

pub struct SharedReader<
    'a,
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    guard: AsyncRwLockReadGuard<'a, Option<SharedStateDb<E, C, I, H, U>>>,
}

pub struct SharedProver<
    'a,
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    guard: UpgradableAsyncRwLockUpgradableReadGuard<'a, Option<SharedStateDb<E, C, I, H, U>>>,
}

fn into_shared_handles<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
>(
    state: SharedStateDb<E, C, I, H, U>,
    sync_policy: SyncPolicy,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
) -> (SharedWriter<E, C, I, H, U>, Shared<E, C, I, H, U>) {
    let inner = Arc::new(SharedInner {
        db: UpgradableAsyncRwLock::new(Some(state)),
        sync_policy,
        merkleize_hasher: Mutex::new(StandardHasher::<H>::new()),
        now,
        last_full_sync: Mutex::new(None),
    });
    (
        SharedWriter {
            inner: inner.clone(),
        },
        Shared { inner },
    )
}

impl<
        E: Storage + Clock + Metrics,
        C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > SharedWriter<E, C, I, H, U>
{
    pub fn read_handle(&self) -> Shared<E, C, I, H, U> {
        Shared {
            inner: self.inner.clone(),
        }
    }

    pub fn sync_policy(&self) -> SyncPolicy {
        self.inner.sync_policy()
    }

    pub async fn reader(&self) -> SharedReader<'_, E, C, I, H, U> {
        SharedReader {
            guard: self.inner.db.read().await,
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
    pub async fn reader(&self) -> SharedReader<'_, E, C, I, H, U> {
        SharedReader {
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
    > SharedReader<'a, E, C, I, H, U>
{
    pub(super) fn state(&self) -> &SharedStateDb<E, C, I, H, U> {
        self.guard.as_ref().expect("state missing")
    }
}

impl<'a, E, K, V, U, C, I, H> kv::Gettable for SharedReader<'a, E, C, I, H, U>
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
    Db<E, C, I, H, U, Merkleized<H>, NonDurable>:
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
        match self.state() {
            SharedStateDb::Clean(db) => kv::Gettable::get(db, key).await,
            SharedStateDb::MerkleizedNonDurable(db) => kv::Gettable::get(db, key).await,
            SharedStateDb::UnmerkleizedDurable(db) => kv::Gettable::get(db, key).await,
            SharedStateDb::Mutable(db) => kv::Gettable::get(db, key).await,
        }
    }
}

impl<E, K, V, U, C, I, H> kv::Gettable for SharedWriter<E, C, I, H, U>
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
    Db<E, C, I, H, U, Merkleized<H>, NonDurable>:
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
        self.reader().await.get(key).await
    }
}

impl<
        'a,
        E: Storage + Clock + Metrics,
        C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
        I: UnorderedIndex<Value = Location>,
        H: Hasher,
        U: Send + Sync,
    > SharedProver<'a, E, C, I, H, U>
{
    pub(super) fn state(&self) -> &SharedStateDb<E, C, I, H, U> {
        self.guard.as_ref().expect("state missing")
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
    pub fn into_shared(
        self,
        sync_policy: SyncPolicy,
        now: impl Fn() -> SystemTime + Send + Sync + 'static,
    ) -> (SharedWriter<E, C, I, H, U>, Shared<E, C, I, H, U>) {
        into_shared_handles(SharedStateDb::Clean(self), sync_policy, Arc::new(now))
    }
}

impl<E, K, V, U, C, I, H> SharedWriter<E, C, I, H, U>
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
    pub fn start_batch(&self) -> kv::Batch<'_, K, V::Value, Self>
    where
        Self: kv::Gettable<Key = K, Value = V::Value, Error = Error> + Sync,
    {
        kv::Batch::new(self)
    }

    pub async fn write_batch<Iter>(&self, iter: Iter) -> Result<(), Error>
    where
        Db<E, C, I, H, U, Unmerkleized, NonDurable>:
            kv::Batchable<Key = K, Value = V::Value, Error = Error> + Send,
        V::Value: Clone,
        Iter: IntoIterator<Item = (K, Option<V::Value>)> + Send,
        Iter::IntoIter: Send,
    {
        let mut guard = self.inner.db.write().await;
        let state = guard.take().expect("state missing");
        let mut db = match state {
            SharedStateDb::Clean(db) => db.into_mutable(),
            SharedStateDb::MerkleizedNonDurable(db) => db.into_mutable(),
            SharedStateDb::UnmerkleizedDurable(db) => db.into_mutable(),
            SharedStateDb::Mutable(db) => db,
        };

        if let Err(err) = kv::Batchable::write_batch(&mut db, iter).await {
            panic!("shared write_batch failed; state is unrecoverable: {err}");
        }

        *guard = Some(SharedStateDb::Mutable(db));
        Ok(())
    }

    pub async fn into_mutable(&self) -> Result<(), Error> {
        let guard = self.inner.db.upgradable_read().await;
        if matches!(
            guard.as_ref().expect("state missing"),
            SharedStateDb::Mutable(_)
        ) {
            return Ok(());
        }

        let mut guard = guard.upgrade().await;
        let state = guard.take().expect("state missing");
        *guard = Some(match state {
            SharedStateDb::Clean(db) => SharedStateDb::Mutable(db.into_mutable()),
            SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::Mutable(db.into_mutable()),
            SharedStateDb::UnmerkleizedDurable(db) => SharedStateDb::Mutable(db.into_mutable()),
            SharedStateDb::Mutable(db) => SharedStateDb::Mutable(db),
        });
        Ok(())
    }

    pub async fn into_merkleized(&self) -> Result<(), Error> {
        let guard = self.inner.db.upgradable_read().await;
        if matches!(
            guard.as_ref().expect("state missing"),
            SharedStateDb::Clean(_) | SharedStateDb::MerkleizedNonDurable(_)
        ) {
            return Ok(());
        }

        self.inner
            .prepare_merkleized(guard.as_ref().expect("state missing"));

        let mut guard = guard.upgrade().await;
        let state = guard.take().expect("state missing");
        *guard = Some(match state {
            SharedStateDb::Clean(db) => SharedStateDb::Clean(db),
            SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::MerkleizedNonDurable(db),
            SharedStateDb::UnmerkleizedDurable(db) => SharedStateDb::Clean(db.into_merkleized()),
            SharedStateDb::Mutable(db) => SharedStateDb::MerkleizedNonDurable(db.into_merkleized()),
        });
        Ok(())
    }

    /// Commit pending operations and fsync without holding an exclusive lock during fsync.
    ///
    /// This leaves the shared db in a durable state on success: `Mutable` normally, or `Clean`
    /// when policy-triggered full sync runs.
    pub async fn commit(&self, metadata: Option<V::Value>) -> Result<Range<Location>, Error> {
        let mut write_guard = self.inner.db.write().await;
        let state = write_guard.take().expect("state missing");
        let mut db = match state {
            SharedStateDb::Clean(db) => db.into_mutable(),
            SharedStateDb::MerkleizedNonDurable(db) => db.into_mutable(),
            SharedStateDb::UnmerkleizedDurable(db) => db.into_mutable(),
            SharedStateDb::Mutable(db) => db,
        };
        let range = match db.commit_no_sync(metadata).await {
            Ok(range) => range,
            Err(err) => {
                panic!("shared commit failed after mutable update; state is unrecoverable: {err}")
            }
        };
        *write_guard = Some(SharedStateDb::Mutable(db));

        // Keep writer serialization while allowing concurrent readers during fsync.
        let upgradable_guard = write_guard.downgrade_to_upgradable();

        if let Err(err) = {
            let state = upgradable_guard.as_ref().expect("state missing");
            match state {
                SharedStateDb::Mutable(db) => db.log.commit().await.map_err(Error::from),
                SharedStateDb::MerkleizedNonDurable(db) => {
                    db.log.commit().await.map_err(Error::from)
                }
                _ => panic!("shared commit invariant violated: expected non-durable state"),
            }
        } {
            panic!("shared commit fsync failed; state is unrecoverable: {err}");
        }

        let now = (self.inner.now)();
        if self.inner.should_auto_full_sync(now) {
            self.inner
                .prepare_merkleized(upgradable_guard.as_ref().expect("state missing"));

            let mut write_guard = upgradable_guard.upgrade().await;
            let state = write_guard.take().expect("state missing");
            *write_guard = Some(match state {
                SharedStateDb::Mutable(db) => {
                    let db = db.into_merkleized();
                    SharedStateDb::Clean(Db {
                        log: db.log,
                        inactivity_floor_loc: db.inactivity_floor_loc,
                        last_commit_loc: db.last_commit_loc,
                        snapshot: db.snapshot,
                        active_keys: db.active_keys,
                        durable_state: store::Durable,
                        _update: core::marker::PhantomData,
                    })
                }
                SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::Clean(Db {
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

            let upgradable_guard = write_guard.downgrade_to_upgradable();
            if let Err(err) = {
                let state = upgradable_guard.as_ref().expect("state missing");
                match state {
                    SharedStateDb::Clean(db) => db.sync().await,
                    _ => panic!("shared commit invariant violated: expected merkleized durable"),
                }
            } {
                panic!("shared full sync after commit failed; state is unrecoverable: {err}");
            }
            let finished_at = (self.inner.now)();
            self.inner.mark_full_sync(finished_at);
        } else {
            let mut write_guard = upgradable_guard.upgrade().await;
            let state = write_guard.take().expect("state missing");
            *write_guard = Some(match state {
                SharedStateDb::Mutable(db) => SharedStateDb::UnmerkleizedDurable(Db {
                    log: db.log,
                    inactivity_floor_loc: db.inactivity_floor_loc,
                    last_commit_loc: db.last_commit_loc,
                    snapshot: db.snapshot,
                    active_keys: db.active_keys,
                    durable_state: store::Durable,
                    _update: core::marker::PhantomData,
                }),
                SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::Clean(Db {
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

    pub async fn prover(&self) -> Result<SharedProver<'_, E, C, I, H, U>, Error> {
        self.inner.prover().await
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
    pub fn sync_policy(&self) -> SyncPolicy {
        self.inner.sync_policy()
    }

    pub async fn prover(&self) -> Result<SharedProver<'_, E, C, I, H, U>, Error> {
        self.inner.prover().await
    }
}

impl<'a, E, K, V, U, C, I, H> SharedProver<'a, E, C, I, H, U>
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
    pub fn root(&self) -> Result<H::Digest, Error> {
        let state = self.state();
        match state {
            SharedStateDb::Clean(db) => Ok(db.root()),
            SharedStateDb::MerkleizedNonDurable(db) => Ok(db.root()),
            _ => panic!("shared prover invariant violated: expected merkleized state"),
        }
    }

    pub async fn proof(
        &self,
        loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V, U>>), Error> {
        let state = self.state();
        match state {
            SharedStateDb::Clean(db) => db.proof(loc, max_ops).await,
            SharedStateDb::MerkleizedNonDurable(db) => db.proof(loc, max_ops).await,
            _ => panic!("shared prover invariant violated: expected merkleized state"),
        }
    }

    pub async fn historical_proof(
        &self,
        historical_size: Location,
        start_loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V, U>>), Error> {
        let state = self.state();
        match state {
            SharedStateDb::Clean(db) => {
                db.historical_proof(historical_size, start_loc, max_ops)
                    .await
            }
            SharedStateDb::MerkleizedNonDurable(db) => {
                db.historical_proof(historical_size, start_loc, max_ops)
                    .await
            }
            _ => panic!("shared prover invariant violated: expected merkleized state"),
        }
    }
}

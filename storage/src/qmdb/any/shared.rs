//! Shared facade for Any QMDB.

use super::{
    db::Db,
    operation::{update::Update, Operation},
    ValueEncoding,
};
use crate::{
    index::Unordered as UnorderedIndex,
    journal::{contiguous::Mutable, Error as JournalError},
    mmr::{Location, Proof},
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
    time::{Duration, Instant},
};

/// Runtime state for a shared Any DB facade.
pub enum SharedStateDb<
    E: Storage + Clock + Metrics,
    C: Mutable<Item: CodecShared> + Persistable<Error = JournalError>,
    I: UnorderedIndex<Value = Location>,
    H: Hasher,
    U: Send + Sync,
> {
    MerkleizedDurable(Db<E, C, I, H, U, Merkleized<H>, Durable>),
    MerkleizedNonDurable(Db<E, C, I, H, U, Merkleized<H>, NonDurable>),
    UnmerkleizedDurable(Db<E, C, I, H, U, Unmerkleized, Durable>),
    UnmerkleizedNonDurable(Db<E, C, I, H, U, Unmerkleized, NonDurable>),
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
    last_full_sync: Mutex<Option<Instant>>,
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

    fn should_auto_full_sync(&self, now: Instant) -> bool {
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
                    Some(last) => now.duration_since(last) >= interval,
                }
            }
        }
    }

    fn mark_full_sync(&self, now: Instant) {
        *self
            .last_full_sync
            .lock()
            .expect("last_full_sync lock poisoned") = Some(now);
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
) -> (SharedWriter<E, C, I, H, U>, Shared<E, C, I, H, U>) {
    let inner = Arc::new(SharedInner {
        db: UpgradableAsyncRwLock::new(Some(state)),
        sync_policy,
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
    pub(super) fn state(&self) -> Result<&SharedStateDb<E, C, I, H, U>, Error> {
        Ok(self
            .guard
            .as_ref()
            .expect("shared any db invariant violated: state missing"))
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
    pub(super) fn state(&self) -> Result<&SharedStateDb<E, C, I, H, U>, Error> {
        Ok(self
            .guard
            .as_ref()
            .expect("shared any db invariant violated: state missing"))
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
    ) -> (SharedWriter<E, C, I, H, U>, Shared<E, C, I, H, U>) {
        into_shared_handles(SharedStateDb::MerkleizedDurable(self), sync_policy)
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
    pub async fn into_mutable(&self) -> Result<(), Error> {
        let guard = self.inner.db.upgradable_read().await;
        if matches!(
            guard
                .as_ref()
                .expect("shared any db invariant violated: state missing"),
            SharedStateDb::UnmerkleizedNonDurable(_)
        ) {
            return Ok(());
        }

        let mut guard = guard.upgrade().await;
        let state = guard
            .take()
            .expect("shared any db invariant violated: state missing");
        *guard = Some(match state {
            SharedStateDb::MerkleizedDurable(db) => {
                SharedStateDb::UnmerkleizedNonDurable(db.into_mutable())
            }
            SharedStateDb::MerkleizedNonDurable(db) => {
                SharedStateDb::UnmerkleizedNonDurable(db.into_mutable())
            }
            SharedStateDb::UnmerkleizedDurable(db) => {
                SharedStateDb::UnmerkleizedNonDurable(db.into_mutable())
            }
            SharedStateDb::UnmerkleizedNonDurable(db) => SharedStateDb::UnmerkleizedNonDurable(db),
        });
        Ok(())
    }

    pub async fn into_merkleized(&self) -> Result<(), Error> {
        let guard = self.inner.db.upgradable_read().await;
        if matches!(
            guard
                .as_ref()
                .expect("shared any db invariant violated: state missing"),
            SharedStateDb::MerkleizedDurable(_) | SharedStateDb::MerkleizedNonDurable(_)
        ) {
            return Ok(());
        }

        match guard
            .as_ref()
            .expect("shared any db invariant violated: state missing")
        {
            SharedStateDb::UnmerkleizedDurable(db) => db.prepare_merkleized(),
            SharedStateDb::UnmerkleizedNonDurable(db) => db.prepare_merkleized(),
            _ => {}
        }

        let mut guard = guard.upgrade().await;
        let state = guard
            .take()
            .expect("shared any db invariant violated: state missing");
        *guard = Some(match state {
            SharedStateDb::MerkleizedDurable(db) => SharedStateDb::MerkleizedDurable(db),
            SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::MerkleizedNonDurable(db),
            SharedStateDb::UnmerkleizedDurable(db) => {
                SharedStateDb::MerkleizedDurable(db.into_merkleized())
            }
            SharedStateDb::UnmerkleizedNonDurable(db) => {
                SharedStateDb::MerkleizedNonDurable(db.into_merkleized())
            }
        });
        Ok(())
    }

    /// Commit pending operations and fsync without holding an exclusive lock during fsync.
    ///
    /// This leaves the shared db in `(Unmerkleized, Durable)` state on success.
    pub async fn commit(&self, metadata: Option<V::Value>) -> Result<Range<Location>, Error> {
        let mut write_guard = self.inner.db.write().await;
        let state = write_guard
            .take()
            .expect("shared any db invariant violated: state missing");
        let mut db = match state {
            SharedStateDb::MerkleizedDurable(db) => db.into_mutable(),
            SharedStateDb::MerkleizedNonDurable(db) => db.into_mutable(),
            SharedStateDb::UnmerkleizedDurable(db) => db.into_mutable(),
            SharedStateDb::UnmerkleizedNonDurable(db) => db,
        };
        let range = match db.commit_no_sync(metadata).await {
            Ok(range) => range,
            Err(err) => {
                panic!("shared commit failed after mutable update; state is unrecoverable: {err}")
            }
        };
        *write_guard = Some(SharedStateDb::UnmerkleizedNonDurable(db));

        // Keep writer serialization while allowing concurrent readers during fsync.
        let upgradable_guard = write_guard.downgrade_to_upgradable();

        if let Err(err) = {
            let state = upgradable_guard
                .as_ref()
                .expect("shared any db invariant violated: state missing");
            match state {
                SharedStateDb::UnmerkleizedNonDurable(db) => {
                    db.log.commit().await.map_err(Error::from)
                }
                SharedStateDb::MerkleizedNonDurable(db) => {
                    db.log.commit().await.map_err(Error::from)
                }
                _ => panic!("shared commit invariant violated: expected non-durable state"),
            }
        } {
            panic!("shared commit fsync failed; state is unrecoverable: {err}");
        }

        let mut write_guard = upgradable_guard.upgrade().await;
        let state = write_guard
            .take()
            .expect("shared any db invariant violated: state missing");
        *write_guard = Some(match state {
            SharedStateDb::UnmerkleizedNonDurable(db) => SharedStateDb::UnmerkleizedDurable(Db {
                log: db.log,
                inactivity_floor_loc: db.inactivity_floor_loc,
                last_commit_loc: db.last_commit_loc,
                snapshot: db.snapshot,
                active_keys: db.active_keys,
                durable_state: store::Durable,
                _update: core::marker::PhantomData,
            }),
            SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::MerkleizedDurable(Db {
                log: db.log,
                inactivity_floor_loc: db.inactivity_floor_loc,
                last_commit_loc: db.last_commit_loc,
                snapshot: db.snapshot,
                active_keys: db.active_keys,
                durable_state: store::Durable,
                _update: core::marker::PhantomData,
            }),
            other => other,
        });

        // Optionally force a full sync according to policy.
        let now = Instant::now();
        if self.inner.should_auto_full_sync(now) {
            let upgradable_guard = write_guard.downgrade_to_upgradable();
            match upgradable_guard
                .as_ref()
                .expect("shared any db invariant violated: state missing")
            {
                SharedStateDb::UnmerkleizedDurable(db) => db.prepare_merkleized(),
                SharedStateDb::MerkleizedDurable(_) => {}
                _ => panic!("shared commit invariant violated: expected durable state"),
            }

            let mut write_guard = upgradable_guard.upgrade().await;
            let state = write_guard
                .take()
                .expect("shared any db invariant violated: state missing");
            *write_guard = Some(match state {
                SharedStateDb::MerkleizedDurable(db) => SharedStateDb::MerkleizedDurable(db),
                SharedStateDb::UnmerkleizedDurable(db) => {
                    SharedStateDb::MerkleizedDurable(db.into_merkleized())
                }
                _ => panic!("shared commit invariant violated: expected durable state"),
            });

            let upgradable_guard = write_guard.downgrade_to_upgradable();
            if let Err(err) = {
                let state = upgradable_guard
                    .as_ref()
                    .expect("shared any db invariant violated: state missing");
                match state {
                    SharedStateDb::MerkleizedDurable(db) => db.sync().await,
                    _ => panic!("shared commit invariant violated: expected merkleized durable"),
                }
            } {
                panic!("shared full sync after commit failed; state is unrecoverable: {err}");
            }
            self.inner.mark_full_sync(now);
        }

        Ok(range)
    }

    pub async fn prover(&self) -> Result<SharedProver<'_, E, C, I, H, U>, Error> {
        let mut guard = self.inner.db.upgradable_read().await;
        if !matches!(
            guard
                .as_ref()
                .expect("shared any db invariant violated: state missing"),
            SharedStateDb::MerkleizedDurable(_) | SharedStateDb::MerkleizedNonDurable(_)
        ) {
            match guard
                .as_ref()
                .expect("shared any db invariant violated: state missing")
            {
                SharedStateDb::UnmerkleizedDurable(db) => db.prepare_merkleized(),
                SharedStateDb::UnmerkleizedNonDurable(db) => db.prepare_merkleized(),
                _ => {}
            }

            let mut write_guard = guard.upgrade().await;
            let state = write_guard
                .take()
                .expect("shared any db invariant violated: state missing");
            *write_guard = Some(match state {
                SharedStateDb::MerkleizedDurable(db) => SharedStateDb::MerkleizedDurable(db),
                SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::MerkleizedNonDurable(db),
                SharedStateDb::UnmerkleizedDurable(db) => {
                    SharedStateDb::MerkleizedDurable(db.into_merkleized())
                }
                SharedStateDb::UnmerkleizedNonDurable(db) => {
                    SharedStateDb::MerkleizedNonDurable(db.into_merkleized())
                }
            });
            guard = write_guard.downgrade_to_upgradable();
        }

        match guard
            .as_ref()
            .expect("shared any db invariant violated: state missing")
        {
            SharedStateDb::MerkleizedDurable(_) | SharedStateDb::MerkleizedNonDurable(_) => {
                Ok(SharedProver { guard })
            }
            _ => panic!("shared prover invariant violated: expected merkleized state"),
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
    pub fn sync_policy(&self) -> SyncPolicy {
        self.inner.sync_policy()
    }

    pub async fn prover(&self) -> Result<SharedProver<'_, E, C, I, H, U>, Error> {
        let mut guard = self.inner.db.upgradable_read().await;
        if !matches!(
            guard
                .as_ref()
                .expect("shared any db invariant violated: state missing"),
            SharedStateDb::MerkleizedDurable(_) | SharedStateDb::MerkleizedNonDurable(_)
        ) {
            match guard
                .as_ref()
                .expect("shared any db invariant violated: state missing")
            {
                SharedStateDb::UnmerkleizedDurable(db) => db.prepare_merkleized(),
                SharedStateDb::UnmerkleizedNonDurable(db) => db.prepare_merkleized(),
                _ => {}
            }

            let mut write_guard = guard.upgrade().await;
            let state = write_guard
                .take()
                .expect("shared any db invariant violated: state missing");
            *write_guard = Some(match state {
                SharedStateDb::MerkleizedDurable(db) => SharedStateDb::MerkleizedDurable(db),
                SharedStateDb::MerkleizedNonDurable(db) => SharedStateDb::MerkleizedNonDurable(db),
                SharedStateDb::UnmerkleizedDurable(db) => {
                    SharedStateDb::MerkleizedDurable(db.into_merkleized())
                }
                SharedStateDb::UnmerkleizedNonDurable(db) => {
                    SharedStateDb::MerkleizedNonDurable(db.into_merkleized())
                }
            });
            guard = write_guard.downgrade_to_upgradable();
        }

        match guard
            .as_ref()
            .expect("shared any db invariant violated: state missing")
        {
            SharedStateDb::MerkleizedDurable(_) | SharedStateDb::MerkleizedNonDurable(_) => {
                Ok(SharedProver { guard })
            }
            _ => panic!("shared prover invariant violated: expected merkleized state"),
        }
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
        let state = self.state()?;
        match state {
            SharedStateDb::MerkleizedDurable(db) => Ok(db.root()),
            SharedStateDb::MerkleizedNonDurable(db) => Ok(db.root()),
            _ => panic!("shared prover invariant violated: expected merkleized state"),
        }
    }

    pub async fn proof(
        &self,
        loc: Location,
        max_ops: NonZeroU64,
    ) -> Result<(Proof<H::Digest>, Vec<Operation<K, V, U>>), Error> {
        let state = self.state()?;
        match state {
            SharedStateDb::MerkleizedDurable(db) => db.proof(loc, max_ops).await,
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
        let state = self.state()?;
        match state {
            SharedStateDb::MerkleizedDurable(db) => {
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

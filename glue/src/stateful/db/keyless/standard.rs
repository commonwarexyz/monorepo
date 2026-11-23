//! [`Qmdb`] implementation for QMDB [`keyless`](commonware_storage::qmdb::keyless) databases.
//!
//! Keyless databases are append-only. Operations are addressed by [`Location`] rather than by
//! key. Batch reads consult the database at the time of the read for locations their batch chain
//! does not hold, and return a `StaleRead` error once the database is at no state of that chain.

use crate::stateful::db::qmdb::{Merkleized, Qmdb, Unmerkleized};
use commonware_codec::EncodeShared;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    journal::contiguous::Mutable,
    merkle::{Family, Location},
    qmdb::{
        Error,
        keyless::{
            Db, Operation,
            batch::{MerkleizedBatch, UnmerkleizedBatch},
        },
        sync,
        value::ValueEncoding,
    },
};
use std::sync::Arc;

impl<F, E, V, C, H, S> Unmerkleized<Db<F, E, V, C, H, S>>
where
    Db<F, E, V, C, H, S>: Qmdb<Batch = UnmerkleizedBatch<F, H, V, S>>,
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Sets the metadata committed by [`merkleize`](crate::stateful::db::Unmerkleized::merkleize).
    /// `None` clears it.
    pub fn with_metadata(mut self, metadata: impl Into<Option<V::Value>>) -> Self {
        self.batch = self.batch.with_metadata(metadata);
        self
    }

    /// Sets the inactivity floor committed by
    /// [`merkleize`](crate::stateful::db::Unmerkleized::merkleize) (inherited from the database or
    /// parent batch when unset).
    pub fn with_inactivity_floor(mut self, floor: Location<F>) -> Self {
        self.batch = self.batch.with_inactivity_floor(floor);
        self
    }

    /// Reads a value by location, falling back to applied state.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::StaleRead`] if the database is at no state of this batch's chain.
    /// - Returns [`Error::LocationOutOfBounds`] if `location` is at or past the batch's end.
    /// - Returns [`Error::BelowInactivityFloor`] if `location` is below the inactivity floor
    ///   this batch builds on.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(location, &db).await
    }

    /// Reads multiple values by location, falling back to applied state.
    ///
    /// Locations must be strictly increasing.
    /// Returns results in the same order as `locations`.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::StaleRead`] if the database is at no state of this batch's chain.
    /// - Returns [`Error::LocationOutOfOrder`] if the locations are not strictly increasing.
    /// - Returns [`Error::LocationOutOfBounds`] if any location is at or past the batch's end.
    /// - Returns [`Error::BelowInactivityFloor`] if any location is below the inactivity floor
    ///   this batch builds on.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(locations, &db).await
    }

    /// Appends `value` to the batch.
    pub fn append(mut self, value: V::Value) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}

impl<F, E, V, C, H, S> Merkleized<Db<F, E, V, C, H, S>>
where
    Db<F, E, V, C, H, S>: Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, V, S>>,
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Reads a value by location, falling back to applied state.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::StaleRead`] if the database is at no state of this batch's chain.
    /// - Returns [`Error::LocationOutOfBounds`] if `location` is at or past the batch's end.
    /// - Returns [`Error::BelowInactivityFloor`] if `location` is below this batch's
    ///   inactivity floor.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(location, &db).await
    }

    /// Reads multiple values by location, falling back to applied state.
    ///
    /// Locations must be strictly increasing.
    /// Returns results in the same order as `locations`.
    ///
    /// # Errors
    ///
    /// - Returns [`Error::StaleRead`] if the database is at no state of this batch's chain.
    /// - Returns [`Error::LocationOutOfOrder`] if the locations are not strictly increasing.
    /// - Returns [`Error::LocationOutOfBounds`] if any location is at or past the batch's end.
    /// - Returns [`Error::BelowInactivityFloor`] if any location is below this batch's
    ///   inactivity floor.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(locations, &db).await
    }
}

impl<F, E, V, C, H, S> Qmdb for Db<F, E, V, C, H, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    type Batch = UnmerkleizedBatch<F, H, V, S>;
    type MerkleizedBatch = MerkleizedBatch<F, H::Digest, V, S>;

    fn new_batch(&self) -> Self::Batch {
        self.new_batch()
    }

    fn new_child(parent: &Arc<Self::MerkleizedBatch>) -> Self::Batch {
        parent.new_batch::<H>()
    }

    async fn merkleize(&self, batch: Self::Batch) -> Result<Arc<Self::MerkleizedBatch>, Error<F>> {
        batch.merkleize(self).await
    }

    async fn apply_batch(self, batch: Arc<Self::MerkleizedBatch>) -> Result<Self, Error<F>> {
        self.apply_batch(batch).await
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::{ManagedDb, Merkleized as MerkleizedTrait, Shared, StateSyncDb};
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, buffer::paged::CacheRef, deterministic,
    };
    use commonware_storage::{
        journal::{
            authenticated::Config as MerkleConfig, contiguous::fixed::Config as FixedJournalConfig,
        },
        mmr,
        qmdb::{
            keyless::{self as storage_keyless, fixed, variable},
            sync::Target as AnySyncTarget,
        },
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, non_empty_range, sequence::U64};
    use std::num::{NonZeroU16, NonZeroUsize};

    type FixedDb = fixed::Db<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;
    type VariableDb =
        variable::Db<mmr::Family, deterministic::Context, Vec<u8>, Sha256, Sequential>;

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn fixed_config(suffix: &str) -> fixed::Config<Sequential> {
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
        storage_keyless::Config {
            merkle: MerkleConfig {
                partition: format!("metadata-{suffix}"),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                resident_height: Default::default(),
            },
            log: FixedJournalConfig {
                partition: format!("log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            init_concurrency: NZUsize!(2),
        }
    }

    fn assert_managed_db<T: ManagedDb<deterministic::Context>>() {}

    fn assert_state_sync_db<T, R>()
    where
        T: StateSyncDb<deterministic::Context, R>,
    {
    }

    #[test]
    fn unset_inactivity_floor_inherits_parent_floor() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-keyless-inherit-parent-floor");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let parent = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1));
            let parent = crate::stateful::db::Unmerkleized::merkleize(parent)
                .await
                .unwrap();
            let child = MerkleizedTrait::new_batch(&parent).append(U64::new(8));
            let child = crate::stateful::db::Unmerkleized::merkleize(child)
                .await
                .unwrap();
            assert_eq!(child.bounds().inactivity_floor, mmr::Location::new(1));
        });
    }

    #[test]
    fn unset_inactivity_floor_inherits_applied_floor() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-keyless-inherit-applied-floor");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let first = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1));
            let first = crate::stateful::db::Unmerkleized::merkleize(first)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                let database = <FixedDb as ManagedDb<_>>::apply(database, first)
                    .await
                    .unwrap();
                slot.put(database);
            }

            let next = db.new_batch_for_test::<_>().await.append(U64::new(9));
            let next = crate::stateful::db::Unmerkleized::merkleize(next)
                .await
                .unwrap();
            assert_eq!(next.bounds().inactivity_floor, mmr::Location::new(1));
            let (slot, database) = db.write().await;
            let database = <FixedDb as ManagedDb<_>>::apply(database, next)
                .await
                .unwrap();
            assert_eq!(database.inactivity_floor(), mmr::Location::new(1));
            slot.put(database);
        });
    }

    #[test]
    fn keyless_trait_impls_compile() {
        assert_managed_db::<FixedDb>();
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<FixedDb, Arc<FixedDb>>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
    }

    #[test]
    fn managed_db_apply_and_finalize_persists_fixed_keyless_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-keyless-managed-db");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(U64::new(9));
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            {
                let (slot, database) = db.write().await;
                let database = <FixedDb as ManagedDb<_>>::apply(database, merkleized)
                    .await
                    .unwrap();
                let (database, sync) = <FixedDb as ManagedDb<_>>::finalize(database).await.unwrap();
                slot.put(database);
                sync.await.expect("database sync failed");
            }

            let guard = db.read().await;
            assert_eq!(
                guard.get(mmr::Location::new(1)).await.unwrap(),
                Some(U64::new(7))
            );
            assert_eq!(guard.get_metadata().await.unwrap(), Some(U64::new(9)));

            let target = <FixedDb as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.root, guard.root());
            assert_eq!(target.range.start(), mmr::Location::new(1));
            assert_eq!(target.range.end(), mmr::Location::new(3));
        });
    }

    #[test]
    fn managed_db_matches_sync_target_rejects_wrong_replay_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("stateful-keyless-matches-sync-target");
            let db = FixedDb::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(U64::new(9));
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            let valid_target = AnySyncTarget {
                root: merkleized.root(),
                range: non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size
                ),
            };
            assert!(<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let wrong_start = AnySyncTarget {
                root: merkleized.root(),
                range: non_empty_range!(mmr::Location::new(0), merkleized.bounds().tip.size),
            };
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_start,
            ));

            let wrong_end = AnySyncTarget {
                root: merkleized.root(),
                range: non_empty_range!(
                    merkleized.bounds().inactivity_floor,
                    merkleized.bounds().tip.size - 1
                ),
            };
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_end,
            ));
        });
    }
}

//! [`Qmdb`] implementations for journaled
//! [`qmdb::keyless`](commonware_storage::qmdb::keyless) databases.

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
        any::value::ValueEncoding,
        keyless::{
            Keyless, Operation,
            batch::{MerkleizedBatch, UnmerkleizedBatch},
        },
        sync,
    },
};
use std::sync::Arc;

impl<F, E, V, C, H, S> Unmerkleized<Keyless<F, E, V, C, H, S>>
where
    Keyless<F, E, V, C, H, S>: Qmdb<Batch = UnmerkleizedBatch<F, H, V, S>>,
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Read a value by location, falling back to applied state.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(location, &db).await
    }

    /// Read multiple values by location, falling back to applied state.
    ///
    /// Locations must be sorted in ascending order. Returns results in the same
    /// order as the input locations.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(locations, &db).await
    }

    /// Append a value to the speculative batch.
    pub fn append(mut self, value: V::Value) -> Self {
        self.batch = self.batch.append(value);
        self
    }
}

impl<F, E, V, C, H, S> Merkleized<Keyless<F, E, V, C, H, S>>
where
    Keyless<F, E, V, C, H, S>: Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, V, S>>,
    F: Family,
    E: Context,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, V>>,
    H: Hasher,
    S: Strategy,
    Operation<F, V>: EncodeShared,
{
    /// Read a value by location, falling back to applied state.
    pub async fn get(&self, location: Location<F>) -> Result<Option<V::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(location, &db).await
    }

    /// Read multiple values by location, falling back to applied state.
    ///
    /// Locations must be sorted in ascending order. Returns results in the same
    /// order as the input locations.
    pub async fn get_many(
        &self,
        locations: &[Location<F>],
    ) -> Result<Vec<Option<V::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(locations, &db).await
    }
}

impl<F, E, V, C, H, S> Qmdb for Keyless<F, E, V, C, H, S>
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
    type Metadata = V::Value;
    type Floor = Option<Location<F>>;

    fn new_batch(&self) -> Self::Batch {
        self.new_batch()
    }

    async fn merkleize(
        &self,
        batch: Self::Batch,
        metadata: Option<Self::Metadata>,
        floor: Option<Location<F>>,
    ) -> Result<Arc<Self::MerkleizedBatch>, Error<F>> {
        let floor = floor.unwrap_or_default();
        Ok(batch.merkleize(self, metadata, floor).await)
    }

    async fn apply_batch(self, batch: Arc<Self::MerkleizedBatch>) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch).await?;
        Ok(db)
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &sync::Target<F, H::Digest>) -> Result<Self, Error<F>> {
        self.prune(target.range.start()).await
    }

    async fn rewind(self, size: Location<F>) -> Result<Self, Error<F>> {
        self.rewind(size).await?.sync().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::{
        ManagedDb, Shared, Unmerkleized as _, tests::configs::keyless::fixed_config,
    };
    use commonware_cryptography::Sha256;
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::{journal::Error as JournalError, mmr, qmdb::keyless::fixed};
    use commonware_utils::sequence::U64;

    type FixedDb = fixed::Db<mmr::Family, deterministic::Context, U64, Sha256, Sequential>;

    #[test]
    fn managed_db_apply_and_finalize_persists_fixed_keyless_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "managed-db");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(U64::new(9));
            let merkleized = batch.merkleize().await.unwrap();

            db.apply_and_finalize_for_test::<_>(merkleized).await;

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
    fn managed_db_prune_drops_history_below_the_target_floor() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "prune");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);

            // Eight appends at locations 1..=8 and a floor of 8: pruning to the floor drops the
            // whole first blob (seven items), which holds the initial commit.
            let mut batch = db.new_batch_for_test::<_>().await;
            for i in 1..=8u64 {
                batch = batch.append(U64::new(i));
            }
            let merkleized = batch
                .with_inactivity_floor(mmr::Location::new(8))
                .merkleize()
                .await
                .unwrap();
            let target = merkleized.target();
            db.apply_and_finalize_for_test::<_>(merkleized).await;

            let (slot, database) = db.write().await;
            let database = <FixedDb as ManagedDb<_>>::prune(database, &target)
                .await
                .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&database), target);
            slot.put(database);

            let guard = db.read().await;
            assert!(matches!(
                guard.get(mmr::Location::new(0)).await,
                Err(Error::Journal(JournalError::ItemPruned(0)))
            ));
            assert_eq!(
                guard.get(mmr::Location::new(8)).await.unwrap(),
                Some(U64::new(8))
            );
        });
    }

    #[test]
    fn merkleize_rejects_floor_at_batch_size() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "floor-at-size");
            let db = FixedDb::init(context.child("db"), config).await.unwrap();
            let db = Shared::new("test", db);

            // The commit lands at location 2, so a floor of 3 is past it and `apply` would
            // reject the batch. Merkleizing reports that instead of producing a batch without
            // a sync target.
            let Err(err) = db
                .new_batch_for_test::<_>()
                .await
                .append(U64::new(7))
                .with_inactivity_floor(mmr::Location::new(3))
                .merkleize()
                .await
            else {
                panic!("expected merkleize to reject the floor");
            };
            assert!(matches!(
                err,
                Error::FloorBeyondSize(floor, commit)
                    if floor == mmr::Location::new(3) && commit == mmr::Location::new(2)
            ));
        });
    }
}

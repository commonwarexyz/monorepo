//! [`Qmdb`] implementations for compact
//! [`qmdb::immutable`](commonware_storage::qmdb::immutable) databases.

use crate::stateful::db::qmdb::{Qmdb, Unmerkleized};
use commonware_codec::{EncodeShared, Read as CodecRead};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::value::ValueEncoding,
        immutable::{CompactDb, CompactMerkleizedBatch, CompactUnmerkleizedBatch, Operation},
        operation::Key,
        sync,
    },
};
use std::sync::Arc;

impl<F, E, K, V, H, C, S> Unmerkleized<CompactDb<F, E, K, V, H, C, S>>
where
    CompactDb<F, E, K, V, H, C, S>: Qmdb<Batch = CompactUnmerkleizedBatch<F, H, K, V, S>>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    /// Set `key` to `value` in the speculative batch.
    pub fn set(mut self, key: K, value: V::Value) -> Self {
        self.batch = self.batch.set(key, value);
        self
    }
}

impl<F, E, K, V, H, C, S> Qmdb for CompactDb<F, E, K, V, H, C, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    H: Hasher,
    Operation<F, K, V>: EncodeShared + CodecRead<Cfg = C>,
    C: Clone + Send + Sync + 'static,
    S: Strategy,
{
    type Batch = CompactUnmerkleizedBatch<F, H, K, V, S>;
    type MerkleizedBatch = CompactMerkleizedBatch<F, H::Digest, K, V, S>;
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

    async fn apply(self, batch: Arc<Self::MerkleizedBatch>) -> Result<Self, Error<F>> {
        let (db, _) = self.apply_batch(batch).await?;
        Ok(db)
    }

    async fn start_sync(self) -> Result<(Self, Handle<()>), Error<F>> {
        self.start_sync().await
    }

    async fn prune(self, target: &sync::Target<F, H::Digest>) -> Result<Self, Error<F>> {
        self.prune(target.range.end()).await
    }

    async fn rewind(self, size: Location<F>) -> Result<Self, Error<F>> {
        self.rewind(size).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::{
        ManagedDb, Shared, StateSyncDb, SyncSession, Unmerkleized as _,
        tests::configs::{immutable::compact_fixed_config, sync_config},
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::{merkle::mmr, qmdb::immutable::fixed};
    use commonware_utils::{NZU64, channel::mpsc};

    type CompactFixedDb =
        fixed::CompactDb<mmr::Family, deterministic::Context, Digest, Digest, Sha256, Sequential>;

    #[test]
    fn managed_db_apply_and_finalize_persists_fixed_immutable_unjournaled_batches() {
        deterministic::Runner::default().start(|context| async move {
            let config = compact_fixed_config(&context, "managed-db");
            let db = CompactFixedDb::init(context.child("db"), config)
                .await
                .unwrap();
            let db = Shared::new("test", db);
            let key = Sha256::hash(&[&[1]]);
            let value = Sha256::hash(&[&[2]]);
            let metadata = Sha256::hash(&[&[3]]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .set(key, value)
                .with_inactivity_floor(mmr::Location::new(1))
                .with_metadata(metadata);
            let merkleized = batch.merkleize().await.unwrap();
            let expected_root = merkleized.root();

            db.apply_and_finalize_for_test::<_>(merkleized).await;

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get_metadata(), Some(metadata));

            let target = <CompactFixedDb as ManagedDb<_>>::sync_target(&guard);
            assert_eq!(target.root, guard.root());
            assert_eq!(target.range.end(), mmr::Location::new(3));
        });
    }

    #[test]
    fn state_sync_fetches_fixed_immutable_compact_state() {
        deterministic::Runner::default().start(|context| async move {
            let source = CompactFixedDb::init(
                context.child("source"),
                compact_fixed_config(&context, "source"),
            )
            .await
            .unwrap();
            let metadata = Sha256::hash(&[&[3]]);
            let floor = source.inactivity_floor_loc();
            let batch = source
                .new_batch()
                .set(Sha256::hash(&[&[1]]), Sha256::hash(&[&[2]]))
                .merkleize(&source, Some(metadata), floor)
                .await;
            let (source, _) = source.apply_batch(batch).await.unwrap();
            let source = source.sync().await.unwrap();

            let target = source.target();
            let (_update_tx, update_rx) = mpsc::channel(1);
            let synced = <CompactFixedDb as StateSyncDb<_, Arc<CompactFixedDb>>>::sync_db(
                context.child("target"),
                compact_fixed_config(&context, "target"),
                Arc::new(source),
                SyncSession {
                    target: target.clone(),
                    tip_updates: update_rx,
                    finish: None,
                    reached_target: None,
                },
                sync_config(),
            )
            .await
            .unwrap();

            assert_eq!(synced.target(), target);
            assert_eq!(synced.get_metadata(), Some(metadata));
        });
    }

    #[test]
    fn managed_db_prune_bounds_fixed_immutable_unjournaled_rewind_history() {
        deterministic::Runner::default().start(|context| async move {
            // One witness entry per section so pruning takes effect at entry granularity.
            let mut config = compact_fixed_config(&context, "prune");
            config.witness.items_per_section = NZU64!(1);
            let mut db = CompactFixedDb::init(context.child("db"), config)
                .await
                .unwrap();

            // Commit three ranges, recording each target.
            let mut targets = Vec::new();
            for i in [1u8, 3, 5] {
                let floor = db.inactivity_floor_loc();
                let batch = db
                    .new_batch()
                    .set(Sha256::hash(&[&[i]]), Sha256::hash(&[&[i + 1]]))
                    .merkleize(&db, Some(Sha256::hash(&[&[i * 11]])), floor)
                    .await;
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.sync().await.unwrap();
                targets.push(<CompactFixedDb as ManagedDb<_>>::sync_target(&db));
            }

            assert_ne!(targets[0], targets[1]);

            // Prune to the second target: the first is no longer a rewind target, but the
            // second still is.
            let db = <CompactFixedDb as ManagedDb<_>>::prune(db, &targets[1])
                .await
                .unwrap();
            let db = <CompactFixedDb as ManagedDb<_>>::rewind_to_target(db, targets[1].clone())
                .await
                .unwrap();
            assert_eq!(
                <CompactFixedDb as ManagedDb<_>>::sync_target(&db),
                targets[1]
            );
            assert_eq!(db.get_metadata(), Some(Sha256::hash(&[&[33]])));
            assert!(matches!(
                db.rewind(targets[0].range.end()).await,
                Err(Error::Merkle(
                    commonware_storage::merkle::Error::RewindBeyondHistory
                ))
            ));
        });
    }
}

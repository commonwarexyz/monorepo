//! [`Qmdb`] implementations for [`qmdb::any`](commonware_storage::qmdb::any).

use crate::stateful::db::{
    Shared,
    qmdb::{Merkleized, Qmdb, Unmerkleized},
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Handle;
use commonware_storage::{
    Context,
    index::Unordered as UnorderedIndex,
    journal::contiguous::{Contiguous, Mutable},
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::{
            batch::{MerkleizedBatch, Staged, UnmerkleizedBatch},
            db::Db,
            operation::{Operation, Update},
            unordered,
            value::ValueEncoding,
        },
        operation::Key,
        sync,
    },
};
use std::{ops::Range, sync::Arc};

/// Staged batch returned by `stage`. Holds a QMDB [`Staged`] plus the database handle it
/// reads through.
///
/// Like any speculative batch, this handle is a branch-scoped view of the shared database: it
/// stays valid only while every batch finalized on the database is an ancestor of this batch
/// (see [`MerkleizedBatch`]'s branch-validity contract).
pub struct AnyStaged<F, E, C, I, H, U, const N: usize, S>
where
    F: Family,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    staged: Staged<F, H, U, S>,
    db: Shared<Db<F, E, C, I, H, U, N, S>>,
    metadata: Option<U::Value>,
}

impl<F, E, C, I, H, U, const N: usize, S> Unmerkleized<Db<F, E, C, I, H, U, N, S>>
where
    Db<F, E, C, I, H, U, N, S>:
        Qmdb<Batch = UnmerkleizedBatch<F, H, U, S>, Metadata = U::Value, Floor = ()>,
    F: Family,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&U::Key]) -> Result<Vec<Option<U::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &db).await
    }

    /// Read multiple values and return a staged batch for the same keys.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn stage(
        self,
        keys: &[&U::Key],
    ) -> Result<(Vec<Option<U::Value>>, AnyStaged<F, E, C, I, H, U, N, S>), Error<F>> {
        let Self {
            batch,
            db,
            metadata,
            floor: (),
        } = self;
        let (values, staged) = {
            let guard = db.read().await;
            batch.stage(keys, &guard).await?
        };
        Ok((
            values,
            AnyStaged {
                staged,
                db,
                metadata,
            },
        ))
    }

    /// Record a mutation. `Some(value)` for upsert, `None` for delete.
    pub fn write(mut self, key: U::Key, value: Option<U::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

impl<F, E, C, I, H, U, const N: usize, S> AnyStaged<F, E, C, I, H, U, N, S>
where
    F: Family,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Set commit metadata included in the [`merkleize`](Self::merkleize) call, replacing any
    /// metadata set before staging.
    pub fn with_metadata(mut self, metadata: U::Value) -> Self {
        self.metadata = Some(metadata);
        self
    }

    /// Expand this staged batch with more reads.
    ///
    /// Existing read indices remain stable. Newly read keys are appended to the staged read set and
    /// assigned the returned range. Expansion does not deduplicate against previously staged keys
    /// and does not observe values computed for earlier staged slots but not yet passed to
    /// `merkleize`.
    pub async fn expand(
        self,
        keys: &[&U::Key],
    ) -> Result<(Range<usize>, Vec<Option<U::Value>>, Self), Error<F>> {
        let Self {
            staged,
            db,
            metadata,
        } = self;
        let (range, values, staged) = {
            let guard = db.read().await;
            staged.expand(keys, &guard).await?
        };
        Ok((
            range,
            values,
            Self {
                staged,
                db,
                metadata,
            },
        ))
    }
}

impl<F, E, C, I, H, K, V, const N: usize, S> AnyStaged<F, E, C, I, H, unordered::Update<K, V>, N, S>
where
    Db<F, E, C, I, H, unordered::Update<K, V>, N, S>: Qmdb<
            Family = F,
            Digest = H::Digest,
            MerkleizedBatch = MerkleizedBatch<F, H::Digest, unordered::Update<K, V>, S>,
        >,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](AnyStaged::expand) before
    /// this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](AnyStaged::expand) ranges. Metadata
    /// set via [`with_metadata`](AnyStaged::with_metadata) (or before staging) is committed with the
    /// returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
    ) -> Result<Merkleized<Db<F, E, C, I, H, unordered::Update<K, V>, N, S>>, Error<F>> {
        let Self {
            staged,
            db,
            metadata,
        } = self;
        let inner = {
            let guard = db.read().await;
            staged.merkleize(updates, upserts, metadata, &guard).await?
        };
        Merkleized::new(inner, db)
    }
}

impl<F, E, C, I, H, U, const N: usize, S> Merkleized<Db<F, E, C, I, H, U, N, S>>
where
    Db<F, E, C, I, H, U, N, S>: Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, U, S>>,
    F: Family,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Read a value by key, falling back to applied state.
    pub async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(key, &db).await
    }

    /// Read multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as the input keys.
    pub async fn get_many(&self, keys: &[&U::Key]) -> Result<Vec<Option<U::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &db).await
    }
}

impl<F, E, C, I, H, K, V, const N: usize, S> Qmdb
    for Db<F, E, C, I, H, unordered::Update<K, V>, N, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    type Batch = UnmerkleizedBatch<F, H, unordered::Update<K, V>, S>;
    type MerkleizedBatch = MerkleizedBatch<F, H::Digest, unordered::Update<K, V>, S>;
    type Metadata = V::Value;
    type Floor = ();

    fn new_batch(&self) -> Self::Batch {
        self.new_batch()
    }

    async fn merkleize(
        &self,
        batch: Self::Batch,
        metadata: Option<Self::Metadata>,
        _floor: (),
    ) -> Result<Arc<Self::MerkleizedBatch>, Error<F>> {
        batch.merkleize(self, metadata).await
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
    use crate::stateful::db::{ManagedDb, Unmerkleized as _, tests::configs::any::fixed_config};
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _, deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, release_pending_syncs},
    };
    use commonware_storage::{merkle::mmr, qmdb::any::unordered::fixed, translator::TwoCap};

    type UnorderedFixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;

    #[test]
    fn unmerkleized_batch_falls_through_to_applied_state() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "unordered-fixed-live-fallback");
            let db = <UnorderedFixedDb as ManagedDb<_>>::init(context.child("db"), config)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"winner"]);
            let pre_finalization = db.new_batch_for_test::<_>().await;
            let winner = db.new_batch_for_test::<_>().await.write(key, Some(value));
            let winner = winner.merkleize().await.unwrap();

            db.apply_and_finalize_for_test::<_>(winner).await;

            // The batch commitment does not provide a historical database view.
            assert_eq!(pre_finalization.get(&key).await.unwrap(), Some(value));
        });
    }

    /// The staged wrapper (`Unmerkleized::stage` -> `AnyStaged::expand` ->
    /// `AnyStaged::merkleize`) must return the same values and root as an explicit `get_many` +
    /// `write` + `merkleize`, including a staged delete, an upsert, and metadata flow (both set
    /// on the staged handle via `with_metadata` and carried from before staging). This guards
    /// metadata flow and db-handle pairing through the wrapper.
    #[test]
    fn unordered_fixed_staged_merkleize_matches_explicit_writes() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "unordered-fixed-glue-staged");
            let db = <UnorderedFixedDb as ManagedDb<_>>::init(context.child("db"), config)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let key = |i: u64| Sha256::hash(&[&i.to_be_bytes()]);
            let val = |i: u64| Sha256::hash(&[&(i + 10_000).to_be_bytes()]);
            let metadata = Sha256::hash(&[b"metadata"]);

            // Seed keys 0..50 and persist them.
            let mut seed = db.new_batch_for_test::<_>().await;
            for i in 0..50u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let merkleized = seed.merkleize().await.unwrap();
            db.apply_and_finalize_for_test::<_>(merkleized).await;

            // Read set: key(1) updated, key(2) deleted, key(999) missing -> created.
            let read_keys = [key(1), key(2), key(999)];
            let keys: Vec<&Digest> = read_keys.iter().collect();
            let indexed_updates = vec![(0, Some(val(1_000))), (1, None), (2, Some(val(1_001)))];
            let upserts = vec![(key(3), Some(val(1_002)))];

            // Explicit path.
            let mut explicit = db.new_batch_for_test::<_>().await;
            let explicit_values = explicit.get_many(&keys).await.unwrap();
            for (slot, value) in &indexed_updates {
                explicit = explicit.write(read_keys[*slot], *value);
            }
            for (k, v) in &upserts {
                explicit = explicit.write(*k, *v);
            }
            let explicit_root = explicit
                .with_metadata(metadata)
                .merkleize()
                .await
                .unwrap()
                .root();

            // Staged path, with metadata set on the staged handle.
            let staged_batch = db.new_batch_for_test::<_>().await;
            let split = 2;
            let (mut staged_values, staged) = staged_batch.stage(&keys[..split]).await.unwrap();
            let (range, suffix_values, staged) = staged.expand(&keys[split..]).await.unwrap();
            assert_eq!(range, split..keys.len());
            staged_values.extend(suffix_values);
            let staged_root = staged
                .with_metadata(metadata)
                .merkleize(indexed_updates.clone(), upserts.clone())
                .await
                .unwrap()
                .root();

            assert_eq!(explicit_values, staged_values);
            assert_eq!(explicit_root, staged_root);

            // Metadata set before staging must be carried through to staged merkleize.
            let carried_batch = db.new_batch_for_test::<_>().await.with_metadata(metadata);
            let (carried_values, staged) = carried_batch.stage(&keys).await.unwrap();
            let carried_root = staged
                .merkleize(indexed_updates.clone(), upserts.clone())
                .await
                .unwrap()
                .root();
            assert_eq!(explicit_values, carried_values);
            assert_eq!(explicit_root, carried_root);
        });
    }

    type DelayedFixedDb = fixed::Db<
        mmr::Family,
        DelayedSyncContext<deterministic::Context>,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        Sequential,
    >;

    #[test]
    fn apply_does_not_finalize() {
        deterministic::Runner::default().start(|context| async move {
            let pending = PendingSyncs::default();
            let delayed = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let config = fixed_config(&delayed, "unordered-fixed-deferred");
            let db = drive_pending_syncs(
                &pending,
                <DelayedFixedDb as ManagedDb<_>>::init(delayed.child("db"), config),
            )
            .await
            .unwrap();
            let db = Shared::new("test", db);

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let batch = db.new_batch_for_test::<_>().await.write(key, Some(value));
            let merkleized = batch.merkleize().await.unwrap();

            let starts = pending.starts();
            let (slot, database) = db.write().await;
            let database = <DelayedFixedDb as ManagedDb<_>>::apply(database, merkleized)
                .await
                .unwrap();
            slot.put(database);

            assert_eq!(pending.starts(), starts, "apply must not start durability");
            {
                let guard = db.read().await;
                assert_eq!(guard.get(&key).await.unwrap(), Some(value));
            }

            let (slot, database) = db.write().await;
            let (database, sync) = <DelayedFixedDb as ManagedDb<_>>::finalize(database)
                .await
                .unwrap();
            slot.put(database);
            assert!(
                pending.starts() > pending.completions(),
                "finalize must leave its flush parked",
            );

            release_pending_syncs(&pending);
            drive_pending_syncs(&pending, sync)
                .await
                .expect("flush must succeed once released");
        });
    }
}

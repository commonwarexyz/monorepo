//! [`Qmdb`] implementations for [`qmdb::current`](commonware_storage::qmdb::current).

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
    index::{Ordered as OrderedIndex, Unordered as UnorderedIndex},
    journal::contiguous::{Contiguous, Mutable},
    merkle::{Graftable, Location},
    qmdb::{
        Error,
        any::{
            operation::{Operation, Update},
            ordered, unordered,
            value::ValueEncoding,
        },
        current::{
            batch::{MerkleizedBatch, Staged, UnmerkleizedBatch},
            db::Db,
        },
        operation::Key,
        sync,
    },
};
use std::{ops::Range, sync::Arc};

/// Staged batch returned by `stage`. Holds a [`Staged`] QMDB plus the database handle it
/// reads through.
///
/// Like any speculative batch, this handle is a branch-scoped view of the shared database: it
/// stays valid only while every batch finalized on the database is an ancestor of this batch
/// (see [`MerkleizedBatch`]'s branch-validity contract).
pub struct CurrentStaged<F, E, C, I, H, U, const N: usize, S>
where
    F: Graftable,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>>,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    staged: Staged<F, H, U, N, S>,
    db: Shared<Db<F, E, C, I, H, U, N, S>>,
    metadata: Option<U::Value>,
}

impl<F, E, C, I, H, U, const N: usize, S> Unmerkleized<Db<F, E, C, I, H, U, N, S>>
where
    Db<F, E, C, I, H, U, N, S>:
        Qmdb<Batch = UnmerkleizedBatch<F, H, U, N, S>, Metadata = U::Value, Floor = ()>,
    F: Graftable,
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
    ) -> Result<(Vec<Option<U::Value>>, CurrentStaged<F, E, C, I, H, U, N, S>), Error<F>> {
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
            CurrentStaged {
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

impl<F, E, C, I, H, U, const N: usize, S> CurrentStaged<F, E, C, I, H, U, N, S>
where
    F: Graftable,
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

impl<F, E, C, I, H, K, V, const N: usize, S>
    CurrentStaged<F, E, C, I, H, unordered::Update<K, V>, N, S>
where
    Db<F, E, C, I, H, unordered::Update<K, V>, N, S>: Qmdb<
            Family = F,
            Digest = H::Digest,
            MerkleizedBatch = MerkleizedBatch<F, H::Digest, unordered::Update<K, V>, N, S>,
        >,
    F: Graftable,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](CurrentStaged::expand)
    /// before this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](CurrentStaged::expand) ranges.
    /// Metadata set via [`with_metadata`](CurrentStaged::with_metadata) (or before staging) is
    /// committed with the returned batch.
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

impl<F, E, C, I, H, K, V, const N: usize, S>
    CurrentStaged<F, E, C, I, H, ordered::Update<K, V>, N, S>
where
    Db<F, E, C, I, H, ordered::Update<K, V>, N, S>: Qmdb<
            Family = F,
            Digest = H::Digest,
            MerkleizedBatch = MerkleizedBatch<F, H::Digest, ordered::Update<K, V>, N, S>,
        >,
    F: Graftable,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    /// Record updates for staged reads and upserts for unread keys, then merkleize.
    ///
    /// Consumes the staged handle and write vectors. Call [`expand`](CurrentStaged::expand)
    /// before this method if more keys must be read into the staged index space.
    ///
    /// A `Some` value is an upsert. `None` is a delete. Update indices refer to the staged read
    /// set: the initial `stage` input followed by any [`expand`](CurrentStaged::expand) ranges.
    /// Metadata set via [`with_metadata`](CurrentStaged::with_metadata) (or before staging) is
    /// committed with the returned batch.
    ///
    /// # Panics
    ///
    /// Panics if any update's `read_index` is out of the staged read range.
    pub async fn merkleize(
        self,
        updates: Vec<(usize, Option<V::Value>)>,
        upserts: Vec<(K, Option<V::Value>)>,
    ) -> Result<Merkleized<Db<F, E, C, I, H, ordered::Update<K, V>, N, S>>, Error<F>> {
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
    Db<F, E, C, I, H, U, N, S>: Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, U, N, S>>,
    F: Graftable,
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
    F: Graftable,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    type Batch = UnmerkleizedBatch<F, H, unordered::Update<K, V>, N, S>;
    type MerkleizedBatch = MerkleizedBatch<F, H::Digest, unordered::Update<K, V>, N, S>;
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
}

impl<F, E, C, I, H, K, V, const N: usize, S> Qmdb for Db<F, E, C, I, H, ordered::Update<K, V>, N, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Graftable,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    type Batch = UnmerkleizedBatch<F, H, ordered::Update<K, V>, N, S>;
    type MerkleizedBatch = MerkleizedBatch<F, H::Digest, ordered::Update<K, V>, N, S>;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stateful::db::{
        DatabaseSet, InitError, ManagedDb, StateSyncDb, Unmerkleized as _,
        tests::configs::current::{fixed_config, variable_config},
    };
    use commonware_codec::FixedSize;
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::boxed;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        BufferPooler, Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{
            self, Config as DeterministicConfig, FaultConfig, PartialWriteMode, WriteConfig,
        },
    };
    use commonware_storage::{
        merkle::mmr,
        qmdb::{
            any::unordered::fixed::Operation as FixedOperation,
            current::{
                FixedConfig,
                ordered::{fixed as ordered_fixed, variable as ordered_variable},
                unordered::{fixed, variable},
            },
        },
        translator::TwoCap,
    };
    use commonware_utils::{NZU64, NZUsize, non_empty_range, probability};
    use std::num::NonZeroU16;

    #[boxed]
    async fn apply_and_finalize<D: ManagedDb<deterministic::Context>>(
        db: D,
        batch: D::Merkleized,
    ) -> D {
        let db = D::apply(db, batch).await.unwrap();
        let (db, sync) = D::finalize(db).await.unwrap();
        sync.await.expect("database sync failed");
        db
    }

    type FixedDb = fixed::Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        64,
        Sequential,
    >;
    type OrderedFixedDb = ordered_fixed::Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        64,
        Sequential,
    >;
    type OrderedVariableDb = ordered_variable::Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        64,
        Sequential,
    >;

    /// The unordered variable wrapper accepts variable-length keys.
    type VariableDb = variable::Db<
        mmr::Family,
        deterministic::Context,
        Vec<u8>,
        Digest,
        Sha256,
        TwoCap,
        64,
        Sequential,
    >;

    fn assert_managed_db<T: ManagedDb<deterministic::Context>>() {}

    fn assert_state_sync_db<T, R>()
    where
        T: StateSyncDb<deterministic::Context, R>,
    {
    }

    fn assert_database_set<T: DatabaseSet<deterministic::Context>>() {}

    #[test]
    fn variable_current_db_trait_impls_compile() {
        assert_managed_db::<VariableDb>();
        assert_state_sync_db::<VariableDb, Arc<VariableDb>>();
        assert_database_set::<Shared<VariableDb>>();
    }

    #[test]
    fn ordered_fixed_managed_db_applies_batch_and_proves_exclusion() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "ordered-fixed-managed-db");
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);
            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let metadata = Sha256::hash(&[b"metadata"]);
            let missing = Sha256::hash(&[b"missing"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = batch.merkleize().await.unwrap();
            let expected_root = merkleized.root();

            db.apply_and_finalize_for_test::<_>(merkleized).await;

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get(&key).await.unwrap(), Some(value));

            let proof = guard.exclusion_proof(&missing).await.unwrap();
            assert!(proof.verify::<Sha256>(&missing, &guard.root()));
        });
    }

    /// The staged wrapper (`Unmerkleized::stage` -> `CurrentStaged::expand` ->
    /// `CurrentStaged::merkleize`) must return the same values and root as an explicit `get_many` +
    /// `write` + `merkleize`, including a staged delete, an upsert, and metadata flow (both set
    /// on the staged handle via `with_metadata` and carried from before staging). This guards
    /// metadata flow and db-handle pairing through the wrapper.
    #[test]
    fn ordered_fixed_staged_merkleize_matches_explicit_writes() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "ordered-fixed-glue-staged");
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config, None)
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

    #[test]
    fn ordered_variable_managed_db_applies_batch_and_proves_exclusion() {
        deterministic::Runner::default().start(|context| async move {
            let config = variable_config(&context, "ordered-variable-managed-db");
            let db = <OrderedVariableDb as ManagedDb<_>>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);
            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let metadata = Sha256::hash(&[b"metadata"]);
            let missing = Sha256::hash(&[b"missing"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = batch.merkleize().await.unwrap();
            let expected_root = merkleized.root();

            db.apply_and_finalize_for_test::<_>(merkleized).await;

            let guard = db.read().await;
            assert_eq!(guard.root(), expected_root);
            assert_eq!(guard.get(&key).await.unwrap(), Some(value));

            let proof = guard.exclusion_proof(&missing).await.unwrap();
            assert!(proof.verify::<Sha256>(&missing, &guard.root()));
        });
    }

    #[test]
    fn ordered_managed_db_matches_sync_target_rejects_wrong_ops_root_and_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "ordered-matches-sync-target");
            let db =
                <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config.clone(), None)
                    .await
                    .unwrap();
            let db = Shared::new("test", db);

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let metadata = Sha256::hash(&[b"metadata"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            let verification_db = <OrderedFixedDb as ManagedDb<_>>::init(
                context.child("verification_db"),
                fixed_config(&context, "ordered-matches-sync-target-verification"),
                None,
            )
            .await
            .unwrap();
            let (verification_db, _) = verification_db
                .apply_batch(merkleized.inner.clone())
                .await
                .unwrap();
            let verification_db = verification_db.sync().await.unwrap();

            let valid_target = <OrderedFixedDb as ManagedDb<_>>::sync_target(&verification_db);
            assert!(<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let mut wrong_root = valid_target.clone();
            wrong_root.root = Sha256::hash(&[b"wrong ops root"]);
            assert!(!<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_root,
            ));

            let mut wrong_range = valid_target.clone();
            wrong_range.range =
                non_empty_range!(valid_target.range.start(), valid_target.range.end() + 1);
            assert!(!<OrderedFixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_range,
            ));
        });
    }

    #[test]
    fn ordered_managed_db_bounded_initialization_to_target_round_trips() {
        deterministic::Runner::default().start(|context| async move {
            // Finalize two distinct checkpoints so bounded initialization must discard a suffix.
            let config = fixed_config(&context, "ordered-bounded-init-round-trip");
            let db =
                <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config.clone(), None)
                    .await
                    .unwrap();
            let db = Shared::new("test", db);

            let key1 = Sha256::hash(&[b"key1"]);
            let value1 = Sha256::hash(&[b"value1"]);
            let metadata1 = Sha256::hash(&[b"metadata1"]);
            let batch1 = db
                .new_batch_for_test::<_>()
                .await
                .write(key1, Some(value1))
                .with_metadata(metadata1);
            let merkleized1 = crate::stateful::db::Unmerkleized::merkleize(batch1)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                slot.put(apply_and_finalize::<OrderedFixedDb>(database, merkleized1).await);
            }
            let target_after_first = {
                let guard = db.read().await;
                <OrderedFixedDb as ManagedDb<_>>::sync_target(&guard)
            };

            let key2 = Sha256::hash(&[b"key2"]);
            let value2 = Sha256::hash(&[b"value2"]);
            let metadata2 = Sha256::hash(&[b"metadata2"]);
            let batch2 = db
                .new_batch_for_test::<_>()
                .await
                .write(key2, Some(value2))
                .with_metadata(metadata2);
            let merkleized2 = crate::stateful::db::Unmerkleized::merkleize(batch2)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                slot.put(apply_and_finalize::<OrderedFixedDb>(database, merkleized2).await);
            }

            // Reopen at the first checkpoint and verify the complete recovered target.
            drop(db);
            let db = <OrderedFixedDb as ManagedDb<_>>::init(
                context.child("cap"),
                config.clone(),
                Some(target_after_first.clone()),
            )
            .await
            .unwrap();
            let target_after_reopen = <OrderedFixedDb as ManagedDb<_>>::sync_target(&db);
            assert_eq!(target_after_reopen, target_after_first);
            drop(db);

            // Root, end, and floor mismatches must each report both sides of the comparison.
            let mut wrong_root = target_after_first.clone();
            wrong_root.root = Sha256::hash(&[b"wrong initialization root"]);
            let mut behind = target_after_first.clone();
            behind.range = non_empty_range!(behind.range.start(), behind.range.end() + 1);
            let mut wrong_floor = target_after_first.clone();
            wrong_floor.range =
                non_empty_range!(wrong_floor.range.start() + 1, wrong_floor.range.end());
            for (index, target) in [wrong_root, behind, wrong_floor].into_iter().enumerate() {
                assert!(matches!(
                    <OrderedFixedDb as ManagedDb<_>>::init(
                        context.child("mismatch").with_attribute("case", index),
                        config.clone(),
                        Some(target.clone()),
                    )
                    .await,
                    Err(InitError::TargetMismatch { expected, recovered })
                        if expected == target && recovered == target_after_first
                ));
                let reopened = <OrderedFixedDb as ManagedDb<_>>::init(
                    context.child("restart").with_attribute("case", index),
                    config.clone(),
                    None,
                )
                .await
                .unwrap();
                assert_eq!(
                    <OrderedFixedDb as ManagedDb<_>>::sync_target(&reopened),
                    target_after_first
                );
                drop(reopened);
            }
        });
    }

    #[test]
    fn managed_db_matches_sync_target_rejects_wrong_ops_root_and_range() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "matches-sync-target");
            let db = FixedDb::init(context.child("db"), config.clone(), None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let metadata = Sha256::hash(&[b"metadata"]);

            let batch = db
                .new_batch_for_test::<_>()
                .await
                .write(key, Some(value))
                .with_metadata(metadata);
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

            let verification_db = FixedDb::init(
                context.child("verification_db"),
                fixed_config(&context, "matches-sync-target-verification"),
                None,
            )
            .await
            .unwrap();
            let (verification_db, _) = verification_db
                .apply_batch(merkleized.inner.clone())
                .await
                .unwrap();
            let verification_db = verification_db.sync().await.unwrap();

            let valid_target = <FixedDb as ManagedDb<_>>::sync_target(&verification_db);
            assert!(<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &valid_target,
            ));

            let mut wrong_root = valid_target.clone();
            wrong_root.root = Sha256::hash(&[b"wrong ops root"]);
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_root,
            ));

            let mut wrong_range = valid_target.clone();
            wrong_range.range =
                non_empty_range!(valid_target.range.start(), valid_target.range.end() + 1);
            assert!(!<FixedDb as ManagedDb<_>>::matches_sync_target(
                &merkleized,
                &wrong_range,
            ));
        });
    }

    /// Finalize two targets, reopen at the first, apply without finalizing, then crash before any
    /// sync. Recovery must yield a legitimate history, the first target must reopen, and the
    /// discarded second target must be rejected.
    #[test]
    fn managed_db_bounded_init_then_apply_crash_recovers_history() {
        type FixedOp = FixedOperation<mmr::Family, Digest, Digest>;

        // One operation per page makes the initialization truncation page aligned and one blob
        // keeps both histories' writes overlapping.
        fn config(pooler: &impl BufferPooler) -> FixedConfig<TwoCap, Sequential> {
            let page_size = NonZeroU16::new(<FixedOp as FixedSize>::SIZE as u16).unwrap();
            let mut config = fixed_config(pooler, "bounded-init-crash");
            config.journal_config.page_cache =
                CacheRef::from_pooler(pooler, page_size, NZUsize!(11));
            config.journal_config.items_per_blob = NZU64!(1000);
            config.merkle_config.items_per_blob = NZU64!(1000);
            config
        }

        fn batch_for(i: u8) -> (Digest, Digest, Digest) {
            (
                Sha256::hash(&[b"key", &[i]]),
                Sha256::hash(&[b"value", &[i]]),
                Sha256::hash(&[b"metadata", &[i]]),
            )
        }

        // Keep unsynced writes and drop unsynced resizes at the crash.
        let runtime = DeterministicConfig::default().with_storage_fault_config(
            FaultConfig::default().write(WriteConfig {
                failure_rate: probability!(0.0),
                retention_rate: probability!(1.0),
                mode: PartialWriteMode::Prefix,
            }),
        );
        let ((first, second, applied), checkpoint) = deterministic::Runner::new(runtime)
            .start_and_recover(|context| async move {
                let db = FixedDb::init(context.child("db"), config(&context), None)
                    .await
                    .unwrap();
                let db = Shared::new("test", db);

                let mut targets = Vec::new();
                for i in 1..=2 {
                    let (key, value, metadata) = batch_for(i);
                    let batch = db
                        .new_batch_for_test::<_>()
                        .await
                        .write(key, Some(value))
                        .with_metadata(metadata);
                    let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                        .await
                        .unwrap();
                    let (slot, database) = db.write().await;
                    slot.put(apply_and_finalize::<FixedDb>(database, merkleized).await);
                    let guard = db.read().await;
                    targets.push(<FixedDb as ManagedDb<_>>::sync_target(&guard));
                }
                let second = targets.pop().unwrap();
                let first = targets.pop().unwrap();
                assert_ne!(first, second);
                drop(db);

                // Reopen at the first target, discarding the second.
                let db = <FixedDb as ManagedDb<_>>::init(
                    context.child("bounded"),
                    config(&context),
                    Some(first.clone()),
                )
                .await
                .unwrap();
                assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), first);
                let db = Shared::new("test", db);

                // Apply over the discarded target's bytes, then crash without finalizing.
                let (key, value, metadata) = batch_for(3);
                let batch = db
                    .new_batch_for_test::<_>()
                    .await
                    .write(key, Some(value))
                    .with_metadata(metadata);
                let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                    .await
                    .unwrap();
                let (slot, database) = db.write().await;
                let database = <FixedDb as ManagedDb<_>>::apply(database, merkleized)
                    .await
                    .unwrap();
                let applied = <FixedDb as ManagedDb<_>>::sync_target(&database);
                assert_ne!(applied, first);
                assert_ne!(applied, second);
                slot.put(database);
                (first, second, applied)
            });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            // Only the first target, or the applied batch on top of it, is a legitimate history.
            let db = FixedDb::init(context.child("recover"), config(&context), None)
                .await
                .unwrap();
            let recovered = <FixedDb as ManagedDb<_>>::sync_target(&db);
            assert!(
                recovered == first || recovered == applied,
                "recovered {recovered:?} from neither history"
            );
            drop(db);

            // The first target reopens and durably discards anything above it.
            let db = <FixedDb as ManagedDb<_>>::init(
                context.child("first"),
                config(&context),
                Some(first.clone()),
            )
            .await
            .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), first);
            drop(db);

            // The discarded second target cannot be restored.
            assert!(matches!(
                <FixedDb as ManagedDb<_>>::init(
                    context.child("second"),
                    config(&context),
                    Some(second.clone()),
                )
                .await,
                Err(InitError::TargetMismatch { expected, recovered })
                    if expected == second && recovered == first
            ));

            // A rejected initialization leaves the first target in place.
            let db = FixedDb::init(context.child("restart"), config(&context), None)
                .await
                .unwrap();
            assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), first);
        });
    }

    /// Pruning to the oldest retained target keeps every retained target initializable, so a
    /// restart whose marshal anchor lags the databases opens at that older target. The pruned
    /// target's range starts a whole chunk above zero, so the prune moves the bitmap.
    #[test]
    fn database_set_current_prune_keeps_recovery_targets_initializable() {
        deterministic::Runner::default().start(|context| async move {
            type DbSet = Shared<FixedDb>;
            let config = fixed_config(&context, "current-prune-recovery-window");
            let databases =
                <DbSet as DatabaseSet<_>>::init(context.child("db"), config.clone(), None).await;

            // Four generations rewrite the same keys. H1 through H3 are durable, and H4 is
            // applied without a barrier of its own when the prune to H2 runs.
            let mut targets = Vec::new();
            for generation in 0..4u64 {
                let mut batch = databases.new_batch_for_test::<_>().await;
                for i in 0..384u64 {
                    batch = batch.write(
                        Sha256::hash(&[&i.to_be_bytes()]),
                        Some(Sha256::hash(&[&(generation * 1_000 + i).to_le_bytes()])),
                    );
                }
                let batch = Unmerkleized::merkleize(batch).await.unwrap();
                <DbSet as DatabaseSet<_>>::apply(&databases, batch).await;
                if generation < 3 {
                    assert!(
                        <DbSet as DatabaseSet<_>>::finalize(&databases)
                            .await
                            .durable()
                            .await
                    );
                }
                targets.push(<DbSet as DatabaseSet<_>>::committed_targets(&databases).await);
            }
            assert!(*targets[1].range.start() > Location::<mmr::Family>::new(0));
            <DbSet as DatabaseSet<_>>::prune(&databases, &targets[1]).await;
            drop(databases);

            // An unbounded reopen recovers H4, which the prune committed.
            let reopened =
                <DbSet as DatabaseSet<_>>::init(context.child("reopen"), config.clone(), None)
                    .await;
            assert_eq!(
                <DbSet as DatabaseSet<_>>::committed_targets(&reopened).await,
                targets[3]
            );
            drop(reopened);

            // H3 and H2 stay inside the retained window, so bounded initialization at either
            // succeeds and reports it.
            for (name, target) in [("h3", &targets[2]), ("h2", &targets[1])] {
                let db = <FixedDb as ManagedDb<_>>::init(
                    context.child(name),
                    config.clone(),
                    Some(target.clone()),
                )
                .await
                .unwrap();
                assert_eq!(<FixedDb as ManagedDb<_>>::sync_target(&db), *target);
            }
        });
    }
}

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

/// Staged batch returned by `stage`. Holds a QMDB [`Staged`] plus the database handle it
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

    async fn apply(self, batch: Arc<Self::MerkleizedBatch>) -> Result<Self, Error<F>> {
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

    async fn apply(self, batch: Arc<Self::MerkleizedBatch>) -> Result<Self, Error<F>> {
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
        ManagedDb, Unmerkleized as _,
        tests::configs::current::{fixed_config, variable_config},
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_storage::{
        merkle::mmr,
        qmdb::current::ordered::{fixed as ordered_fixed, variable as ordered_variable},
        translator::TwoCap,
    };

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

    #[test]
    fn ordered_fixed_managed_db_applies_batch_and_proves_exclusion() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config(&context, "ordered-fixed-managed-db");
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config)
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
            assert!(OrderedFixedDb::verify_exclusion_proof(
                &missing,
                &proof,
                &guard.root(),
            ));
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
            let db = <OrderedFixedDb as ManagedDb<_>>::init(context.child("db"), config)
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
            let db = <OrderedVariableDb as ManagedDb<_>>::init(context.child("db"), config)
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
            assert!(OrderedVariableDb::verify_exclusion_proof(
                &missing,
                &proof,
                &guard.root(),
            ));
        });
    }
}

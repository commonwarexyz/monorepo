//! [`Qmdb`] implementation for QMDB [`any`](commonware_storage::qmdb::any) databases.
//!
//! Batch reads consult the database at the time of the read for keys their batch chain does not
//! write, and return a `StaleRead` error once the database is at no state of that chain.

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
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::{
            Db,
            batch::{MerkleizedBatch, Slot, Staged, UnmerkleizedBatch},
            operation::{Operation, Update},
            ordered, unordered,
        },
        operation::Key,
        sync,
        value::ValueEncoding,
    },
};
use core::borrow::Borrow;
use std::{ops::Range, sync::Arc};

/// A staged batch returned by [`Unmerkleized::stage`].
///
/// Like any speculative batch, this handle reads the shared database only while the database is
/// at a state of the batch's chain, and its reads return [`Error::StaleRead`] once the database
/// is at any other state (see [`MerkleizedBatch`]'s "Batch validity" docs).
pub struct AnyStaged<F, E, C, I, H, U, S>
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
    db: Shared<Db<F, E, C, I, H, U, S>>,
}

impl<F, E, C, I, H, U, S> Unmerkleized<Db<F, E, C, I, H, U, S>>
where
    Db<F, E, C, I, H, U, S>: Qmdb<Batch = UnmerkleizedBatch<F, H, U, S>>,
    F: Family,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Sets the metadata committed by [`merkleize`](crate::stateful::db::Unmerkleized::merkleize).
    /// `None` clears it.
    ///
    /// The metadata carries over to a batch returned by [`Self::stage`].
    pub fn with_metadata(mut self, metadata: impl Into<Option<U::Value>>) -> Self {
        self.batch = self.batch.with_metadata(metadata);
        self
    }

    /// Reads a value by key, falling back to applied state.
    pub async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get(key, &db).await
    }

    /// Reads multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as `keys`.
    pub async fn get_many(
        &self,
        keys: &[impl Borrow<U::Key> + Sync],
    ) -> Result<Vec<Option<U::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.batch.get_many(keys, &db).await
    }

    /// Reads multiple values and returns `(staged, values)` for the same keys.
    ///
    /// Returns results in the same order as `keys`.
    pub async fn stage(
        self,
        keys: &[impl Borrow<U::Key> + Sync],
    ) -> Result<(AnyStaged<F, E, C, I, H, U, S>, Vec<Option<U::Value>>), Error<F>> {
        let Self { batch, db } = self;
        let (staged, values) = {
            let guard = db.read().await;
            batch.stage(keys, &guard).await?
        };
        Ok((AnyStaged { staged, db }, values))
    }

    /// Records an upsert (`Some`) or a delete (`None`) of `key`.
    pub fn write(mut self, key: U::Key, value: Option<U::Value>) -> Self {
        self.batch = self.batch.write(key, value);
        self
    }
}

impl<F, E, C, I, H, U, S> AnyStaged<F, E, C, I, H, U, S>
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
    /// Sets the metadata committed by [`merkleize`](Self::merkleize), replacing any metadata set
    /// before staging. `None` clears it.
    pub fn with_metadata(mut self, metadata: impl Into<Option<U::Value>>) -> Self {
        self.staged = self.staged.with_metadata(metadata);
        self
    }

    /// The number of staged read slots: the keys passed to `stage` plus every
    /// [`expand`](Self::expand) range. [`merkleize`](Self::merkleize) takes one [`Slot`] per
    /// staged read.
    pub const fn len(&self) -> usize {
        self.staged.len()
    }

    /// Whether no reads are staged.
    pub const fn is_empty(&self) -> bool {
        self.staged.is_empty()
    }

    /// Expands this staged batch with more reads, returning `(self, range, values)`.
    ///
    /// Existing slots keep their positions. Newly read keys are appended to the staged read set
    /// and assigned the returned range of slots. Expansion does not deduplicate against previously
    /// staged keys and does not observe values computed for earlier staged slots but not yet
    /// passed to `merkleize`.
    pub async fn expand(
        self,
        keys: &[impl Borrow<U::Key> + Sync],
    ) -> Result<(Self, Range<usize>, Vec<Option<U::Value>>), Error<F>> {
        let Self { staged, db } = self;
        let (staged, range, values) = {
            let guard = db.read().await;
            staged.expand(keys, &guard).await?
        };
        Ok((Self { staged, db }, range, values))
    }
}

impl<F, E, C, I, H, K, V, S> AnyStaged<F, E, C, I, H, unordered::Update<K, V>, S>
where
    Db<F, E, C, I, H, unordered::Update<K, V>, S>:
        Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, unordered::Update<K, V>, S>>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    /// Applies `slots` to staged reads and `unstaged` writes to unread keys, then merkleizes.
    ///
    /// `slots` holds one [`Slot`] per staged read, in the order of the keys passed to `stage`
    /// followed by each [`expand`](Self::expand) range. A key staged in several slots takes its
    /// last put or delete, and an unstaged write to a staged key wins. Metadata set through
    /// [`with_metadata`](Self::with_metadata), or before staging, is committed with the batch.
    ///
    /// # Panics
    ///
    /// Panics if `slots` does not hold one entry per staged read.
    pub async fn merkleize(
        self,
        slots: Vec<Slot<V::Value>>,
        unstaged: Vec<(K, Option<V::Value>)>,
    ) -> Result<Merkleized<Db<F, E, C, I, H, unordered::Update<K, V>, S>>, Error<F>> {
        let Self { staged, db } = self;
        let inner = {
            let guard = db.read().await;
            staged.merkleize(slots, unstaged, &guard).await?
        };
        Ok(Merkleized { inner, db })
    }
}

impl<F, E, C, I, H, K, V, S> AnyStaged<F, E, C, I, H, ordered::Update<K, V>, S>
where
    Db<F, E, C, I, H, ordered::Update<K, V>, S>:
        Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, ordered::Update<K, V>, S>>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    /// Applies `slots` to staged reads and `unstaged` writes to unread keys, then merkleizes.
    ///
    /// `slots` holds one [`Slot`] per staged read, in the order of the keys passed to `stage`
    /// followed by each [`expand`](Self::expand) range. A key staged in several slots takes its
    /// last put or delete, and an unstaged write to a staged key wins. Metadata set through
    /// [`with_metadata`](Self::with_metadata), or before staging, is committed with the batch.
    ///
    /// # Panics
    ///
    /// Panics if `slots` does not hold one entry per staged read.
    pub async fn merkleize(
        self,
        slots: Vec<Slot<V::Value>>,
        unstaged: Vec<(K, Option<V::Value>)>,
    ) -> Result<Merkleized<Db<F, E, C, I, H, ordered::Update<K, V>, S>>, Error<F>> {
        let Self { staged, db } = self;
        let inner = {
            let guard = db.read().await;
            staged.merkleize(slots, unstaged, &guard).await?
        };
        Ok(Merkleized { inner, db })
    }
}

impl<F, E, C, I, H, U, S> Merkleized<Db<F, E, C, I, H, U, S>>
where
    Db<F, E, C, I, H, U, S>: Qmdb<MerkleizedBatch = MerkleizedBatch<F, H::Digest, U, S>>,
    F: Family,
    E: Context,
    U: Update,
    C: Contiguous<Item = Operation<F, U>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, U>: Codec,
{
    /// Reads a value by key, falling back to applied state.
    pub async fn get(&self, key: &U::Key) -> Result<Option<U::Value>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get(key, &db).await
    }

    /// Reads multiple values by key, falling back to applied state.
    ///
    /// Returns results in the same order as `keys`.
    pub async fn get_many(
        &self,
        keys: &[impl Borrow<U::Key> + Sync],
    ) -> Result<Vec<Option<U::Value>>, Error<F>> {
        let db = self.db.read().await;
        self.inner.get_many(keys, &db).await
    }
}

impl<F, E, C, I, H, K, V, S> Qmdb for Db<F, E, C, I, H, unordered::Update<K, V>, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, unordered::Update<K, V>>>,
    I: UnorderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, unordered::Update<K, V>>: Codec,
{
    type Batch = UnmerkleizedBatch<F, H, unordered::Update<K, V>, S>;
    type MerkleizedBatch = MerkleizedBatch<F, H::Digest, unordered::Update<K, V>, S>;

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

impl<F, E, C, I, H, K, V, S> Qmdb for Db<F, E, C, I, H, ordered::Update<K, V>, S>
where
    Self: sync::Database<Family = F, Context = E, Digest = H::Digest, Hasher = H, Config: Send>,
    F: Family,
    E: Context,
    K: Key,
    V: ValueEncoding,
    C: Mutable<Item = Operation<F, ordered::Update<K, V>>>,
    I: OrderedIndex<Value = Location<F>> + 'static,
    H: Hasher,
    S: Strategy,
    Operation<F, ordered::Update<K, V>>: Codec,
{
    type Batch = UnmerkleizedBatch<F, H, ordered::Update<K, V>, S>;
    type MerkleizedBatch = MerkleizedBatch<F, H::Digest, ordered::Update<K, V>, S>;

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
    use crate::stateful::db::ManagedDb;
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs, release_pending_syncs},
    };
    use commonware_storage::{
        journal::{
            authenticated::Config as MerkleConfig, contiguous::fixed::Config as FixedJournalConfig,
        },
        merkle::mmr,
        qmdb::{self, any::unordered::fixed},
        translator::TwoCap,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use std::num::{NonZeroU16, NonZeroUsize};

    /// Ordered databases get the same [`Qmdb`] support as unordered ones.
    #[test]
    fn ordered_any_is_qmdb() {
        fn assert_qmdb<D: Qmdb>() {}
        assert_qmdb::<
            qmdb::any::ordered::fixed::Db<
                mmr::Family,
                deterministic::Context,
                Digest,
                Digest,
                Sha256,
                TwoCap,
                Sequential,
            >,
        >();
    }

    type UnorderedFixedDb =
        fixed::Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;

    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    fn fixed_config(suffix: &str) -> fixed::Config<TwoCap, Sequential> {
        let page_cache = CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE);
        fixed::Config {
            merkle: MerkleConfig {
                partition: format!("stateful-any-metadata-{suffix}"),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                resident_height: Default::default(),
            },
            log: FixedJournalConfig {
                partition: format!("stateful-any-log-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: TwoCap,
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency: NZUsize!(2),
        }
    }

    #[test]
    fn unmerkleized_batch_refuses_after_competing_finalization() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("unordered-fixed-stale-refusal");
            let db = <UnorderedFixedDb as ManagedDb<_>>::init(context.child("db"), config, None)
                .await
                .unwrap();
            let db = Shared::new("test", db);

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"winner"]);
            let pre_finalization = db.new_batch_for_test::<_>().await;
            let winner = db.new_batch_for_test::<_>().await.write(key, Some(value));
            let winner = crate::stateful::db::Unmerkleized::merkleize(winner)
                .await
                .unwrap();

            let (slot, database) = db.write().await;
            let database = <UnorderedFixedDb as ManagedDb<_>>::apply(database, winner)
                .await
                .unwrap();
            let (database, sync) = <UnorderedFixedDb as ManagedDb<_>>::finalize(database)
                .await
                .unwrap();
            slot.put(database);
            sync.await.expect("database sync failed");

            // `winner` is a sibling built on the same state, so applying it moves the database to
            // a state outside `pre_finalization`'s chain and reads through `pre_finalization`
            // return `StaleRead`.
            assert!(matches!(
                pre_finalization.get(&key).await,
                Err(qmdb::Error::StaleRead)
            ));
        });
    }

    /// The glue staged wrapper (`AnyUnmerkleized::stage` -> `AnyStaged::expand` ->
    /// `AnyStaged::merkleize`) must return the same values and root as an explicit `get_many` +
    /// `write` + `merkleize`, including a staged delete, an unstaged write, and metadata flow (both
    /// set on the staged handle via `with_metadata` and carried from before staging). This guards
    /// metadata flow and db-handle pairing through the wrapper.
    #[test]
    fn unordered_fixed_staged_merkleize_matches_explicit_writes() {
        deterministic::Runner::default().start(|context| async move {
            let config = fixed_config("unordered-fixed-glue-staged");
            let db = <UnorderedFixedDb as ManagedDb<_>>::init(context.child("db"), config, None)
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
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(seed)
                .await
                .unwrap();
            {
                let (slot, database) = db.write().await;
                let database = <UnorderedFixedDb as ManagedDb<_>>::apply(database, merkleized)
                    .await
                    .unwrap();
                let (database, sync) = <UnorderedFixedDb as ManagedDb<_>>::finalize(database)
                    .await
                    .unwrap();
                slot.put(database);
                sync.await.expect("database sync failed");
            }

            // Read set: key(1) updated, key(2) deleted, key(999) missing -> created.
            let keys = [key(1), key(2), key(999)];
            let slots = vec![Slot::Put(val(1_000)), Slot::Delete, Slot::Put(val(1_001))];
            let unstaged = vec![(key(3), Some(val(1_002)))];

            // Explicit path.
            let mut explicit = db.new_batch_for_test::<_>().await;
            let explicit_values = explicit.get_many(&keys).await.unwrap();
            for (key, slot) in keys.iter().zip(&slots) {
                let value = match slot {
                    Slot::Put(value) => Some(*value),
                    Slot::Delete => None,
                    Slot::Keep => unreachable!("every staged read must be written"),
                };
                explicit = explicit.write(*key, value);
            }
            for (k, v) in &unstaged {
                explicit = explicit.write(*k, *v);
            }
            let explicit_root =
                crate::stateful::db::Unmerkleized::merkleize(explicit.with_metadata(metadata))
                    .await
                    .unwrap()
                    .root();

            // Staged path, with metadata set on the staged handle.
            let staged_batch = db.new_batch_for_test::<_>().await;
            let split = 2;
            let (staged, mut staged_values) = staged_batch.stage(&keys[..split]).await.unwrap();
            let (staged, range, suffix_values) = staged.expand(&keys[split..]).await.unwrap();
            assert_eq!(range, split..keys.len());
            assert_eq!(staged.len(), keys.len());
            assert!(!staged.is_empty());
            staged_values.extend(suffix_values);
            let staged_root = staged
                .with_metadata(metadata)
                .merkleize(slots.clone(), unstaged.clone())
                .await
                .unwrap()
                .root();

            assert_eq!(explicit_values, staged_values);
            assert_eq!(explicit_root, staged_root);

            // Metadata set before staging must be carried through to staged merkleize.
            let carried_batch = db.new_batch_for_test::<_>().await.with_metadata(metadata);
            let (staged, carried_values) = carried_batch.stage(&keys.each_ref()).await.unwrap();
            let carried_root = staged
                .merkleize(slots.clone(), unstaged.clone())
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
            let config = fixed_config("unordered-fixed-deferred");
            let db = drive_pending_syncs(
                &pending,
                <DelayedFixedDb as ManagedDb<_>>::init(delayed.child("db"), config, None),
            )
            .await
            .unwrap();
            let db = Shared::new("test", db);

            let key = Sha256::hash(&[b"key"]);
            let value = Sha256::hash(&[b"value"]);
            let batch = db.new_batch_for_test::<_>().await.write(key, Some(value));
            let merkleized = crate::stateful::db::Unmerkleized::merkleize(batch)
                .await
                .unwrap();

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

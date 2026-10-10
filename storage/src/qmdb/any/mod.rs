//! An _Any_ authenticated database provides succinct proofs of any value ever associated with a
//! key.
//!
//! The specific variants provided within this module include:
//! - Unordered: The database does not maintain or require any ordering over the key space.
//!   - Fixed-size values
//!   - Variable-size values
//! - Ordered: The database maintains a total order over active keys.
//!   - Fixed-size values
//!   - Variable-size values
//!
//! # Examples
//!
//! ```ignore
//! // 1. Create a batch and apply it.
//! let batch = db.new_batch()
//!     .write(key, Some(value))    // upsert
//!     .write(other_key, None)     // delete
//!     .merkleize(&db, None, &mut Proportional).await?;
//! let root = batch.root();        // speculative root
//! let (db, _) = db.apply_batch(batch).await?;
//! let db = db.commit().await?;    // flush to disk
//! ```
//!
//! ```ignore
//! // 2. Fork two batches from the same parent. Apply one; the other is stale.
//! let parent = db.new_batch().write(k1, Some(v1))
//!     .merkleize(&db, None, &mut Proportional).await?;
//! let fork_a = parent.new_batch::<Sha256>().write(k2, Some(v2))
//!     .merkleize(&db, None, &mut Proportional).await?;
//! let fork_b = parent.new_batch::<Sha256>().write(k3, Some(v3))
//!     .merkleize(&db, None, &mut Proportional).await?;
//!
//! let (db, _) = db.apply_batch(fork_a).await?;   // OK -- includes parent
//! assert!(db.validate_batch(&fork_b).is_err());  // StaleBatch; applying would consume the db
//! ```
//!
//! ```ignore
//! // 3. Chain two batches. Apply parent first, then child.
//! let parent = db.new_batch().write(k1, Some(v1))
//!     .merkleize(&db, None, &mut Proportional).await?;
//! let child = parent.new_batch::<Sha256>().write(k2, Some(v2))
//!     .merkleize(&db, None, &mut Proportional).await?;
//!
//! let (db, _) = db.apply_batch(parent).await?;   // apply parent
//! let (db, _) = db.apply_batch(child).await?;    // ancestors skipped automatically
//! let db = db.commit().await?;
//! ```
//!
//! ```ignore
//! // 4. Chain two batches. Apply child directly (includes parent's changes).
//! let parent = db.new_batch().write(k1, Some(v1))
//!     .merkleize(&db, None, &mut Proportional).await?;
//! let child = parent.new_batch::<Sha256>().write(k2, Some(v2))
//!     .merkleize(&db, None, &mut Proportional).await?;
//!
//! let (db, _) = db.apply_batch(child).await?;    // OK -- includes parent
//! assert!(db.validate_batch(&parent).is_err());  // StaleBatch
//! ```
//!
//! ```ignore
//! // 5. Two independent chains. Apply the tail of one; the other chain is stale.
//! let a1 = db.new_batch().write(k1, Some(v1))
//!     .merkleize(&db, None, &mut Proportional).await?;
//! let a2 = a1.new_batch::<Sha256>().write(k2, Some(v2))
//!     .merkleize(&db, None, &mut Proportional).await?;
//!
//! let b1 = db.new_batch().write(k3, Some(v3))
//!     .merkleize(&db, None, &mut Proportional).await?;
//! let b2 = b1.new_batch::<Sha256>().write(k4, Some(v4))
//!     .merkleize(&db, None, &mut Proportional).await?;
//!
//! let (db, _) = db.apply_batch(a2).await?;   // OK -- includes a1
//! assert!(db.validate_batch(&b2).is_err());  // StaleBatch
//! ```
//!
//! ```ignore
//! // 6. Advance the floor with a policy. `Key` and `Value` are the caller's types, `Value` has an
//! //    `expiry` height, and `now` is the caller's current height. This policy evicts expired
//! //    updates at the floor, records each evicted key and value, and stops at the first unexpired
//! //    update. Stopping at the first unexpired update leaves any later expired updates to a later
//! //    walk. It decides at most 8 updates and passes at most 16 inactive locations.
//! struct Expire {
//!     now: u64,
//!     expired: Vec<(Key, Value)>,
//! }
//! impl<F: Family> Policy<F, Key, Value> for Expire {
//!     fn evicts(&self) -> bool {
//!         true
//!     }
//!     fn limits(&self, _inactive: usize) -> Limits {
//!         Limits { entries: 8, skips: 16 }
//!     }
//!     fn decide<'a>(&mut self, entry: Entry<'a, F, Key, Value>) -> Decision<'a, Value> {
//!         if entry.value().expiry > self.now {
//!             return entry.stop();
//!         }
//!         let key = entry.key().clone();
//!         let (decision, value) = entry.evict();
//!         self.expired.push((key, value));
//!         decision
//!     }
//! }
//! let mut policy = Expire { now, expired: Vec::new() };
//! let batch = db.new_batch().write(k1, Some(v1));
//! let merkleized = batch.merkleize(&db, None, &mut policy).await?;
//! let (db, _) = db.apply_batch(merkleized).await?;
//!
//! // Hold the floor at its inherited location.
//! let batch = db.new_batch().write(k2, None);
//! let merkleized = batch.merkleize(&db, None, &mut Hold).await?;
//! let (db, _) = db.apply_batch(merkleized).await?;
//!
//! // Keep at most 4 updates and pass at most 8 inactive locations.
//! let mut policy = Bounded { entries: 4, skips: 8 };
//! let batch = db.new_batch().write(k3, Some(v3));
//! let merkleized = batch.merkleize(&db, None, &mut policy).await?;
//! let (db, _) = db.apply_batch(merkleized).await?;
//! ```

use crate::{
    Context,
    index::Factory as IndexFactory,
    journal::{
        authenticated,
        authenticated::Config as MerkleConfig,
        contiguous::{fixed::Config as FConfig, variable::Config as VConfig},
    },
    merkle::{Family, Location},
    qmdb::{
        Error as QmdbError,
        any::operation::{Operation, Update},
        bitmap::Shared,
        metrics::Metrics,
        single_operation_root,
    },
    translator::Translator,
};
use commonware_codec::Codec;
use commonware_cryptography::Hasher;
use commonware_macros::boxed;
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use core::num::NonZeroUsize;
use std::sync::Arc;
use tracing::warn;

pub mod batch;
pub mod db;
pub mod operation;
#[cfg(any(test, feature = "test-traits"))]
pub mod traits;
pub mod value;
pub use value::{FixedValue, ValueEncoding, VariableValue};
pub mod ordered;
pub(crate) mod sync;
pub mod unordered;

/// Compute the authenticated root of a newly initialized database without opening storage.
///
/// The initial commit never carries metadata, so this root always represents
/// `CommitFloor(None, 0)`.
pub fn initial_root<F, U, H>() -> H::Digest
where
    F: Family,
    H: Hasher,
    U: Update,
    Operation<F, U>: Codec,
{
    single_operation_root::<F, H>(&Operation::<F, U>::CommitFloor(None, Location::new(0)))
}

pub(crate) const BITMAP_CHUNK_BYTES: usize = 64;

/// Configuration for an `Any` authenticated db.
#[derive(Clone)]
pub struct Config<T: Translator, J, S: Strategy, B = ()> {
    /// Configuration for the Merkle structure backing the authenticated journal.
    pub merkle_config: MerkleConfig<S>,

    /// Configuration for the operations log journal.
    pub journal_config: J,

    /// The translator used by the compressed index.
    pub translator: T,

    /// Maximum number of entries in the `(location -> key)` cache used during init to resolve
    /// snapshot collisions without re-reading the log; `None` disables it.
    pub init_cache: Option<NonZeroUsize>,

    /// Size (in bytes) of the read buffer used to replay the log during init.
    pub init_buffer: NonZeroUsize,

    /// The index's snapshot-build concurrency (see [crate::qmdb::SnapshotBuild::Concurrency]): `()`
    /// for index types that build serially, and the number of build tasks for index types that
    /// build in parallel. A value of `1` builds the index entirely on the init task. Values of
    /// `2` and `3` decode on the init task and insert on one or two workers. Larger values split
    /// between spawned decode and insert tasks while the init task merely forwards batches.
    pub init_concurrency: B,
}

/// Configuration for an `Any` authenticated db with fixed-size values.
pub type FixedConfig<T, S, B = ()> = Config<T, FConfig, S, B>;

/// Configuration for an `Any` authenticated db with variable-sized values.
pub type VariableConfig<T, C, S, B = ()> = Config<T, VConfig<C>, S, B>;

/// Initialize an `Any` authenticated db from the given config.
/// `Some(max_size)` selects the latest retained commit with at most `max_size` operations.
/// `None` selects the latest retained state.
///
/// The selected state is durable before return. Zero is invalid because the initial commit
/// requires one operation. Subsequent appends may exceed this initialization bound.
pub async fn init<F, E, U, H, I, J, S>(
    context: E,
    cfg: Config<I::Translator, J::Config, S, <I as crate::qmdb::SnapshotBuild<F>>::Concurrency>,
    max_size: Option<Location<F>>,
) -> Result<db::Db<F, E, J, I, H, U, BITMAP_CHUNK_BYTES, S>, QmdbError<F>>
where
    F: Family,
    E: Context + Spawner,
    U: Update,
    H: Hasher,
    I: IndexFactory<Value = Location<F>> + crate::qmdb::SnapshotBuild<F>,
    J: authenticated::Backing<E, Item = Operation<F, U>> + 'static,
    S: Strategy,
    Operation<F, U>: Codec,
{
    init_with_bitmap::<F, E, U, H, I, J, S, BITMAP_CHUNK_BYTES>(context, cfg, None, max_size, None)
        .await
}

/// Like [`init`] but accepts a pre-allocated bitmap (used by `current::Db`, which sizes pruned
/// chunks from grafted metadata). `bitmap = None` allocates internally.
#[boxed]
pub(crate) async fn init_with_bitmap<F, E, U, H, I, J, S, const N: usize>(
    context: E,
    cfg: Config<I::Translator, J::Config, S, <I as crate::qmdb::SnapshotBuild<F>>::Concurrency>,
    bitmap: Option<Arc<Shared<N>>>,
    max_size: Option<Location<F>>,
    pair_absorption_threshold: Option<u64>,
) -> Result<db::Db<F, E, J, I, H, U, N, S>, QmdbError<F>>
where
    F: Family,
    E: Context + Spawner,
    U: Update,
    H: Hasher,
    I: IndexFactory<Value = Location<F>> + crate::qmdb::SnapshotBuild<F>,
    J: authenticated::Backing<E, Item = Operation<F, U>> + 'static,
    S: Strategy,
    Operation<F, U>: Codec,
{
    // Keep the selected commit unpublished until every variant-owned reconstruction constraint has
    // been checked against the same retained prefix.
    let pending = crate::qmdb::prepare_initialization::<F, E, J, H, S>(
        context.child("log"),
        cfg.merkle_config,
        cfg.journal_config,
        max_size,
    )
    .await?;

    // Snapshot replay requires both the selected commit and its floor to remain above the bitmap
    // boundary. Current also requires every absorbed chunk pair to exist at the selected size.
    let size = pending.bounds().end;
    if bitmap
        .as_ref()
        .is_some_and(|bitmap| size < bitmap.pruned_bits())
    {
        return Err(QmdbError::HistoricalFloorPruned(Location::new(size)));
    }
    let floor = crate::qmdb::validate_initialization(&pending, true).await?;
    if let (Some(bitmap), Some(floor)) = (&bitmap, floor)
        && *floor < bitmap.pruned_bits()
    {
        return Err(QmdbError::HistoricalFloorPruned(Location::new(size)));
    }
    if pair_absorption_threshold.is_some_and(|minimum| size < minimum) {
        return Err(QmdbError::HistoricalFloorPruned(Location::new(size)));
    }

    // Publish the selected journal prefix only after its in-memory state is reconstructible.
    let mut log = pending.finish().await?;

    if log.size() == 0 {
        warn!("Authenticated log is empty, initializing new db");
        let commit_floor = Operation::CommitFloor(None, Location::new(0));
        (log, _) = log.append(&commit_floor).await?;
        log = log.sync().await?;
    }

    // Rebuild the volatile snapshot and bitmap from the selected commit's retained floor.
    let index = I::new(context.child("index"), cfg.translator);
    let snapshot_context = context.child("snapshot");
    let metrics = Metrics::new(context);
    db::Db::init_from_log(
        snapshot_context,
        index,
        log,
        bitmap,
        cfg.init_concurrency,
        cfg.init_buffer,
        cfg.init_cache,
        metrics,
    )
    .await
}

#[cfg(test)]
// pub(crate) so qmdb/current can use the generic tests.
pub(crate) mod test {
    use super::*;
    use crate::{
        index::Unordered as UnorderedIndex,
        journal::contiguous::{
            Contiguous as _, Mutable, fixed::Config as FConfig, variable::Config as VConfig,
        },
        merkle::Location as GenericLocation,
        qmdb::{
            any::{FixedConfig, MerkleConfig, VariableConfig, db::Db},
            chain::Bounds,
        },
        translator::OneCap,
    };
    use commonware_codec::{Codec, CodecShared, Encode as _};
    use commonware_cryptography::{Hasher, Sha256, sha256::Digest};
    use commonware_runtime::{
        BufferPooler, Supervisor as _, buffer::paged::CacheRef, deterministic::Context,
    };
    use commonware_utils::{
        NZU16, NZU64, NZUsize, Widen,
        bitmap::{Prunable, Readable as _},
    };
    use core::{fmt::Debug, future::Future, pin::Pin};
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap},
        num::{NonZeroU16, NonZeroUsize},
        sync::Weak,
    };

    pub(crate) fn colliding_digest(prefix: u8, suffix: u64) -> Digest {
        let mut bytes = [0u8; 32];
        bytes[0] = prefix;
        bytes[24..].copy_from_slice(&suffix.to_be_bytes());
        Digest::from(bytes)
    }

    // Janky page & cache sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(11);

    pub(crate) fn fixed_db_config<T: Translator + Default>(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> FixedConfig<T, Sequential> {
        fixed_db_config_with_strategy(suffix, pooler, Sequential)
    }

    pub(crate) fn fixed_db_config_with_strategy<
        T: Translator + Default,
        S: commonware_parallel::Strategy,
    >(
        suffix: &str,
        pooler: &impl BufferPooler,
        strategy: S,
    ) -> FixedConfig<T, S> {
        fixed_db_config_full(suffix, pooler, strategy, ())
    }

    /// Shared config construction for every fixed-value flavor, generic over the strategy and
    /// the index's snapshot-build concurrency.
    pub(crate) fn fixed_db_config_full<
        T: Translator + Default,
        S: commonware_parallel::Strategy,
        B,
    >(
        suffix: &str,
        pooler: &impl BufferPooler,
        strategy: S,
        init_concurrency: B,
    ) -> FixedConfig<T, S, B> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        FixedConfig {
            merkle_config: MerkleConfig {
                metadata_partition: format!("metadata-{suffix}"),
                replay_buffer: NZUsize!(1024),
                strategy,
                cache: crate::journal::authenticated::single_region_cache(),
            },
            journal_config: FConfig {
                partition: format!("log-journal-{suffix}"),
                items_per_blob: NZU64!(7),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: T::default(),
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency,
        }
    }

    /// Like [fixed_db_config], typed for a partitioned index at the serial concurrency.
    pub(crate) fn fixed_db_config_partitioned<T: Translator + Default>(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> FixedConfig<T, Sequential, NonZeroUsize> {
        fixed_db_config_full(suffix, pooler, Sequential, NZUsize!(1))
    }

    /// Like [variable_db_config], typed for a partitioned index at the serial concurrency.
    pub(crate) fn variable_db_config_partitioned<T: Translator + Default>(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> VariableConfig<T, ((), ()), Sequential, NonZeroUsize> {
        variable_db_config_full(suffix, pooler, NZUsize!(1))
    }

    pub(crate) fn variable_db_config<T: Translator + Default>(
        suffix: &str,
        pooler: &impl BufferPooler,
    ) -> VariableConfig<T, ((), ()), Sequential> {
        variable_db_config_full(suffix, pooler, ())
    }

    /// Shared config construction for every variable-value flavor, generic over the index's
    /// snapshot-build concurrency.
    pub(crate) fn variable_db_config_full<T: Translator + Default, B>(
        suffix: &str,
        pooler: &impl BufferPooler,
        init_concurrency: B,
    ) -> VariableConfig<T, ((), ()), Sequential, B> {
        let page_cache = CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE);
        VariableConfig {
            merkle_config: MerkleConfig {
                metadata_partition: format!("metadata-{suffix}"),
                replay_buffer: NZUsize!(1024),
                strategy: Sequential,
                cache: crate::journal::authenticated::single_region_cache(),
            },
            journal_config: VConfig {
                partition: format!("log-journal-{suffix}"),
                items_per_section: NZU64!(7),
                compression: None,
                codec_config: ((), ()),
                page_cache,
                write_buffer: NZUsize!(1024),
                replay_buffer: NZUsize!(1024),
            },
            translator: T::default(),
            init_cache: Some(NZUsize!(1024)),
            init_buffer: NZUsize!(1 << 21),
            init_concurrency,
        }
    }

    use crate::{
        merkle::mmr,
        qmdb::any::traits::{DbAny, Provable, UnmerkleizedBatch as _},
    };

    type Error = crate::qmdb::Error<mmr::Family>;
    type Location = mmr::Location;

    /// Test recovery on non-empty db.
    pub(crate) async fn test_any_db_non_empty_recovery<F: Family, D, V: Clone + CodecShared>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
    {
        const ELEMENTS: u64 = 1000;

        // Commit initial batch.
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
        }
        let db = db.commit().await.unwrap();
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        let root = db.root();
        let op_count = db.size();
        let inactivity_floor_loc = db.inactivity_floor_loc();

        drop(db);
        let db = reopen_db(context.child("reopen").with_attribute("index", 1)).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_eq!(db.root(), root);

        // Write without applying (unapplied batch should be lost on reopen).
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        }
        drop(db);
        let db = reopen_db(context.child("reopen").with_attribute("index", 2)).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_eq!(db.root(), root);

        // Write without applying again.
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        }
        drop(db);
        let db = reopen_db(context.child("reopen").with_attribute("index", 3)).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.root(), root);

        // Three rounds of unapplied batches.
        for _ in 0..3 {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        }
        drop(db);
        let mut db = reopen_db(context.child("reopen").with_attribute("index", 4)).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.root(), root);

        // Now actually commit a batch.
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
        }
        db.commit().await.unwrap();
        let db = reopen_db(context.child("reopen").with_attribute("index", 5)).await;
        assert!(db.size() > op_count);
        assert_ne!(db.inactivity_floor_loc(), inactivity_floor_loc);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test recovery on empty db.
    pub(crate) async fn test_any_db_empty_recovery<F: Family, D, V: Clone + CodecShared>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
    {
        let root = db.root();

        drop(db);
        let db = reopen_db(context.child("reopen").with_attribute("index", 1)).await;
        assert_eq!(db.size(), 1);
        assert_eq!(db.root(), root);

        // Write without applying (unapplied batch should be lost on reopen).
        {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        }
        drop(db);
        let db = reopen_db(context.child("reopen").with_attribute("index", 2)).await;
        assert_eq!(db.size(), 1);
        assert_eq!(db.root(), root);

        // Write without applying again.
        {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        }
        drop(db);
        let db = reopen_db(context.child("reopen").with_attribute("index", 3)).await;
        assert_eq!(db.size(), 1);
        assert_eq!(db.root(), root);

        // Three rounds of unapplied batches.
        for _ in 0..3 {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let _merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        }
        drop(db);
        let mut db = reopen_db(context.child("reopen").with_attribute("index", 4)).await;
        assert_eq!(db.size(), 1);
        assert_eq!(db.root(), root);

        // Now actually commit a batch.
        {
            let mut batch = db.new_batch();
            for i in 0u64..1000 {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
        }
        db.commit().await.unwrap();
        let db = reopen_db(context.child("reopen").with_attribute("index", 5)).await;
        assert!(db.size() > 1);
        assert_ne!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Test that a commit after an older sync boundary is recovered without another sync.
    pub(crate) async fn test_any_db_commit_after_sync_recovery<F: Family, D, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
        V: Clone + CodecShared + Eq + std::fmt::Debug,
    {
        let key0 = Sha256::hash(&[&0u64.to_be_bytes()]);
        let key1 = Sha256::hash(&[&1u64.to_be_bytes()]);
        let value0 = make_value(100);
        let value1 = make_value(200);

        // Establish a synced baseline so recovery starts before the later commit.
        let merkleized = db
            .new_batch()
            .write(key0, Some(value0.clone()))
            .merkleize(&db, None, &mut Proportional)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        let db = db.sync().await.unwrap();

        // Commit a second batch without syncing; reopen must replay it from the journal.
        let merkleized = db
            .new_batch()
            .write(key1, Some(value1.clone()))
            .merkleize(&db, None, &mut Proportional)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        let committed_root = db.root();
        let committed_size = db.size();
        drop(db);

        let db = reopen_db(context.child("reopen").with_attribute("index", 1)).await;
        assert_eq!(db.root(), committed_root);
        assert_eq!(db.size(), committed_size);
        assert_eq!(db.get(&key0).await.unwrap(), Some(value0));
        assert_eq!(db.get(&key1).await.unwrap(), Some(value1));

        db.destroy().await.unwrap();
    }

    /// Test that state committed via an awaited start_sync handle is recovered on reopen.
    pub(crate) async fn test_any_db_start_sync_recovery<F: Family, D, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
        V: Clone + CodecShared + Eq + std::fmt::Debug,
    {
        let key0 = Sha256::hash(&[&0u64.to_be_bytes()]);
        let value0 = make_value(100);

        // Apply a batch and begin committing it, awaiting the handle for durability.
        let merkleized = db
            .new_batch()
            .write(key0, Some(value0.clone()))
            .merkleize(&db, None, &mut Proportional)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let (db, handle) = db.start_sync().await.unwrap();
        handle.await.unwrap();
        let committed_root = db.root();
        let committed_size = db.size();
        drop(db);

        let db = reopen_db(context.child("reopen").with_attribute("index", 1)).await;
        assert_eq!(db.root(), committed_root);
        assert_eq!(db.size(), committed_size);
        assert_eq!(db.get(&key0).await.unwrap(), Some(value0));

        db.destroy().await.unwrap();
    }

    /// Pruning to a floor advanced by an applied-but-uncommitted batch must not durably outrun
    /// the last durable commit: after a crash, the recovered commit's floor would lie below the
    /// pruned boundary and the database could never reopen.
    pub(crate) async fn test_any_db_prune_after_unsynced_floor_recovery<
        F: Family,
        D,
        V: Clone + CodecShared,
    >(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
    {
        const ELEMENTS: u64 = 1000;

        // Establish a durable state whose last commit declares an early inactivity floor.
        let mut batch = db.new_batch();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            batch = batch.write(k, Some(make_value(i)));
        }
        let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        let durable_floor = db.inactivity_floor_loc();

        // Apply (but do not commit) a batch that advances the in-memory floor well past the
        // durable commit's floor.
        let mut batch = db.new_batch();
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            batch = batch.write(k, Some(make_value(i + 1)));
        }
        let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let unsynced_floor = db.inactivity_floor_loc();
        assert!(unsynced_floor > durable_floor);

        // Prune to the in-memory floor, then crash before any further commit.
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        let root = db.root();
        let op_count = db.size();
        drop(db);

        // Reopening must succeed: pruning made the floor-declaring commit durable before the
        // journal durably advanced its boundary past positions that commit still needs.
        let db = reopen_db(context.child("reopen").with_attribute("index", 1)).await;
        assert_eq!(db.size(), op_count);
        assert_eq!(db.inactivity_floor_loc(), unsynced_floor);
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    /// Open a prior committed state at a bound and recover it on ordinary reopen.
    pub(crate) async fn test_any_db_bounded_initialization_recovery<D, V>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        bounded_db: impl Fn(Context, Location) -> Pin<Box<dyn Future<Output = Result<D, Error>> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest>,
        V: Clone + CodecShared + Eq + std::fmt::Debug,
    {
        let key0 = Sha256::hash(&[&0u64.to_be_bytes()]);
        let key1 = Sha256::hash(&[&1u64.to_be_bytes()]);
        let key2 = Sha256::hash(&[&2u64.to_be_bytes()]);
        let initial_root = db.root();
        let initial_size = db.size();
        let initial_floor = db.inactivity_floor_loc();

        // Selecting the earlier empty commit must rebuild an empty snapshot.
        let merkleized = db
            .new_batch()
            .merkleize(&db, None, &mut Proportional)
            .await
            .unwrap();
        let (db, empty_range) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(empty_range.start, initial_size);
        assert_eq!(db.size(), empty_range.end);
        drop(db);
        let db = bounded_db(context.child("cap"), initial_size)
            .await
            .unwrap();
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.size(), initial_size);
        assert_eq!(db.inactivity_floor_loc(), initial_floor);
        assert_eq!(db.get_metadata().await.unwrap(), None);

        let value0_a = make_value(10);
        let value1_a = make_value(11);
        let metadata_a = make_value(12);

        let merkleized = db
            .new_batch()
            .write(key0, Some(value0_a.clone()))
            .write(key1, Some(value1_a.clone()))
            .merkleize(&db, Some(metadata_a.clone()), &mut Proportional)
            .await
            .unwrap();
        let (db, range_a) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        let root_a = db.root();
        let size_a = db.size();
        let floor_a = db.inactivity_floor_loc();
        assert_eq!(size_a, range_a.end);

        let value0_b = make_value(20);
        let value2_b = make_value(21);
        let metadata_b = make_value(22);

        let merkleized = db
            .new_batch()
            .write(key0, Some(value0_b))
            .write(key1, None)
            .write(key2, Some(value2_b))
            .merkleize(&db, Some(metadata_b), &mut Proportional)
            .await
            .unwrap();
        let (db, range_b) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(range_b.start, size_a);
        assert_ne!(db.root(), root_a);

        let value0_c = make_value(30);
        let value1_c = make_value(31);
        let metadata_c = make_value(32);
        let merkleized = db
            .new_batch()
            .write(key0, Some(value0_c))
            .write(key1, Some(value1_c))
            .write(key2, None)
            .merkleize(&db, Some(metadata_c), &mut Proportional)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        // Select a commit before a tail where
        // - the same key (`key0`) was updated multiple times
        // - `key1` was deleted then recreated, with opposite membership changes to `key2`
        //   keeping each batch's active-key delta at zero
        drop(db);
        let db = bounded_db(context.child("cap"), size_a).await.unwrap();
        assert_eq!(db.root(), root_a);
        assert_eq!(db.size(), size_a);
        assert_eq!(db.inactivity_floor_loc(), floor_a);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a.clone()));
        assert_eq!(db.get(&key0).await.unwrap(), Some(value0_a));
        assert_eq!(db.get(&key1).await.unwrap(), Some(value1_a));
        assert_eq!(db.get(&key2).await.unwrap(), None);

        db.commit().await.unwrap();
        let db = reopen_db(context.child("reopen_after_rewind")).await;
        assert_eq!(db.root(), root_a);
        assert_eq!(db.size(), size_a);
        assert_eq!(db.inactivity_floor_loc(), floor_a);
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_a));
        assert_eq!(db.get(&key0).await.unwrap(), Some(make_value(10)));
        assert_eq!(db.get(&key1).await.unwrap(), Some(make_value(11)));
        assert_eq!(db.get(&key2).await.unwrap(), None);

        // Fresh writes from the selected tip should produce a correct new chain and persist
        // across reopen.
        let value2_d = make_value(40);
        let metadata_d = make_value(41);
        let merkleized = db
            .new_batch()
            .write(key2, Some(value2_d.clone()))
            .merkleize(&db, Some(metadata_d.clone()), &mut Proportional)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_d.clone()));
        assert_eq!(db.get(&key0).await.unwrap(), Some(make_value(10)));
        assert_eq!(db.get(&key1).await.unwrap(), Some(make_value(11)));
        assert_eq!(db.get(&key2).await.unwrap(), Some(value2_d.clone()));

        drop(db);
        let db = reopen_db(context.child("reopen_after_rewind_new_writes")).await;
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_d));
        assert_eq!(db.get(&key0).await.unwrap(), Some(make_value(10)));
        assert_eq!(db.get(&key1).await.unwrap(), Some(make_value(11)));
        assert_eq!(db.get(&key2).await.unwrap(), Some(value2_d));

        // Reopen at the initial commit boundary (`first_commit_loc + 1`).
        drop(db);
        let db = bounded_db(context.child("cap"), initial_size)
            .await
            .unwrap();
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.size(), initial_size);
        assert_eq!(db.inactivity_floor_loc(), initial_floor);
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.get(&key0).await.unwrap(), None);
        assert_eq!(db.get(&key1).await.unwrap(), None);
        assert_eq!(db.get(&key2).await.unwrap(), None);

        db.commit().await.unwrap();
        let db = reopen_db(context.child("reopen_initial_boundary")).await;
        assert_eq!(db.root(), initial_root);
        assert_eq!(db.size(), initial_size);
        assert_eq!(db.inactivity_floor_loc(), initial_floor);
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert_eq!(db.get(&key0).await.unwrap(), None);
        assert_eq!(db.get(&key1).await.unwrap(), None);
        assert_eq!(db.get(&key2).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    /// Test that a large mixed workload can be authenticated and replayed correctly.
    #[boxed]
    pub(crate) async fn test_any_db_build_and_authenticate<D, V>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + Provable<mmr::Family>,
        V: CodecShared + Clone + Eq + std::hash::Hash + std::fmt::Debug,
        <D as Provable<mmr::Family>>::Operation: Codec,
    {
        use crate::qmdb::verify_proof;

        const ELEMENTS: u64 = 1000;

        let mut map = HashMap::<Digest, V>::default();
        {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v.clone()));
                map.insert(k, v);
            }

            // Update every 3rd key.
            for i in 0u64..ELEMENTS {
                if i % 3 != 0 {
                    continue;
                }
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value((i + 1) * 10000);
                batch = batch.write(k, Some(v.clone()));
                map.insert(k, v);
            }

            // Delete every 7th key.
            for i in 0u64..ELEMENTS {
                if i % 7 != 1 {
                    continue;
                }
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                batch = batch.write(k, None);
                map.remove(&k);
            }

            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
        }
        // Commit + sync with pruning raises inactivity floor.
        let db = db.sync().await.unwrap();
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();

        // Drop & reopen and ensure state matches.
        let root = db.root();
        db.sync().await.unwrap();
        let db = reopen_db(context.child("reopened")).await;
        assert_eq!(root, db.root());

        // State matches reference map.
        for i in 0u64..ELEMENTS {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            if let Some(map_value) = map.get(&k) {
                let Some(db_value) = db.get(&k).await.unwrap() else {
                    panic!("key not found in db: {k}");
                };
                assert_eq!(*map_value, db_value);
            } else {
                assert!(db.get(&k).await.unwrap().is_none());
            }
        }
        let bounds = db.bounds();
        let inactivity_floor = db.inactivity_floor_loc();
        for loc in *inactivity_floor..*bounds.end {
            let loc = Location::new(loc);
            let (proof, ops) = db.proof(loc, NZU64!(10)).await.unwrap();
            assert!(verify_proof::<Sha256, _, _>(&proof, loc, &ops, &root));
        }

        db.destroy().await.unwrap();
    }

    /// Test that replaying multiple updates of the same key on startup preserves correct state.
    pub(crate) async fn test_any_db_log_replay<
        F: Family,
        D,
        V: Clone + CodecShared + PartialEq + std::fmt::Debug,
    >(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
    {
        // Update the same key many times within a single batch.
        const UPDATES: u64 = 100;
        let k = Sha256::hash(&[&UPDATES.to_be_bytes()]);
        let mut last_value = None;
        {
            let mut batch = db.new_batch();
            for i in 0u64..UPDATES {
                let v = make_value(i * 1000);
                last_value = Some(v.clone());
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
        }
        let db = db.commit().await.unwrap();
        let root = db.root();

        // Reopen and verify the state is preserved correctly.
        drop(db);
        let db = reopen_db(context.child("reopened")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.get(&k).await.unwrap(), last_value);

        db.destroy().await.unwrap();
    }

    /// Test that historical_proof returns correct proofs for past database states.
    pub(crate) async fn test_any_db_historical_proof_basic<D, V: Clone + CodecShared>(
        _context: Context,
        mut db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + Provable<mmr::Family>,
        <D as Provable<mmr::Family>>::Operation: Codec + PartialEq + std::fmt::Debug,
    {
        use crate::qmdb::verify_proof;
        use commonware_utils::NZU64;

        // Add some operations
        const OPS: u64 = 20;
        {
            let mut batch = db.new_batch();
            for i in 0u64..OPS {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
        }
        let root_hash = db.root();
        let original_op_count = db.size();

        // Historical proof should match "regular" proof when historical size == current database size
        let max_ops = NZU64!(10);
        let start_loc = Location::new(5);
        let (historical_proof, historical_ops) = db
            .historical_proof(original_op_count, start_loc, max_ops)
            .await
            .unwrap();
        let (regular_proof, regular_ops) = db.proof(start_loc, max_ops).await.unwrap();

        assert_eq!(historical_proof.leaves, regular_proof.leaves);
        assert_eq!(historical_proof.digests, regular_proof.digests);
        assert_eq!(historical_ops, regular_ops);
        assert!(verify_proof::<Sha256, _, _>(
            &historical_proof,
            start_loc,
            &historical_ops,
            &root_hash,
        ));

        // Add more operations to the database
        {
            let mut batch = db.new_batch();
            for i in OPS..(OPS + 5) {
                let k = Sha256::hash(&[&(i + 1000).to_be_bytes()]); // different keys
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
        }

        // Historical proof should remain the same even though database has grown
        let (historical_proof2, historical_ops2) = db
            .historical_proof(original_op_count, start_loc, max_ops)
            .await
            .unwrap();
        assert_eq!(historical_proof2.leaves, original_op_count);
        assert_eq!(historical_proof2.digests, regular_proof.digests);
        assert_eq!(historical_ops2, regular_ops);
        assert!(verify_proof::<Sha256, _, _>(
            &historical_proof2,
            start_loc,
            &historical_ops2,
            &root_hash,
        ));

        db.destroy().await.unwrap();
    }

    /// Test that tampering with historical proofs causes verification to fail.
    pub(crate) async fn test_any_db_historical_proof_invalid<D, V: Clone + CodecShared>(
        _context: Context,
        mut db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + Provable<mmr::Family>,
        <D as Provable<mmr::Family>>::Operation: Codec + PartialEq + std::fmt::Debug + Clone,
    {
        use crate::qmdb::verify_proof;
        use commonware_utils::NZU64;

        // Apply two single-write batches and capture the commit-boundary size after the
        // first batch. `historical_proof` requires the historical size to land on a commit
        // boundary when the db commits to an inactive peak boundary.
        let mut historical_op_count = Location::new(0);
        for i in 0u64..2 {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            let v = make_value(i * 1000);
            let merkleized = db
                .new_batch()
                .write(k, Some(v))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
            if i == 0 {
                historical_op_count = db.bounds().end;
            }
        }

        let expected_ops_len = (*historical_op_count - 1) as usize;
        let (proof, ops) = db
            .historical_proof(historical_op_count, Location::new(1), NZU64!(10))
            .await
            .unwrap();
        assert_eq!(proof.leaves, historical_op_count);
        assert_eq!(ops.len(), expected_ops_len);

        // Changing the proof digests should cause verification to fail
        {
            let mut tampered_proof = proof.clone();
            tampered_proof.digests[0] = Sha256::hash(&[b"invalid"]);
            let root_hash = db.root();
            assert!(!verify_proof::<Sha256, _, _>(
                &tampered_proof,
                Location::new(1),
                &ops,
                &root_hash,
            ));
        }

        // Appending an extra digest should cause verification to fail
        {
            let mut tampered_proof = proof.clone();
            tampered_proof.digests.push(Sha256::hash(&[b"invalid"]));
            let root_hash = db.root();
            assert!(!verify_proof::<Sha256, _, _>(
                &tampered_proof,
                Location::new(1),
                &ops,
                &root_hash,
            ));
        }

        // Changing the ops should cause verification to fail
        {
            let root_hash = db.root();
            let mut tampered_ops = ops.clone();
            // Swap first two ops if we have at least 2
            if tampered_ops.len() >= 2 {
                tampered_ops.swap(0, 1);
                assert!(!verify_proof::<Sha256, _, _>(
                    &proof,
                    Location::new(1),
                    &tampered_ops,
                    &root_hash,
                ));
            }
        }

        // Appending an extra (duplicate) op should cause verification to fail
        {
            let root_hash = db.root();
            let mut tampered_ops = ops.clone();
            tampered_ops.push(tampered_ops[0].clone());
            assert!(!verify_proof::<Sha256, _, _>(
                &proof,
                Location::new(1),
                &tampered_ops,
                &root_hash,
            ));
        }

        // Changing the start location should cause verification to fail
        {
            let root_hash = db.root();
            assert!(!verify_proof::<Sha256, _, _>(
                &proof,
                Location::new(2),
                &ops,
                &root_hash,
            ));
        }

        // Changing the root digest should cause verification to fail
        {
            let invalid_root = Sha256::hash(&[b"invalid"]);
            assert!(!verify_proof::<Sha256, _, _>(
                &proof,
                Location::new(1),
                &ops,
                &invalid_root,
            ));
        }

        // Changing the proof leaves count should cause verification to fail
        {
            let mut tampered_proof = proof.clone();
            tampered_proof.leaves = Location::new(100);
            let root_hash = db.root();
            assert!(!verify_proof::<Sha256, _, _>(
                &tampered_proof,
                Location::new(1),
                &ops,
                &root_hash,
            ));
        }

        db.destroy().await.unwrap();
    }

    /// Test historical_proof edge cases: singleton db, limited ops, min position.
    pub(crate) async fn test_any_db_historical_proof_edge_cases<D, V: Clone + CodecShared>(
        _context: Context,
        mut db: D,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<mmr::Family, Key = Digest, Value = V, Digest = Digest> + Provable<mmr::Family>,
        <D as Provable<mmr::Family>>::Operation: Codec + PartialEq + std::fmt::Debug,
    {
        use commonware_utils::NZU64;

        // Apply a sequence of single-write batches and record the commit-boundary size
        // reached after each. `historical_proof` requires the historical size to be a
        // commit boundary when the db commits to an inactive peak boundary, so we anchor each test on
        // one of the boundaries we recorded here rather than hardcoding sizes that depend
        // on internal floor-raising behavior.
        let initial_size = db.bounds().end;
        let mut boundaries = vec![initial_size];
        for i in 0u64..5 {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            let v = make_value(i * 1000);
            let merkleized = db
                .new_batch()
                .write(k, Some(v))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
            boundaries.push(db.bounds().end);
        }

        // Singleton historical state: only the initial CommitFloor is visible.
        let singleton_size = boundaries[0];
        let (single_proof, single_ops) = db
            .historical_proof(singleton_size, Location::new(0), NZU64!(1))
            .await
            .unwrap();
        assert_eq!(single_proof.leaves, singleton_size);
        assert_eq!(single_ops.len(), 1);

        // max_ops exceeds the ops remaining at this historical size, so the returned count
        // is capped at `historical_size - start_loc`. Anchor at the earliest post-batch
        // boundary that has at least 3 ops past `boundaries[1]`.
        let limited_size = boundaries[2];
        let limited_start = boundaries[1];
        let expected_limited = (*limited_size - *limited_start) as usize;
        assert!(expected_limited > 0);
        let (_limited_proof, limited_ops) = db
            .historical_proof(limited_size, limited_start, NZU64!(20))
            .await
            .unwrap();
        assert_eq!(limited_ops.len(), expected_limited);

        // Standard historical proof anchored at an early commit boundary, requesting a
        // bounded number of ops within the historical range.
        let min_size = boundaries[2];
        let max_ops = NZU64!(3);
        let expected_min = core::cmp::min(max_ops.get(), *min_size - 1) as usize;
        let (min_proof, min_ops) = db
            .historical_proof(min_size, Location::new(1), max_ops)
            .await
            .unwrap();
        assert_eq!(min_proof.leaves, min_size);
        assert_eq!(min_ops.len(), expected_min);

        db.destroy().await.unwrap();
    }

    /// Test making multiple commits, one of which deletes a key from a previous commit.
    pub(crate) async fn test_any_db_multiple_commits_delete_replayed<F: Family, D, V>(
        context: Context,
        mut db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> V,
    ) where
        D: DbAny<F, Key = Digest, Value = V, Digest = Digest>,
        V: Clone + CodecShared + Eq + std::fmt::Debug,
    {
        let mut map = HashMap::<Digest, V>::default();
        const ELEMENTS: u64 = 10;
        let metadata_value = make_value(42);
        let key_at = |j: u64, i: u64| Sha256::hash(&[&(j * 1000 + i).to_be_bytes()]);
        for j in 0u64..ELEMENTS {
            let mut batch = db.new_batch();
            for i in 0u64..ELEMENTS {
                let k = key_at(j, i);
                let v = make_value(i * 1000);
                batch = batch.write(k, Some(v.clone()));
                map.insert(k, v);
            }
            let merkleized = batch
                .merkleize(&db, Some(metadata_value.clone()), &mut Proportional)
                .await
                .unwrap();
            (db, _) = db.apply_batch(merkleized).await.unwrap();
            db = db.commit().await.unwrap();
        }
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata_value));
        let k = key_at(ELEMENTS - 1, ELEMENTS - 1);

        let merkleized = db
            .new_batch()
            .write(k, None)
            .merkleize(&db, None, &mut Proportional)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(db.get(&k).await.unwrap().is_none());

        let root = db.root();
        drop(db);
        let db = reopen_db(context.child("reopened")).await;
        assert_eq!(root, db.root());
        assert_eq!(db.get_metadata().await.unwrap(), None);
        assert!(db.get(&k).await.unwrap().is_none());

        db.destroy().await.unwrap();
    }

    /// State of an `any` db that a rebuild from the log must reproduce.
    struct Observed<F: Family, D, V> {
        /// Number of active keys.
        active_keys: usize,
        /// Sorted snapshot locations in the translated bucket of each observed key.
        locs: Vec<Vec<GenericLocation<F>>>,
        /// Active locations of the bitmap in `[pruned_bits, len)`.
        bits: Vec<u64>,
        /// Length of the bitmap.
        len: u64,
        /// Inactivity floor.
        floor: GenericLocation<F>,
        /// Root.
        root: D,
        /// Value of each observed key.
        values: Vec<Option<V>>,
    }

    /// Observe the state of `db` for `keys`.
    async fn observe<F, C, I, H, U, const N: usize, S>(
        db: &Db<F, Context, C, I, H, U, N, S>,
        keys: &[U::Key],
    ) -> Observed<F, H::Digest, U::Value>
    where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>>,
        H: Hasher,
        U: Update,
        S: Strategy,
        Operation<F, U>: Codec,
    {
        let mut values = Vec::with_capacity(keys.len());
        for key in keys {
            values.push(db.get(key).await.unwrap());
        }
        let bitmap = &db.bitmap;
        Observed {
            active_keys: db.active_keys,
            locs: keys
                .iter()
                .map(|key| {
                    let mut locs: Vec<_> = db.snapshot.get(key).copied().collect();
                    locs.sort();
                    locs
                })
                .collect(),
            bits: (bitmap.pruned_bits()..bitmap.len())
                .filter(|loc| bitmap.get_bit(*loc))
                .collect(),
            len: bitmap.len(),
            floor: db.inactivity_floor_loc(),
            root: db.root(),
            values,
        }
    }

    /// Commit and drop `db`, await `reopen` to rebuild it from the log, and assert the rebuilt
    /// snapshot locations, bitmap, inactivity floor, root, and values of `keys` equal the live
    /// ones. The live snapshot must also hold as many entries as active keys. Returns the rebuilt
    /// db.
    ///
    /// The rebuilt pruned prefix is the retained log start rounded down to a chunk boundary, so it
    /// lies below the live prefix after a prune whose chunk floor exceeds the retained start.
    #[boxed]
    pub(crate) async fn assert_rebuild_matches<F, C, I, H, U, const N: usize, S>(
        db: Db<F, Context, C, I, H, U, N, S>,
        reopen: impl Future<Output = Db<F, Context, C, I, H, U, N, S>>,
        keys: &[U::Key],
    ) -> Db<F, Context, C, I, H, U, N, S>
    where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>>,
        H: Hasher,
        U: Update<Value: PartialEq + Debug>,
        S: Strategy,
        Operation<F, U>: Codec,
    {
        assert_eq!(
            db.snapshot.items(),
            db.active_keys,
            "live snapshot entries diverged from active keys",
        );
        assert_exact(&db).await;

        // Capture the live state, then commit, drop, and rebuild from the log.
        let live = observe(&db, keys).await;
        let pruned = db.bitmap.pruned_bits();
        let start = *db.bounds().start;
        db.commit().await.unwrap();
        let db = reopen.await;

        // The rebuilt pruned prefix derives from the retained start.
        let chunk_bits = Prunable::<N>::CHUNK_SIZE_BITS;
        assert_eq!(
            db.bitmap.pruned_bits(),
            start / chunk_bits * chunk_bits,
            "pruned_bits diverged from the retained start on reopen",
        );
        assert!(
            db.bitmap.pruned_bits() <= pruned,
            "pruned_bits exceeds the live prefix on reopen",
        );

        // Every captured value must survive the rebuild.
        let rebuilt = observe(&db, keys).await;
        assert_eq!(
            rebuilt.active_keys, live.active_keys,
            "active keys diverged on reopen",
        );
        assert_eq!(
            rebuilt.locs, live.locs,
            "snapshot locations diverged on reopen",
        );
        assert_eq!(rebuilt.len, live.len, "bitmap len diverged on reopen");
        assert_eq!(
            rebuilt.bits, live.bits,
            "active locations diverged on reopen",
        );
        assert_eq!(
            rebuilt.floor, live.floor,
            "inactivity floor diverged on reopen",
        );
        assert_eq!(rebuilt.root, live.root, "root diverged on reopen");
        assert_eq!(rebuilt.values, live.values, "values diverged on reopen");
        assert_exact(&db).await;
        db
    }

    /// Record in `live` the location of each key's last update in `ops` and remove each key
    /// `ops` last deletes. The first operation in `ops` lies at `start`.
    pub(crate) fn replay<F: Family, U: Update>(
        live: &mut BTreeMap<U::Key, GenericLocation<F>>,
        start: GenericLocation<F>,
        ops: &[Operation<F, U>],
    ) {
        for (i, op) in ops.iter().enumerate() {
            match op {
                Operation::Update(update) => {
                    live.insert(update.key().clone(), start + Widen::widen(i));
                }
                Operation::Delete(key) => {
                    live.remove(key);
                }
                Operation::CommitFloor(..) => {}
            }
        }
    }

    /// Replay the retained log of `db` and return the location of every live key's update.
    pub(crate) async fn live<F, C, I, H, U, const N: usize, S>(
        db: &Db<F, Context, C, I, H, U, N, S>,
    ) -> BTreeMap<U::Key, GenericLocation<F>>
    where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>>,
        H: Hasher,
        U: Update,
        S: Strategy,
        Operation<F, U>: Codec,
    {
        let bounds = db.bounds();
        let positions: Vec<u64> = (*bounds.start..*bounds.end).collect();
        let ops = db.log.read_many(&positions).await.unwrap();
        let mut live = BTreeMap::new();
        replay(&mut live, bounds.start, &ops);
        live
    }

    /// Assert that the activity bitmap of `db` is exact against a replay of its retained log.
    /// The bitmap covers the log. Every unpruned bit is set if and only if its location holds a
    /// live update or the last commit, and every live update lies at or above the inactivity
    /// floor. The active key count matches the live keys, and the snapshot maps each live key to
    /// its update and holds no other entry.
    pub(crate) async fn assert_exact<F, C, I, H, U, const N: usize, S>(
        db: &Db<F, Context, C, I, H, U, N, S>,
    ) where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>>,
        H: Hasher,
        U: Update,
        S: Strategy,
        Operation<F, U>: Codec,
    {
        let live = live(db).await;
        let size = *db.bounds().end;
        let floor = db.inactivity_floor_loc();
        assert!(
            live.values().all(|loc| *loc >= floor),
            "a live update lies below the inactivity floor",
        );
        assert_eq!(db.bitmap.len(), size, "bitmap length diverged from the log");
        assert_bits(db.bitmap.as_ref(), &live);
        assert_eq!(
            db.active_keys,
            live.len(),
            "active keys diverged from the log"
        );
        assert_eq!(
            db.snapshot.items(),
            live.len(),
            "snapshot entries diverged from the log",
        );
        for (key, loc) in &live {
            assert!(
                db.snapshot.get(key).any(|entry| entry == loc),
                "snapshot misses the live update at {loc}",
            );
        }
    }

    /// Assert that the unpruned bits of `bitmap` are set exactly at the locations in `live` and
    /// at the last location, which holds the commit.
    pub(crate) fn assert_bits<F: Family, K, const N: usize>(
        bitmap: &impl commonware_utils::bitmap::Readable<N>,
        live: &BTreeMap<K, GenericLocation<F>>,
    ) {
        let len = bitmap.len();
        let active: BTreeSet<u64> = live.values().map(|loc| **loc).chain([len - 1]).collect();
        for loc in bitmap.pruned_bits()..len {
            assert_eq!(
                bitmap.get_bit(loc),
                active.contains(&loc),
                "bit {loc} diverged from the live updates",
            );
        }
    }

    /// Siblings seeded by each chained-rebuild shape.
    const SIBLINGS: u64 = 48;

    /// Colliding sibling `i`. Every key the chained-rebuild shapes write shares one translated
    /// bucket.
    fn sibling(i: u64) -> Digest {
        colliding_digest(0xA0, i)
    }

    /// Expected value of every key written by applied batches.
    #[derive(Clone, Default)]
    struct Model {
        /// Value of each active key.
        values: BTreeMap<Digest, Digest>,
        /// Every key ever written.
        keys: BTreeSet<Digest>,
    }

    impl Model {
        /// Record `writes` as applied.
        fn apply(&mut self, writes: &[(Digest, Option<Digest>)]) {
            for &(key, value) in writes {
                self.keys.insert(key);
                match value {
                    Some(value) => self.values.insert(key, value),
                    None => self.values.remove(&key),
                };
            }
        }
    }

    /// Merkleize `writes` on top of `batch`.
    pub(crate) async fn build<F: Family, D>(
        db: &D,
        batch: D::Batch,
        writes: &[(Digest, Option<Digest>)],
    ) -> D::Merkleized
    where
        D: DbAny<F, Key = Digest, Value = Digest>,
    {
        writes
            .iter()
            .fold(batch, |batch, &(key, value)| batch.write(key, value))
            .merkleize(db, None, &mut Proportional)
            .await
            .unwrap()
    }

    /// Apply and commit `writes` as one batch, recording them in `model`.
    async fn write_all<F: Family, D>(
        db: D,
        model: &mut Model,
        writes: &[(Digest, Option<Digest>)],
    ) -> D
    where
        D: DbAny<F, Key = Digest, Value = Digest>,
    {
        let batch = build(&db, db.new_batch(), writes).await;
        let (db, _) = db.apply_batch(batch).await.unwrap();
        model.apply(writes);
        db.commit().await.unwrap()
    }

    /// Commit siblings `0..SIBLINGS`.
    async fn seed_siblings<F: Family, D>(
        db: D,
        model: &mut Model,
        make_value: &impl Fn(u64) -> Digest,
    ) -> D
    where
        D: DbAny<F, Key = Digest, Value = Digest>,
    {
        let writes: Vec<_> = (0..SIBLINGS)
            .map(|i| (sibling(i), Some(make_value(i))))
            .collect();
        write_all(db, model, &writes).await
    }

    /// Apply the chain A <- B <- C. A is applied and dropped before C is merkleized on B, so C
    /// resolves the keys A created through the base locations of the dropped prefix. B and C
    /// touch only keys A created, so a lost base location duplicates them silently.
    #[boxed]
    async fn apply_dropped_chain<F: Family, U, S, D>(
        db: D,
        model: &mut Model,
        make_value: &impl Fn(u64) -> Digest,
    ) -> D
    where
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        D: DbAny<
                F,
                Key = Digest,
                Value = Digest,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
                Batch = batch::UnmerkleizedBatch<F, Sha256, U, S>,
            >,
    {
        // A updates and deletes siblings and creates new ones.
        let a = vec![
            (sibling(5), Some(make_value(100))),
            (sibling(6), Some(make_value(101))),
            (sibling(7), None),
            (sibling(1000), Some(make_value(102))),
            (sibling(1001), Some(make_value(103))),
        ];

        // B and C update the keys A created.
        let b = vec![
            (sibling(1000), Some(make_value(104))),
            (sibling(1001), Some(make_value(105))),
        ];
        let c = vec![
            (sibling(1000), Some(make_value(106))),
            (sibling(1001), Some(make_value(107))),
        ];

        // Build A <- B, apply A and drop it, then merkleize C on B and apply it.
        let a_batch = build(&db, db.new_batch(), &a).await;
        let b_batch = build(&db, a_batch.new_batch::<Sha256>(), &b).await;
        let (db, _) = db.apply_batch(a_batch).await.unwrap();
        let db = db.commit().await.unwrap();
        let c_batch = build(&db, b_batch.new_batch::<Sha256>(), &c).await;
        let (db, _) = db.apply_batch(c_batch).await.unwrap();
        for writes in [&a, &b, &c] {
            model.apply(writes);
        }
        db
    }

    /// Apply the chain A <- B <- C by applying A, then C over pending B, so the applied and
    /// pending ancestors are both non-empty. On a db without active keys, every key in A's diff
    /// is created by A, so a key misresolved through either partition is duplicated silently.
    #[boxed]
    async fn apply_mixed_chain<F: Family, U, S, D>(
        db: D,
        model: &mut Model,
        make_value: &impl Fn(u64) -> Digest,
    ) -> D
    where
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        D: DbAny<
                F,
                Key = Digest,
                Value = Digest,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
                Batch = batch::UnmerkleizedBatch<F, Sha256, U, S>,
            >,
    {
        // A recreates deleted siblings and creates new ones.
        let a = vec![
            (sibling(0), Some(make_value(200))),
            (sibling(1), Some(make_value(201))),
            (sibling(1000), Some(make_value(202))),
            (sibling(1001), Some(make_value(203))),
        ];

        // B updates a key A created and creates a sibling. C updates keys A and B created.
        let b = vec![
            (sibling(1001), Some(make_value(204))),
            (sibling(2000), Some(make_value(205))),
        ];
        let c = vec![
            (sibling(1000), Some(make_value(206))),
            (sibling(2000), Some(make_value(207))),
        ];

        // Build A <- B <- C, then apply A and C.
        let a_batch = build(&db, db.new_batch(), &a).await;
        let b_batch = build(&db, a_batch.new_batch::<Sha256>(), &b).await;
        let c_batch = build(&db, b_batch.new_batch::<Sha256>(), &c).await;
        let (db, _) = db.apply_batch(a_batch).await.unwrap();
        let (db, _) = db.apply_batch(c_batch).await.unwrap();
        for writes in [&a, &b, &c] {
            model.apply(writes);
        }
        db
    }

    /// Apply the chain A <- B <- C <- D. A is applied and dropped before D is merkleized, and B
    /// is applied before D. D then resolves B's keys through the applied ancestor and the keys A
    /// shares with C through the base locations of the dropped prefix.
    #[boxed]
    async fn apply_crossed_chain<F: Family, U, S, D>(
        db: D,
        model: &mut Model,
        make_value: &impl Fn(u64) -> Digest,
    ) -> D
    where
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        D: DbAny<
                F,
                Key = Digest,
                Value = Digest,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
                Batch = batch::UnmerkleizedBatch<F, Sha256, U, S>,
            >,
    {
        // A updates and deletes siblings and creates new ones.
        let a = vec![
            (sibling(5), Some(make_value(300))),
            (sibling(6), Some(make_value(301))),
            (sibling(7), None),
            (sibling(1000), Some(make_value(302))),
            (sibling(1001), Some(make_value(303))),
            (sibling(1002), Some(make_value(304))),
        ];

        // B updates keys A updated and created, and creates a sibling.
        let b = vec![
            (sibling(5), Some(make_value(305))),
            (sibling(1000), Some(make_value(306))),
            (sibling(2000), Some(make_value(307))),
        ];

        // C updates keys A updated and created and recreates the key A deleted. B touches none
        // of them.
        let c = vec![
            (sibling(6), Some(make_value(308))),
            (sibling(7), Some(make_value(309))),
            (sibling(1001), Some(make_value(310))),
        ];

        // D updates keys written by A, B, and C.
        let d = vec![
            (sibling(5), Some(make_value(311))),
            (sibling(1001), Some(make_value(312))),
            (sibling(1002), Some(make_value(313))),
            (sibling(2000), Some(make_value(314))),
        ];

        // Build A <- B <- C, then apply A and drop it before D is merkleized on C.
        let a_batch = build(&db, db.new_batch(), &a).await;
        let b_batch = build(&db, a_batch.new_batch::<Sha256>(), &b).await;
        let c_batch = build(&db, b_batch.new_batch::<Sha256>(), &c).await;
        let (db, _) = db.apply_batch(a_batch).await.unwrap();
        let db = db.commit().await.unwrap();
        let d_batch = build(&db, c_batch.new_batch::<Sha256>(), &d).await;

        // Apply B, then D over pending C.
        let (db, _) = db.apply_batch(b_batch).await.unwrap();
        let (db, _) = db.apply_batch(d_batch).await.unwrap();
        for writes in [&a, &b, &c, &d] {
            model.apply(writes);
        }
        db
    }

    /// Assert `db` serves `model` for every written key, then that a rebuild from the log matches
    /// the live state. Returns the rebuilt db.
    #[boxed]
    async fn assert_model_rebuild<F, C, I, U, const N: usize, S>(
        db: Db<F, Context, C, I, Sha256, U, N, S>,
        model: &Model,
        reopen: impl Future<Output = Db<F, Context, C, I, Sha256, U, N, S>>,
    ) -> Db<F, Context, C, I, Sha256, U, N, S>
    where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>>,
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
    {
        assert_eq!(
            db.active_keys,
            model.values.len(),
            "active keys diverged from the model",
        );
        let keys: Vec<_> = model.keys.iter().copied().collect();
        for key in &keys {
            assert_eq!(
                db.get(key).await.unwrap(),
                model.values.get(key).copied(),
                "value of {key} diverged from the model",
            );
        }
        assert_rebuild_matches(db, reopen, &keys).await
    }

    /// Batches applied across dropped, applied, and pending ancestors must leave a live snapshot,
    /// bitmap, floor, root, and values equal to a rebuild from the log. A superseded location
    /// misresolved to `None` leaves a duplicate snapshot entry and a stale bitmap bit.
    pub(crate) async fn test_any_db_chained_rebuild<F, C, I, U, const N: usize, S, Fut>(
        context: Context,
        db: Db<F, Context, C, I, Sha256, U, N, S>,
        reopen: impl Fn(Context) -> Fut,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>>,
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        Db<F, Context, C, I, Sha256, U, N, S>: DbAny<
                F,
                Key = Digest,
                Value = Digest,
                Digest = Digest,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
                Batch = batch::UnmerkleizedBatch<F, Sha256, U, S>,
            >,
        Fut: Future<Output = Db<F, Context, C, I, Sha256, U, N, S>>,
    {
        // Shape 1: A is applied and dropped before C is merkleized on B.
        let mut model = Model::default();
        let db = seed_siblings(db, &mut model, &make_value).await;
        let db = apply_dropped_chain(db, &mut model, &make_value).await;
        let db = assert_model_rebuild(
            db,
            &model,
            reopen(context.child("rebuild").with_attribute("index", 1)),
        )
        .await;
        db.destroy().await.unwrap();

        // Shape 2: A is applied, then C is applied over pending B. The seed is deleted first, so
        // the chain starts without active keys.
        let db = reopen(context.child("shape").with_attribute("index", 2)).await;
        let mut model = Model::default();
        let db = seed_siblings(db, &mut model, &make_value).await;
        let clear: Vec<_> = (0..SIBLINGS).map(|i| (sibling(i), None)).collect();
        let db = write_all(db, &mut model, &clear).await;
        let db = apply_mixed_chain(db, &mut model, &make_value).await;
        let db = assert_model_rebuild(
            db,
            &model,
            reopen(context.child("rebuild").with_attribute("index", 2)),
        )
        .await;
        db.destroy().await.unwrap();

        // Shape 3: the applied ancestor and the dropped prefix both resolve keys in one apply.
        let db = reopen(context.child("shape").with_attribute("index", 3)).await;
        let mut model = Model::default();
        let db = seed_siblings(db, &mut model, &make_value).await;
        let db = apply_crossed_chain(db, &mut model, &make_value).await;
        let db = assert_model_rebuild(
            db,
            &model,
            reopen(context.child("rebuild").with_attribute("index", 3)),
        )
        .await;
        db.destroy().await.unwrap();

        // Shape 4: rewrite the seed eight times so the floor passes a bitmap chunk, then prune to
        // the sync boundary and reopen. Shape 3 then runs over a rebuilt snapshot and a pruned
        // bitmap.
        let db = reopen(context.child("shape").with_attribute("index", 4)).await;
        let mut model = Model::default();
        let mut db = seed_siblings(db, &mut model, &make_value).await;
        for round in 1..=8 {
            let writes: Vec<_> = (0..SIBLINGS)
                .map(|i| (sibling(i), Some(make_value(round * 1000 + i))))
                .collect();
            db = write_all(db, &mut model, &writes).await;
        }
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        db.commit().await.unwrap();
        let db = reopen(context.child("pruned")).await;
        assert!(
            db.bitmap.pruned_bits() > 0,
            "setup must prune a bitmap chunk",
        );
        let db = apply_crossed_chain(db, &mut model, &make_value).await;
        let db = assert_model_rebuild(
            db,
            &model,
            reopen(context.child("rebuild").with_attribute("index", 4)),
        )
        .await;
        db.destroy().await.unwrap();
    }

    use crate::qmdb::{
        any::{
            ordered::{fixed::Db as OrderedFixedDb, variable::Db as OrderedVariableDb},
            traits::MerkleizedBatch as MerkleizedTrait,
            unordered::{fixed::Db as UnorderedFixedDb, variable::Db as UnorderedVariableDb},
        },
        floor::{Bounded, Decision, Entry, Hold, Limits, Policy, Proportional},
    };
    use commonware_macros::{test_group, test_traced};
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        Clock as _, Metrics as _, Runner as _, deterministic, telemetry::metrics::metric_samples,
    };
    use core::time::Duration;
    use futures::{pin_mut, poll};
    use rand::RngExt as _;

    // Type aliases for all 12 MMR variants (all use OneCap for collision coverage).
    type UnorderedFixed =
        UnorderedFixedDb<mmr::Family, Context, Digest, Digest, Sha256, OneCap, Sequential>;
    type UnorderedVariable =
        UnorderedVariableDb<mmr::Family, Context, Digest, Digest, Sha256, OneCap, Sequential>;
    type OrderedFixed =
        OrderedFixedDb<mmr::Family, Context, Digest, Digest, Sha256, OneCap, Sequential>;
    type OrderedVariable =
        OrderedVariableDb<mmr::Family, Context, Digest, Digest, Sha256, OneCap, Sequential>;
    type UnorderedFixedP1 = unordered::fixed::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        Sequential,
    >;
    type UnorderedVariableP1 = unordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        Sequential,
    >;
    type OrderedFixedP1 = ordered::fixed::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        Sequential,
    >;
    type OrderedVariableP1 = ordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        1,
        Sequential,
    >;
    type UnorderedFixedP2 = unordered::fixed::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        Sequential,
    >;
    type UnorderedVariableP2 = unordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        Sequential,
    >;
    type OrderedFixedP2 = ordered::fixed::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        Sequential,
    >;
    type OrderedVariableP2 = ordered::variable::partitioned::Db<
        mmr::Family,
        Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        2,
        Sequential,
    >;

    // MMB type aliases for with_all_variants.
    mod mmb_types {
        use super::*;
        use crate::{
            index::{ordered::Index as OrderedIndex, unordered::Index as UnorderedIndex},
            journal::contiguous::{fixed::Journal as FJournal, variable::Journal as VJournal},
            merkle::{Location, mmb},
            qmdb::any::{
                operation::{Operation, update},
                value::{FixedEncoding, VariableEncoding},
            },
        };

        type MmbLocation = Location<mmb::Family>;

        pub type MmbUnorderedFixed = super::super::db::Db<
            mmb::Family,
            Context,
            FJournal<
                Context,
                Operation<mmb::Family, update::Unordered<Digest, FixedEncoding<Digest>>>,
            >,
            UnorderedIndex<OneCap, MmbLocation>,
            Sha256,
            update::Unordered<Digest, FixedEncoding<Digest>>,
            { crate::qmdb::any::BITMAP_CHUNK_BYTES },
            Sequential,
        >;

        pub type MmbUnorderedVariable = super::super::db::Db<
            mmb::Family,
            Context,
            VJournal<
                Context,
                Operation<mmb::Family, update::Unordered<Digest, VariableEncoding<Digest>>>,
            >,
            UnorderedIndex<OneCap, MmbLocation>,
            Sha256,
            update::Unordered<Digest, VariableEncoding<Digest>>,
            { crate::qmdb::any::BITMAP_CHUNK_BYTES },
            Sequential,
        >;

        pub type MmbOrderedFixed = super::super::db::Db<
            mmb::Family,
            Context,
            FJournal<
                Context,
                Operation<mmb::Family, update::Ordered<Digest, FixedEncoding<Digest>>>,
            >,
            OrderedIndex<OneCap, MmbLocation>,
            Sha256,
            update::Ordered<Digest, FixedEncoding<Digest>>,
            { crate::qmdb::any::BITMAP_CHUNK_BYTES },
            Sequential,
        >;

        pub type MmbOrderedVariable = super::super::db::Db<
            mmb::Family,
            Context,
            VJournal<
                Context,
                Operation<mmb::Family, update::Ordered<Digest, VariableEncoding<Digest>>>,
            >,
            OrderedIndex<OneCap, MmbLocation>,
            Sha256,
            update::Ordered<Digest, VariableEncoding<Digest>>,
            { crate::qmdb::any::BITMAP_CHUNK_BYTES },
            Sequential,
        >;
    }
    use mmb_types::*;

    #[inline]
    fn to_digest(i: u64) -> Digest {
        Sha256::hash(&[&i.to_be_bytes()])
    }

    // Defines MMR-only variants (for tests that require mmr::Family, e.g. proof verification).
    macro_rules! with_mmr_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, uf, UnorderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, uv, UnorderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, of, OrderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, ov, OrderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, ufp1, UnorderedFixedP1, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, uvp1, UnorderedVariableP1, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, ofp1, OrderedFixedP1, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, ovp1, OrderedVariableP1, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, ufp2, UnorderedFixedP2, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, uvp2, UnorderedVariableP2, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, ofp2, OrderedFixedP2, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, ovp2, OrderedVariableP2, mmr::Family, variable_db_config_partitioned);
        };
    }

    // Defines all variants (MMR + MMB). Calls $cb!($($args)*, $label, $type, $family, $config) for each.
    macro_rules! with_all_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, uf, UnorderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, uv, UnorderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, of, OrderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, ov, OrderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, ufp1, UnorderedFixedP1, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, uvp1, UnorderedVariableP1, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, ofp1, OrderedFixedP1, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, ovp1, OrderedVariableP1, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, ufp2, UnorderedFixedP2, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, uvp2, UnorderedVariableP2, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, ofp2, OrderedFixedP2, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, ovp2, OrderedVariableP2, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, uf_mmb, MmbUnorderedFixed, mmb::Family, fixed_db_config);
            $cb!($($args)*, uv_mmb, MmbUnorderedVariable, mmb::Family, variable_db_config);
            $cb!($($args)*, of_mmb, MmbOrderedFixed, mmb::Family, fixed_db_config);
            $cb!($($args)*, ov_mmb, MmbOrderedVariable, mmb::Family, variable_db_config);
        };
    }

    // Defines the ordered variants (MMR + MMB).
    macro_rules! with_ordered_variants {
        ($cb:ident!($($args:tt)*)) => {
            $cb!($($args)*, of, OrderedFixed, mmr::Family, fixed_db_config);
            $cb!($($args)*, ov, OrderedVariable, mmr::Family, variable_db_config);
            $cb!($($args)*, ofp1, OrderedFixedP1, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, ovp1, OrderedVariableP1, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, ofp2, OrderedFixedP2, mmr::Family, fixed_db_config_partitioned);
            $cb!($($args)*, ovp2, OrderedVariableP2, mmr::Family, variable_db_config_partitioned);
            $cb!($($args)*, of_mmb, MmbOrderedFixed, mmb::Family, fixed_db_config);
            $cb!($($args)*, ov_mmb, MmbOrderedVariable, mmb::Family, variable_db_config);
        };
    }

    // Emit one `#[test_group("slow")] #[test_traced]` test per variant, named
    // `<f>_<variant_label>`. `with_reopen` hands the test a db plus a reopen
    // closure, `with_make_value` hands it just the db.
    macro_rules! test_for_variant {
        (with_cap: $f:ident, $traced:literal, $l:ident, $db:ty, $family:ty, $cfg:ident) => {
            paste::paste! {
                #[test_group("slow")]
                #[test_traced($traced)]
                fn [<$f _ $l>]() {
                    let executor = deterministic::Runner::default();
                    executor.start(|context| async move {
                        let ctx = context.child(stringify!($l));
                        let db = <$db>::init(ctx.child("storage"), $cfg::<OneCap>("db", &ctx), None)
                            .await
                            .unwrap();
                        $f(
                            ctx,
                            db,
                            |ctx| {
                                Box::pin(async move {
                                    <$db>::init(ctx.child("storage"), $cfg::<OneCap>("db", &ctx), None)
                                        .await
                                        .unwrap()
                                })
                            },
                            |ctx, cap| {
                                Box::pin(async move {
                                    <$db>::init(
                                        ctx.child("storage"),
                                        $cfg::<OneCap>("db", &ctx),
                                        Some(cap),
                                    )
                                    .await
                                })
                            },
                            to_digest,
                        )
                        .await;
                    });
                }
            }
        };
        (with_reopen: $f:ident, $traced:literal, $l:ident, $db:ty, $family:ty, $cfg:ident) => {
            paste::paste! {
                #[test_group("slow")]
                #[test_traced($traced)]
                fn [<$f _ $l>]() {
                    let executor = deterministic::Runner::default();
                    executor.start(|context| async move {
                        let ctx = context.child(stringify!($l));
                        let db = <$db>::init(ctx.child("storage"), $cfg::<OneCap>("db", &ctx), None)
                            .await
                            .unwrap();
                        $f(
                            ctx,
                            db,
                            |ctx| {
                                Box::pin(async move {
                                    <$db>::init(ctx.child("storage"), $cfg::<OneCap>("db", &ctx), None)
                                        .await
                                        .unwrap()
                                })
                            },
                            to_digest,
                        )
                        .await;
                    });
                }
            }
        };
        (with_make_value: $f:ident, $traced:literal, $l:ident, $db:ty, $family:ty, $cfg:ident) => {
            paste::paste! {
                #[test_group("slow")]
                #[test_traced($traced)]
                fn [<$f _ $l>]() {
                    let executor = deterministic::Runner::default();
                    executor.start(|context| async move {
                        let ctx = context.child(stringify!($l));
                        let db = <$db>::init(ctx.child("storage"), $cfg::<OneCap>("db", &ctx), None)
                            .await
                            .unwrap();
                        $f(ctx, db, to_digest).await;
                    });
                }
            }
        };
        (with_seeds: $f:ident, $traced:literal, $l:ident, $db:ty, $family:ty, $cfg:ident) => {
            paste::paste! {
                #[rstest::rstest]
                #[test_traced($traced)]
                fn [<$f _ $l>](#[values(0, 1, 7, 0x5133)] seed: u64) {
                    let executor = deterministic::Runner::seeded(seed);
                    executor.start(|context| async move {
                        let ctx = context.child(stringify!($l));
                        let db = <$db>::init(ctx.child("storage"), $cfg::<OneCap>("db", &ctx), None)
                            .await
                            .unwrap();
                        $f(ctx, db, to_digest).await;
                    });
                }
            }
        };
    }

    // Generate one slow test per variant across all variants (MMR + MMB).
    macro_rules! test_for_all_variants {
        (with_reopen: $f:ident, $traced:literal) => {
            with_all_variants!(test_for_variant!(with_reopen: $f, $traced));
        };
        (with_make_value: $f:ident, $traced:literal) => {
            with_all_variants!(test_for_variant!(with_make_value: $f, $traced));
        };
    }

    // Generate one slow test per variant across the MMR-only variants (for
    // tests that use mmr::Family-specific features like Location::new or
    // verify_proof).
    macro_rules! test_for_mmr_variants {
        (with_reopen: $f:ident, $traced:literal) => {
            with_mmr_variants!(test_for_variant!(with_reopen: $f, $traced));
        };
        (with_make_value: $f:ident, $traced:literal) => {
            with_mmr_variants!(test_for_variant!(with_make_value: $f, $traced));
        };
    }

    test_for_all_variants!(with_reopen: test_any_db_log_replay, "WARN");
    test_for_mmr_variants!(with_reopen: test_any_db_build_and_authenticate, "WARN");
    test_for_mmr_variants!(with_make_value: test_any_db_historical_proof_basic, "WARN");
    test_for_mmr_variants!(with_make_value: test_any_db_historical_proof_invalid, "WARN");
    test_for_mmr_variants!(with_make_value: test_any_db_historical_proof_edge_cases, "WARN");
    test_for_all_variants!(with_reopen: test_any_db_multiple_commits_delete_replayed, "WARN");
    test_for_all_variants!(with_reopen: test_any_db_non_empty_recovery, "WARN");
    test_for_all_variants!(with_reopen: test_any_db_empty_recovery, "WARN");
    test_for_all_variants!(with_reopen: test_any_db_commit_after_sync_recovery, "WARN");
    test_for_all_variants!(with_reopen: test_any_db_start_sync_recovery, "WARN");
    test_for_all_variants!(with_reopen: test_any_db_prune_after_unsynced_floor_recovery, "WARN");
    test_for_all_variants!(with_reopen: test_any_db_chained_rebuild, "WARN");
    test_for_all_variants!(with_make_value: test_any_policy_hold, "WARN");
    test_for_all_variants!(with_reopen: test_any_policy_keep_evict_and_recover, "WARN");
    test_for_all_variants!(with_make_value: test_any_policy_limits_after_colliding_writes, "WARN");
    test_for_all_variants!(with_make_value: test_any_policy_matches_proportional, "WARN");
    test_for_all_variants!(with_make_value: test_any_policy_decisions_match_writes, "WARN");
    test_for_all_variants!(with_make_value: test_any_policy_after_staged_writes, "WARN");
    test_for_all_variants!(with_reopen: test_any_policy_after_ancestor_applied, "WARN");
    test_for_all_variants!(with_reopen: test_any_activity_depths, "WARN");
    test_for_all_variants!(with_make_value: test_any_proportional_bound, "WARN");
    test_for_all_variants!(with_make_value: test_any_policy_limits_with_writes, "WARN");
    test_for_all_variants!(with_reopen: test_any_policy_own_writes, "WARN");
    test_for_all_variants!(with_reopen: test_any_policy_evicts_parent_created_key, "WARN");
    test_for_all_variants!(with_make_value: test_any_policy_ancestor_twins, "WARN");
    test_for_all_variants!(with_make_value: test_any_proportional_one_batch, "WARN");
    test_for_variant!(
        with_seeds: test_any_proportional_randomized_bound,
        "WARN",
        uf,
        UnorderedFixed,
        mmr::Family,
        fixed_db_config
    );
    test_for_variant!(
        with_seeds: test_any_proportional_randomized_bound,
        "WARN",
        of,
        OrderedFixed,
        mmr::Family,
        fixed_db_config
    );
    test_for_variant!(
        with_seeds: test_any_proportional_pending_bound,
        "WARN",
        uf,
        UnorderedFixed,
        mmr::Family,
        fixed_db_config
    );
    test_for_variant!(
        with_seeds: test_any_proportional_pending_bound,
        "WARN",
        of,
        OrderedFixed,
        mmr::Family,
        fixed_db_config
    );
    with_ordered_variants!(
        test_for_variant!(with_reopen: test_any_ordered_policy_eviction_matrix, "WARN")
    );
    with_ordered_variants!(
        test_for_variant!(with_reopen: test_any_ordered_policy_repair_across_ancestors, "WARN")
    );
    test_for_variant!(
        with_reopen: test_any_policy_reads_in_one_read,
        "WARN",
        uf,
        UnorderedFixed,
        mmr::Family,
        fixed_db_config
    );
    test_for_variant!(
        with_reopen: test_any_policy_reads_in_one_read,
        "WARN",
        of,
        OrderedFixed,
        mmr::Family,
        fixed_db_config
    );
    test_for_variant!(
        with_make_value: test_any_policy_unordered_reads_nothing,
        "WARN",
        uf,
        UnorderedFixed,
        mmr::Family,
        fixed_db_config
    );
    with_mmr_variants!(
        test_for_variant!(with_cap: test_any_db_bounded_initialization_recovery, "WARN")
    );

    /// A test policy that decides each update from its key and records it.
    pub(crate) struct Script<F: Family, D> {
        /// The fixed limits the policy returns, or `None` for proportional limits.
        limits: Option<Limits>,
        /// Decides an update from its key.
        decide: D,
        /// The location, key, and value of each decided update, in order.
        pub(crate) visited: Vec<(GenericLocation<F>, Digest, Digest)>,
    }

    /// A scripted decision for an update.
    #[derive(Clone, Copy, Debug)]
    pub(crate) enum Choice {
        /// Move the update to the tip.
        Keep,
        /// Delete the key.
        Evict,
        /// Write the value for the key at the tip.
        Replace(Digest),
        /// End the walk without deciding the update.
        Stop,
    }

    impl<F: Family, D: FnMut(&Digest) -> Choice> Script<F, D> {
        /// Return a policy with fixed limits that decides each update with `decide`.
        pub(crate) const fn new(entries: usize, skips: u64, decide: D) -> Self {
            Self {
                limits: Some(Limits { entries, skips }),
                decide,
                visited: Vec::new(),
            }
        }

        /// Return a policy with proportional limits whose `decide` must keep every entry.
        pub(crate) const fn proportional(decide: D) -> Self {
            Self {
                limits: None,
                decide,
                visited: Vec::new(),
            }
        }

        /// Return the location of each decided update, in order.
        pub(crate) fn locations(&self) -> Vec<GenericLocation<F>> {
            self.visited.iter().map(|(loc, _, _)| *loc).collect()
        }
    }

    impl<F: Family, D: FnMut(&Digest) -> Choice> Policy<F, Digest, Digest> for Script<F, D> {
        fn evicts(&self) -> bool {
            self.limits.is_some()
        }

        fn limits(&self, made_inactive: usize) -> Limits {
            self.limits.unwrap_or_else(|| {
                Policy::<F, Digest, Digest>::limits(&Proportional, made_inactive)
            })
        }

        fn decide<'a>(&mut self, entry: Entry<'a, F, Digest, Digest>) -> Decision<'a, Digest> {
            self.visited
                .push((entry.location(), *entry.key(), *entry.value()));
            match (self.decide)(entry.key()) {
                Choice::Keep => entry.keep(),
                Choice::Evict => entry.evict().0,
                Choice::Replace(value) => entry.replace(value),
                Choice::Stop => entry.stop(),
            }
        }
    }

    pub(crate) const fn keep(_: &Digest) -> Choice {
        Choice::Keep
    }

    /// Merkleize `writes` on `batch` with [`Hold`].
    pub(crate) async fn hold_batch<F: Family, D>(
        db: &D,
        batch: D::Batch,
        writes: &[(Digest, Option<Digest>)],
    ) -> D::Merkleized
    where
        D: DbAny<F, Key = Digest, Value = Digest>,
    {
        writes
            .iter()
            .fold(batch, |batch, &(key, value)| batch.write(key, value))
            .merkleize(db, None, &mut Hold)
            .await
            .unwrap()
    }

    /// Apply `writes` as one batch with [`Hold`].
    pub(crate) async fn hold<F: Family, D>(db: D, writes: &[(Digest, Option<Digest>)]) -> D
    where
        D: DbAny<F, Key = Digest, Value = Digest>,
    {
        let merkleized = hold_batch(&db, db.new_batch(), writes).await;
        db.apply_batch(merkleized).await.unwrap().0
    }

    /// Merkleize `batch` with `policy` and without metadata through [`DbAny`], for callers whose
    /// generic database type implements the batch trait only through its [`DbAny::Batch`].
    async fn merkleize<F: Family, D>(
        db: &D,
        batch: D::Batch,
        policy: &mut (impl Policy<F, Digest, Digest> + Send),
    ) -> Result<D::Merkleized, crate::qmdb::Error<F>>
    where
        D: DbAny<F, Key = Digest, Value = Digest>,
    {
        batch.merkleize(db, None, policy).await
    }

    /// Merkleize `batch` with a policy whose entries and skips are unbounded and that decides each
    /// update with `choose`. Returns the merkleized batch and the decided locations.
    async fn decide<F: Family, D>(
        db: &D,
        batch: D::Batch,
        choose: impl FnMut(&Digest) -> Choice + Send,
    ) -> (D::Merkleized, Vec<GenericLocation<F>>)
    where
        D: DbAny<F, Key = Digest, Value = Digest>,
    {
        let mut policy = Script::new(usize::MAX, u64::MAX, choose);
        let merkleized = batch.merkleize(db, None, &mut policy).await.unwrap();
        (merkleized, policy.locations())
    }

    /// Replay the log of `db`, then each of the pending `batches` (oldest first). Return the
    /// location of every live key's update.
    async fn replayed<F: Family, D: Inspect<F>>(
        db: &D,
        batches: &[&D::Merkleized],
    ) -> BTreeMap<Digest, GenericLocation<F>> {
        let mut live = db.live().await;
        for batch in batches {
            let (start, ops) = D::ops(batch);
            replay(&mut live, start, &ops);
        }
        live
    }

    /// Return the ascending locations of the live updates after the log of `db` and the pending
    /// `batches` (oldest first).
    pub(crate) async fn active<F: Family, D: Inspect<F>>(
        db: &D,
        batches: &[&D::Merkleized],
    ) -> Vec<GenericLocation<F>> {
        let mut active: Vec<_> = replayed(db, batches).await.into_values().collect();
        active.sort();
        active
    }

    /// The state a floor walk sees: the state after a batch's writes.
    pub(crate) struct Written<F: Family> {
        /// The location of every live key's update.
        pub(crate) live: BTreeMap<Digest, GenericLocation<F>>,
        /// The tip the writes reach, where the walk ends.
        pub(crate) tip: GenericLocation<F>,
        /// The operations the writes make inactive: one for each update of a key live before the
        /// batch, whose update it supersedes, and two for each delete, which supersedes an update
        /// and is itself inactive.
        pub(crate) inactive: usize,
        /// The encoded operations the writes append.
        ops: Vec<Vec<u8>>,
    }

    impl<F: Family> Written<F> {
        /// Return the ascending locations of the live updates.
        pub(crate) fn active(&self) -> Vec<GenericLocation<F>> {
            let mut active: Vec<_> = self.live.values().copied().collect();
            active.sort();
            active
        }
    }

    /// Return the state after `writes` on `batch`, a child of the pending `ancestors` (oldest
    /// first) of `db`.
    ///
    /// Every policy sees the same state: the writes resolve before the floor walk, so every batch
    /// with these writes appends the same operations below the tip. [`Hold`] decides nothing, so
    /// its batch appends only those operations and its commit.
    pub(crate) async fn written<F: Family, D: Inspect<F>>(
        db: &D,
        ancestors: &[&D::Merkleized],
        batch: D::Batch,
        writes: &[(Digest, Option<Digest>)],
    ) -> Written<F>
    where
        Operation<F, D::Update>: Codec,
    {
        let held = hold_batch(db, batch, writes).await;
        let before = replayed(db, ancestors).await;
        let batches: Vec<_> = ancestors.iter().copied().chain([&held]).collect();
        let (_, ops) = D::ops(&held);
        let ops = &ops[..ops.len() - 1];
        let inactive = ops
            .iter()
            .map(|op| match op {
                Operation::Update(update) => usize::from(before.contains_key(update.key())),
                Operation::Delete(_) => 2,
                Operation::CommitFloor(..) => panic!("the writes append a commit"),
            })
            .sum();
        Written {
            live: replayed(db, &batches).await,
            tip: D::span(&held).tip.size - 1,
            inactive,
            ops: ops.iter().map(|op| op.encode().to_vec()).collect(),
        }
    }

    /// Return what the floor walk of `batch` appends: its operations from the tip of its writes up
    /// to its commit, an update as its key and value and a delete as its key and `None`. Asserts
    /// that its operations below the tip are the writes of `written`.
    pub(crate) fn appended<F: Family, D: Inspect<F>>(
        batch: &D::Merkleized,
        written: &Written<F>,
    ) -> Vec<(Digest, Option<Digest>)>
    where
        Operation<F, D::Update>: Codec,
    {
        let (start, ops) = D::ops(batch);
        let below = (*written.tip - *start) as usize;
        let prefix: Vec<_> = ops[..below].iter().map(|op| op.encode().to_vec()).collect();
        assert_eq!(
            prefix, written.ops,
            "the writes diverged from the held batch"
        );
        ops[below..ops.len() - 1]
            .iter()
            .map(|op| match op {
                Operation::Update(update) => (*update.key(), Some(*update.value())),
                Operation::Delete(key) => (*key, None),
                Operation::CommitFloor(..) => panic!("a commit precedes the last operation"),
            })
            .collect()
    }

    /// Sum the samples of the counter `name` across every database instance.
    pub(crate) fn counter(context: &Context, name: &str) -> u64 {
        metric_samples(&context.encode(), name)
            .map(|(_, value)| value.parse::<u64>().unwrap())
            .sum()
    }

    /// Model a fixed-limit walk from `floor` over the ascending `active` locations below
    /// `tip`, the tip of the batch's writes, where the policy stops at the `stops` locations and
    /// decides every other one. Returns the floor the walk reaches and the locations it visits,
    /// a stopped one included.
    ///
    /// Reaching an active update spends the inactive gap before it in skips; when the gap exceeds
    /// the remaining skips, the floor advances by them and the walk ends. Deciding an update spends
    /// an entry and moves the floor past it, and stopping leaves the floor at it. Once no active
    /// update remains, the floor moves to `tip` if the remaining skips reach it, and by them
    /// otherwise. With no entries left the walk ends.
    pub(crate) fn walk_model(
        active: &[u64],
        mut floor: u64,
        tip: u64,
        mut entries: usize,
        mut skips: u64,
        stops: &[u64],
    ) -> (u64, Vec<u64>) {
        let mut visited = Vec::new();
        while entries > 0 {
            let next = active
                .iter()
                .copied()
                .find(|loc| *loc >= floor && *loc < tip)
                .unwrap_or(tip);
            let gap = next - floor;
            if gap > skips {
                floor += skips;
                break;
            }
            skips -= gap;
            floor = next;
            if next == tip {
                break;
            }
            visited.push(next);
            if stops.contains(&next) {
                break;
            }
            floor = next + 1;
            entries -= 1;
        }
        (floor, visited)
    }

    /// [`Hold`] keeps the inherited floor while the batch's writes apply, and moves it to the new
    /// commit location when the batch empties the database.
    pub(crate) async fn test_any_policy_hold<F: Family, D>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        D: DbAny<F, Key = Digest, Value = Digest, Digest = Digest>,
    {
        let writes: Vec<_> = (0..4)
            .map(|i| (to_digest(i), Some(make_value(i))))
            .collect();
        let db = hold(db, &writes).await;
        let floor = db.inactivity_floor_loc();

        // Hold the floor for a batch that updates, deletes, and creates keys.
        let merkleized = db
            .new_batch()
            .write(to_digest(0), Some(make_value(100)))
            .write(to_digest(1), None)
            .write(to_digest(4), Some(make_value(4)))
            .merkleize(&db, None, &mut Hold)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();

        // The writes apply and the untouched keys keep their values.
        assert_eq!(db.inactivity_floor_loc(), floor);
        for (key, expected) in [
            (0, Some(make_value(100))),
            (1, None),
            (2, Some(make_value(2))),
            (3, Some(make_value(3))),
            (4, Some(make_value(4))),
        ] {
            assert_eq!(db.get(&to_digest(key)).await.unwrap(), expected);
        }

        // Deleting every key moves the floor to the new commit location.
        let deletes: Vec<_> = [0, 2, 3, 4].map(|i| (to_digest(i), None)).into();
        let db = hold(db, &deletes).await;
        assert_eq!(db.inactivity_floor_loc(), db.size() - 1);
        db.destroy().await.unwrap();
    }

    /// A policy in a batch with writes passes the locations the writes make inactive, keeps and
    /// evicts applied updates, and replaces and evicts the batch's own writes. The result
    /// survives commit, reopen, and prune.
    pub(crate) async fn test_any_policy_keep_evict_and_recover<F: Family, D>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> Digest,
    ) where
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        // Seed four keys in key order at 1..5, with the initial commit at 0 and the seed commit
        // at 5.
        let keys = [0x10, 0x20, 0x30, 0x40, 0x50].map(|prefix| colliding_digest(prefix, 0));
        let seed: Vec<_> = (0..4)
            .map(|i| (keys[i], Some(make_value(i as u64))))
            .collect();
        let db = hold(db, &seed).await;
        assert_eq!(*db.size(), 6);

        // Delete the smallest key, update the largest, and create a larger one. Both orderings
        // append the delete at 6, the update at 7, and the create at 8: an ordered batch rewrites
        // no predecessor, since the updated key precedes both the deleted key (by wrapping) and
        // the created one. The writes reach the tip 9.
        let with = |batch: D::Batch| {
            batch
                .write(keys[0], None)
                .write(keys[3], Some(make_value(103)))
                .write(keys[4], Some(make_value(4)))
        };
        let replacement = make_value(203);
        let choose = |key: &Digest| match key {
            key if *key == keys[1] => Choice::Keep,
            key if *key == keys[3] => Choice::Replace(replacement),
            _ => Choice::Evict,
        };

        // The active updates are the second and third keys at 2 and 3 and the batch's own writes
        // at 7 and 8. Reaching them passes 0 and 1, then 4 (superseded), 5 (the seed commit), and
        // 6 (the batch's delete): five skips. With four, the walk ends at 4 + 2 = 6.
        let mut policy = Script::new(usize::MAX, 4, choose);
        let merkleized = with(db.new_batch())
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();
        assert_eq!(policy.locations(), [2, 3].map(GenericLocation::<F>::new));
        assert_eq!(*D::span(&merkleized).inactivity_floor, 6);
        drop(merkleized);

        // With five skips, the policy keeps the second key, evicts the third, replaces the
        // batch's update of the largest key, and evicts the key the batch creates. Each decided
        // update sees the value the writes left, and the floor reaches the tip.
        let mut policy = Script::new(usize::MAX, 5, choose);
        let merkleized = with(db.new_batch())
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();
        let visited = [
            (2, keys[1], make_value(1)),
            (3, keys[2], make_value(2)),
            (7, keys[3], make_value(103)),
            (8, keys[4], make_value(4)),
        ]
        .map(|(loc, key, value)| (GenericLocation::<F>::new(loc), key, value));
        assert_eq!(policy.visited, visited);
        assert_eq!(*D::span(&merkleized).inactivity_floor, 9);

        // The decisions follow the writes in walk order. An ordered batch folds each evicted
        // key's link into its kept or replaced predecessor, so it appends no other rewrite.
        let (_, ops) = D::ops(&merkleized);
        let decided: Vec<_> = ops[3..ops.len() - 1]
            .iter()
            .map(|op| match op {
                Operation::Update(update) => (*update.key(), Some(*update.value())),
                Operation::Delete(key) => (*key, None),
                Operation::CommitFloor(..) => unreachable!(),
            })
            .collect();
        assert_eq!(
            decided,
            [
                (keys[1], Some(make_value(1))),
                (keys[2], None),
                (keys[3], Some(make_value(203))),
                (keys[4], None),
            ]
        );

        // The batch commits the tip as the floor. The created key is absent, so two keys remain.
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        assert_eq!(*db.inactivity_floor_loc(), 9);
        assert_eq!(db.live().await.len(), 2);
        db.assert_exact().await;
        let expected = [
            (keys[0], None),
            (keys[1], Some(make_value(1))),
            (keys[2], None),
            (keys[3], Some(make_value(203))),
            (keys[4], None),
        ];
        for (key, value) in expected {
            assert_eq!(db.get(&key).await.unwrap(), value);
        }

        // The state survives commit and reopen.
        let db = db.commit().await.unwrap();
        let root = db.root();
        let size = db.size();
        let floor = db.inactivity_floor_loc();
        drop(db);
        let db = reopen_db(context.child("committed")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.size(), size);
        assert_eq!(db.inactivity_floor_loc(), floor);
        for (key, value) in expected {
            assert_eq!(db.get(&key).await.unwrap(), value);
        }

        // The state survives prune and reopen.
        let db = db.sync().await.unwrap();
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        let root = db.root();
        let size = db.size();
        let floor = db.inactivity_floor_loc();
        drop(db);
        let db = reopen_db(context.child("pruned")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.size(), size);
        assert_eq!(db.inactivity_floor_loc(), floor);
        for (key, value) in expected {
            assert_eq!(db.get(&key).await.unwrap(), value);
        }
        db.destroy().await.unwrap();
    }

    /// Writes to keys that share a translated-key bucket with active updates leave the floor where
    /// [`walk_model`] predicts from the state after the writes under every limit pair, and the
    /// walk reads nothing past its window.
    pub(crate) async fn test_any_policy_limits_after_colliding_writes<F: Family, D: Inspect<F>>(
        context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        Operation<F, D::Update>: Codec,
    {
        // Lay out the initial commit at 0, six colliding updates at 1..7, and the seed commit
        // at 7.
        let keys: Vec<_> = (0..7).map(|i| colliding_digest(0xAA, i)).collect();
        let seed: Vec<_> = keys[..6]
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let db = hold(db, &seed).await;
        let floor = db.inactivity_floor_loc();
        let tip = db.size();
        assert_eq!((*floor, *tip), (0, 8));

        // Updating the last seeded key supersedes its update at 6, and creating a seventh key
        // supersedes nothing. Every active update shares the written keys' bucket.
        let writes = [
            (keys[5], Some(make_value(105))),
            (keys[6], Some(make_value(6))),
        ];
        let with = |batch: D::Batch| {
            writes
                .iter()
                .fold(batch, |batch, &(key, value)| batch.write(key, value))
        };

        // Both orderings append the update at 8 and the create at 9: an ordered batch rewrites no
        // predecessor, since the created key's predecessor is the updated one. The walk sees the
        // five untouched updates and both writes, up to the tip 10.
        let state = written(&db, &[], db.new_batch(), &writes).await;
        let active: Vec<u64> = state.active().into_iter().map(|loc| *loc).collect();
        assert_eq!(active, [1, 2, 3, 4, 5, 8, 9]);
        assert_eq!(*state.tip, 10);

        // Resolving the writes reads their bucket. [`Hold`] decides nothing, so its batch reads
        // only what the resolution reads.
        let items = || counter(&context, "log_journal_items_read_total");
        let before = items();
        drop(hold_batch(&db, db.new_batch(), &writes).await);
        let resolution = items() - before;
        assert!(
            resolution >= 6,
            "the resolution reads the six colliding updates"
        );

        // A window of one skip and one entry ends at 2, so the walk reads only the update at 1,
        // after the resolution's reads and before deciding it.
        let before = items();
        let mut reads = Vec::new();
        let mut policy = Script::new(1, 1, |_: &Digest| {
            reads.push(items());
            Choice::Keep
        });
        let merkleized = with(db.new_batch())
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();
        assert_eq!(
            policy.visited,
            [(GenericLocation::new(1), keys[0], make_value(0))]
        );
        assert_eq!(*D::span(&merkleized).inactivity_floor, 2);
        assert_eq!(reads, [before + resolution + 1]);
        assert_eq!(items(), before + resolution + 1);
        drop(merkleized);

        // Every limit pair matches the model. Entries beyond the five updates below the base decide
        // the batch's own writes.
        for entries in 0..=8 {
            for skips in 0..=8 {
                let (expected, decisions) =
                    walk_model(&active, *floor, *state.tip, entries, skips, &[]);
                let mut policy = Script::new(entries, skips, keep);
                let merkleized = with(db.new_batch())
                    .merkleize(&db, None, &mut policy)
                    .await
                    .unwrap();
                let reached = *D::span(&merkleized).inactivity_floor;
                let decided: Vec<u64> = policy.locations().into_iter().map(|loc| *loc).collect();
                assert_eq!(decided, decisions, "entries={entries} skips={skips}");
                assert_eq!(reached, expected, "entries={entries} skips={skips}");
            }
        }
        db.destroy().await.unwrap();
    }

    /// Under every pair of limits in a grid, a batch with no writes and a batch that updates,
    /// deletes, and creates keys walk the state after their writes, their own writes included, up
    /// to the tip those writes reach.
    ///
    /// A policy that keeps every update, and policies that evict, replace, and stop at chosen
    /// keys, decide the updates and reach the floor that [`walk_model`] predicts from that state.
    /// Each of their batches serves the values its decisions leave.
    ///
    /// Each batch then applies under a window that ends one skip short of the tip of its writes,
    /// commits the modeled floor, and serves the model. The batch with writes walks the state the
    /// applied batch with no writes leaves.
    ///
    /// The grid includes zero entries, zero skips, skips that exactly reach the tip, and windows
    /// that end inside the batch's writes.
    pub(crate) async fn test_any_policy_limits_with_writes<F: Family, D: Inspect<F>>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        Operation<F, D::Update>: Codec,
    {
        // Lay out the initial commit at 0, superseded updates at 1..4, active updates at 4..7,
        // the seed commit at 7, active updates at 8..11, and the last commit at 11.
        let keys =
            [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70].map(|prefix| colliding_digest(prefix, 0));
        let seed: Vec<_> = keys[..6]
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let mut db = hold(db, &seed).await;
        let updates: Vec<_> = keys[..3]
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64 + 100))))
            .collect();
        db = hold(db, &updates).await;
        let mut model = Model::default();
        model.apply(&seed);
        model.apply(&updates);

        // The second batch updates an applied key, deletes an updated one, and creates one key
        // between two others and one past the largest.
        let writes = [
            (keys[4], Some(make_value(204))),
            (keys[1], None),
            (colliding_digest(0x35, 0), Some(make_value(235))),
            (keys[6], Some(make_value(206))),
        ];

        // One script keeps every update. Each other script evicts, replaces, and stops at keys
        // live in both batches, and keeps the rest.
        let replacement = make_value(300);
        let scripts = [
            None,
            Some((keys[3], keys[0], keys[5])),
            Some((keys[5], keys[3], keys[2])),
        ];
        let choose = |script: Option<(Digest, Digest, Digest)>, key: &Digest| match script {
            Some((evicted, _, _)) if *key == evicted => Choice::Evict,
            Some((_, replaced, _)) if *key == replaced => Choice::Replace(replacement),
            Some((_, _, stopped)) if *key == stopped => Choice::Stop,
            _ => Choice::Keep,
        };

        for writes in [&[][..], &writes[..]] {
            let with = |batch: D::Batch| {
                writes
                    .iter()
                    .fold(batch, |batch, &(key, value)| batch.write(key, value))
            };
            let mut written_model = model.clone();
            written_model.apply(writes);
            let floor = *db.inactivity_floor_loc();
            let base = *db.size();

            // The walk sees the update of each live key: the batch's update, both creates, and
            // each predecessor an ordered batch rewrites lie at or above the base, and the
            // untouched updates below it.
            let state = written(&db, &[], db.new_batch(), writes).await;
            let active: Vec<u64> = state.active().into_iter().map(|loc| *loc).collect();
            let tip = *state.tip;
            if writes.is_empty() {
                assert_eq!(
                    (floor, base, tip, active.as_slice()),
                    (0, 12, 12, [4, 5, 6, 8, 9, 10].as_slice())
                );
            } else {
                assert_eq!(active.len(), 7);
                assert!(active.iter().filter(|loc| **loc >= base).count() >= 3);
            }
            let inactive = tip - floor - active.len() as u64;

            // The model covers the limit regimes the grid exercises: zero entries pass nothing,
            // zero skips cannot pass the initial commit, and with an entry for every live update
            // and one more, the walk reaches the tip with exactly as many skips as inactive
            // locations but not with one fewer.
            let model_of = |entries, skips| walk_model(&active, floor, tip, entries, skips, &[]);
            let entries = active.len() + 1;
            assert_eq!(model_of(0, u64::MAX), (floor, Vec::new()));
            assert_eq!(model_of(usize::MAX, 0), (floor, Vec::new()));
            assert_eq!(model_of(entries, inactive), (tip, active.clone()));
            assert!(model_of(entries, inactive - 1).0 < tip);

            // Every limit pair matches the model with each script's stops, and the batch serves
            // each decided key's evicted, replaced, or kept value. With writes, some windows end
            // inside them after deciding one of them.
            let mut inside = false;
            for script in scripts {
                let stops: Vec<u64> = script
                    .iter()
                    .map(|(_, _, stopped)| *state.live[stopped])
                    .collect();
                for entries in 0..=active.len() + 1 {
                    for skips in 0..=inactive + 1 {
                        let (expected, decisions) =
                            walk_model(&active, floor, tip, entries, skips, &stops);
                        let mut policy =
                            Script::new(entries, skips, |key: &Digest| choose(script, key));
                        let merkleized = with(db.new_batch())
                            .merkleize(&db, None, &mut policy)
                            .await
                            .unwrap();
                        let reached = *D::span(&merkleized).inactivity_floor;
                        let decided: Vec<u64> =
                            policy.locations().into_iter().map(|loc| *loc).collect();
                        assert_eq!(decided, decisions, "entries={entries} skips={skips}");
                        assert_eq!(reached, expected, "entries={entries} skips={skips}");
                        inside |= (base..tip).contains(&expected)
                            && decided.iter().any(|loc| *loc >= base);
                        let mut decided_model = written_model.clone();
                        for (_, key, _) in &policy.visited {
                            match choose(script, key) {
                                Choice::Evict => decided_model.apply(&[(*key, None)]),
                                Choice::Replace(value) => {
                                    decided_model.apply(&[(*key, Some(value))])
                                }
                                Choice::Keep | Choice::Stop => {}
                            }
                        }
                        assert_serves(&db, &merkleized, &decided_model).await;
                    }
                }
            }
            assert_eq!(inside, !writes.is_empty());

            // The applied batch commits the floor of a window that ends one skip short of the tip.
            let (expected, _) = model_of(entries, inactive - 1);
            let mut policy = Script::new(entries, inactive - 1, keep);
            let merkleized = with(db.new_batch())
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            db = db.apply_batch(merkleized).await.unwrap().0;
            assert_eq!(*db.inactivity_floor_loc(), expected);
            db.assert_exact().await;
            model = written_model;
            assert_values(&db, &model).await;
        }
        db.destroy().await.unwrap();
    }

    /// Evicting a key a pending parent created leaves it absent once the child applies over the
    /// still-pending parent: the child's diff deletes the key with no base location, the live
    /// keys return to the base's, and the applied bitmap never marks the parent's create.
    #[boxed]
    pub(crate) async fn test_any_policy_evicts_parent_created_key<F, D, Fut>(
        context: Context,
        db: D,
        reopen: impl Fn(Context) -> Fut,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Changes<F>,
        Operation<F, D::Update>: Codec,
        Fut: Future<Output = D>,
    {
        // Seed three keys with a held floor, and create a fourth in a pending parent.
        let [k1, k2, k3, k4] = [0x10, 0x20, 0x30, 0x40].map(|prefix| colliding_digest(prefix, 0));
        let seed: Vec<_> = [k1, k2, k3]
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let db = hold(db, &seed).await;
        let live = db.live().await.len();
        let parent = hold_batch(&db, db.new_batch(), &[(k4, Some(make_value(4)))]).await;
        let (start, ops) = D::ops(&parent);
        let created = ops
            .iter()
            .position(|op| matches!(op, Operation::Update(update) if *update.key() == k4))
            .expect("the parent creates the key");
        let created = start + created as u64;

        // The child evicts the created key and keeps every other update it reaches.
        let mut policy = Script::new(usize::MAX, u64::MAX, move |key: &Digest| {
            if *key == k4 {
                Choice::Evict
            } else {
                Choice::Keep
            }
        });
        let child = D::child(&parent)
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();
        assert!(policy.visited.contains(&(created, k4, make_value(4))));
        assert_eq!(D::changes(&child, &k4), [(None, None)]);

        // Applying the child over the pending parent leaves the base's keys alone and the created
        // key absent, with an exact bitmap, through commit and reopen.
        let (db, _) = db.apply_batch(child).await.unwrap();
        drop(parent);
        assert_eq!(db.get(&k4).await.unwrap(), None);
        assert_eq!(db.live().await.len(), live);
        db.assert_exact().await;
        let mut model = Model::default();
        model.apply(&seed);
        assert_values(&db, &model).await;
        let db = db.commit().await.unwrap();
        let (root, floor) = (db.root(), db.inactivity_floor_loc());
        drop(db);
        let db = reopen(context.child("reopened")).await;
        assert_eq!((db.root(), db.inactivity_floor_loc()), (root, floor));
        assert_eq!(db.get(&k4).await.unwrap(), None);
        db.assert_exact().await;
        assert_values(&db, &model).await;
        db.destroy().await.unwrap();
    }

    /// A policy decides the batch's own writes like any other active update: it keeps and replaces
    /// the batch's updates and creates, and evicting a key the batch creates leaves it absent with
    /// no net change in live keys. A policy that stops at the batch's own write commits the floor
    /// inside the batch. Both batches survive reopen with an exact activity bitmap.
    #[boxed]
    pub(crate) async fn test_any_policy_own_writes<F, D, Fut>(
        context: Context,
        db: D,
        reopen: impl Fn(Context) -> Fut,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
        Fut: Future<Output = D>,
    {
        // Seed six keys in key order at 1..7, with the seed commit at 7. The batch creates two
        // more keys between them.
        let keys = [0x10, 0x20, 0x25, 0x30, 0x40, 0x45, 0x50, 0x60]
            .map(|prefix| colliding_digest(prefix, 0));
        let [k1, k2, k25, k3, k4, k45, k5, k6] = keys;
        let seed: Vec<_> = [k1, k2, k3, k4, k5, k6]
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let db = hold(db, &seed).await;
        let mut model = Model::default();
        model.apply(&seed);

        // Update two keys, delete one, and create two whose predecessors are the updated keys, so
        // an ordered batch rewrites no predecessor. The writes append five operations at 8..13.
        let writes = [
            (k2, Some(make_value(102))),
            (k4, Some(make_value(104))),
            (k5, None),
            (k25, Some(make_value(125))),
            (k45, Some(make_value(145))),
        ];
        let state = written(&db, &[], db.new_batch(), &writes).await;
        assert_eq!(*state.tip, 13);
        let with = |batch: D::Batch| {
            writes
                .iter()
                .fold(batch, |batch, &(key, value)| batch.write(key, value))
        };

        // The policy keeps, evicts, and replaces the untouched applied updates, keeps and
        // replaces the two updates the batch writes, keeps one created key, and evicts the other.
        let choices = [
            (k1, Choice::Keep),
            (k3, Choice::Evict),
            (k6, Choice::Replace(make_value(606))),
            (k2, Choice::Keep),
            (k4, Choice::Replace(make_value(404))),
            (k25, Choice::Keep),
            (k45, Choice::Evict),
        ];
        let choose = |key: &Digest| choices.iter().find(|(k, _)| k == key).unwrap().1;

        // The walk visits the applied updates at 1, 3, and 6, then the four live writes, each
        // with the value the writes left. Both orderings append the updates before the creates and
        // keep key order within each.
        let mut policy = Script::new(usize::MAX, u64::MAX, choose);
        let merkleized = with(db.new_batch())
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();
        let visited: Vec<_> = [
            (k1, 0),
            (k3, 2),
            (k6, 5),
            (k2, 102),
            (k4, 104),
            (k25, 125),
            (k45, 145),
        ]
        .into_iter()
        .map(|(key, value)| (state.live[&key], key, make_value(value)))
        .collect();
        assert_eq!(policy.visited, visited);
        assert_eq!(
            policy.locations()[..3],
            [1, 3, 6].map(GenericLocation::<F>::new)
        );
        assert!(policy.locations()[3..].iter().all(|loc| **loc >= 8));

        // The floor reaches the tip of the writes, and the walk appends its decisions in order.
        // An ordered batch folds the link past each evicted key into its decided predecessor: the
        // kept created key precedes the third key, and the replaced fourth key the evicted create.
        assert_eq!(D::span(&merkleized).inactivity_floor, state.tip);
        assert_eq!(
            appended::<F, D>(&merkleized, &state),
            [
                (k1, Some(make_value(0))),
                (k3, None),
                (k6, Some(make_value(606))),
                (k2, Some(make_value(102))),
                (k4, Some(make_value(404))),
                (k25, Some(make_value(125))),
                (k45, None),
            ]
        );
        assert_eq!(db.read(&merkleized, &k45).await, None);

        // The created and evicted key leaves no trace: five keys remain, the six seeded less the
        // deleted and evicted ones plus the kept create.
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        model.apply(&writes);
        model.apply(&[
            (k3, None),
            (k6, Some(make_value(606))),
            (k4, Some(make_value(404))),
            (k45, None),
        ]);
        assert_eq!(db.inactivity_floor_loc(), state.tip);
        assert!(db.live().await.keys().eq(model.values.keys()));
        assert_eq!(model.values.len(), 5);
        assert_values(&db, &model).await;
        db.assert_exact().await;

        // The state survives reopen.
        let db = db.commit().await.unwrap();
        let (root, floor) = (db.root(), db.inactivity_floor_loc());
        drop(db);
        let db = reopen(context.child("decided")).await;
        assert_eq!((db.root(), db.inactivity_floor_loc()), (root, floor));
        assert_values(&db, &model).await;
        db.assert_exact().await;

        // A batch updates the first key at its first location. Its policy keeps every other live
        // update, which the previous batch moved, and stops at that write, so the floor stays at
        // the batch's first location.
        let start = db.size();
        let update = [(k1, Some(make_value(201)))];
        let state = written(&db, &[], db.new_batch(), &update).await;
        assert_eq!(state.live[&k1], start);
        let mut policy = Script::new(usize::MAX, u64::MAX, |key: &Digest| {
            if *key == k1 {
                Choice::Stop
            } else {
                Choice::Keep
            }
        });
        let merkleized = db
            .new_batch()
            .write(k1, update[0].1)
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();
        assert_eq!(policy.locations(), state.active());
        assert_eq!(policy.visited.last(), Some(&(start, k1, make_value(201))));
        assert_eq!(D::span(&merkleized).inactivity_floor, start);
        let kept: Vec<_> = policy.visited[..4]
            .iter()
            .map(|(_, key, value)| (*key, Some(*value)))
            .collect();
        assert_eq!(appended::<F, D>(&merkleized, &state), kept);

        // The applied floor survives reopen, and the next batch's policy decides the stopped write
        // without a skip.
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        model.apply(&update);
        assert_eq!(db.inactivity_floor_loc(), start);
        db.assert_exact().await;
        let db = db.commit().await.unwrap();
        let root = db.root();
        drop(db);
        let db = reopen(context.child("stopped")).await;
        assert_eq!((db.root(), db.inactivity_floor_loc()), (root, start));
        assert_values(&db, &model).await;
        db.assert_exact().await;
        let mut policy = Script::new(1, 0, keep);
        drop(
            db.new_batch()
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap(),
        );
        assert_eq!(policy.visited, [(start, k1, make_value(201))]);
        db.destroy().await.unwrap();
    }

    /// Merkleize `writes` on batches from `start`, children of the pending `ancestors` (oldest
    /// first) of `db`, under [`Proportional`], under proportional limits with a policy that decides
    /// nothing, and under [`Bounded`] with unlimited skips and one entry for the previous commit
    /// and for each operation the writes make inactive.
    ///
    /// Asserts that all three append the same operations under the same floor and root.
    ///
    /// Asserts that they move exactly the live updates a [modeled walk](walk_model) with that many
    /// entries reaches from the inherited floor, each with its value.
    ///
    /// Returns the state after the writes, the floor, and the moved locations.
    async fn assert_proportional<F, D>(
        db: &D,
        ancestors: &[&D::Merkleized],
        start: impl Fn() -> D::Batch,
        writes: &[(Digest, Option<Digest>)],
    ) -> (Written<F>, u64, Vec<u64>)
    where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        let with = || {
            writes
                .iter()
                .fold(start(), |batch, &(key, value)| batch.write(key, value))
        };
        let floor = ancestors.last().map_or_else(
            || db.inactivity_floor_loc(),
            |parent| D::span(parent).inactivity_floor,
        );
        let state = written(db, ancestors, start(), writes).await;
        let entries = state.inactive + 1;
        let active: Vec<u64> = state.active().iter().map(|loc| **loc).collect();
        let (expected, moved) = walk_model(&active, *floor, *state.tip, entries, u64::MAX, &[]);

        // The three policies append the same operations under the same floor and root.
        let built = build(db, start(), writes).await;
        let mut policy = Script::proportional(|_: &Digest| Choice::Keep);
        let proportional = with().merkleize(db, None, &mut policy).await.unwrap();
        assert_same(db, &built, &proportional);
        let mut policy = Bounded {
            entries,
            skips: u64::MAX,
        };
        let compacted = with().merkleize(db, None, &mut policy).await.unwrap();
        assert_same(db, &built, &compacted);

        // They move the modeled updates and commit the modeled floor.
        let at: BTreeMap<u64, Digest> = state.live.iter().map(|(key, loc)| (**loc, *key)).collect();
        let mut kept = Vec::new();
        for loc in &moved {
            let key = at[loc];
            kept.push((key, db.read(&built, &key).await));
        }
        assert_eq!(appended::<F, D>(&built, &state), kept);
        assert_eq!(*D::span(&built).inactivity_floor, expected);
        (state, expected, moved)
    }

    /// A [`Bounded`] policy with unlimited skips and one entry for the previous commit and for
    /// each operation the batch's writes make inactive (an update of a key live before the batch,
    /// an ordered predecessor rewrite included, and two for a delete) reproduces the operations,
    /// floor, and root of a [`Proportional`] batch, as does a policy with proportional limits that
    /// decides nothing. Each moves the live updates a walk with that allowance reaches.
    ///
    /// From the database and from a pending parent that moved its own floor, the allowance runs
    /// out below the base tip, runs out among the batch's own writes after moving some, and
    /// outlasts the live updates so the floor reaches the tip of the writes.
    pub(crate) async fn test_any_policy_matches_proportional<F, D>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        // Seed 32 updates with a held floor, then supersede every third one.
        let seed: Vec<_> = (0..32)
            .map(|i| (to_digest(i), Some(make_value(i))))
            .collect();
        let churn: Vec<_> = (0..32)
            .step_by(3)
            .map(|i| (to_digest(i), Some(make_value(i + 100))))
            .collect();
        let db = hold(db, &seed).await;
        let db = hold(db, &churn).await;

        // A small batch updates, deletes, and creates a key. Deleting 16 keys while creating 40
        // leaves more live updates than the allowance. Deleting 24 keys and updating 4 leaves
        // fewer.
        let small = [
            (to_digest(1), Some(make_value(201))),
            (to_digest(4), None),
            (to_digest(40), Some(make_value(40))),
        ];
        let exhausted: Vec<_> = (0..16)
            .map(|i| (to_digest(i), None))
            .chain((100..140).map(|i| (to_digest(i), Some(make_value(i)))))
            .collect();
        let outlasted: Vec<_> = (0..24)
            .map(|i| (to_digest(i), None))
            .chain((24..28).map(|i| (to_digest(i), Some(make_value(i + 300)))))
            .collect();

        // Run each batch from the database, then from a pending parent.
        let parent = build(
            &db,
            db.new_batch(),
            &[
                (to_digest(2), Some(make_value(202))),
                (to_digest(41), Some(make_value(41))),
            ],
        )
        .await;
        let starts: [(Vec<&D::Merkleized>, GenericLocation<F>); 2] = [
            (Vec::new(), db.bounds().end),
            (vec![&parent], D::span(&parent).tip.size),
        ];
        for (ancestors, base) in starts {
            let start = || {
                ancestors
                    .last()
                    .map_or_else(|| db.new_batch(), |p| D::child(p))
            };
            let (_, floor, _) = assert_proportional(&db, &ancestors, start, &small).await;
            assert!(floor < *base, "the allowance outlasts the base region");

            let (state, floor, moved) =
                assert_proportional(&db, &ancestors, start, &exhausted).await;
            assert!(
                *base <= floor && floor < *state.tip,
                "the allowance runs out outside the batch's writes",
            );
            assert!(moved.iter().any(|loc| *loc >= *base), "no own write moved");

            let (state, floor, moved) =
                assert_proportional(&db, &ancestors, start, &outlasted).await;
            assert_eq!(floor, *state.tip, "the allowance runs out before the tip");
            assert!(moved.iter().any(|loc| *loc >= *base), "no own write moved");
        }
        drop(parent);
        db.destroy().await.unwrap();
    }

    /// Assert that `decided` and `written`, batches of `db`, serve the same value for every key in
    /// `keys`, that `decided` serves `value` for `target`, and that each commits the tip of its
    /// writes (`tips`, in order) as its floor.
    async fn assert_same_state<F: Family, D: Inspect<F>>(
        db: &D,
        decided: &D::Merkleized,
        written: &D::Merkleized,
        keys: &[Digest],
        (target, value): (Digest, Option<Digest>),
        tips: [GenericLocation<F>; 2],
    ) {
        for key in keys {
            assert_eq!(
                db.read(decided, key).await,
                db.read(written, key).await,
                "{key} diverged",
            );
        }
        assert_eq!(db.read(decided, &target).await, value);
        assert_eq!(
            [decided, written].map(|batch| D::span(batch).inactivity_floor),
            tips
        );
    }

    /// Evicting or replacing an update leaves the same state as deleting or writing its key in the
    /// batch. The update may resolve in the applied database, in a live parent, or in a
    /// grandparent applied and freed before merkleize. Every key shares one translated-key bucket.
    ///
    /// The two batches append different operations: a decision follows the writes, while a write
    /// resolves among them, and the walk of the writing batch also decides its own write. Each
    /// policy keeps every other update, so each walk ends at the tip of its batch's writes.
    pub(crate) async fn test_any_policy_decisions_match_writes<F, D>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        // Seed colliding keys with a held floor.
        let keys: Vec<_> = (0..8).map(|i| colliding_digest(0xAA, i)).collect();
        let seed: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let mut db = hold(db, &seed).await;
        let target = keys[2];
        let decisions = [
            (Choice::Evict, None),
            (Choice::Replace(make_value(500)), Some(make_value(500))),
        ];
        let only = |decision: &Choice| {
            let decision = *decision;
            move |key: &Digest| {
                if *key == target {
                    decision
                } else {
                    Choice::Keep
                }
            }
        };

        // The decided update resolves in the applied database.
        for (decision, value) in &decisions {
            let tips = [
                written(&db, &[], db.new_batch(), &[]).await.tip,
                written(&db, &[], db.new_batch(), &[(target, *value)])
                    .await
                    .tip,
            ];
            let (decided, _) = decide(&db, db.new_batch(), only(decision)).await;
            let (writing, _) = decide(&db, db.new_batch().write(target, *value), keep).await;
            assert_same_state(&db, &decided, &writing, &keys, (target, *value), tips).await;
        }

        // The decided update resolves in a live parent.
        let parent = hold_batch(
            &db,
            db.new_batch(),
            &[
                (target, Some(make_value(300))),
                (keys[5], Some(make_value(305))),
            ],
        )
        .await;
        for (decision, value) in &decisions {
            let tips = [
                written(&db, &[&parent], D::child(&parent), &[]).await.tip,
                written(&db, &[&parent], D::child(&parent), &[(target, *value)])
                    .await
                    .tip,
            ];
            let (decided, _) = decide(&db, D::child(&parent), only(decision)).await;
            let writing = D::child(&parent).write(target, *value);
            let (writing, _) = decide(&db, writing, keep).await;
            assert_same_state(&db, &decided, &writing, &keys, (target, *value), tips).await;
        }
        drop(parent);

        // The decided update resolves in a grandparent that is applied and freed after both
        // batches start and before merkleize. The decided batch then applies with an exact
        // activity bitmap, and the next grandparent writes the target again.
        for (decision, value) in &decisions {
            let grandparent =
                hold_batch(&db, db.new_batch(), &[(target, Some(make_value(400)))]).await;
            let parent = hold_batch(
                &db,
                D::child(&grandparent),
                &[(keys[6], Some(make_value(406)))],
            )
            .await;
            let tips = [
                written(&db, &[&grandparent, &parent], D::child(&parent), &[])
                    .await
                    .tip,
                written(
                    &db,
                    &[&grandparent, &parent],
                    D::child(&parent),
                    &[(target, *value)],
                )
                .await
                .tip,
            ];
            let decided = D::child(&parent);
            let writing = D::child(&parent).write(target, *value);
            drop(parent);
            (db, _) = db.apply_batch(grandparent).await.unwrap();
            let (decided, _) = decide(&db, decided, only(decision)).await;
            let (writing, _) = decide(&db, writing, keep).await;
            assert_same_state(&db, &decided, &writing, &keys, (target, *value), tips).await;
            drop(writing);
            (db, _) = db.apply_batch(decided).await.unwrap();
            assert_eq!(db.get(&target).await.unwrap(), *value);
            assert_eq!(db.get(&keys[6]).await.unwrap(), Some(make_value(406)));
            db.assert_exact().await;
        }
        db.destroy().await.unwrap();
    }

    /// Staged merkleization with a policy over either update kind.
    pub(crate) trait StagedPolicy<D, F: Family>: Sized {
        /// The merkleized batch.
        type Merkleized;

        /// Merkleize with `updates`, `upserts`, and `policy`, and without metadata.
        async fn merkleize_staged<P: Policy<F, Digest, Digest> + Send>(
            self,
            updates: Vec<(usize, Option<Digest>)>,
            upserts: Vec<(Digest, Option<Digest>)>,
            db: &D,
            policy: &mut P,
        ) -> Self::Merkleized;
    }

    impl<F, C, I, V, const N: usize, S>
        StagedPolicy<Db<F, Context, C, I, Sha256, operation::update::Unordered<Digest, V>, N, S>, F>
        for batch::Staged<F, Sha256, operation::update::Unordered<Digest, V>, S>
    where
        F: Family,
        C: Mutable<Item = Operation<F, operation::update::Unordered<Digest, V>>>,
        I: UnorderedIndex<Value = GenericLocation<F>>,
        V: ValueEncoding<Value = Digest>,
        S: Strategy,
        Operation<F, operation::update::Unordered<Digest, V>>: Codec,
    {
        type Merkleized =
            Arc<batch::MerkleizedBatch<F, Digest, operation::update::Unordered<Digest, V>, S>>;

        async fn merkleize_staged<P: Policy<F, Digest, Digest> + Send>(
            self,
            updates: Vec<(usize, Option<Digest>)>,
            upserts: Vec<(Digest, Option<Digest>)>,
            db: &Db<F, Context, C, I, Sha256, operation::update::Unordered<Digest, V>, N, S>,
            policy: &mut P,
        ) -> Self::Merkleized {
            self.merkleize(updates, upserts, None, db, policy)
                .await
                .unwrap()
        }
    }

    impl<F, C, I, V, const N: usize, S>
        StagedPolicy<Db<F, Context, C, I, Sha256, operation::update::Ordered<Digest, V>, N, S>, F>
        for batch::Staged<F, Sha256, operation::update::Ordered<Digest, V>, S>
    where
        F: Family,
        C: Mutable<Item = Operation<F, operation::update::Ordered<Digest, V>>>,
        I: crate::index::Ordered<Value = GenericLocation<F>>,
        V: ValueEncoding<Value = Digest>,
        S: Strategy,
        Operation<F, operation::update::Ordered<Digest, V>>: Codec,
    {
        type Merkleized =
            Arc<batch::MerkleizedBatch<F, Digest, operation::update::Ordered<Digest, V>, S>>;

        async fn merkleize_staged<P: Policy<F, Digest, Digest> + Send>(
            self,
            updates: Vec<(usize, Option<Digest>)>,
            upserts: Vec<(Digest, Option<Digest>)>,
            db: &Db<F, Context, C, I, Sha256, operation::update::Ordered<Digest, V>, N, S>,
            policy: &mut P,
        ) -> Self::Merkleized {
            self.merkleize(updates, upserts, None, db, policy)
                .await
                .unwrap()
        }
    }

    /// Writes staged in the batch supersede their keys' updates, so the policy passes those
    /// updates as inactive, and it decides the staged writes themselves: it evicts a staged update
    /// that won by last-write-wins and replaces an upsert. The batch matches an unstaged batch with
    /// the same writes and policy. A staged key resolves in the applied snapshot or in a live
    /// parent.
    pub(crate) async fn test_any_policy_after_staged_writes<F, C, I, U, const N: usize, S>(
        _context: Context,
        db: Db<F, Context, C, I, Sha256, U, N, S>,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>> + 'static,
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        Db<F, Context, C, I, Sha256, U, N, S>: DbAny<
                F,
                Key = Digest,
                Value = Digest,
                Digest = Digest,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
                Batch = batch::UnmerkleizedBatch<F, Sha256, U, S>,
            >,
        batch::Staged<F, Sha256, U, S>: StagedPolicy<
                Db<F, Context, C, I, Sha256, U, N, S>,
                F,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
            >,
    {
        // Seed five updates in key order at locations 1..6 with a held floor.
        let mut keys: Vec<_> = (0..5).map(to_digest).collect();
        keys.sort();
        let seed: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let db = hold(db, &seed).await;
        let writes = [
            (keys[1], Some(make_value(101))),
            (keys[2], None),
            (keys[3], Some(make_value(103))),
        ];

        // The staged keys resolve in the applied snapshot.
        let decided =
            staged_matches_writes(&db, &[], || db.new_batch(), &writes, &make_value).await;
        assert_eq!(decided[..2], [1, 5].map(GenericLocation::<F>::new));

        // The staged update resolves in a live parent that supersedes its applied update.
        let parent = hold_batch(&db, db.new_batch(), &[(keys[1], Some(make_value(201)))]).await;
        let decided = staged_matches_writes(
            &db,
            &[&parent],
            || parent.new_batch::<Sha256>(),
            &writes,
            &make_value,
        )
        .await;
        assert_eq!(decided[..2], [1, 5].map(GenericLocation::<F>::new));
        drop(parent);
        db.destroy().await.unwrap();
    }

    /// Stage the first two `writes` through reads of their keys and upsert the third, then
    /// merkleize a batch from `make`, a child of the pending `ancestors`, under unbounded limits
    /// with a policy that evicts the first written key, replaces the third, and keeps every other
    /// update. The staged updates write a stale value to the first key before its final one, and
    /// to the second key before an upsert of its final write wins.
    ///
    /// Asserts that the policy decides every live update after the writes in location order, the
    /// two surviving writes included, that the floor reaches the tip of the writes, that the batch
    /// serves the decided values, and that it matches an unstaged batch with the same writes and
    /// policy. Returns the decided locations.
    async fn staged_matches_writes<F, C, I, U, const N: usize, S>(
        db: &Db<F, Context, C, I, Sha256, U, N, S>,
        ancestors: &[&Arc<batch::MerkleizedBatch<F, Digest, U, S>>],
        make: impl Fn() -> batch::UnmerkleizedBatch<F, Sha256, U, S>,
        writes: &[(Digest, Option<Digest>); 3],
        make_value: &impl Fn(u64) -> Digest,
    ) -> Vec<GenericLocation<F>>
    where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>> + 'static,
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        Db<F, Context, C, I, Sha256, U, N, S>: DbAny<
                F,
                Key = Digest,
                Value = Digest,
                Digest = Digest,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
                Batch = batch::UnmerkleizedBatch<F, Sha256, U, S>,
            >,
        batch::Staged<F, Sha256, U, S>: StagedPolicy<
                Db<F, Context, C, I, Sha256, U, N, S>,
                F,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
            >,
    {
        // The walk decides every live update after the writes, up to their tip. Two of them are
        // the batch's surviving writes, at or above the batch's base.
        let state = written(db, ancestors, make(), writes).await;
        let expected = state.active();
        let base = written(db, ancestors, make(), &[]).await.tip;
        assert_eq!(expected.iter().filter(|loc| **loc >= base).count(), 2);
        let replacement = make_value(303);
        let choose = |key: &Digest| match key {
            key if *key == writes[0].0 => Choice::Evict,
            key if *key == writes[2].0 => Choice::Replace(replacement),
            _ => Choice::Keep,
        };

        // Merkleize the staged writes. The repeated slot and the upsert resolve to `writes`.
        let read = [&writes[0].0, &writes[1].0];
        let (_, staged) = make().stage(&read, db).await.unwrap();
        let mut policy = Script::new(usize::MAX, u64::MAX, choose);
        let staged = staged
            .merkleize_staged(
                vec![
                    (0, Some(make_value(901))),
                    (1, Some(make_value(902))),
                    (0, writes[0].1),
                ],
                vec![writes[2], writes[1]],
                db,
                &mut policy,
            )
            .await;
        assert_eq!(policy.locations(), expected);
        assert_eq!(staged.bounds().inactivity_floor, state.tip);
        for (key, value) in [
            (writes[0].0, None),
            (writes[1].0, None),
            (writes[2].0, Some(replacement)),
        ] {
            assert_eq!(staged.get(&key, db).await.unwrap(), value);
        }

        // An unstaged batch with the same writes and policy decides the same updates and produces
        // the same batch.
        let unstaged = writes
            .iter()
            .fold(make(), |batch, &(key, value)| batch.write(key, value));
        let mut twin = Script::new(usize::MAX, u64::MAX, choose);
        let unstaged = merkleize(db, unstaged, &mut twin).await.unwrap();
        assert_eq!(twin.visited, policy.visited);
        assert_same(db, &staged, &unstaged);
        expected
    }

    /// A batch whose parent is applied before merkleize decides the same updates, reads only the
    /// decided updates below the parent's operations, and produces the same batch as a twin over
    /// the pending parent. A batch whose chain a fork replaced returns `StaleBatch` before
    /// deciding any update.
    pub(crate) async fn test_any_policy_after_ancestor_applied<F, C, I, U, const N: usize, S, Fut>(
        context: Context,
        db: Db<F, Context, C, I, Sha256, U, N, S>,
        reopen: impl Fn(Context) -> Fut,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>> + 'static,
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        Db<F, Context, C, I, Sha256, U, N, S>: DbAny<
                F,
                Key = Digest,
                Value = Digest,
                Digest = Digest,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
                Batch = batch::UnmerkleizedBatch<F, Sha256, U, S>,
            >,
        Fut: Future<Output = Db<F, Context, C, I, Sha256, U, N, S>>,
    {
        // Seed eight updates in key order at locations 1..9 with a held floor.
        let mut keys: Vec<_> = (0..8).map(to_digest).collect();
        keys.sort();
        let seed: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let db = hold(db, &seed).await;
        let superseded = GenericLocation::<F>::new(2);

        // A pending parent supersedes the second update.
        let parent = hold_batch(&db, db.new_batch(), &[(keys[1], Some(make_value(101)))]).await;

        // A twin over the pending parent keeps every update.
        let (twin, expected) = decide(&db, parent.new_batch::<Sha256>(), keep).await;
        assert!(!expected.contains(&superseded));

        // Apply the parent, then merkleize a batch started before the apply. The parent's
        // update resolves in memory.
        let batch = parent.new_batch::<Sha256>();
        let base = parent.bounds().base.size;
        let (db, _) = db.apply_batch(parent).await.unwrap();
        let before = counter(&context, "log_journal_items_read_total");
        let (merkleized, decided) = decide(&db, batch, keep).await;
        assert_eq!(decided, expected);
        let below_base = expected.iter().filter(|loc| **loc < base).count() as u64;
        assert!(below_base < expected.len() as u64);
        assert_eq!(
            counter(&context, "log_journal_items_read_total"),
            before + below_base
        );
        assert_same(&db, &twin, &merkleized);
        drop(twin);

        // The applied batch serves the parent's write and survives reopen.
        let root = merkleized.root();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.root(), root);
        assert_eq!(db.get(&keys[1]).await.unwrap(), Some(make_value(101)));
        let db = db.commit().await.unwrap();
        drop(db);
        let db = reopen(context.child("reopen")).await;
        assert_eq!(db.root(), root);
        assert_eq!(db.get(&keys[1]).await.unwrap(), Some(make_value(101)));

        // A fork replaces the chain of a pending batch. The batch returns `StaleBatch` before
        // deciding any update.
        let parent = hold_batch(&db, db.new_batch(), &[(keys[3], Some(make_value(103)))]).await;
        let fork = hold_batch(&db, db.new_batch(), &[(keys[4], Some(make_value(104)))]).await;
        let batch = parent.new_batch::<Sha256>();
        let (db, _) = db.apply_batch(fork).await.unwrap();
        let mut policy = Script::new(usize::MAX, u64::MAX, keep);
        assert!(matches!(
            merkleize(&db, batch, &mut policy).await,
            Err(crate::qmdb::Error::StaleBatch)
        ));
        assert!(policy.visited.is_empty());
        drop(parent);
        db.destroy().await.unwrap();
    }

    /// Database access the policy tests need beyond [`DbAny`].
    pub(crate) trait Inspect<F: Family>:
        DbAny<F, Key = Digest, Value = Digest, Digest = Digest>
    {
        /// The update kind.
        type Update: Update<Key = Digest, Value = Digest>;

        /// Assert that the activity bitmap is [exact](assert_exact).
        async fn assert_exact(&self);

        /// Return the location of every live key's update in a [replay](live) of the retained log.
        async fn live(&self) -> BTreeMap<Digest, GenericLocation<F>>;

        /// Start a child of `batch`.
        fn child(batch: &Self::Merkleized) -> Self::Batch;

        /// Return the bounds of `batch`.
        fn span(batch: &Self::Merkleized) -> &Bounds<F, Digest>;

        /// Return the operations `batch` appends and the location of the first.
        #[allow(clippy::type_complexity)]
        fn ops(
            batch: &Self::Merkleized,
        ) -> (GenericLocation<F>, Arc<Vec<Operation<F, Self::Update>>>);

        /// Read `key` through `batch`.
        async fn read(&self, batch: &Self::Merkleized, key: &Digest) -> Option<Digest>;
    }

    impl<F, C, I, U, const N: usize, S> Inspect<F> for Db<F, Context, C, I, Sha256, U, N, S>
    where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>> + 'static,
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        Self: DbAny<
                F,
                Key = Digest,
                Value = Digest,
                Digest = Digest,
                Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>,
                Batch = batch::UnmerkleizedBatch<F, Sha256, U, S>,
            >,
    {
        type Update = U;

        async fn assert_exact(&self) {
            assert_exact(self).await;
        }

        async fn live(&self) -> BTreeMap<Digest, GenericLocation<F>> {
            live(self).await
        }

        fn child(batch: &Self::Merkleized) -> Self::Batch {
            batch.new_batch::<Sha256>()
        }

        fn span(batch: &Self::Merkleized) -> &Bounds<F, Digest> {
            batch.bounds()
        }

        fn ops(batch: &Self::Merkleized) -> (GenericLocation<F>, Arc<Vec<Operation<F, U>>>) {
            batch.operations()
        }

        async fn read(&self, batch: &Self::Merkleized, key: &Digest) -> Option<Digest> {
            batch.get(key, self).await.unwrap()
        }
    }

    /// Ordered database access the link tests need beyond [`Inspect`].
    pub(crate) trait Links<F: Family>: Inspect<F> {
        /// Assert that `key` holds `value` and links to `next`.
        async fn assert_link(&self, key: Digest, value: Digest, next: Digest);

        /// Assert that `key` is absent.
        async fn assert_absent(&self, key: Digest);
    }

    impl<F, C, I, V, const N: usize, S> Links<F>
        for Db<F, Context, C, I, Sha256, operation::update::Ordered<Digest, V>, N, S>
    where
        F: Family,
        C: Mutable<Item = Operation<F, operation::update::Ordered<Digest, V>>>,
        I: crate::index::Ordered<Value = GenericLocation<F>> + 'static,
        V: ValueEncoding<Value = Digest>,
        S: Strategy,
        Operation<F, operation::update::Ordered<Digest, V>>: Codec,
        Self: Inspect<F>,
    {
        async fn assert_link(&self, key: Digest, value: Digest, next: Digest) {
            assert_eq!(
                self.get_all(&key).await.unwrap(),
                Some((value, next)),
                "{key} diverged from its value and link",
            );
        }

        async fn assert_absent(&self, key: Digest) {
            assert_eq!(self.get_all(&key).await.unwrap(), None, "{key} is live");
        }
    }

    /// Assert that two merkleized batches of `db` append the same operations under the same floor
    /// and root.
    pub(crate) fn assert_same<F, D>(_: &D, a: &D::Merkleized, b: &D::Merkleized)
    where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        let encoded = |merkleized: &D::Merkleized| {
            let (start, ops) = D::ops(merkleized);
            let ops: Vec<Vec<u8>> = ops.iter().map(|op| op.encode().to_vec()).collect();
            (start, ops)
        };
        assert_eq!(encoded(a), encoded(b));
        assert_eq!(D::span(a).inactivity_floor, D::span(b).inactivity_floor);
        assert_eq!(MerkleizedTrait::root(a), MerkleizedTrait::root(b));
    }

    /// Assert that `db` serves the value `model` holds for every written key.
    async fn assert_values<F, D>(db: &D, model: &Model)
    where
        F: Family,
        D: DbAny<F, Key = Digest, Value = Digest>,
    {
        for key in &model.keys {
            assert_eq!(
                db.get(key).await.unwrap(),
                model.values.get(key).copied(),
                "value of {key} diverged from the model",
            );
        }
    }

    /// Assert that `batch` serves the value `model` holds for every written key.
    async fn assert_serves<F: Family, D: Inspect<F>>(db: &D, batch: &D::Merkleized, model: &Model) {
        for key in &model.keys {
            assert_eq!(
                db.read(batch, key).await,
                model.values.get(key).copied(),
                "value of {key} diverged from the model",
            );
        }
    }

    /// Merkleize `batch` with a policy and apply the result to `db`. `batch` is a child of the
    /// pending `ancestors` (oldest first). The policy writes the value `decisions` holds for a key
    /// (`None` evicts) and keeps every other update. It decides the live update of every key in
    /// location order. The applied state serves `model` with the decisions recorded and keeps an
    /// exact activity bitmap.
    async fn apply_decided<F: Family, D: Inspect<F>>(
        db: D,
        ancestors: &[&D::Merkleized],
        batch: D::Batch,
        decisions: &[(Digest, Option<Digest>)],
        model: &mut Model,
    ) -> D
    where
        Operation<F, D::Update>: Codec,
    {
        // Replay the log, then each ancestor. The policy decides every live update.
        let expected = active(&db, ancestors).await;

        // Decide each update, then apply over the pending ancestors.
        let choose = |key: &Digest| match decisions.iter().find(|(k, _)| k == key) {
            Some((_, Some(value))) => Choice::Replace(*value),
            Some((_, None)) => Choice::Evict,
            None => Choice::Keep,
        };
        let (merkleized, decided) = decide(&db, batch, choose).await;
        assert_eq!(decided, expected);
        model.apply(decisions);
        let db = db.apply_batch(merkleized).await.unwrap().0;
        assert_values(&db, model).await;
        db.assert_exact().await;
        db
    }

    /// Over two pending ancestors, one, and none, and for batches started before their ancestors
    /// are applied, the [`Proportional`] walk produces the same batch, and so does a policy that
    /// keeps every update. Policies that keep, evict, and replace each ancestor's updates then
    /// apply over two pending ancestors and over one. Every policy decides exactly the live
    /// updates after its batch's writes, the batch's own included, every batch serves the model's
    /// values, and every applied state keeps an exact activity bitmap. Every key shares one
    /// translated-key bucket.
    #[boxed]
    pub(crate) async fn test_any_activity_depths<F, D, Fut>(
        context: Context,
        db: D,
        reopen: impl Fn(Context) -> Fut,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
        Fut: Future<Output = D>,
    {
        // Seed eight keys with a held floor.
        let key = |i: u64| colliding_digest(0xB0, i);
        let seed: Vec<_> = (0..8).map(|i| (key(i), Some(make_value(i)))).collect();
        let mut model = Model::default();
        let db = hold(db, &seed).await;
        model.apply(&seed);
        db.assert_exact().await;

        // The grandparent updates and deletes seeded keys and creates two keys. The parent updates
        // and deletes seeded keys and the grandparent's creates, and creates a key.
        let grand = [
            (key(1), Some(make_value(101))),
            (key(2), None),
            (key(100), Some(make_value(102))),
            (key(101), Some(make_value(103))),
        ];
        let middle = [
            (key(3), Some(make_value(201))),
            (key(4), None),
            (key(100), Some(make_value(202))),
            (key(101), None),
            (key(102), Some(make_value(203))),
        ];
        let grandparent = hold_batch(&db, db.new_batch(), &grand).await;
        let parent = hold_batch(&db, D::child(&grandparent), &middle).await;
        model.apply(&grand);
        model.apply(&middle);

        // The batch deletes and updates seeded keys, updates the grandparent's update, and updates
        // the parent's create.
        let writes = [
            (key(0), None),
            (key(1), Some(make_value(301))),
            (key(5), Some(make_value(302))),
            (key(102), Some(make_value(303))),
        ];
        let with = |batch: D::Batch| {
            writes
                .iter()
                .fold(batch, |batch, &(k, v)| batch.write(k, v))
        };

        // Replay the log, the grandparent, the parent, and the writes. A policy decides the live
        // update of every key in location order, including the three the batch writes.
        let state = written(&db, &[&grandparent, &parent], D::child(&parent), &writes).await;
        let expected = state.active();
        let base = D::span(&parent).tip.size;
        assert_eq!(expected.iter().filter(|loc| **loc >= base).count(), 3);
        model.apply(&writes);

        // Depth 2: the proportional walk passes the grandparent's operations, and a policy decides
        // the expected updates.
        let proportional = build(&db, D::child(&parent), &writes).await;
        assert!(
            D::span(&proportional).inactivity_floor > D::span(&parent).base.size,
            "the walk passes the grandparent's operations",
        );
        assert_serves(&db, &proportional, &model).await;
        let (kept, decided) = decide(&db, with(D::child(&parent)), keep).await;
        assert_eq!(decided, expected);
        assert_serves(&db, &kept, &model).await;

        // A proportional batch and two policy batches start before the grandparent is applied.
        let early = with(D::child(&parent));
        let first = with(D::child(&parent));
        let last = with(D::child(&parent));

        // Depth 1: apply and free the grandparent. The proportional and policy batches started
        // after the apply, and the proportional and first policy batches started before it, match
        // depth 2. The first policy batch has one more entry than there are updates to decide, so
        // its walk reaches the tip in read rounds sized to its remaining entries.
        let db = db.apply_batch(grandparent).await.unwrap().0;
        db.assert_exact().await;
        let proportional1 = build(&db, D::child(&parent), &writes).await;
        assert_same(&db, &proportional, &proportional1);
        let early = early.merkleize(&db, None, &mut Proportional).await.unwrap();
        assert_same(&db, &proportional, &early);
        let (kept1, decided1) = decide(&db, with(D::child(&parent)), keep).await;
        assert_eq!(decided1, expected);
        assert_same(&db, &kept, &kept1);
        let mut policy = Script::new(expected.len() + 1, u64::MAX, keep);
        let first = first.merkleize(&db, None, &mut policy).await.unwrap();
        assert_eq!(policy.locations(), expected);
        assert_same(&db, &kept, &first);

        // Depth 0: apply the parent. The proportional and policy batches started after the apply,
        // and the last policy batch started before the grandparent's apply, match depth 2.
        let db = db.apply_batch(parent).await.unwrap().0;
        db.assert_exact().await;
        let (last, decided) = decide(&db, last, keep).await;
        assert_eq!(decided, expected);
        assert_same(&db, &kept, &last);
        let proportional0 = build(&db, db.new_batch(), &writes).await;
        assert_same(&db, &proportional, &proportional0);
        let (kept0, decided0) = decide(&db, with(db.new_batch()), keep).await;
        assert_eq!(decided0, expected);
        assert_same(&db, &kept, &kept0);

        // Apply the proportional batch. The state serves the model and keeps an exact bitmap.
        drop((
            proportional,
            proportional1,
            early,
            kept,
            kept1,
            first,
            last,
            kept0,
        ));
        let db = db.apply_batch(proportional0).await.unwrap().0;
        assert_values(&db, &model).await;
        db.assert_exact().await;

        // Apply a policy that keeps every live update. The state serves the model and keeps an
        // exact bitmap.
        let expected = active(&db, &[]).await;
        let (kept, decided) = decide(&db, db.new_batch(), keep).await;
        assert_eq!(decided, expected);
        let db = db.apply_batch(kept).await.unwrap().0;
        assert_values(&db, &model).await;
        db.assert_exact().await;

        // Depth 2 apply: the grandparent and the parent each update two existing keys and create a
        // key. The policy keeps one update of each ancestor, evicts the other, and replaces the
        // create.
        let grand = [
            (key(1), Some(make_value(401))),
            (key(6), Some(make_value(402))),
            (key(103), Some(make_value(403))),
        ];
        let middle = [
            (key(3), Some(make_value(404))),
            (key(102), Some(make_value(405))),
            (key(104), Some(make_value(406))),
        ];
        let grandparent = hold_batch(&db, db.new_batch(), &grand).await;
        let parent = hold_batch(&db, D::child(&grandparent), &middle).await;
        model.apply(&grand);
        model.apply(&middle);
        let decisions = [
            (key(6), None),
            (key(103), Some(make_value(407))),
            (key(102), None),
            (key(104), Some(make_value(408))),
        ];
        let ancestors = [&grandparent, &parent];
        let db = apply_decided(db, &ancestors, D::child(&parent), &decisions, &mut model).await;
        drop((grandparent, parent));

        // Depth 1 apply: the parent updates three existing keys and creates a key. The policy keeps
        // one update, evicts another and the create, and replaces the third.
        let middle = [
            (key(1), Some(make_value(501))),
            (key(5), Some(make_value(502))),
            (key(104), Some(make_value(503))),
            (key(105), Some(make_value(504))),
        ];
        let parent = hold_batch(&db, db.new_batch(), &middle).await;
        model.apply(&middle);
        let decisions = [
            (key(5), None),
            (key(104), Some(make_value(505))),
            (key(105), None),
        ];
        let db = apply_decided(db, &[&parent], D::child(&parent), &decisions, &mut model).await;
        drop(parent);

        // Prune to the sync boundary. The bitmap stays exact.
        let db = db.commit().await.unwrap();
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        db.assert_exact().await;

        // Reopen. The rebuilt state matches and keeps an exact bitmap.
        let root = db.root();
        let db = db.commit().await.unwrap();
        drop(db);
        let db = reopen(context.child("reopen")).await;
        assert_eq!(db.root(), root);
        assert_values(&db, &model).await;
        db.assert_exact().await;
        db.destroy().await.unwrap();
    }

    /// Return the keys of `live` ordered by the location of their updates, oldest first.
    pub(crate) fn age<K: Copy + Ord, L: Copy + Ord>(live: &BTreeMap<K, L>) -> Vec<K> {
        let mut entries: Vec<_> = live.iter().map(|(key, loc)| (*loc, *key)).collect();
        entries.sort_unstable();
        entries.into_iter().map(|(_, key)| key).collect()
    }

    /// Return the keys live after applying `writes`, in order, to the keys of `live`.
    pub(crate) fn keys_after<K: Copy + Ord, V, L>(
        live: &BTreeMap<K, L>,
        writes: &[(K, Option<V>)],
    ) -> BTreeSet<K> {
        let mut keys: BTreeSet<_> = live.keys().copied().collect();
        for (key, value) in writes {
            if value.is_some() {
                keys.insert(*key);
            } else {
                keys.remove(key);
            }
        }
        keys
    }

    /// Assert the [`Proportional`] bound at a batch boundary with `floor`, exclusive tip `tip`,
    /// and the location of every live key's update in `live`.
    ///
    /// Every live update lies at or above the floor and below the commit at `tip - 1`.
    ///
    /// When every batch since the initial commit is [`Proportional`], the floor trails the tip by
    /// at most `3 * n + 1` operations for `n` live keys.
    pub(crate) fn assert_bound<F: Family, K>(
        floor: GenericLocation<F>,
        tip: GenericLocation<F>,
        live: &BTreeMap<K, GenericLocation<F>>,
    ) {
        let n = live.len() as u64;
        assert!(floor < tip, "floor={floor:?}, tip={tip:?}");
        assert!(
            live.values().all(|loc| *loc >= floor && **loc < *tip - 1),
            "a live update lies outside the floor and the commit: floor={floor:?}, tip={tip:?}",
        );
        assert!(
            *tip - *floor <= 3 * n + 1,
            "tip={tip:?}, floor={floor:?}, n={n}, gap={}, bound={}",
            *tip - *floor,
            3 * n + 1,
        );
    }

    /// Return deletes of the `n` live keys with the highest locations.
    fn newest<K: Copy + Ord, L: Copy + Ord, V>(
        live: &BTreeMap<K, L>,
        n: usize,
    ) -> Vec<(K, Option<V>)> {
        age(live)
            .into_iter()
            .rev()
            .take(n)
            .map(|key| (key, None))
            .collect()
    }

    /// Apply a large batch of creates, hot-key updates, delete and recreate churn, shrinking by
    /// deleting the newest keys, bursts of creates followed by deletes of the newest keys, and
    /// large mixed batches to `db`. Keys come from `key` and values from `value`. `apply` applies
    /// one batch and records the location of each live key in its map.
    pub(crate) async fn churn<D, K, V, L>(
        mut db: D,
        key: impl Fn(u64) -> K,
        value: impl Fn(u64) -> V,
        mut apply: impl AsyncFnMut(D, &mut BTreeMap<K, L>, &[(K, Option<V>)]) -> D,
    ) -> D
    where
        K: Copy + Ord,
        L: Copy + Ord,
    {
        let mut live = BTreeMap::new();

        // Create 256 keys in one batch.
        let writes: Vec<_> = (0..256).map(|i| (key(i), Some(value(i)))).collect();
        db = apply(db, &mut live, &writes).await;

        // Update four hot keys in each of 64 batches.
        for round in 0..64 {
            let writes: Vec<_> = (0..4)
                .map(|i| (key(i), Some(value(1000 + round))))
                .collect();
            db = apply(db, &mut live, &writes).await;
        }

        // Delete eight keys, then delete the next eight in each of 64 batches while recreating
        // the eight the previous batch deleted.
        let window = |round: u64| (8 * round..8 * round + 8).map(|i| key(i % 256));
        let writes: Vec<_> = window(0).map(|key| (key, None)).collect();
        db = apply(db, &mut live, &writes).await;
        for round in 0..64 {
            let writes: Vec<_> = window(round)
                .map(|key| (key, Some(value(2000 + round))))
                .chain(window(round + 1).map(|key| (key, None)))
                .collect();
            db = apply(db, &mut live, &writes).await;
        }

        // Delete the eight newest keys in each batch until eight keys remain.
        while live.len() > 8 {
            let writes = newest(&live, 8);
            db = apply(db, &mut live, &writes).await;
        }

        // Four times, create a burst of 64 keys and then delete the eight newest keys in each of
        // eight batches.
        for burst in 0..4 {
            let start = 1000 + 64 * burst;
            let writes: Vec<_> = (start..start + 64)
                .map(|i| (key(i), Some(value(i))))
                .collect();
            db = apply(db, &mut live, &writes).await;
            for _ in 0..8 {
                let writes = newest(&live, 8);
                db = apply(db, &mut live, &writes).await;
            }
        }

        // Create 512 keys in one batch, then delete 64 keys, update 128, and create 32 in each of
        // four batches.
        let writes: Vec<_> = (2000..2512).map(|i| (key(i), Some(value(i)))).collect();
        db = apply(db, &mut live, &writes).await;
        for round in 0..4 {
            let keys: Vec<_> = live.keys().copied().collect();
            let start = 3000 + 32 * round;
            let deletes = keys[..64].iter().map(|&key| (key, None));
            let updates = keys[64..192].iter().map(|&key| (key, Some(value(round))));
            let creates = (start..start + 32).map(|i| (key(i), Some(value(i))));
            let writes: Vec<_> = deletes.chain(updates).chain(creates).collect();
            db = apply(db, &mut live, &writes).await;
        }
        db
    }

    /// Apply a fixed then a randomized schedule of batches to `db`, drawing choices from
    /// `context`. Keys come from `key` and values from `value`. `apply` applies one batch and
    /// records the location of each live key in its map.
    ///
    /// The fixed prefix creates 20 keys, deletes all but the oldest in one batch, and empties the
    /// database. It then creates 19 keys, deletes the three newest in each batch until one
    /// remains, and empties the database again.
    ///
    /// Each of two epochs then creates 96 keys, rewrites hot keys, and deletes the newest (first
    /// epoch) or the oldest (second epoch) keys in batches until one remains. It applies batches
    /// of random writes and empty batches, and ends by emptying the database.
    pub(crate) async fn randomized_churn<D, K, V, L>(
        context: &mut Context,
        mut db: D,
        key: impl Fn(u64) -> K,
        value: impl Fn(u64) -> V,
        mut apply: impl AsyncFnMut(D, &mut BTreeMap<K, L>, &[(K, Option<V>)]) -> D,
    ) -> D
    where
        K: Copy + Ord,
        L: Copy + Ord,
    {
        let mut live = BTreeMap::new();

        // Delete all but the oldest of 20 keys in one batch, then empty the database.
        let writes: Vec<_> = (0..20).map(|i| (key(i), Some(value(i)))).collect();
        db = apply(db, &mut live, &writes).await;
        let writes: Vec<_> = age(&live).into_iter().skip(1).map(|k| (k, None)).collect();
        db = apply(db, &mut live, &writes).await;
        assert_eq!(live.len(), 1);
        let writes: Vec<_> = live.keys().map(|k| (*k, None)).collect();
        db = apply(db, &mut live, &writes).await;
        db = apply(db, &mut live, &[]).await;

        // Create 19 keys, delete the three newest in each batch until one remains, then empty the
        // database.
        let writes: Vec<_> = (0..19).map(|i| (key(i), Some(value(i)))).collect();
        db = apply(db, &mut live, &writes).await;
        while live.len() > 1 {
            let writes = newest(&live, 3.min(live.len() - 1));
            db = apply(db, &mut live, &writes).await;
        }
        let writes: Vec<_> = live.keys().map(|k| (*k, None)).collect();
        db = apply(db, &mut live, &writes).await;

        for epoch in 0..2u64 {
            let writes: Vec<_> = (0..96)
                .map(|i| (key(i), Some(value(epoch * 1000 + i))))
                .collect();
            db = apply(db, &mut live, &writes).await;

            // Rewrite up to four of eight hot keys in each of 32 batches.
            let hot: Vec<_> = live.keys().copied().take(8).collect();
            for round in 0..32u64 {
                let count = context.random_range(0..=4u64);
                let writes: Vec<_> = (0..count)
                    .map(|i| {
                        let k = hot[context.random_range(0..hot.len())];
                        (k, Some(value(epoch * 1000 + round * 8 + i)))
                    })
                    .collect();
                db = apply(db, &mut live, &writes).await;
            }

            // Delete up to eight of the newest (first epoch) or oldest (second epoch) keys in each
            // batch until one remains.
            while live.len() > 1 {
                let count = context.random_range(1..=8.min(live.len() - 1));
                let mut keys = age(&live);
                if epoch == 0 {
                    keys.reverse();
                }
                let writes: Vec<_> = keys.into_iter().take(count).map(|k| (k, None)).collect();
                db = apply(db, &mut live, &writes).await;
            }

            // Apply 48 batches of up to 12 random writes over 160 keys, each a delete with
            // probability 0.45. They likely create, update, and delete live keys, delete absent
            // keys, write a key twice, and recreate deleted keys. An empty batch follows each
            // round divisible by eight.
            for round in 0..48 {
                let count = context.random_range(0..=12usize);
                let writes: Vec<_> = (0..count)
                    .map(|_| {
                        let k = key(context.random_range(0..160u64));
                        let v = context
                            .random_bool(0.55)
                            .then(|| value(context.random::<u64>()));
                        (k, v)
                    })
                    .collect();
                db = apply(db, &mut live, &writes).await;
                if round % 8 == 0 {
                    db = apply(db, &mut live, &[]).await;
                }
            }

            // Delete all but the oldest key, apply an empty batch, then empty the database.
            if live.is_empty() {
                db = apply(db, &mut live, &[(key(0), Some(value(epoch)))]).await;
            }
            let writes: Vec<_> = age(&live).into_iter().skip(1).map(|k| (k, None)).collect();
            db = apply(db, &mut live, &writes).await;
            assert_eq!(live.len(), 1);
            db = apply(db, &mut live, &[]).await;
            let writes: Vec<_> = live.keys().map(|k| (*k, None)).collect();
            db = apply(db, &mut live, &writes).await;
            for _ in 0..3 {
                db = apply(db, &mut live, &[]).await;
                assert!(live.is_empty());
            }
        }
        db
    }

    /// Merkleize and apply `writes` as one [`Proportional`] batch, replaying its operations into
    /// `live`. Asserts that the live keys match an independent key-set model and that both the
    /// merkleized and the applied state satisfy [`assert_bound`], so every batch since the initial
    /// commit must be [`Proportional`].
    async fn bounded<F: Family, D: Inspect<F>>(
        db: D,
        live: &mut BTreeMap<Digest, GenericLocation<F>>,
        writes: &[(Digest, Option<Digest>)],
    ) -> D
    where
        Operation<F, D::Update>: Codec,
    {
        let expected = keys_after(live, writes);
        let merkleized = build(&db, db.new_batch(), writes).await;
        let (start, ops) = D::ops(&merkleized);
        replay(live, start, &ops);
        assert_eq!(live.keys().copied().collect::<BTreeSet<_>>(), expected);
        let span = D::span(&merkleized);
        let (floor, tip) = (span.inactivity_floor, span.tip.size);
        assert_bound(floor, tip, live);
        let db = db.apply_batch(merkleized).await.unwrap().0;
        assert_eq!((db.inactivity_floor_loc(), db.size()), (floor, tip));
        db
    }

    /// Merkleize `writes` as one [`Proportional`] batch on the newest of the `pending` batches,
    /// or on the database when none is pending, and assert [`assert_bound`] on its bounds and the
    /// live keys after it and its ancestors. Applies the newest batch, and with it its ancestors,
    /// once three are pending.
    async fn pending_bounded<F: Family, D: Inspect<F>>(
        (mut db, mut pending): (D, Vec<D::Merkleized>),
        live: &mut BTreeMap<Digest, GenericLocation<F>>,
        writes: &[(Digest, Option<Digest>)],
    ) -> (D, Vec<D::Merkleized>)
    where
        Operation<F, D::Update>: Codec,
    {
        let expected = keys_after(live, writes);
        let batch = pending.last().map_or_else(|| db.new_batch(), D::child);
        let merkleized = build(&db, batch, writes).await;
        let (start, ops) = D::ops(&merkleized);
        replay(live, start, &ops);
        assert_eq!(live.keys().copied().collect::<BTreeSet<_>>(), expected);
        let span = D::span(&merkleized);
        assert_bound(span.inactivity_floor, span.tip.size, live);
        pending.push(merkleized);
        if pending.len() == 3 {
            let tip = pending.pop().unwrap();
            db = db.apply_batch(tip).await.unwrap().0;
            pending.clear();
            assert_bound(db.inactivity_floor_loc(), db.size(), live);
        }
        (db, pending)
    }

    /// Every [`Proportional`] batch of [`randomized_churn`] satisfies [`assert_bound`] before
    /// and after it applies. Every batch since the initial commit is [`Proportional`], as the
    /// bound requires.
    ///
    /// The final state's activity bitmap is exact.
    pub(crate) async fn test_any_proportional_randomized_bound<F, D>(
        mut context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        let db = randomized_churn(&mut context, db, to_digest, make_value, bounded::<F, D>).await;
        db.assert_exact().await;
        db.destroy().await.unwrap();
    }

    /// Every [`Proportional`] batch of [`randomized_churn`], merkleized on a chain of up to two
    /// pending ancestors, satisfies [`assert_bound`] over the chain's live keys, and so does each
    /// applied state. Every batch since the initial commit is [`Proportional`], as the bound
    /// requires.
    pub(crate) async fn test_any_proportional_pending_bound<F, D>(
        mut context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        let (mut db, mut pending) = randomized_churn(
            &mut context,
            (db, Vec::new()),
            to_digest,
            make_value,
            pending_bounded::<F, D>,
        )
        .await;
        if let Some(tip) = pending.pop() {
            db = db.apply_batch(tip).await.unwrap().0;
        }
        drop(pending);
        db.assert_exact().await;
        db.destroy().await.unwrap();
    }

    /// Every batch of [`churn`] satisfies [`assert_bound`]. Every batch since the initial commit
    /// is [`Proportional`], as the bound requires.
    pub(crate) async fn test_any_proportional_bound<F, D>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        let db = churn(db, to_digest, make_value, bounded::<F, D>).await;
        db.destroy().await.unwrap();
    }

    /// A [`Proportional`] batch moves one active update for each operation it makes inactive: two
    /// for each delete (the delete and the update it supersedes), one for each update it
    /// supersedes, and one for its previous commit.
    ///
    /// Its walk ends at the tip of its writes, so deleting 19 of 20 keys in one batch leaves the
    /// floor two operations below the tip, within `3 * n + 1` for the one remaining key.
    /// Every batch since the initial commit is [`Proportional`], as the bound requires.
    pub(crate) async fn test_any_proportional_one_batch<F, D>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        Operation<F, D::Update>: Codec,
    {
        // Seed 20 keys in key order at 1..21. The seed makes only its previous commit inactive, so
        // it moves one update, the smallest key's from 1 to 21, and the floor passes it.
        let mut keys: Vec<_> = (0..20).map(to_digest).collect();
        keys.sort();
        let seed: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let merkleized = build(&db, db.new_batch(), &seed).await;
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let live = db.live().await;
        assert_eq!((*db.inactivity_floor_loc(), *db.size()), (2, 23));
        assert_eq!(*live[&keys[0]], 21);

        // Deleting the five newest keys (the smallest and the four largest) makes ten operations
        // inactive, plus one for each predecessor an ordered batch rewrites (an update of a live
        // key, which supersedes it), plus the previous commit. The live updates from 2 on are
        // contiguous, so the walk moves that many of them and the floor passes them.
        let deletes = newest(&live, 5);
        let state = written(&db, &[], db.new_batch(), &deletes).await;
        let rewrites = state.live.values().filter(|loc| **loc >= db.size()).count();
        let entries = 2 * deletes.len() + rewrites + 1;
        let active = state.active();
        assert!(
            active[..entries]
                .iter()
                .zip(2..)
                .all(|(loc, at)| **loc == at)
        );
        let at: BTreeMap<_, _> = state.live.iter().map(|(key, loc)| (*loc, *key)).collect();
        let moved: Vec<_> = active[..entries]
            .iter()
            .map(|loc| {
                let key = at[loc];
                let i = keys.binary_search(&key).unwrap();
                (key, Some(make_value(i as u64)))
            })
            .collect();
        let merkleized = build(&db, db.new_batch(), &deletes).await;
        assert_eq!(appended::<F, D>(&merkleized, &state), moved);
        assert_eq!(*D::span(&merkleized).inactivity_floor, 2 + entries as u64);
        drop(merkleized);

        // Delete every key but the one at 2. The only live update after the writes is its own:
        // at 2, or where an ordered batch rewrites it as the deleted keys' predecessor. The walk
        // moves it and reaches the tip of the writes.
        let deletes: Vec<_> = keys
            .iter()
            .filter(|key| **key != keys[1])
            .map(|key| (*key, None))
            .collect();
        let state = written(&db, &[], db.new_batch(), &deletes).await;
        assert!(state.live.keys().eq([&keys[1]]));
        let merkleized = build(&db, db.new_batch(), &deletes).await;
        assert_eq!(
            appended::<F, D>(&merkleized, &state),
            [(keys[1], Some(make_value(1)))]
        );
        assert_eq!(D::span(&merkleized).inactivity_floor, state.tip);

        // The commit follows the move, so the floor trails the tip by two.
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        assert_eq!(*db.size() - *db.inactivity_floor_loc(), 2);
        assert_eq!(db.get(&keys[1]).await.unwrap(), Some(make_value(1)));
        db.assert_exact().await;
        db.destroy().await.unwrap();
    }

    /// The same batch, a child of a pending parent of a pending grandparent, makes the same
    /// decisions and appends the same operations under the same floor and root whether it
    /// merkleizes with both ancestors pending, after the grandparent is applied while still
    /// referenced and after its reference is dropped, and after the parent is applied while still
    /// referenced and after its reference is dropped. Its policy evicts and replaces updates of
    /// the applied state, of each ancestor, and of the batch itself, and stops at the batch's
    /// own create. The applied batch serves the model's values with an exact activity bitmap.
    #[boxed]
    pub(crate) async fn test_any_policy_ancestor_twins<F, D>(
        _context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Inspect<F>,
        D::Merkleized: Clone,
        Operation<F, D::Update>: Codec,
    {
        // Seed eight keys and a sibling of the third in its translated-key bucket.
        let key = |prefix: u8| colliding_digest(prefix, 0);
        let sibling = colliding_digest(0x30, 1);
        let seed: Vec<_> = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]
            .map(key)
            .into_iter()
            .chain([sibling])
            .enumerate()
            .map(|(i, key)| (key, Some(make_value(i as u64))))
            .collect();
        let db = hold(db, &seed).await;
        let mut model = Model::default();
        model.apply(&seed);

        // The grandparent updates, creates, and deletes a key. The parent updates the
        // grandparent's create and a seeded key and deletes the sibling. The batch updates a
        // seeded key, deletes the smallest, and creates the largest.
        let grand = [
            (key(0x20), Some(make_value(102))),
            (key(0x45), Some(make_value(145))),
            (key(0x70), None),
        ];
        let middle = [
            (key(0x45), Some(make_value(245))),
            (key(0x30), Some(make_value(230))),
            (sibling, None),
        ];
        let writes = [
            (key(0x50), Some(make_value(350))),
            (key(0x10), None),
            (key(0x85), Some(make_value(385))),
        ];
        let grandparent = hold_batch(&db, db.new_batch(), &grand).await;
        let parent = hold_batch(&db, D::child(&grandparent), &middle).await;
        let with = |batch: D::Batch| {
            writes
                .iter()
                .fold(batch, |batch, &(key, value)| batch.write(key, value))
        };
        let batches: Vec<_> = (0..5).map(|_| with(D::child(&parent))).collect();

        // The policy evicts the grandparent's update, a key whose ordered predecessor the
        // grandparent creates, and the batch's own update, replaces the parent's update of the
        // grandparent's create, and stops at the batch's create.
        let evicted = [0x20, 0x40, 0x50].map(key);
        let (replaced, replacement, stop) = (key(0x45), make_value(445), key(0x85));
        let choose = |k: &Digest| {
            if evicted.contains(k) {
                Choice::Evict
            } else if *k == replaced {
                Choice::Replace(replacement)
            } else if *k == stop {
                Choice::Stop
            } else {
                Choice::Keep
            }
        };
        let state = written(&db, &[&grandparent, &parent], D::child(&parent), &writes).await;
        let mut batches = batches.into_iter();
        let mut twin = async |db: &D| {
            let mut policy = Script::new(usize::MAX, u64::MAX, choose);
            let merkleized = batches
                .next()
                .unwrap()
                .merkleize(db, None, &mut policy)
                .await
                .unwrap();
            (merkleized, policy.visited)
        };

        // With both ancestors pending, the walk visits every evicted and replaced update before
        // the batch's create, where it stops and leaves the floor.
        let (pending, visited) = twin(&db).await;
        let stopped = state.live[&stop];
        assert_eq!(visited.last().map(|(loc, ..)| *loc), Some(stopped));
        assert_eq!(D::span(&pending).inactivity_floor, stopped);
        for target in evicted.iter().chain([&replaced]) {
            assert!(visited.iter().any(|(_, key, _)| key == target));
        }

        // Apply each ancestor while holding a reference to it, then drop the reference. Each
        // batch matches the one over pending ancestors.
        let retained = grandparent.clone();
        let db = db.apply_batch(grandparent).await.unwrap().0;
        let mut twins = vec![twin(&db).await];
        drop(retained);
        twins.push(twin(&db).await);
        let retained = parent.clone();
        let db = db.apply_batch(parent).await.unwrap().0;
        twins.push(twin(&db).await);
        drop(retained);
        twins.push(twin(&db).await);
        for (merkleized, decided) in &twins {
            assert_eq!(*decided, visited);
            assert_same(&db, &pending, merkleized);
        }
        let last = twins.pop().unwrap().0;
        drop((pending, twins));

        // Apply the batch. It serves the model's values with an exact bitmap.
        let db = db.apply_batch(last).await.unwrap().0;
        model.apply(&grand);
        model.apply(&middle);
        model.apply(&writes);
        model.apply(&[
            (key(0x20), None),
            (key(0x40), None),
            (key(0x50), None),
            (key(0x45), Some(make_value(445))),
        ]);
        assert_eq!(db.inactivity_floor_loc(), stopped);
        assert_values(&db, &model).await;
        assert!(db.live().await.keys().eq(model.values.keys()));
        db.assert_exact().await;
        db.destroy().await.unwrap();
    }

    /// Assert that `db` holds exactly the `live` keys with their values, that each links to the
    /// next live key and the largest to the smallest, that every `absent` key is absent, and that
    /// the activity bitmap is [exact](assert_exact).
    pub(crate) async fn assert_links<F: Family, D: Links<F>>(
        db: &D,
        live: &BTreeMap<Digest, Digest>,
        absent: &[Digest],
    ) {
        assert!(db.live().await.keys().eq(live.keys()), "live keys diverged");
        let next = live.keys().cycle().skip(1);
        for ((key, value), next) in live.iter().zip(next) {
            db.assert_link(*key, *value, *next).await;
        }
        for key in absent {
            db.assert_absent(*key).await;
        }
        db.assert_exact().await;
    }

    /// A diff entry of a batch: the update of its key in the database the batch's chain was built
    /// on, and its location in the batch (`None` when deleted).
    type Change<F> = (Option<GenericLocation<F>>, Option<GenericLocation<F>>);

    /// Batch internals the ordered repair test needs beyond [`Inspect`].
    pub(crate) trait Changes<F: Family>: Inspect<F> {
        /// Return each entry the own diff of `batch` holds for `key`.
        fn changes(batch: &Self::Merkleized, key: &Digest) -> Vec<Change<F>>;

        /// Return a reference to `batch` that does not keep it alive.
        fn downgrade(batch: &Self::Merkleized) -> Weak<impl Sized + use<Self, F>>;
    }

    /// Return each entry `diff` holds for `key`, as [`Changes::changes`] returns them.
    fn changes<F: Family>(
        diff: &[(Digest, batch::DiffEntry<F, Digest>)],
        key: &Digest,
    ) -> Vec<Change<F>> {
        diff.iter()
            .filter(|(k, _)| k == key)
            .map(|(_, entry)| (entry.base_old_loc(), entry.loc()))
            .collect()
    }

    impl<F, C, I, U, const N: usize, S> Changes<F> for Db<F, Context, C, I, Sha256, U, N, S>
    where
        F: Family,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>> + 'static,
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        Self: Inspect<F> + DbAny<F, Merkleized = Arc<batch::MerkleizedBatch<F, Digest, U, S>>>,
    {
        fn changes(batch: &Self::Merkleized, key: &Digest) -> Vec<Change<F>> {
            changes(&batch.diff, key)
        }

        fn downgrade(batch: &Self::Merkleized) -> Weak<impl Sized + use<F, C, I, U, N, S>> {
            Arc::downgrade(batch)
        }
    }

    impl<F, C, I, U, const N: usize, S> Changes<F>
        for crate::qmdb::current::db::Db<F, Context, C, I, Sha256, U, N, S>
    where
        F: crate::merkle::Graftable,
        C: Mutable<Item = Operation<F, U>>,
        I: UnorderedIndex<Value = GenericLocation<F>> + 'static,
        U: Update<Key = Digest, Value = Digest>,
        S: Strategy,
        Operation<F, U>: Codec,
        Self: Inspect<F>
            + DbAny<
                F,
                Merkleized = Arc<crate::qmdb::current::batch::MerkleizedBatch<F, Digest, U, N, S>>,
            >,
    {
        fn changes(batch: &Self::Merkleized, key: &Digest) -> Vec<Change<F>> {
            changes(&batch.inner.diff, key)
        }

        fn downgrade(batch: &Self::Merkleized) -> Weak<impl Sized + use<F, C, I, U, N, S>> {
            Arc::downgrade(batch)
        }
    }

    /// Ordered database access the eviction tests need beyond [`Links`] and [`Changes`].
    pub(crate) trait Neighbors<F: Family>: Links<F> + Changes<F> {
        /// Return the next and the previous live key of `key`, without wrapping, through `batch`,
        /// or through the database without one.
        async fn neighbors(
            &self,
            batch: Option<&Self::Merkleized>,
            key: &Digest,
        ) -> (Option<Digest>, Option<Digest>);
    }

    impl<F, C, I, V, const N: usize, S> Neighbors<F>
        for Db<F, Context, C, I, Sha256, operation::update::Ordered<Digest, V>, N, S>
    where
        F: Family,
        C: Mutable<Item = Operation<F, operation::update::Ordered<Digest, V>>>,
        I: crate::index::Ordered<Value = GenericLocation<F>> + 'static,
        V: ValueEncoding<Value = Digest>,
        S: Strategy,
        Operation<F, operation::update::Ordered<Digest, V>>: Codec,
        Self: Links<F>
            + DbAny<
                F,
                Merkleized = Arc<
                    batch::MerkleizedBatch<F, Digest, operation::update::Ordered<Digest, V>, S>,
                >,
            >,
    {
        async fn neighbors(
            &self,
            batch: Option<&Self::Merkleized>,
            key: &Digest,
        ) -> (Option<Digest>, Option<Digest>) {
            match batch {
                Some(batch) => (
                    batch.get_next_key(key, self).await.unwrap(),
                    batch.get_prev_key(key, self).await.unwrap(),
                ),
                None => (
                    self.get_next_key(key).await.unwrap(),
                    self.get_prev_key(key).await.unwrap(),
                ),
            }
        }
    }

    /// A case of [`test_any_ordered_policy_eviction_matrix`]. Each starts from an empty state.
    struct Case {
        /// Labels the case in assertion messages and its reopen context.
        name: &'static str,
        /// The keys one applied batch creates.
        seed: Vec<Digest>,
        /// The writes one batch applies after the seed.
        applied: Vec<(Digest, Option<Digest>)>,
        /// The writes of a pending parent, if the batch is its child.
        parent: Option<Vec<(Digest, Option<Digest>)>>,
        /// The batch's own writes.
        writes: Vec<(Digest, Option<Digest>)>,
        /// The policy's entries and skips.
        limits: (usize, u64),
        /// The policy's choice for each listed key. It keeps every other update.
        choices: Vec<(Digest, Choice)>,
        /// The predecessors of evicted keys the walk leaves undecided, in key order. The batch
        /// rewrites each once after its decisions.
        rewritten: Vec<Digest>,
    }

    /// Assert that `db` holds exactly the `live` keys, linked in a cycle, that the other `keys`
    /// are absent, and that the database's neighbor queries for every key in `keys` match `live`.
    async fn assert_neighbors<F: Family, D: Neighbors<F>>(
        db: &D,
        batch: Option<&D::Merkleized>,
        live: &BTreeMap<Digest, Digest>,
        keys: &BTreeSet<Digest>,
        name: &str,
    ) {
        if batch.is_none() {
            let absent: Vec<_> = keys
                .iter()
                .filter(|key| !live.contains_key(key))
                .copied()
                .collect();
            assert_links(db, live, &absent).await;
        }
        for key in keys {
            let next = live
                .range((
                    core::ops::Bound::Excluded(*key),
                    core::ops::Bound::Unbounded,
                ))
                .next()
                .map(|(next, _)| *next);
            let prev = live.range(..*key).next_back().map(|(prev, _)| *prev);
            assert_eq!(
                db.neighbors(batch, key).await,
                (next, prev),
                "{name}: neighbors of {key}",
            );
        }
    }

    /// Run `case` on `db` and return the database reopened after applying it.
    ///
    /// The oracle replays the batch's writes into the [state its walk sees](written) and walks it
    /// with [`walk_model`]. The final key set applies the decisions to that state. The
    /// walk appends its decisions in walk order, then rewrites each evicted key's predecessor in
    /// the final key set once, in key order, unless the walk kept or replaced it, which carries
    /// the link in its decision. The batch commits the walk's floor, or its commit location if no
    /// key remains.
    ///
    /// Asserts that the modeled walk reaches every stop, then the decisions, the appended
    /// operations, the floor, and the diff entry of each key the batch creates and evicts, then
    /// the links and neighbor queries of the final key set through the batch, after applying it,
    /// and after reopening.
    #[boxed]
    async fn run_case<F, D, Fut>(
        context: &Context,
        db: D,
        reopen: &impl Fn(Context) -> Fut,
        make_value: &impl Fn(u64) -> Digest,
        case: Case,
    ) -> D
    where
        F: Family,
        D: Neighbors<F>,
        Operation<F, D::Update>: Codec,
        Fut: Future<Output = D>,
    {
        let name = case.name;

        // Delete every key, then seed, apply the writes after the seed, and stage the parent.
        let deletes: Vec<_> = db.live().await.into_keys().map(|key| (key, None)).collect();
        let db = if deletes.is_empty() {
            db
        } else {
            hold(db, &deletes).await
        };
        let seed: Vec<_> = case
            .seed
            .iter()
            .enumerate()
            .map(|(i, key)| (*key, Some(make_value(i as u64))))
            .collect();
        let mut model = Model::default();
        model.apply(&seed);
        let mut db = hold(db, &seed).await;
        if !case.applied.is_empty() {
            model.apply(&case.applied);
            db = hold(db, &case.applied).await;
        }
        let mut parent = None;
        if let Some(writes) = &case.parent {
            model.apply(writes);
            parent = Some(hold_batch(&db, db.new_batch(), writes).await);
        }
        let start = || parent.as_ref().map_or_else(|| db.new_batch(), D::child);
        let floor = parent.as_ref().map_or_else(
            || db.inactivity_floor_loc(),
            |parent| D::span(parent).inactivity_floor,
        );
        let ancestors: Vec<_> = parent.iter().collect();
        let state = written(&db, &ancestors, start(), &case.writes).await;
        let prior: BTreeSet<Digest> = model.values.keys().copied().collect();
        model.apply(&case.writes);

        // Walk the state after the writes.
        let choose = |key: &Digest| {
            case.choices
                .iter()
                .find(|(k, _)| k == key)
                .map_or(Choice::Keep, |(_, choice)| *choice)
        };
        let at: BTreeMap<u64, Digest> = state.live.iter().map(|(key, loc)| (**loc, *key)).collect();
        let active: Vec<u64> = at.keys().copied().collect();
        let stops: Vec<u64> = at
            .iter()
            .filter(|(_, key)| matches!(choose(key), Choice::Stop))
            .map(|(loc, _)| *loc)
            .collect();
        let (entries, skips) = case.limits;
        let (walk_floor, visited) = walk_model(&active, *floor, *state.tip, entries, skips, &stops);
        assert!(
            stops.iter().all(|loc| visited.contains(loc)),
            "{name}: the walk reaches every stop",
        );

        // Apply the decisions, then find the evicted keys' predecessors in the final key set.
        let mut live = model.values.clone();
        let mut appended_ops = Vec::new();
        let mut evicted = Vec::new();
        let mut decided = BTreeSet::new();
        for loc in &visited {
            let key = at[loc];
            match choose(&key) {
                Choice::Keep => {
                    appended_ops.push((key, Some(live[&key])));
                    decided.insert(key);
                }
                Choice::Replace(value) => {
                    live.insert(key, value);
                    appended_ops.push((key, Some(value)));
                    decided.insert(key);
                }
                Choice::Evict => {
                    live.remove(&key);
                    appended_ops.push((key, None));
                    evicted.push(key);
                }
                Choice::Stop => {}
            }
        }
        let rewritten: BTreeSet<Digest> = evicted
            .iter()
            .filter_map(|key| {
                live.range(..*key)
                    .next_back()
                    .or_else(|| live.iter().next_back())
                    .map(|(prev, _)| *prev)
            })
            .filter(|prev| !decided.contains(prev))
            .collect();
        assert!(
            rewritten.iter().eq(&case.rewritten),
            "{name}: rewritten predecessors {rewritten:?}",
        );
        appended_ops.extend(rewritten.iter().map(|key| (*key, Some(live[key]))));
        let floor = if live.is_empty() {
            *state.tip + appended_ops.len() as u64
        } else {
            walk_floor
        };

        // The batch makes the modeled decisions, appends the modeled operations after its writes,
        // and commits the modeled floor.
        let mut policy = Script::new(entries, skips, choose);
        let batch = case
            .writes
            .iter()
            .fold(start(), |batch, &(key, value)| batch.write(key, value));
        let merkleized = batch.merkleize(&db, None, &mut policy).await.unwrap();
        let expected: Vec<_> = visited
            .iter()
            .map(|loc| (GenericLocation::new(*loc), at[loc], model.values[&at[loc]]))
            .collect();
        assert_eq!(policy.visited, expected, "{name}: decisions");
        assert_eq!(
            appended::<F, D>(&merkleized, &state),
            appended_ops,
            "{name}: appended operations",
        );
        assert_eq!(
            *D::span(&merkleized).inactivity_floor,
            floor,
            "{name}: floor"
        );

        // A key the batch creates and the walk evicts ends deleted with no base location.
        for key in evicted.iter().filter(|key| !prior.contains(key)) {
            assert_eq!(
                D::changes(&merkleized, key),
                [(None, None)],
                "{name}: created and evicted {key}",
            );
        }

        // The final key set holds through the batch, after applying it, and after reopening.
        let keys: BTreeSet<_> = model.keys.iter().copied().collect();
        assert_neighbors(&db, Some(&merkleized), &live, &keys, name).await;
        let db = match parent {
            Some(parent) => db.apply_batch(parent).await.unwrap().0,
            None => db,
        };
        let db = db.apply_batch(merkleized).await.unwrap().0;
        assert_eq!(*db.inactivity_floor_loc(), floor, "{name}: applied floor");
        assert_neighbors(&db, None, &live, &keys, name).await;
        let db = db.commit().await.unwrap();
        drop(db);
        let db = reopen(context.child(name)).await;
        assert_eq!(*db.inactivity_floor_loc(), floor, "{name}: reopened floor");
        assert_neighbors(&db, None, &live, &keys, name).await;
        db
    }

    /// Evicting ordered keys rewrites each evicted key's predecessor in the final key set to link
    /// past it, whatever holds the predecessor's update: an applied update the walk leaves
    /// undecided, kept, or stops at; a write of the batch the walk leaves undecided (written
    /// twice), or one it creates; a pending parent's update; a sibling in the evicted key's
    /// translated-key bucket; or the largest key, for the smallest evicted key.
    ///
    /// The cases also evict chains of two and three adjacent keys, the largest key, the batch's own
    /// writes, a key whose predecessor the walk decides later or replaces, every key but one, and
    /// every key.
    ///
    /// Under tight skips, the walk never reaches the predecessor, or stops at it with its last skip.
    ///
    /// Each case checks the decisions, the operations the walk appends, and the floor against a
    /// [model](run_case) of the state after the batch's writes, and the links and neighbor queries
    /// of the final key set through the batch, after applying it, and after reopening.
    ///
    /// A key the batch creates and the walk evicts ends with no base location in the batch's diff.
    #[boxed]
    pub(crate) async fn test_any_ordered_policy_eviction_matrix<F, D, Fut>(
        context: Context,
        db: D,
        reopen: impl Fn(Context) -> Fut,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Neighbors<F>,
        Operation<F, D::Update>: Codec,
        Fut: Future<Output = D>,
    {
        let key = |prefix: u8| colliding_digest(prefix, 0);
        let [a, b, c, d, e, f, g] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70].map(key);
        let [x0, x1, x2] = [0, 1, 2].map(|suffix| colliding_digest(0x30, suffix));
        let value = |i: u64| Some(make_value(1000 + i));
        let evict =
            |keys: &[Digest]| -> Vec<_> { keys.iter().map(|key| (*key, Choice::Evict)).collect() };
        let unbounded = (usize::MAX, u64::MAX);
        let case = |name, seed: &[Digest], limits, choices, rewritten: &[Digest]| Case {
            name,
            seed: seed.to_vec(),
            applied: Vec::new(),
            parent: None,
            writes: Vec::new(),
            limits,
            choices,
            rewritten: rewritten.to_vec(),
        };
        let five = [a, b, c, d, e];
        let eight = [a, b, c, x1, d, e, f, g];
        let cases = [
            // The kept smallest key links past the adjacent second and third, and the replaced
            // fourth links past the evicted largest key to the smallest.
            Case {
                choices: vec![
                    (b, Choice::Evict),
                    (c, Choice::Evict),
                    (d, Choice::Replace(make_value(1004))),
                    (e, Choice::Evict),
                ],
                ..case("kept_and_replaced", &five, unbounded, Vec::new(), &[])
            },
            // The smallest key's update lies past the two updates the walk decides.
            Case {
                applied: vec![(a, value(1))],
                ..case("undecided_applied", &five, (2, u64::MAX), evict(&[b]), &[a])
            },
            // The walk stops at the smallest key's update, past the evicted second.
            Case {
                applied: vec![(a, value(1))],
                choices: vec![(b, Choice::Evict), (a, Choice::Stop)],
                ..case("stopped", &five, unbounded, Vec::new(), &[a])
            },
            // Emptying the previous case's state moves the floor to its commit, so the seed lies
            // just past the floor. The inactive locations below the smallest key's last update are
            // that commit, the key's superseded update, and the seed commit. Two skips reach the
            // second key, and after keeping the third through fifth keys the walk has no skip left
            // to pass the seed commit, so it never reaches the smallest key's update.
            Case {
                applied: vec![(a, value(10))],
                ..case(
                    "unreached_predecessor",
                    &five,
                    (usize::MAX, 2),
                    evict(&[b]),
                    &[a],
                )
            },
            // Three skips exactly reach the smallest key's update, where the walk stops after
            // evicting the second.
            Case {
                applied: vec![(a, value(11))],
                choices: vec![(b, Choice::Evict), (a, Choice::Stop)],
                ..case(
                    "stopped_at_last_skip",
                    &five,
                    (usize::MAX, 3),
                    Vec::new(),
                    &[a],
                )
            },
            // The walk keeps the smallest key's update after evicting its successor.
            Case {
                applied: vec![(a, value(1))],
                ..case("decided_later", &five, unbounded, evict(&[b]), &[])
            },
            // The same, with the smallest key's update in a pending parent.
            Case {
                parent: Some(vec![(a, value(1))]),
                ..case("parent_decided_later", &five, unbounded, evict(&[b]), &[])
            },
            // The batch updates the smallest key, and the walk decides only the second.
            Case {
                writes: vec![(a, value(2))],
                ..case("undecided_write", &five, (1, u64::MAX), evict(&[b]), &[a])
            },
            // The batch creates the second key, and the walk decides only the third.
            Case {
                writes: vec![(b, value(3))],
                ..case("created", &[a, c, d, e], (1, u64::MAX), evict(&[c]), &[b])
            },
            // A pending parent creates the second key, and the walk decides only the third.
            Case {
                parent: Some(vec![(b, value(3))]),
                ..case(
                    "parent_created",
                    &[a, c, d, e],
                    (1, u64::MAX),
                    evict(&[c]),
                    &[b],
                )
            },
            // The evicted key's predecessor shares its bucket, and its update lies past the two
            // updates the walk decides.
            Case {
                applied: vec![(x0, value(5))],
                ..case(
                    "sibling",
                    &[a, x0, x1, x2, e],
                    (2, u64::MAX),
                    evict(&[x1]),
                    &[x0],
                )
            },
            // The three smallest keys share the undecided largest key as their predecessor.
            case(
                "wrapped_chain",
                &five,
                (3, u64::MAX),
                evict(&[a, b, c]),
                &[e],
            ),
            // The adjacent third and fourth keys share the undecided second key as predecessor,
            // whose update lies past the three updates the walk decides. The repair reaches it
            // through the fourth key's previous bucket, the evicted third key's, and then that
            // key's previous bucket.
            Case {
                applied: vec![(b, value(9))],
                ..case(
                    "two_bucket_chain",
                    &five,
                    (3, u64::MAX),
                    evict(&[c, d]),
                    &[b],
                )
            },
            // The middle key links to itself.
            case("all_but_one", &five, unbounded, evict(&[a, b, d, e]), &[]),
            case("every_key", &five, unbounded, evict(&five), &[]),
            // The batch updates the second key and creates the sixth, rewriting the largest as
            // its predecessor. The walk evicts both writes and keeps the rewrite.
            Case {
                writes: vec![(b, value(6)), (f, value(7))],
                ..case("own_writes", &five, unbounded, evict(&[b, f]), &[])
            },
            // A child of a pending parent evicts the parent's update of the third key and the
            // adjacent fourth.
            Case {
                parent: Some(vec![(c, value(8))]),
                ..case("parent_chain", &five, unbounded, evict(&[c, d]), &[])
            },
            // Of eight keys, the third and fourth share a translated-key bucket. The walk evicts
            // the second, fourth, sixth, and largest keys, so each predecessor it keeps carries
            // the link, including the fourth key's sibling. It stops at the smallest key's update,
            // which it rewrites to link past the second.
            Case {
                applied: vec![(a, value(20))],
                choices: vec![
                    (b, Choice::Evict),
                    (x1, Choice::Evict),
                    (e, Choice::Evict),
                    (g, Choice::Evict),
                    (a, Choice::Stop),
                ],
                ..case("links_stop_smallest", &eight, unbounded, Vec::new(), &[a])
            },
            // The same evictions from a child of a pending parent that updates the fifth key,
            // which the walk keeps.
            Case {
                parent: Some(vec![(d, value(21))]),
                ..case(
                    "links_parent_kept",
                    &eight,
                    unbounded,
                    evict(&[b, x1, e, g]),
                    &[],
                )
            },
            // The two smallest keys share the largest as their predecessor, which the walk keeps
            // and links to the third key.
            case("links_two_smallest", &eight, unbounded, evict(&[a, b]), &[]),
            // A child evicts a pending parent's update of the fourth key, so its sibling, the
            // third key, links to the fifth.
            Case {
                parent: Some(vec![(x1, value(22))]),
                ..case("links_parent_evicted", &eight, unbounded, evict(&[x1]), &[])
            },
        ];
        let mut db = db;
        for case in cases {
            db = run_case(&context, db, &reopen, &make_value, case).await;
        }
        db.destroy().await.unwrap();
    }

    /// Evicting the first live update a child of two pending ancestors reaches rewrites the key's
    /// predecessor, an update of the parent the walk leaves undecided, to link past it. Keys
    /// A < B < C < D < E share one translated-key bucket. The grandparent writes B, the parent
    /// updates it, and the child, with one entry, evicts C. The child appends the delete and then
    /// B with the parent's value, and its diff holds one entry for B whose base is the update of B
    /// in the database the ancestors were built on: none when the grandparent creates B
    /// (rewriting A), and B's last applied update when the database holds it.
    ///
    /// The child makes the same decision and appends the same operations under the same floor and
    /// root whether it applies directly over both pending ancestors, merkleizes after the
    /// grandparent is applied and freed, or applies after the parent is applied. Each run links A,
    /// B, D, and E through the batch, after applying it, and after reopening, with an exact
    /// activity bitmap.
    #[boxed]
    pub(crate) async fn test_any_ordered_policy_repair_across_ancestors<F, D, Fut>(
        context: Context,
        db: D,
        reopen: impl Fn(Context) -> Fut,
        make_value: impl Fn(u64) -> Digest,
    ) where
        F: Family,
        D: Neighbors<F>,
        Operation<F, D::Update>: Codec,
        Fut: Future<Output = D>,
    {
        /// When the child merkleizes and applies relative to its ancestors.
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Lifecycle {
            /// Merkleize and apply over both pending ancestors.
            Pending,
            /// Apply and free the grandparent, then merkleize and apply over the pending parent.
            Freed,
            /// Merkleize over both pending ancestors, apply the parent, then apply the child.
            Applied,
        }

        let keys: [Digest; 5] = core::array::from_fn(|i| colliding_digest(0xAA, i as u64));
        assert!(keys.is_sorted());
        let [_, b, c, _, _] = keys;
        let all: BTreeSet<_> = keys.into_iter().collect();
        let parent_value = make_value(301);

        // Each variant seeds keys, then updates some in later batches, all with a held floor.
        let variants: [(&'static str, &[usize], &[usize]); 2] = [
            ("created", &[0, 2, 3, 4], &[]),
            ("applied", &[0, 1, 2, 3, 4], &[0, 1]),
        ];
        let lifecycles = [
            ("pending", Lifecycle::Pending),
            ("freed", Lifecycle::Freed),
            ("applied", Lifecycle::Applied),
        ];
        let mut db = db;
        for (variant, seeded, updated) in variants {
            let mut outcomes = Vec::new();
            for (name, lifecycle) in lifecycles {
                let label = format!("{variant} {name}");
                let ctx = context.child(variant).child(name);
                db.destroy().await.unwrap();
                let mut fresh = reopen(ctx.child("fresh")).await;
                let seed: Vec<_> = seeded
                    .iter()
                    .map(|&i| (keys[i], Some(make_value(i as u64))))
                    .collect();
                fresh = hold(fresh, &seed).await;
                for &i in updated {
                    fresh = hold(fresh, &[(keys[i], Some(make_value(100 + i as u64)))]).await;
                }
                let applied = fresh.live().await;
                let mut live: BTreeMap<_, _> = seed
                    .iter()
                    .map(|(key, value)| (*key, value.unwrap()))
                    .collect();
                for &i in updated {
                    live.insert(keys[i], make_value(100 + i as u64));
                }
                live.insert(b, parent_value);
                live.remove(&c);

                // The grandparent writes B and the parent updates it. With one entry, the walk
                // decides only C, the first live update it reaches.
                let grandparent =
                    hold_batch(&fresh, fresh.new_batch(), &[(b, Some(make_value(201)))]).await;
                let parent =
                    hold_batch(&fresh, D::child(&grandparent), &[(b, Some(parent_value))]).await;
                let state = written(&fresh, &[&grandparent, &parent], D::child(&parent), &[]).await;
                let active: Vec<u64> = state.active().iter().map(|loc| **loc).collect();
                let floor = *D::span(&parent).inactivity_floor;
                let (floor, visited) = walk_model(&active, floor, *state.tip, 1, u64::MAX, &[]);
                assert_eq!(
                    visited,
                    [*state.live[&c]],
                    "{label}: C is not the first update"
                );

                // Merkleize the child, after applying and freeing the grandparent when the
                // lifecycle requires it. Only the parent's batch references the grandparent, and
                // only weakly.
                let child = D::child(&parent);
                let (fresh, grandparent) = if lifecycle == Lifecycle::Freed {
                    let weak = D::downgrade(&grandparent);
                    let fresh = fresh.apply_batch(grandparent).await.unwrap().0;
                    assert_eq!(weak.strong_count(), 0, "{label}: the grandparent is alive");
                    (fresh, None)
                } else {
                    (fresh, Some(grandparent))
                };
                let choose = |key: &Digest| {
                    assert_eq!(*key, c, "{label}: decided a key other than C");
                    Choice::Evict
                };
                let mut policy = Script::new(1, u64::MAX, choose);
                let merkleized = child.merkleize(&fresh, None, &mut policy).await.unwrap();
                assert_eq!(policy.locations(), [state.live[&c]], "{label}: decisions");
                assert_eq!(
                    appended::<F, D>(&merkleized, &state),
                    [(c, None), (b, Some(parent_value))],
                    "{label}: appended operations",
                );
                assert_eq!(
                    *D::span(&merkleized).inactivity_floor,
                    floor,
                    "{label}: floor"
                );
                assert_eq!(
                    D::changes(&merkleized, &b),
                    [(applied.get(&b).copied(), Some(state.tip + 1))],
                    "{label}: B's diff entries",
                );
                assert_eq!(
                    D::changes(&merkleized, &c),
                    [(Some(applied[&c]), None)],
                    "{label}: C's diff entries",
                );
                assert_neighbors(&fresh, Some(&merkleized), &live, &all, &label).await;
                let (start, ops) = D::ops(&merkleized);
                let ops: Vec<_> = ops.iter().map(|op| op.encode().to_vec()).collect();
                outcomes.push((start, ops, floor, MerkleizedTrait::root(&merkleized)));

                // Apply the child, after applying the parent when the lifecycle requires it.
                let (fresh, parent) = if lifecycle == Lifecycle::Applied {
                    (fresh.apply_batch(parent).await.unwrap().0, None)
                } else {
                    (fresh, Some(parent))
                };
                let fresh = fresh.apply_batch(merkleized).await.unwrap().0;
                drop((grandparent, parent));
                assert_eq!(
                    *fresh.inactivity_floor_loc(),
                    floor,
                    "{label}: applied floor"
                );
                assert_neighbors(&fresh, None, &live, &all, &label).await;
                drop(fresh.commit().await.unwrap());
                db = reopen(ctx.child("reopened")).await;
                assert_eq!(*db.inactivity_floor_loc(), floor, "{label}: reopened floor");
                assert_neighbors(&db, None, &live, &all, &label).await;
            }
            for outcome in &outcomes[1..] {
                assert_eq!(*outcome, outcomes[0], "{variant}: the lifecycles diverged");
            }
        }
        db.destroy().await.unwrap();
    }

    /// A policy over uncached updates reads every update it decides in one batched read of
    /// exactly those updates, and merkleize reads nothing more.
    ///
    /// The decided updates lie among superseded ones, superseded either by applied updates or by
    /// the batch's writes. Writes add one batched read before the first decision: the
    /// resolution's read of the written keys.
    pub(crate) async fn test_any_policy_reads_in_one_read<F: Family, D>(
        context: Context,
        db: D,
        reopen_db: impl Fn(Context) -> Pin<Box<dyn Future<Output = D> + Send>>,
        make_value: impl Fn(u64) -> Digest,
    ) where
        D: DbAny<F, Key = Digest, Value = Digest, Digest = Digest>,
    {
        let names = [
            "log_journal_read_calls_total",
            "log_journal_read_many_calls_total",
            "log_journal_items_read_total",
        ];
        let mut db = db;
        for in_batch in [false, true] {
            let ctx = context.child(if in_batch { "in_batch" } else { "applied" });

            // Seed the 64 smallest keys in key order with a held floor. Then either supersede all
            // but every eighth one, or seed the 64 larger keys after them. Only the largest seeded
            // key precedes a larger key, so an ordered database rewrites no other seeded update.
            let mut keys: Vec<_> = (0..128).map(to_digest).collect();
            keys.sort();
            let seed: Vec<_> = keys[..64]
                .iter()
                .enumerate()
                .map(|(i, key)| (*key, Some(make_value(i as u64))))
                .collect();
            db = hold(db, &seed).await;
            let later: Vec<_> = if in_batch {
                keys[64..]
                    .iter()
                    .enumerate()
                    .map(|(i, key)| (*key, Some(make_value(64 + i as u64))))
                    .collect()
            } else {
                seed.iter()
                    .enumerate()
                    .filter(|(i, _)| i % 8 != 0)
                    .map(|(i, (key, _))| (*key, Some(make_value(i as u64 + 100))))
                    .collect()
            };
            db = hold(db, &later).await;
            drop(db.commit().await.unwrap());

            // Reopen so no operation is cached.
            db = reopen_db(ctx.child("cold")).await;

            // Decide every eighth update, or write every odd one of the first sixteen updates and
            // decide the eight even ones, which spends every entry before the writes. Every
            // decision follows the same batched reads. Without writes, those reads hold exactly
            // the eight decided updates.
            let (stride, batch, deltas): (_, _, &[u64]) = if in_batch {
                let batch = (1..16).step_by(2).fold(db.new_batch(), |batch, i| {
                    batch.write(keys[i], Some(make_value(i as u64 + 100)))
                });
                (2, batch, &[0, 2])
            } else {
                (8, db.new_batch(), &[0, 1, 8])
            };
            let sample = || -> Vec<_> {
                names[..deltas.len()]
                    .iter()
                    .map(|name| counter(&context, name))
                    .collect()
            };
            let after: Vec<_> = sample().iter().zip(deltas).map(|(n, d)| n + d).collect();
            let mut probes = Vec::new();
            let mut policy = Script::new(8, u64::MAX, |_: &Digest| {
                probes.push(sample());
                Choice::Keep
            });
            batch.merkleize(&db, None, &mut policy).await.unwrap();
            let expected: Vec<_> = (0..8 * stride)
                .step_by(stride)
                .map(|i| (GenericLocation::<F>::new(1 + i as u64), keys[i]))
                .collect();
            let decided: Vec<_> = policy
                .visited
                .iter()
                .map(|(loc, key, _)| (*loc, *key))
                .collect();
            assert_eq!(decided, expected, "in_batch={in_batch}");
            assert_eq!(probes, vec![after.clone(); 8], "in_batch={in_batch}");
            assert_eq!(sample(), after, "in_batch={in_batch}");

            // Start the next case from an empty database.
            db.destroy().await.unwrap();
            db = reopen_db(ctx.child("fresh")).await;
        }
        db.destroy().await.unwrap();
    }

    /// Merkleizing an unordered batch whose policy keeps, evicts, and replaces updates reads no
    /// operation past the policy's reads.
    pub(crate) async fn test_any_policy_unordered_reads_nothing<F: Family, D>(
        context: Context,
        db: D,
        make_value: impl Fn(u64) -> Digest,
    ) where
        D: DbAny<F, Key = Digest, Value = Digest, Digest = Digest>,
    {
        // Seed sixteen updates with a held floor.
        let seed: Vec<_> = (0..16)
            .map(|i| (to_digest(i), Some(make_value(i))))
            .collect();
        let db = hold(db, &seed).await;

        // Evict one key, replace another, and keep the rest. Merkleize reads nothing after the
        // last decision.
        let replacement = make_value(200);
        let mut probes = Vec::new();
        let mut policy = Script::new(usize::MAX, u64::MAX, |key: &Digest| {
            probes.push(counter(&context, "log_journal_items_read_total"));
            if *key == to_digest(1) {
                Choice::Evict
            } else if *key == to_digest(2) {
                Choice::Replace(replacement)
            } else {
                Choice::Keep
            }
        });
        let merkleized = db
            .new_batch()
            .merkleize(&db, None, &mut policy)
            .await
            .unwrap();
        assert_eq!(policy.visited.len(), 16);
        assert_eq!(
            probes.last().copied(),
            Some(counter(&context, "log_journal_items_read_total"))
        );

        // Published values reflect the keeps, replacement, and eviction.
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        for (i, (key, value)) in seed.into_iter().enumerate() {
            let expected = match i {
                1 => None,
                2 => Some(replacement),
                _ => value,
            };
            assert_eq!(db.get(&key).await.unwrap(), expected);
        }
        db.destroy().await.unwrap();
    }

    /// Skips that run out before a live update leave it undecided, and a window that ends at the
    /// update leaves it unread. A policy that stops at the update commits the floor at its
    /// location.
    #[test_traced("INFO")]
    fn test_any_policy_skips_stop_before_live_update() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("policy-skips", &ctx),
                None,
            )
            .await
            .unwrap();

            // Seed two keys, then delete the first, with a held floor.
            let mut keys = [key(0), key(1)];
            keys.sort();
            let seed = db
                .new_batch()
                .write(keys[0], Some(val(0)))
                .write(keys[1], Some(val(1)))
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, seed_range) = db.apply_batch(seed).await.unwrap();
            let deleted = db
                .new_batch()
                .write(keys[0], None)
                .merkleize(&db, None, &mut Hold)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(deleted).await.unwrap();
            let reads = || counter(&context, "log_journal_items_read_total");
            let live = seed_range.start + 1;
            let gap = *live - *db.inactivity_floor_loc();

            // One skip short of the live update, the policy decides nothing. With one entry, the
            // window ends at the update, so the walk reads nothing. With unbounded entries, the
            // window reaches the tip, and the walk reads the update it cannot reach: the limits
            // bound what the walk passes and decides, and the window bounds what it reads.
            for (entries, read) in [(1, 0), (usize::MAX, 1)] {
                let before = reads();
                let mut policy = Script::new(entries, gap - 1, keep);
                let merkleized = db
                    .new_batch()
                    .merkleize(&db, None, &mut policy)
                    .await
                    .unwrap();
                assert!(policy.visited.is_empty());
                assert_eq!(*merkleized.bounds().inactivity_floor, *live - 1);
                assert_eq!(reads(), before + read, "entries={entries}");
            }

            // A policy with unbounded limits reads only the live update. The inactive suffix and
            // the last commit need no read.
            let before = reads();
            let mut policy = Script::new(usize::MAX, u64::MAX, keep);
            let merkleized = db
                .new_batch()
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(policy.locations(), [live]);
            assert_eq!(merkleized.bounds().inactivity_floor, db.size());
            assert_eq!(reads(), before + 1, "only the live update is read");
            drop(merkleized);

            // With exactly enough skips, a policy that stops at the live update commits the
            // floor at its location.
            let mut policy = Script::new(usize::MAX, gap, |_: &Digest| Choice::Stop);
            let merkleized = db
                .new_batch()
                .merkleize(&db, None, &mut policy)
                .await
                .unwrap();
            assert_eq!(policy.locations(), [live]);
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            assert_eq!(db.inactivity_floor_loc(), live);
            assert_eq!(db.get(&keys[0]).await.unwrap(), None);
            assert_eq!(db.get(&keys[1]).await.unwrap(), Some(val(1)));
            db.destroy().await.unwrap();
        });
    }

    fn key(i: u64) -> Digest {
        Sha256::hash(&[&i.to_be_bytes()])
    }

    fn val(i: u64) -> Digest {
        Sha256::hash(&[&(i + 10000).to_be_bytes()])
    }

    /// Helper: commit a batch of key-value writes and return the db and applied range.
    async fn commit_writes(
        db: UnorderedVariable,
        writes: impl IntoIterator<Item = (Digest, Option<Digest>)>,
        metadata: Option<Digest>,
    ) -> (UnorderedVariable, std::ops::Range<crate::mmr::Location>) {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch
            .merkleize(&db, metadata, &mut Proportional)
            .await
            .unwrap();
        let (db, range) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        (db, range)
    }

    /// Dropping an in-flight parallel init (e.g. losing a select against a timeout) aborts
    /// its snapshot workers and decoders rather than leaving them running until they happen
    /// to observe a closed channel.
    #[test_traced("INFO")]
    fn test_parallel_init_aborted_on_cancel() {
        /// Sum of the runtime's running-task gauges for snapshot build tasks.
        fn running_build_tasks(metrics: &str) -> u64 {
            metrics
                .lines()
                .filter(|line| {
                    line.starts_with("runtime_tasks_running{")
                        && (line.contains("snapshot_worker") || line.contains("snapshot_decoder"))
                })
                .filter_map(|line| line.rsplit_once(' ')?.1.trim().parse::<u64>().ok())
                .sum()
        }

        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let cfg =
                || fixed_db_config_full::<OneCap, _, _>("cancel", &ctx, Sequential, NZUsize!(4));

            // Persist enough operations that the reopen's build spans many decode chunks.
            let db: UnorderedFixedP1 = UnorderedFixedP1::init(ctx.child("storage"), cfg(), None)
                .await
                .unwrap();
            let mut batch = db.new_batch();
            for i in 0..2_000u64 {
                batch = batch.write(key(i), Some(key(i)));
            }
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let db = db.commit().await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            {
                // Poll until snapshot tasks own the pending build, then cancel before init returns.
                let init = UnorderedFixedP1::init(ctx.child("storage"), cfg(), None);
                pin_mut!(init);
                let mut spawned = false;
                for _ in 0..10_000 {
                    if poll!(&mut init).is_ready() {
                        panic!("init completed before it could be cancelled");
                    }
                    context.sleep(Duration::from_millis(1)).await;
                    if running_build_tasks(&context.encode()) > 0 {
                        spawned = true;
                        break;
                    }
                }
                assert!(spawned, "build tasks never spawned");
            }

            // Leaving the scope dropped the init future. Give the runtime a beat to reap
            // the aborted tasks.
            context.sleep(Duration::from_millis(10)).await;
            let metrics = context.encode();
            assert_eq!(running_build_tasks(&metrics), 0, "{metrics}");
        });
    }

    /// An empty batch (no mutations) still produces a valid commit.
    #[test_traced("INFO")]
    fn test_any_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("e", &ctx),
                None,
            )
            .await
            .unwrap();

            let root_before = db.root();
            let batch = db.new_batch();
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();

            // A CommitFloor op was appended, so root must change.
            assert_ne!(db.root(), root_before);

            // DB should still be functional.
            let (db, _) = commit_writes(db, [(key(0), Some(val(0)))], None).await;
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            db.destroy().await.unwrap();
        });
    }

    /// Metadata propagates through merkleize and clears with None.
    #[test_traced("INFO")]
    fn test_any_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("m", &ctx),
                None,
            )
            .await
            .unwrap();

            let metadata = val(42);

            // Batch with metadata.
            let (db, _) = commit_writes(db, [(key(0), Some(val(0)))], Some(metadata)).await;
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            // Batch without metadata clears it.
            let batch = db.new_batch();
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// batch.get() reads through: pending mutations -> base DB.
    /// Updates shadow the base value; deletes hide the key.
    #[test_traced("INFO")]
    fn test_any_batch_get_read_through() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("g", &ctx),
                None,
            )
            .await
            .unwrap();

            // Pre-populate with key A.
            let ka = key(0);
            let va = val(0);
            let (db, _) = commit_writes(db, [(ka, Some(va))], None).await;

            let kb = key(1);
            let vb = val(1);
            let kc = key(2);

            let mut batch = db.new_batch();

            // Read-through to base DB.
            assert_eq!(batch.get(&ka, &db).await.unwrap(), Some(va));

            // Pending mutation visible.
            batch = batch.write(kb, Some(vb));
            assert_eq!(batch.get(&kb, &db).await.unwrap(), Some(vb));

            // Nonexistent key.
            assert_eq!(batch.get(&kc, &db).await.unwrap(), None);

            // Update shadows base DB value.
            let va2 = val(100);
            batch = batch.write(ka, Some(va2));
            assert_eq!(batch.get(&ka, &db).await.unwrap(), Some(va2));

            // Delete hides the key.
            batch = batch.write(ka, None);
            assert_eq!(batch.get(&ka, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// merkleized.get() reflects the resolved diff after merkleize.
    #[test_traced("INFO")]
    fn test_any_batch_get_on_merkleized() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("mg", &ctx),
                None,
            )
            .await
            .unwrap();

            let ka = key(0);
            let kb = key(1);
            let kc = key(2);
            let kd = key(3);

            // Pre-populate A and B.
            let (db, _) = commit_writes(db, [(ka, Some(val(0))), (kb, Some(val(1)))], None).await;

            // Batch: update A, delete B, create C.
            let va2 = val(100);
            let vc = val(2);
            let mut batch = db.new_batch();
            batch = batch.write(ka, Some(va2));
            batch = batch.write(kb, None);
            batch = batch.write(kc, Some(vc));
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();

            assert_eq!(merkleized.get(&ka, &db).await.unwrap(), Some(va2));
            assert_eq!(merkleized.get(&kb, &db).await.unwrap(), None);
            assert_eq!(merkleized.get(&kc, &db).await.unwrap(), Some(vc));
            assert_eq!(merkleized.get(&kd, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Child batch reads through: child mutations -> parent diff -> base DB.
    #[test_traced("INFO")]
    fn test_any_batch_stacked_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("sg", &ctx),
                None,
            )
            .await
            .unwrap();

            let ka = key(0);
            let kb = key(1);

            // Parent batch writes A.
            let mut batch = db.new_batch();
            batch = batch.write(ka, Some(val(0)));
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();

            // Child reads parent's A.
            let mut child = merkleized.new_batch::<Sha256>();
            assert_eq!(child.get(&ka, &db).await.unwrap(), Some(val(0)));

            // Child overwrites A.
            child = child.write(ka, Some(val(100)));
            assert_eq!(child.get(&ka, &db).await.unwrap(), Some(val(100)));

            // Child writes new key B.
            child = child.write(kb, Some(val(1)));
            assert_eq!(child.get(&kb, &db).await.unwrap(), Some(val(1)));

            // Child deletes A.
            child = child.write(ka, None);
            assert_eq!(child.get(&ka, &db).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Parent deletes a base-DB key, child re-creates it.
    #[test_traced("INFO")]
    fn test_any_batch_stacked_delete_recreate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("dr", &ctx),
                None,
            )
            .await
            .unwrap();

            let ka = key(0);

            // Pre-populate with key A.
            let (db, _) = commit_writes(db, [(ka, Some(val(0)))], None).await;

            // Parent batch deletes A.
            let mut parent = db.new_batch();
            parent = parent.write(ka, None);
            let parent_m = parent
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert_eq!(parent_m.get(&ka, &db).await.unwrap(), None);

            // Child re-creates A with a new value.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.write(ka, Some(val(200)));
            let child_m = child.merkleize(&db, None, &mut Proportional).await.unwrap();
            assert_eq!(child_m.get(&ka, &db).await.unwrap(), Some(val(200)));

            // Apply and verify DB state.
            let (db, _) = db.apply_batch(child_m).await.unwrap();
            assert_eq!(db.get(&ka).await.unwrap(), Some(val(200)));

            db.destroy().await.unwrap();
        });
    }

    /// The floor walk during merkleize moves active operations to the tip. All keys remain
    /// accessible with correct values.
    #[test_traced("INFO")]
    fn test_any_batch_floor_walk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("fr", &ctx),
                None,
            )
            .await
            .unwrap();

            // Pre-populate with 100 keys.
            let init: Vec<_> = (0..100).map(|i| (key(i), Some(val(i)))).collect();
            let (db, _) = commit_writes(db, init, None).await;

            let floor_before = db.inactivity_floor_loc();

            // Update 30 keys.
            let updates: Vec<_> = (0..30).map(|i| (key(i), Some(val(i + 500)))).collect();
            let (db, _) = commit_writes(db, updates, None).await;

            // Floor should have advanced.
            assert!(db.inactivity_floor_loc() > floor_before);

            // All keys should still be accessible with correct values.
            for i in 0..30 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i + 500)),
                    "updated key {i} mismatch"
                );
            }
            for i in 30..100 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i)),
                    "untouched key {i} mismatch"
                );
            }

            db.destroy().await.unwrap();
        });
    }

    /// apply_batch() returns the correct range of committed locations.
    #[test_traced("INFO")]
    fn test_any_batch_apply_returns_range() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("ar", &ctx),
                None,
            )
            .await
            .unwrap();

            // First batch: 5 keys.
            let writes: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
            let (db, range1) = commit_writes(db, writes, None).await;

            // Range should start after the initial CommitFloor (location 0).
            assert_eq!(range1.start, crate::mmr::Location::new(1));
            // Range length >= 6 (5 writes + 1 CommitFloor + possible floor walk ops).
            assert!(range1.end.saturating_sub(*range1.start) >= 6);

            // Second batch: ranges must be contiguous.
            let writes: Vec<_> = (5..10).map(|i| (key(i), Some(val(i)))).collect();
            let (db, range2) = commit_writes(db, writes, None).await;
            assert_eq!(range2.start, range1.end);

            db.destroy().await.unwrap();
        });
    }

    /// 3-level chain: parent -> child -> grandchild, merkleize grandchild and apply.
    #[test_traced("INFO")]
    fn test_any_batch_deep_chain() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("dc", &ctx),
                None,
            )
            .await
            .unwrap();

            // Pre-populate with keys 0..5.
            let init: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
            let (db, _) = commit_writes(db, init, None).await;

            // Parent: overwrite key 0, add key 5.
            let mut parent = db.new_batch();
            parent = parent.write(key(0), Some(val(100)));
            parent = parent.write(key(5), Some(val(5)));
            let parent_m = parent
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child: overwrite key 1, add key 6.
            let mut child = parent_m.new_batch::<Sha256>();
            child = child.write(key(1), Some(val(101)));
            child = child.write(key(6), Some(val(6)));
            let child_m = child.merkleize(&db, None, &mut Proportional).await.unwrap();

            // Grandchild: delete key 2, add key 7.
            let mut grandchild = child_m.new_batch::<Sha256>();
            grandchild = grandchild.write(key(2), None);
            grandchild = grandchild.write(key(7), Some(val(7)));
            let grandchild_m = grandchild
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Verify reads through the chain.
            assert_eq!(
                grandchild_m.get(&key(0), &db).await.unwrap(),
                Some(val(100))
            );
            assert_eq!(
                grandchild_m.get(&key(1), &db).await.unwrap(),
                Some(val(101))
            );
            assert_eq!(grandchild_m.get(&key(2), &db).await.unwrap(), None);
            assert_eq!(grandchild_m.get(&key(7), &db).await.unwrap(), Some(val(7)));

            // Apply.
            let (db, _) = db.apply_batch(grandchild_m).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(100)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(101)));
            assert_eq!(db.get(&key(2)).await.unwrap(), None);
            assert_eq!(db.get(&key(3)).await.unwrap(), Some(val(3)));
            assert_eq!(db.get(&key(4)).await.unwrap(), Some(val(4)));
            assert_eq!(db.get(&key(5)).await.unwrap(), Some(val(5)));
            assert_eq!(db.get(&key(6)).await.unwrap(), Some(val(6)));
            assert_eq!(db.get(&key(7)).await.unwrap(), Some(val(7)));

            db.destroy().await.unwrap();
        });
    }

    /// Chained batch produces the same DB state as sequential apply_batch calls.
    #[test_traced("INFO")]
    fn test_any_batch_chain_matches_sequential() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");

            // DB A: sequential apply.
            let ctx_a = ctx.child("a");
            let db_a: UnorderedVariable = UnorderedVariableDb::init(
                ctx_a.child("db"),
                variable_db_config::<OneCap>("cms-a", &ctx_a),
                None,
            )
            .await
            .unwrap();

            // DB B: chained batch.
            let ctx_b = ctx.child("b");
            let db_b: UnorderedVariable = UnorderedVariableDb::init(
                ctx_b.child("db"),
                variable_db_config::<OneCap>("cms-b", &ctx_b),
                None,
            )
            .await
            .unwrap();

            // Batch 1 operations: create keys 0..5.
            let writes1: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();

            // Batch 2 operations: update key 0, delete key 1, create key 5.
            let writes2 = vec![
                (key(0), Some(val(100))),
                (key(1), None),
                (key(5), Some(val(5))),
            ];

            // DB A: apply sequentially.
            let (db_a, _) = commit_writes(db_a, writes1.clone(), None).await;
            let (db_a, _) = commit_writes(db_a, writes2.clone(), None).await;

            // DB B: apply as chain.
            let mut parent = db_b.new_batch();
            for (k, v) in &writes1 {
                parent = parent.write(*k, *v);
            }
            let parent_m = parent
                .merkleize(&db_b, None, &mut Proportional)
                .await
                .unwrap();

            let mut child = parent_m.new_batch::<Sha256>();
            for (k, v) in &writes2 {
                child = child.write(*k, *v);
            }
            let child_m = child
                .merkleize(&db_b, None, &mut Proportional)
                .await
                .unwrap();
            let (db_b, _) = db_b.apply_batch(child_m).await.unwrap();

            // Both DBs must have the same state.
            assert_eq!(db_a.root(), db_b.root());
            for i in 0..6 {
                assert_eq!(
                    db_a.get(&key(i)).await.unwrap(),
                    db_b.get(&key(i)).await.unwrap(),
                    "key {i} mismatch"
                );
            }

            db_a.destroy().await.unwrap();
            db_b.destroy().await.unwrap();
        });
    }

    /// Create and delete the same key in a single batch produces no net change for that key.
    #[test_traced("INFO")]
    fn test_any_batch_create_then_delete_same_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("cd", &ctx),
                None,
            )
            .await
            .unwrap();

            // Pre-populate key A.
            let (db, _) = commit_writes(db, [(key(0), Some(val(0)))], None).await;

            // In one batch: create B then delete B, also create C and delete A.
            let mut batch = db.new_batch();
            batch = batch.write(key(1), Some(val(1))); // create B
            batch = batch.write(key(1), None); // delete B (net: no B)
            batch = batch.write(key(2), Some(val(2))); // create C
            batch = batch.write(key(0), None); // delete A
            let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), None);
            assert_eq!(db.get(&key(1)).await.unwrap(), None);
            assert_eq!(db.get(&key(2)).await.unwrap(), Some(val(2)));

            db.destroy().await.unwrap();
        });
    }

    /// Deleting all keys exercises the empty-state floor rule: the floor moves to the commit.
    #[test_traced("INFO")]
    fn test_any_batch_delete_all_keys() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("da", &ctx),
                None,
            )
            .await
            .unwrap();

            // Pre-populate 5 keys.
            let init: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
            let (db, _) = commit_writes(db, init, None).await;

            // Delete all 5.
            let deletes: Vec<_> = (0..5).map(|i| (key(i), None)).collect();
            let (db, _) = commit_writes(db, deletes, None).await;

            for i in 0..5 {
                assert_eq!(db.get(&key(i)).await.unwrap(), None, "key {i} not deleted");
            }

            // DB should still be functional after deleting everything.
            let (db, _) = commit_writes(db, [(key(10), Some(val(10)))], None).await;
            assert_eq!(db.get(&key(10)).await.unwrap(), Some(val(10)));

            db.destroy().await.unwrap();
        });
    }

    /// Two independent batches from the same DB do not interfere with each other.
    #[test_traced("INFO")]
    fn test_any_batch_parallel_forks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("pf", &ctx),
                None,
            )
            .await
            .unwrap();

            // Pre-populate.
            let (db, _) = commit_writes(db, [(key(0), Some(val(0)))], None).await;
            let root_before = db.root();

            // Fork A: update key 0 and create key 1.
            let fork_a_m = db
                .new_batch()
                .write(key(0), Some(val(100)))
                .write(key(1), Some(val(1)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Fork B: delete key 0 and create key 2.
            let fork_b_m = db
                .new_batch()
                .write(key(0), None)
                .write(key(2), Some(val(2)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Different mutations must produce different roots.
            assert_ne!(fork_a_m.root(), fork_b_m.root());

            // DB is unchanged (neither batch applied).
            assert_eq!(db.root(), root_before);
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), None);

            // Apply fork A only.
            let (db, _) = db.apply_batch(fork_a_m).await.unwrap();
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(100)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get(&key(2)).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// The floor walk advances the floor correctly across a chained batch.
    #[test_traced("INFO")]
    fn test_any_batch_floor_walk_chained() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("frc", &ctx),
                None,
            )
            .await
            .unwrap();

            // Pre-populate with 50 keys.
            let init: Vec<_> = (0..50).map(|i| (key(i), Some(val(i)))).collect();
            let (db, _) = commit_writes(db, init, None).await;
            let floor_before = db.inactivity_floor_loc();

            // Parent: update keys 0..20.
            let mut parent = db.new_batch();
            for i in 0..20 {
                parent = parent.write(key(i), Some(val(i + 500)));
            }
            let parent_m = parent
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Child: update keys 20..30.
            let mut child = parent_m.new_batch::<Sha256>();
            for i in 20..30 {
                child = child.write(key(i), Some(val(i + 500)));
            }
            let child_m = child.merkleize(&db, None, &mut Proportional).await.unwrap();
            let (db, _) = db.apply_batch(child_m).await.unwrap();

            // Floor must have advanced.
            assert!(db.inactivity_floor_loc() > floor_before);

            // All keys should be accessible.
            for i in 0..30 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i + 500)),
                    "updated key {i} mismatch"
                );
            }
            for i in 30..50 {
                assert_eq!(
                    db.get(&key(i)).await.unwrap(),
                    Some(val(i)),
                    "untouched key {i} mismatch"
                );
            }

            db.destroy().await.unwrap();
        });
    }

    /// Dropping a batch without applying it leaves the DB unchanged.
    #[test_traced("INFO")]
    fn test_any_batch_abandoned() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("ab", &ctx),
                None,
            )
            .await
            .unwrap();

            let (db, _) = commit_writes(db, [(key(0), Some(val(0)))], None).await;
            let root_before = db.root();

            // Create, populate, merkleize, then drop without apply.
            {
                let mut batch = db.new_batch();
                batch = batch.write(key(0), Some(val(999)));
                batch = batch.write(key(1), Some(val(1)));
                let _merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
                // dropped here
            }

            // DB state is identical.
            assert_eq!(db.root(), root_before);
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    /// Applying without `commit()` publishes in memory but is not recovered after reopen.
    #[test_traced("INFO")]
    fn test_any_batch_apply_requires_commit_for_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "apply_requires_commit";
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>(partition, &ctx),
                None,
            )
            .await
            .unwrap();

            let committed_root = db.root();

            let merkleized = db
                .new_batch()
                .write(key(0), Some(val(0)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            drop(db);

            let reopened: UnorderedVariable = UnorderedVariableDb::init(
                context.child("reopen"),
                variable_db_config::<OneCap>(partition, &context),
                None,
            )
            .await
            .unwrap();
            assert_eq!(reopened.root(), committed_root);
            assert_eq!(reopened.get(&key(0)).await.unwrap(), None);

            reopened.destroy().await.unwrap();
        });
    }

    /// Reopening at a pruned target returns an error.
    #[test_traced("INFO")]
    fn test_any_bounded_initialization_pruned_target_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const KEYS: u64 = 64;

            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("rp", &ctx),
                None,
            )
            .await
            .unwrap();

            let initial: Vec<_> = (0..KEYS).map(|i| (key(i), Some(val(i)))).collect();
            let (mut db, first_range) = commit_writes(db, initial, None).await;

            let mut round = 0u64;
            loop {
                round += 1;
                assert!(
                    round <= 64,
                    "failed to prune enough history for the bounded initialization test"
                );

                let updates: Vec<_> = (0..KEYS)
                    .map(|i| (key(i), Some(val(1000 + round * KEYS + i))))
                    .collect();
                (db, _) = commit_writes(db, updates, None).await;

                let boundary = db.sync_boundary();
                db = db.prune(boundary).await.unwrap();
                let bounds = db.bounds();
                if bounds.start > first_range.start {
                    break;
                }
            }

            let oldest_retained = db.bounds().start;
            _ = db.sync().await.unwrap();
            let Err(boundary_err) = UnorderedVariable::init(
                ctx.child("cap"),
                variable_db_config::<OneCap>("rp", &ctx),
                Some(oldest_retained),
            )
            .await
            else {
                panic!("expected bounded initialization at retained boundary to fail");
            };
            assert!(
                matches!(
                    boundary_err,
                    crate::qmdb::Error::Journal(crate::journal::Error::ItemPruned(_))
                ),
                "unexpected bounded initialization error at retained boundary: {boundary_err:?}"
            );

            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("reopen"),
                variable_db_config::<OneCap>("rp", &ctx),
                None,
            )
            .await
            .unwrap();
            _ = db.sync().await.unwrap();
            let Err(err) = UnorderedVariable::init(
                ctx.child("cap"),
                variable_db_config::<OneCap>("rp", &ctx),
                Some(first_range.start),
            )
            .await
            else {
                panic!("expected bounded initialization to pruned target to fail");
            };
            assert!(
                matches!(
                    err,
                    crate::qmdb::Error::Journal(crate::journal::Error::ItemPruned(_))
                ),
                "unexpected bounded initialization error: {err:?}"
            );
        });
    }

    /// Zero is rejected. Equal and above-end bounds preserve the committed state.
    #[test_traced("INFO")]
    fn test_any_bounded_initialization_zero_equal_and_above_end() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("ri", &ctx),
                None,
            )
            .await
            .unwrap();

            // Commit one key so the reopen checks below verify real state.
            let (db, _) = commit_writes(db, [(key(0), Some(val(0)))], None).await;

            let root_before = db.root();
            let size_before = db.size();
            let db = {
                _ = db.sync().await.unwrap();
                UnorderedVariable::init(
                    ctx.child("cap"),
                    variable_db_config::<OneCap>("ri", &ctx),
                    Some(size_before),
                )
                .await
            }
            .unwrap();
            assert_eq!(db.root(), root_before);
            assert_eq!(db.size(), size_before);

            _ = db.sync().await.unwrap();
            let Err(zero_err) = UnorderedVariable::init(
                ctx.child("cap"),
                variable_db_config::<OneCap>("ri", &ctx),
                Some(Location::new(0)),
            )
            .await
            else {
                panic!("expected bounded initialization to zero to fail");
            };
            assert!(
                matches!(zero_err, QmdbError::InvalidInitializationBound),
                "unexpected bounded initialization error: {zero_err:?}"
            );

            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("reopen"),
                variable_db_config::<OneCap>("ri", &ctx),
                None,
            )
            .await
            .unwrap();
            assert_eq!(db.root(), root_before);
            assert_eq!(db.size(), size_before);

            let too_large_target = size_before + 1;
            drop(db);
            let db = UnorderedVariable::init(
                ctx.child("above"),
                variable_db_config::<OneCap>("ri", &ctx),
                Some(too_large_target),
            )
            .await
            .unwrap();
            assert_eq!(db.root(), root_before);
            drop(db);

            let db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("reopen2"),
                variable_db_config::<OneCap>("ri", &ctx),
                None,
            )
            .await
            .unwrap();
            assert_eq!(db.root(), root_before);
            assert_eq!(db.size(), size_before);

            db.destroy().await.unwrap();
        });
    }

    /// Bounded initialization fails when the target commit's inactivity floor has been pruned, even
    /// if the target commit location is still retained.
    #[test_traced("INFO")]
    fn test_any_bounded_initialization_rejects_target_with_pruned_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const KEYS: u64 = 64;

            let ctx = context.child("db");
            let db: UnorderedVariable =
                UnorderedVariableDb::init(
                    ctx.child("storage"),
                    variable_db_config::<OneCap>("rf", &ctx), None,
                )
                    .await
                    .unwrap();

            let (db, _) = commit_writes(db, (0..KEYS).map(|i| (key(i), Some(val(i)))), None).await;
            let (mut db, _) = commit_writes(
                db,
                (0..KEYS).map(|i| (key(i), Some(val(1_000 + i)))),
                None,
            )
            .await;

            let initialization_bound = db.size();
            let target_floor = db.inactivity_floor_loc();
            let prune_loc = target_floor + (KEYS / 2);
            assert!(
                initialization_bound > *prune_loc,
                "test setup expected target size > prune_loc. target={initialization_bound:?}, \
                 floor={target_floor:?}"
            );

            let mut round = 0u64;
            while db.inactivity_floor_loc() < prune_loc {
                round += 1;
                assert!(
                    round <= 8,
                    "failed to advance inactivity floor enough for floor-pruned initialization test"
                );
                (db, _) = commit_writes(
                    db,
                    (0..KEYS).map(|i| (key(i), Some(val(10_000 + round * KEYS + i)))),
                    None,
                )
                .await;
            }

            let db = db.prune(prune_loc).await.unwrap();
            let bounds = db.bounds();
            assert!(
                bounds.start > *target_floor,
                "test setup expected pruned start beyond target floor; bounds={bounds:?}, target_floor={target_floor:?}"
            );
            assert!(
                initialization_bound > bounds.start,
                "test setup expected target commit retained. target={initialization_bound:?}, \
                 bounds={bounds:?}"
            );

            let original_root = db.root();
            _ = db.sync().await.unwrap();
            let Err(err) = UnorderedVariable::init(
                ctx.child("cap"),
                variable_db_config::<OneCap>("rf", &ctx),
                Some(initialization_bound),
            )
            .await else {
                panic!("expected bounded initialization to floor-pruned target to fail");
            };
            assert!(
                matches!(
                    err,
                    QmdbError::HistoricalFloorPruned(_)
                ),
                "unexpected bounded initialization error: {err:?}"
            );
            let db = UnorderedVariable::init(
                ctx.child("unchanged"),
                variable_db_config::<OneCap>("rf", &ctx), None,
            )
            .await.unwrap();
            assert_eq!(db.root(), original_root);
        });
    }

    #[test_traced("INFO")]
    fn test_any_bounded_reopen_below_pruned_bitmap() {
        deterministic::Runner::default().start(|context| async move {
            let ctx = context.child("db");
            let mut cfg = variable_db_config::<OneCap>("coarse-prune", &ctx);
            cfg.journal_config.items_per_section = NZU64!(2048);
            let db = UnorderedVariable::init(ctx.child("storage"), cfg.clone(), None)
                .await
                .unwrap();
            let (db, _) = commit_writes(db, (0..100).map(|i| (key(i), Some(val(i)))), None).await;
            let target = db.size();
            let root = db.root();
            let (db, _) =
                commit_writes(db, (0..700).map(|i| (key(i), Some(val(1_000 + i)))), None).await;
            let (db, _) =
                commit_writes(db, (0..700).map(|i| (key(i), Some(val(10_000 + i)))), None).await;
            let prune_loc = Location::new(600);
            assert!(db.inactivity_floor_loc() >= prune_loc);
            let live_root = db.root();
            let db = db.prune(prune_loc).await.unwrap();
            assert_eq!(db.root(), live_root);
            assert_eq!(db.bounds().start, Location::new(0));
            assert!(*target < db.bitmap.pruned_bits());
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(10_000)));
            drop(db.sync().await.unwrap());

            for cap in [Some(target), None] {
                let db = UnorderedVariable::init(ctx.child("reopen"), cfg.clone(), cap)
                    .await
                    .unwrap();
                assert_eq!(db.size(), target);
                assert_eq!(db.root(), root);
                for i in 0..100 {
                    assert_eq!(db.get(&key(i)).await.unwrap(), Some(val(i)));
                }
                assert_eq!(db.get(&key(100)).await.unwrap(), None);
                drop(db);
            }
        });
    }

    /// Valid children of an applied parent retain their state across bitmap pruning,
    /// including children merkleized before pruning and children constructed afterward.
    #[test_traced("INFO")]
    fn test_any_live_child_across_coarse_prune() {
        deterministic::Runner::default().start(|context| async move {
            const CHUNK_BITS: u64 =
                commonware_utils::bitmap::Prunable::<BITMAP_CHUNK_BYTES>::CHUNK_SIZE_BITS;
            const { assert!(CHUNK_BITS <= 600) };

            for child_after_prune in [false, true] {
                let mut reference = None;
                for prune in [false, true] {
                    let suffix = format!("any-live-child-{child_after_prune}-{prune}");
                    let ctx = context.child("db").with_attribute("case", &suffix);
                    let mut cfg = variable_db_config::<OneCap>(&suffix, &ctx);
                    cfg.journal_config.items_per_section = NZU64!(2048);
                    let db = UnorderedVariable::init(ctx.child("storage"), cfg, None)
                        .await
                        .unwrap();
                    let (mut db, _) =
                        commit_writes(db, (0..700).map(|i| (key(i), Some(val(i)))), None).await;

                    let mut parent = db.new_batch();
                    for i in 0..700 {
                        parent = parent.write(key(i), (i != 1).then(|| val(10_000 + i)));
                    }
                    let parent = parent
                        .merkleize(&db, None, &mut Proportional)
                        .await
                        .unwrap();
                    (db, _) = db.apply_batch(Arc::clone(&parent)).await.unwrap();
                    db = db.commit().await.unwrap();

                    let make_child = || {
                        parent
                            .new_batch::<Sha256>()
                            .write(key(0), Some(val(20_000)))
                            .write(key(1), Some(val(20_001)))
                            .write(key(2), None)
                    };
                    let child = if child_after_prune {
                        None
                    } else {
                        Some(
                            make_child()
                                .merkleize(&db, None, &mut Proportional)
                                .await
                                .unwrap(),
                        )
                    };

                    let prune_loc = Location::new(600);
                    assert!(db.inactivity_floor_loc() >= prune_loc);
                    let parent_root = db.root();
                    if prune {
                        db = db.prune(prune_loc).await.unwrap();
                    }
                    assert_eq!(db.root(), parent_root);
                    assert_eq!(db.bounds().start, Location::new(0));
                    assert_eq!(
                        db.bitmap.pruned_bits(),
                        if prune {
                            600 / CHUNK_BITS * CHUNK_BITS
                        } else {
                            0
                        },
                    );

                    let child = match child {
                        Some(child) => child,
                        None => make_child()
                            .merkleize(&db, None, &mut Proportional)
                            .await
                            .unwrap(),
                    };
                    for (i, expected) in [
                        (0, Some(val(20_000))),
                        (1, Some(val(20_001))),
                        (2, None),
                        (3, Some(val(10_003))),
                        (700, None),
                    ] {
                        assert_eq!(child.get(&key(i), &db).await.unwrap(), expected);
                    }
                    let child_root = child.root();
                    let operations = child.operations();
                    (db, _) = db.apply_batch(child).await.unwrap();
                    assert_eq!(db.root(), child_root);

                    let mut values = Vec::new();
                    for i in 0..=700 {
                        let expected = match i {
                            0 => Some(val(20_000)),
                            1 => Some(val(20_001)),
                            2 | 700 => None,
                            _ => Some(val(10_000 + i)),
                        };
                        let actual = db.get(&key(i)).await.unwrap();
                        assert_eq!(actual, expected);
                        values.push(actual);
                    }
                    let observed = (db.root(), operations, values);
                    if let Some(reference) = &reference {
                        assert_eq!(&observed, reference);
                    } else {
                        reference = Some(observed);
                    }
                    db.destroy().await.unwrap();
                }
            }
        });
    }

    //
    // The tests above use MMR-backed databases (via the concrete Db type aliases). The tests
    // below verify the same core operations work with the MMB family, exercising the generic
    // `init_fixed`/`init_variable` path with `mmb::Family`.

    type MmbVariable = super::db::Db<
        crate::merkle::mmb::Family,
        Context,
        crate::journal::contiguous::variable::Journal<
            Context,
            super::operation::Operation<
                crate::merkle::mmb::Family,
                super::operation::update::Unordered<Digest, super::value::VariableEncoding<Digest>>,
            >,
        >,
        crate::index::unordered::Index<OneCap, crate::merkle::Location<crate::merkle::mmb::Family>>,
        Sha256,
        super::operation::update::Unordered<Digest, super::value::VariableEncoding<Digest>>,
        { crate::qmdb::any::BITMAP_CHUNK_BYTES },
        Sequential,
    >;

    async fn open_mmb_db(context: Context, suffix: &str) -> MmbVariable {
        let cfg = variable_db_config::<OneCap>(suffix, &context);
        super::init(context, cfg, None).await.unwrap()
    }

    async fn commit_writes_mmb(
        db: MmbVariable,
        writes: impl IntoIterator<Item = (Digest, Option<Digest>)>,
        metadata: Option<Digest>,
    ) -> MmbVariable {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch
            .merkleize(&db, metadata, &mut Proportional)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap()
    }

    #[test_traced("INFO")]
    fn test_mmb_batch_crud() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_mmb_db(context.child("db"), "crud").await;

            // Insert and read back.
            let db = commit_writes_mmb(db, [(key(0), Some(val(0)))], None).await;
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            // Update existing key.
            let db = commit_writes_mmb(db, [(key(0), Some(val(1)))], None).await;
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(1)));

            // Delete key.
            let db = commit_writes_mmb(db, [(key(0), None)], None).await;
            assert!(db.get(&key(0)).await.unwrap().is_none());

            // Multiple keys.
            let db =
                commit_writes_mmb(db, [(key(1), Some(val(1))), (key(2), Some(val(2)))], None).await;
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get(&key(2)).await.unwrap(), Some(val(2)));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_mmb_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_mmb_db(context.child("db"), "empty").await;
            let root_before = db.root();

            let merkleized = db
                .new_batch()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            assert_ne!(db.root(), root_before);

            let db = commit_writes_mmb(db, [(key(0), Some(val(0)))], None).await;
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_mmb_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_mmb_db(context.child("db"), "meta").await;

            let metadata = val(42);
            let db = commit_writes_mmb(db, [(key(0), Some(val(0)))], Some(metadata)).await;
            assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

            let merkleized = db
                .new_batch()
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("WARN")]
    fn test_mmb_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = open_mmb_db(context.child("db").with_attribute("index", 0), "recovery").await;

            let db = commit_writes_mmb(db, [(key(0), Some(val(0)))], Some(val(99))).await;
            let db = commit_writes_mmb(db, [(key(1), Some(val(1)))], None).await;

            let root = db.root();
            let bounds = db.bounds();
            db.sync().await.unwrap();

            // Reopen and verify state.
            let db = open_mmb_db(context.child("db").with_attribute("index", 1), "recovery").await;
            assert_eq!(db.root(), root);
            assert_eq!(db.bounds(), bounds);
            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));
            assert_eq!(db.get_metadata().await.unwrap(), None);

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("INFO")]
    fn test_mmb_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = open_mmb_db(context.child("db"), "prune").await;

            for i in 0u64..20 {
                db = commit_writes_mmb(db, [(key(i), Some(val(i)))], None).await;
            }

            let floor = db.inactivity_floor_loc();
            let db = db.prune(floor).await.unwrap();

            // All keys still accessible.
            for i in 0u64..20 {
                assert_eq!(db.get(&key(i)).await.unwrap(), Some(val(i)));
            }

            db.destroy().await.unwrap();
        });
    }

    /// One-stage pipelining lets the next batch be built while the prior batch commits.
    #[test_traced("INFO")]
    fn test_any_batch_single_stage_pipeline() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ctx = context.child("db");
            let mut db: UnorderedVariable = UnorderedVariableDb::init(
                ctx.child("storage"),
                variable_db_config::<OneCap>("pipe", &ctx),
                None,
            )
            .await
            .unwrap();

            {
                let mut batch = db.new_batch();
                batch = batch.write(key(0), Some(val(0)));
                let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
                (db, _) = db.apply_batch(merkleized).await.unwrap();
            }

            let child_merkleized = {
                assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
                let mut child = db.new_batch();
                child = child.write(key(1), Some(val(1)));
                child.merkleize(&db, None, &mut Proportional).await.unwrap()
            };
            let db = db.commit().await.unwrap();

            let (db, _) = db.apply_batch(child_merkleized).await.unwrap();
            let db = db.commit().await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1)));

            db.destroy().await.unwrap();
        });
    }
}

#[cfg(test)]
mod bitmap_tests {
    //! Regression tests for activity-bitmap maintenance in `any::Db`. The mutation code in
    //! `apply_batch`, `prune_bitmap`, and initialization is independent of the snapshot index
    //! variant, so one variant (`unordered::variable`) suffices as the test bed.
    use crate::{
        merkle::Location,
        qmdb::{
            any::{
                BITMAP_CHUNK_BYTES,
                test::assert_rebuild_matches,
                unordered::variable::test::{AnyTest, create_test_config},
            },
            floor::Proportional,
        },
    };
    use commonware_cryptography::{Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        Runner as _, Supervisor as _,
        deterministic::{self, Context},
    };
    use commonware_utils::bitmap::{Prunable, Readable as _};

    /// Bits per chunk of the test database's activity bitmap.
    const CHUNK_BITS: u64 = Prunable::<BITMAP_CHUNK_BYTES>::CHUNK_SIZE_BITS;

    /// Open a fresh test DB.
    async fn open_db(context: Context) -> AnyTest {
        let cfg = create_test_config(0, &context);
        AnyTest::init(context, cfg, None).await.unwrap()
    }

    /// CommitFloor convention: only the *current* last commit carries bit=1; every earlier
    /// (now intermediate) commit boundary carries bit=0.
    ///
    /// Maintained by `apply_batch`'s explicit demote-then-promote pair on CommitFloor bits. If
    /// the demote step were missed, intermediate commits would persist at bit=1.
    #[test_traced]
    fn current_commit_floor_bit_is_one_others_zero() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db(context.child("db")).await;

            // Apply three single-write batches; each produces one CommitFloor op.
            let keys: Vec<_> = (0..3u64)
                .map(|i| Sha256::hash(&[&i.to_be_bytes()]))
                .collect();
            let mut commit_locs = Vec::new();
            for (i, key) in keys.iter().enumerate() {
                let batch = db
                    .new_batch()
                    .write(*key, Some(vec![i as u8]))
                    .merkleize(&db, None, &mut Proportional)
                    .await
                    .unwrap();
                commit_locs.push(batch.bounds.tip.size - 1);
                (db, _) = db.apply_batch(batch).await.unwrap();
            }
            let db = db.commit().await.unwrap();

            // Setup sanity: three strictly-increasing commit locations, all within the bitmap.
            assert_eq!(commit_locs.len(), 3);
            assert!(*commit_locs[0] < *commit_locs[1]);
            assert!(*commit_locs[1] < *commit_locs[2]);
            assert!(*commit_locs[2] < db.bitmap.len());

            // Earlier two commits are intermediate -> bit=0.
            assert!(!db.bitmap.get_bit(*commit_locs[0]));
            assert!(!db.bitmap.get_bit(*commit_locs[1]));
            // Most recent commit is current -> bit=1.
            assert!(db.bitmap.get_bit(*commit_locs[2]));

            let reopen = open_db(
                context
                    .child("reopen")
                    .with_attribute("case", "commit_floor"),
            );
            let db = assert_rebuild_matches(db, reopen, &keys).await;
            db.destroy().await.unwrap();
        });
    }

    /// Bounded initialization rebuilds bitmap activity for the selected commit. Retained keys are
    /// active, discarded keys are absent, and the selected commit is active. An ordinary reopen
    /// must reconstruct the same bitmap.
    #[test_traced]
    fn bounded_initialization_restores_bitmap_to_target_commit() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db(context.child("db")).await;
            let k1 = Sha256::hash(&[&[1]]);
            let k2 = Sha256::hash(&[&[2]]);

            // Two committed batches; remember the size after the first.
            let b1 = db
                .new_batch()
                .write(k1, Some(vec![10]))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(b1).await.unwrap();
            let db = db.commit().await.unwrap();
            let size_after_first = db.bounds().end;

            let b2 = db
                .new_batch()
                .write(k2, Some(vec![20]))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(b2).await.unwrap();

            // Setup sanity: both keys present, db has advanced past size_after_first.
            assert_eq!(db.get(&k1).await.unwrap(), Some(vec![10]));
            assert_eq!(db.get(&k2).await.unwrap(), Some(vec![20]));
            assert!(*db.bounds().end > *size_after_first);

            // Reopen at the state after the first commit.
            let db = {
                _ = db.sync().await.unwrap();
                AnyTest::init(
                    context.child("cap"),
                    create_test_config(0, &context),
                    Some(size_after_first),
                )
                .await
            }
            .unwrap();

            // After recovery, k2 is gone and k1 remains.
            assert_eq!(db.get(&k1).await.unwrap(), Some(vec![10]));
            assert!(db.get(&k2).await.unwrap().is_none());

            let reopen = open_db(context.child("reopen").with_attribute("case", "rewind"));
            let db = assert_rebuild_matches(db, reopen, &[k1, k2]).await;
            db.destroy().await.unwrap();
        });
    }

    /// The floor walk crosses the end of the applied bitmap into pending ancestor operations.
    ///
    /// A child overwrites its parent's update of an applied key, so the walk must pass the
    /// superseded ancestor location as inactive. The anchor overwrite and the previous commit
    /// provide the walk's entries.
    ///
    /// Applying the child publishes its latest values. Rebuilding independently checks the root
    /// and activity state after the walk.
    #[test_traced]
    fn floor_scan_falls_through_to_uncommitted_tail() {
        deterministic::Runner::default().start(|context| async move {
            let db = open_db(context.child("db")).await;
            let anchor = Sha256::hash(&[&[0xAA]]);

            // Commit one key.
            let b = db
                .new_batch()
                .write(anchor, Some(vec![1]))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(b).await.unwrap();

            // Setup sanity: anchor in committed snapshot.
            assert_eq!(db.get(&anchor).await.unwrap(), Some(vec![1]));
            let committed_bitmap_len = db.bitmap.len();

            // Uncommitted parent: re-touch anchor at a location above the committed bitmap.
            let parent = db
                .new_batch()
                .write(anchor, Some(vec![2]))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert!(
                parent.bounds.tip.size > committed_bitmap_len,
                "parent must extend past committed bitmap to exercise the tail path",
            );

            // The pending child supersedes the anchor and creates 16 other keys.
            let others: Vec<_> = (0..16u64)
                .map(|i| Sha256::hash(&[&(1000 + i).to_be_bytes()]))
                .collect();
            let mut child_batch = parent.new_batch::<Sha256>();
            child_batch = child_batch.write(anchor, Some(vec![3]));
            for (i, k) in others.iter().enumerate() {
                child_batch = child_batch.write(*k, Some(vec![i as u8]));
            }
            let child = child_batch
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            assert!(
                child.bounds.tip.size > committed_bitmap_len,
                "child must include an uncommitted tail beyond committed bitmap",
            );
            let expected_root = child.root();

            let (db, _) = db.apply_batch(child).await.unwrap();
            assert_eq!(db.root(), expected_root);
            assert_eq!(db.get(&anchor).await.unwrap(), Some(vec![3]));

            let keys: Vec<_> = [anchor].into_iter().chain(others).collect();
            let reopen = open_db(context.child("reopen").with_attribute("case", "tail"));
            let db = assert_rebuild_matches(db, reopen, &keys).await;
            db.destroy().await.unwrap();
        });
    }

    /// Pruning two chunks retains a log start inside the second chunk. A reopen rebuilds the
    /// pruned prefix from that start, one chunk below the live prefix.
    #[test_traced]
    fn pruned_prefix_derives_from_retained_start_on_reopen() {
        deterministic::Runner::default().start(|context| async move {
            let mut db = open_db(context.child("db")).await;

            // Write the same 700 keys in three commits so the inactivity floor passes two chunks.
            let keys: Vec<_> = (0..700u64)
                .map(|i| Sha256::hash(&[&i.to_be_bytes()]))
                .collect();
            for round in 0..3u8 {
                let mut batch = db.new_batch();
                for (i, key) in keys.iter().enumerate() {
                    batch = batch.write(*key, Some(vec![round, i as u8]));
                }
                let batch = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
                (db, _) = db.apply_batch(batch).await.unwrap();
                db = db.commit().await.unwrap();
            }
            let loc = Location::new(2 * CHUNK_BITS);
            assert!(db.inactivity_floor_loc() >= loc);

            // Prune two chunks. The log retains the section containing the prune location, which
            // starts inside the second chunk, while the live bitmap drops both chunks.
            let db = db.prune(loc).await.unwrap();
            let start = *db.bounds().start;
            assert!(
                (CHUNK_BITS..2 * CHUNK_BITS).contains(&start),
                "retained start {start} must lie in the second chunk",
            );
            assert_eq!(db.bitmap.pruned_bits(), 2 * CHUNK_BITS);

            // Reopen. The rebuilt prefix keeps the second chunk.
            let reopen = open_db(context.child("reopen").with_attribute("case", "coarse"));
            let db = assert_rebuild_matches(db, reopen, &keys).await;
            assert_eq!(db.bitmap.pruned_bits(), CHUNK_BITS);
            db.destroy().await.unwrap();
        });
    }
}

//! An Any database implementation with an unordered key space and fixed-size values.

use crate::{
    Context,
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    merkle::{Family, Location},
    qmdb::{
        Error,
        any::{FixedConfig as Config, FixedValue, unordered, value::FixedEncoding},
    },
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_utils::Array;

pub type Update<K, V> = unordered::Update<K, FixedEncoding<V>>;
pub type Operation<F, K, V> = unordered::Operation<F, K, FixedEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<F, E, K, V, H, T, S> = super::Db<
    F,
    E,
    Journal<E, Operation<F, K, V>>,
    Index<T, Location<F>>,
    H,
    Update<K, V>,
    { crate::qmdb::any::BITMAP_CHUNK_BYTES },
    S,
>;

impl<
    F: Family,
    E: Context + Spawner,
    K: Array,
    V: FixedValue,
    H: Hasher,
    T: Translator,
    S: Strategy,
> Db<F, E, K, V, H, T, S>
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T, S>) -> Result<Self, Error<F>> {
        crate::qmdb::any::init(context, cfg).await
    }
}

/// Partitioned index variants that divide the key space into `2^(P*8)` partitions.
///
/// See [partitioned::Db] for the generic type, or use the convenience aliases:
/// - [partitioned::p256::Db] for 256 partitions (P=1)
/// - [partitioned::p64k::Db] for 65,536 partitions (P=2)
pub mod partitioned {
    pub use super::{Operation, Update};
    use crate::{
        Context,
        index::partitioned::unordered::Index,
        journal::contiguous::fixed::Journal,
        merkle::{Family, Location},
        qmdb::{
            Error,
            any::{FixedConfig as Config, FixedValue},
        },
        translator::Translator,
    };
    use commonware_cryptography::Hasher;
    use commonware_parallel::Strategy;
    use commonware_runtime::Spawner;
    use commonware_utils::Array;

    /// A key-value QMDB with a partitioned snapshot index.
    ///
    /// This is the partitioned variant of [super::Db]. The const generic `P` specifies
    /// the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    ///
    /// Use partitioned indices when you have a large number of keys (>> 2^(P*8)) and memory
    /// efficiency is important. Keys should be uniformly distributed across the prefix space.
    pub type Db<F, E, K, V, H, T, const P: usize, S> = crate::qmdb::any::unordered::Db<
        F,
        E,
        Journal<E, Operation<F, K, V>>,
        Index<T, Location<F>, P>,
        H,
        Update<K, V>,
        { crate::qmdb::any::BITMAP_CHUNK_BYTES },
        S,
    >;

    impl<
        F: Family,
        E: Context + Spawner,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const P: usize,
        S: Strategy,
    > Db<F, E, K, V, H, T, P, S>
    {
        /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
        /// discarded and the state of the db will be as of the last committed operation.
        pub async fn init(
            context: E,
            cfg: Config<T, S, core::num::NonZeroUsize>,
        ) -> Result<Self, Error<F>> {
            crate::qmdb::any::init(context, cfg).await
        }
    }

    /// Convenience type aliases for 256 partitions (P=1).
    pub mod p256 {
        /// Fixed-value DB with 256 partitions.
        pub type Db<F, E, K, V, H, T, S> = super::Db<F, E, K, V, H, T, 1, S>;
    }

    /// Convenience type aliases for 65,536 partitions (P=2).
    pub mod p64k {
        /// Fixed-value DB with 65,536 partitions.
        pub type Db<F, E, K, V, H, T, S> = super::Db<F, E, K, V, H, T, 2, S>;
    }
}

// pub(crate) so helpers can be used by the sync module.
#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        index::Unordered as _,
        journal::{Error as JournalError, contiguous::Contiguous},
        merkle::{
            Location as GenericLocation,
            mmr::{self, Location},
        },
        qmdb::{
            SnapshotBuild as _,
            any::{
                test::{
                    colliding_digest, fixed_db_config, fixed_db_config_partitioned,
                    fixed_db_config_with_strategy,
                },
                unordered::{Update, fixed::Operation},
            },
            verify_proof,
        },
        translator::{OneCap, TwoCap},
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::{select, test_traced};
    use commonware_math::algebra::Random;
    use commonware_parallel::{Rayon, Sequential};
    use commonware_runtime::{
        Clock as _, Metrics as _, Runner as _, Strategizer as _, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic::{self, Context},
        mocks::{DelayedSyncContext, PendingSyncs, drive_pending_syncs},
        reschedule,
    };
    use commonware_utils::{NZU16, NZU64, NZUsize, TestRng};
    use core::num::NonZeroUsize;
    use futures::{FutureExt as _, Stream};
    use rand::Rng;
    use std::{
        collections::HashMap,
        future::{Future, ready},
        sync::Arc,
        time::Duration,
    };

    /// A generic type alias for an Any database parameterized by merkle family.
    type AnyTestGeneric<F> = crate::qmdb::any::db::Db<
        F,
        deterministic::Context,
        Journal<
            deterministic::Context,
            crate::qmdb::any::operation::Unordered<F, Digest, FixedEncoding<Digest>>,
        >,
        Index<TwoCap, GenericLocation<F>>,
        Sha256,
        crate::qmdb::any::operation::update::Unordered<Digest, FixedEncoding<Digest>>,
        { crate::qmdb::any::BITMAP_CHUNK_BYTES },
        Sequential,
    >;

    /// A type alias for the concrete [Db] type used in these unit tests.
    pub(crate) type AnyTest =
        Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap, Sequential>;

    /// Return an `Any` database initialized with a fixed config, generic over merkle family.
    async fn open_db_generic<F: Family>(context: deterministic::Context) -> AnyTestGeneric<F> {
        let cfg = fixed_db_config::<TwoCap>("partition", &context);
        crate::qmdb::any::init(context, cfg).await.unwrap()
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let cfg = fixed_db_config::<TwoCap>(&seed.to_string(), &context);
        AnyTest::init(context, cfg).await.unwrap()
    }

    /// A [Db] over a delayed-sync storage backend.
    type DelayedTest = Db<
        mmr::Family,
        DelayedSyncContext<deterministic::Context>,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        Sequential,
    >;

    /// Open a [DelayedTest] whose blob syncs park on `pending`.
    ///
    /// Init durably persists the recovered database, so while syncs park the returned future
    /// must be driven with [drive_pending_syncs] (or the mock unblocked first). The journal
    /// uses large pages and blobs: an apply that fills the write buffer or rolls the blob over
    /// waits for the in-flight sync, so mid-sync applies must stay clear of both.
    fn open_delayed_db(
        context: &Context,
        label: &'static str,
        suffix: &str,
        pending: &PendingSyncs,
    ) -> impl Future<Output = Result<DelayedTest, crate::qmdb::Error<mmr::Family>>> {
        let mut cfg = fixed_db_config::<TwoCap>(suffix, context);
        cfg.journal_config.items_per_blob = NZU64!(1000);
        cfg.journal_config.page_cache = CacheRef::from_pooler(context, NZU16!(1024), NZUsize!(8));
        DelayedTest::init(
            DelayedSyncContext {
                inner: context.child(label),
                pending: pending.clone(),
            },
            cfg,
        )
    }

    /// Apply a single-key batch writing `key -> value`.
    async fn apply_write(db: DelayedTest, key: Digest, value: Digest) -> DelayedTest {
        let merkleized = db
            .new_batch()
            .write(key, Some(value))
            .merkleize(&db, None)
            .await
            .unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db
    }

    /// A commit handle must not block database use while the backend sync is pending.
    #[test_traced]
    fn test_start_commit_overlaps_work() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&context, "delayed", "start_commit_overlap", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            let key0 = Sha256::hash(&[&0u64.to_be_bytes()]);
            let value0 = Sha256::hash(&[&100u64.to_be_bytes()]);
            db = apply_write(db, key0, value0).await;

            let starts_before = pending.starts();
            let entered_before = pending.entered();
            let completions_before = pending.completions();
            let handle;
            (db, handle) = db.start_commit().await.unwrap();
            assert_eq!(
                pending.starts(),
                starts_before + 1,
                "start_commit began exactly one blob sync"
            );
            assert_eq!(pending.completions(), completions_before);

            // Observe the sync while the database keeps working.
            let waiter = context
                .child("await_sync")
                .spawn(|_| async move { handle.await.unwrap() });
            while pending.entered() == entered_before {
                reschedule().await;
            }

            // Reads and applies complete before the sync does.
            assert_eq!(db.get(&key0).await.unwrap(), Some(value0));
            let key1 = Sha256::hash(&[&1u64.to_be_bytes()]);
            let value1 = Sha256::hash(&[&200u64.to_be_bytes()]);
            db = apply_write(db, key1, value1).await;
            assert_eq!(
                pending.completions(),
                completions_before,
                "the database made progress while the sync was still in flight"
            );

            pending.unblock();
            waiter.await.unwrap();

            // The mid-sync batch is durable after the next commit.
            let handle;
            (db, handle) = db.start_commit().await.unwrap();
            handle.await.unwrap();
            let root = db.root();
            let size = db.bounds().end;
            drop(db);

            let db = open_delayed_db(&context, "reopen", "start_commit_overlap", &pending)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
            assert_eq!(db.bounds().end, size);
            assert_eq!(db.get(&key1).await.unwrap(), Some(value1));
            db.destroy().await.unwrap();
        });
    }

    /// A commit whose in-flight sync fails surfaces the error through both the returned handle
    /// and the next durability operation.
    #[test_traced]
    fn test_start_commit_failure_propagates() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Pass syncs through so opening the database doesn't park.
            let pending = PendingSyncs::default();
            pending.unblock();
            let mut db = open_delayed_db(&context, "delayed", "start_commit_fail", &pending)
                .await
                .unwrap();
            let key0 = Sha256::hash(&[&0u64.to_be_bytes()]);
            let value0 = Sha256::hash(&[&100u64.to_be_bytes()]);
            db = apply_write(db, key0, value0).await;

            // Arm all future syncs to resolve to an injected error.
            pending.arm_fail();

            let handle;
            (db, handle) = db.start_commit().await.unwrap();
            assert!(
                handle.await.is_err(),
                "the commit handle surfaces the failure"
            );
            let starts_before = pending.starts();
            // A failed mutable method consumes the database per the failures-are-fatal contract.
            assert!(
                matches!(
                    db.commit().await,
                    Err(crate::qmdb::Error::Journal(crate::journal::Error::Runtime(
                        _
                    )))
                ),
                "the next durability op surfaces the failed in-flight sync"
            );
            assert_eq!(
                pending.starts(),
                starts_before,
                "the surfaced error is the retained failure, not a fresh sync's"
            );
        });
    }

    /// Pruning drains the in-flight commit before mutating storage.
    #[test_traced]
    fn test_start_commit_prune_waits() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let open = open_delayed_db(&context, "delayed", "start_commit_prune", &pending);
            let mut db = drive_pending_syncs(&pending, open).await.unwrap();
            let key0 = Sha256::hash(&[&0u64.to_be_bytes()]);
            let value0 = Sha256::hash(&[&100u64.to_be_bytes()]);
            db = apply_write(db, key0, value0).await;

            let starts_before = pending.starts();
            let handle;
            (db, handle) = db.start_commit().await.unwrap();
            assert_eq!(
                pending.starts(),
                starts_before + 1,
                "start_commit began exactly one blob sync"
            );

            // A non-trivial prune: the floor advanced past the seed commit.
            let floor = db.inactivity_floor_loc();
            assert!(*floor > 0);
            let db = {
                let mut prune = std::pin::pin!(db.prune(floor));
                assert!(
                    prune.as_mut().now_or_never().is_none(),
                    "prune proceeded while the commit sync was pending"
                );
                assert_eq!(
                    pending.starts(),
                    starts_before + 2,
                    "prune started the merkle journal sync before blocking"
                );

                // Release only the merkle sync (parked last): prune must still wait on the
                // in-flight commit's sync before mutating the log.
                {
                    let mut parked = pending.lock();
                    assert_eq!(
                        parked.len(),
                        2,
                        "expected the commit and merkle syncs parked"
                    );
                    let merkle_sync = parked.pop().unwrap();
                    merkle_sync.release.send(Ok(())).unwrap();
                }
                assert!(
                    prune.as_mut().now_or_never().is_none(),
                    "prune proceeded while the commit sync was pending"
                );
                assert_eq!(
                    pending.lock().len(),
                    1,
                    "prune is blocked on the commit sync, not a new sync of its own"
                );

                pending.unblock();
                prune.await.unwrap()
            };
            handle.await.unwrap();
            db.destroy().await.unwrap();
        });
    }

    /// `get_many` over a batch large enough for the fused sharded path matches per-key `get`.
    #[test_traced]
    fn test_get_many_fused_sharded_matches_get() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // The fused path requires parallelism > 1 (the Sequential test config never takes
            // it) and at least 4096 keys. The tiny test page cache pushes most keys through
            // the batched miss fallback, and TwoCap produces translated-key collisions.
            type ParTest = Db<mmr::Family, Context, Digest, Digest, Sha256, TwoCap, Rayon>;
            let strategy = context.strategy(NZUsize!(2));
            let cfg = fixed_db_config_with_strategy::<TwoCap, Rayon>("fused", &context, strategy);
            let db = ParTest::init(context, cfg).await.unwrap();

            let mut rng = TestRng::new(7);
            let mut keys = Vec::with_capacity(4300);
            let mut batch = db.new_batch();
            for _ in 0..4200 {
                let key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                keys.push(key);
                batch = batch.write(key, Some(value));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let db = db.commit().await.unwrap();

            // Mix in absent keys so some probes resolve to nothing.
            for _ in 0..100 {
                keys.push(Digest::random(&mut rng));
            }
            let refs: Vec<&Digest> = keys.iter().collect();
            let fused = db.get_many(&refs).await.unwrap();
            assert_eq!(fused.len(), keys.len());
            for (key, result) in keys.iter().zip(fused) {
                assert_eq!(result, db.get(key).await.unwrap());
            }

            db.destroy().await.unwrap();
        });
    }

    /// A merkleize future dropped mid-flight leaves the database fully usable.
    ///
    /// With a parallel strategy, merkleize's hashing job may keep running detached against its
    /// snapshot of committed Merkle state after the future is dropped. Later mutations must not
    /// observe it (they copy-on-write instead), and its discarded result must not corrupt
    /// anything. Runs on the tokio runtime for the same reason as
    /// [`test_get_many_fused_sharded_matches_get`].
    #[test_traced]
    fn test_merkleize_cancellation_leaves_db_usable() {
        let executor = commonware_runtime::tokio::Runner::default();
        executor.start(|context| async move {
            type ParTest = Db<
                mmr::Family,
                commonware_runtime::tokio::Context,
                Digest,
                Digest,
                Sha256,
                TwoCap,
                Rayon,
            >;
            let strategy = context.strategy(NZUsize!(2));
            let cfg = fixed_db_config_with_strategy::<TwoCap, Rayon>("cancel", &context, strategy);
            let db = ParTest::init(context.child("db"), cfg).await.unwrap();

            // Populate and commit so later snapshots carry committed nodes.
            let mut rng = TestRng::new(11);
            let mut keys = Vec::with_capacity(1024);
            let mut batch = db.new_batch();
            for _ in 0..1024 {
                let key = Digest::random(&mut rng);
                let value = Digest::random(&mut rng);
                keys.push((key, value));
                batch = batch.write(key, Some(value));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let mut db = db.commit().await.unwrap();

            // Drop one merkleize after a single poll and race another against a timer, so the
            // future is abandoned at whatever stage it reached (possibly mid-hashing-job).
            for delay in [None, Some(Duration::from_millis(1))] {
                // Fork the abandoned batch off a two-deep unapplied chain: the hashing job
                // reaches the grandparent only through Weak references, so dropping the chain
                // below exercises a mid-job truncation (any resulting panic is caught and
                // discarded by `Strategy::spawn`).
                let grandparent = db
                    .new_batch()
                    .write(Digest::random(&mut rng), Some(Digest::random(&mut rng)))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                let parent = grandparent
                    .new_batch::<Sha256>()
                    .write(Digest::random(&mut rng), Some(Digest::random(&mut rng)))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                let mut abandoned = parent.new_batch::<Sha256>();
                for _ in 0..4200 {
                    abandoned =
                        abandoned.write(Digest::random(&mut rng), Some(Digest::random(&mut rng)));
                }
                let fut = abandoned.merkleize(&db, None);
                match delay {
                    None => {
                        let _ = fut.now_or_never();
                    }
                    Some(delay) => {
                        select! {
                            _ = fut => {},
                            _ = context.sleep(delay) => {},
                        }
                    }
                }
                drop(parent);
                drop(grandparent);

                // The database remains fully usable: mutate, merkleize, apply, and read back.
                let (key, _) = keys[0];
                let value = Digest::random(&mut rng);
                let merkleized = db
                    .new_batch()
                    .write(key, Some(value))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                (db, _) = db.apply_batch(merkleized).await.unwrap();
                db = db.commit().await.unwrap();
                assert_eq!(db.get(&key).await.unwrap(), Some(value));
                keys[0].1 = value;
                for (key, value) in &keys[1..] {
                    assert_eq!(db.get(key).await.unwrap(), Some(*value));
                }
            }

            db.destroy().await.unwrap();
        });
    }

    /// Create n random operations using the default seed (0). Some portion of
    /// the updates are deletes. create_test_ops(n) is a prefix of
    /// create_test_ops(n') for n < n'.
    pub(crate) fn create_test_ops(n: usize) -> Vec<Operation<mmr::Family, Digest, Digest>> {
        create_test_ops_seeded(n, 0)
    }

    /// Create n random operations using a specific seed.
    /// Use different seeds when you need non-overlapping keys in the same test.
    pub(crate) fn create_test_ops_seeded(
        n: usize,
        seed: u64,
    ) -> Vec<Operation<mmr::Family, Digest, Digest>> {
        let mut rng = TestRng::new(seed);
        let mut prev_key = Digest::random(&mut rng);
        let mut ops = Vec::new();
        for i in 0..n {
            let key = Digest::random(&mut rng);
            if i % 10 == 0 && i > 0 {
                ops.push(Operation::Delete(prev_key));
            } else {
                let value = Digest::random(&mut rng);
                ops.push(Operation::Update(Update(key, value)));
                prev_key = key;
            }
        }
        ops
    }

    /// Applies the given operations to the database.
    pub(crate) async fn apply_ops(
        db: AnyTest,
        ops: Vec<Operation<mmr::Family, Digest, Digest>>,
    ) -> AnyTest {
        let mut batch = db.new_batch();
        for op in ops {
            match op {
                Operation::Update(Update(key, value)) => {
                    batch = batch.write(key, Some(value));
                }
                Operation::Delete(key) => {
                    batch = batch.write(key, None);
                }
                Operation::CommitFloor(_, _) => {
                    panic!("CommitFloor not supported in apply_ops");
                }
            }
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        db
    }

    /// Helper: commit a batch of key-value writes and return the db and applied range (generic).
    async fn commit_writes_generic<F: Family>(
        db: AnyTestGeneric<F>,
        writes: impl IntoIterator<Item = (Digest, Option<Digest>)>,
        metadata: Option<Digest>,
    ) -> (AnyTestGeneric<F>, std::ops::Range<GenericLocation<F>>) {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(&db, metadata).await.unwrap();
        let (db, range) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        (db, range)
    }

    fn key(i: u64) -> Digest {
        Sha256::hash(&[&i.to_be_bytes()])
    }

    fn val(i: u64) -> Digest {
        Sha256::hash(&[&(i + 10000).to_be_bytes()])
    }

    /// The init-time `(location -> key)` cache only memoizes log reads, so rebuilding the snapshot
    /// with the cache disabled (`init_cache_size = None`) or enabled must produce the identical root.
    #[test_traced("WARN")]
    fn test_unordered_fixed_init_cache_equivalence() {
        deterministic::Runner::default().start(|context| async move {
            // Populate a database with churny operations (repeated updates and deletes drive the
            // collision resolution that the cache accelerates), then commit and drop it.
            let cfg = fixed_db_config::<TwoCap>("cache_equiv", &context);
            let db = AnyTest::init(context.child("populate"), cfg).await.unwrap();
            let db = apply_ops(db, create_test_ops(10_000)).await;
            let db = db.commit().await.unwrap();
            let db = db.sync().await.unwrap();
            let root = db.root();
            drop(db);

            // Reopen with the cache disabled and with a large cache; both rebuild the snapshot by
            // replaying the same immutable log, so both roots must equal the pre-drop root.
            for cache_size in [None, Some(NZUsize!(1 << 20))] {
                let mut cfg = fixed_db_config::<TwoCap>("cache_equiv", &context);
                cfg.init_cache_size = cache_size;
                let ctx = context
                    .child("reopen")
                    .with_attribute("cache", cache_size.map_or(0, NonZeroUsize::get));
                let db = AnyTest::init(ctx, cfg).await.unwrap();
                assert_eq!(
                    db.root(),
                    root,
                    "root mismatch at cache_size={cache_size:?}"
                );
                drop(db);
            }
        });
    }

    /// Build a `P`-partitioned unordered db with churny ops, then assert that reopening it with a
    /// range of `init_concurrency` values (`1` for the serial path, `2` for the single-worker
    /// de-interleave, counts that round down to fewer workers with wider ranges, and counts
    /// above the partition count that clamp) all reconstruct the identical root and key-value
    /// state: the parallel build replays the same immutable log, just split across workers
    /// owning disjoint partition ranges.
    #[commonware_macros::boxed]
    async fn check_parallel_init_equivalence<const P: usize>(
        context: deterministic::Context,
        partition: &'static str,
        concurrency_sweep: &[usize],
    ) {
        type PartDb<const P: usize, S> =
            partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, P, S>;

        /// The value each key holds after the three commits below. Keys deleted in commit 2 and
        /// reinserted in commit 3 hold the reinserted value. Keys deleted and not reinserted are
        /// absent. Updated keys hold the commit-2 value. The rest hold their commit-1 value.
        fn expected_value(i: u64) -> Option<Digest> {
            if i % 21 == 1 {
                Some(Sha256::hash(&[&(i * 13).to_be_bytes()]))
            } else if i % 7 == 1 {
                None
            } else if i.is_multiple_of(3) {
                Some(Sha256::hash(&[&((i + 1) * 11).to_be_bytes()]))
            } else {
                Some(Sha256::hash(&[&(i * 7).to_be_bytes()]))
            }
        }

        /// Assert every key resolves to its expected value, catching a location filed under the
        /// wrong key (which the root comparison alone cannot detect since the `any` root is a pure
        /// function of the log).
        async fn assert_expected_values<const P: usize, S: commonware_parallel::Strategy>(
            db: &PartDb<P, S>,
        ) {
            for i in 0u64..4000 {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                assert_eq!(
                    db.get(&k).await.unwrap(),
                    expected_value(i),
                    "value mismatch for key {i}"
                );
            }
        }

        let cfg = fixed_db_config_partitioned::<OneCap>(partition, &context);
        let db = PartDb::<P, Sequential>::init(context.child("populate"), cfg)
            .await
            .unwrap();

        // Commit 1: insert every key.
        let mut batch = db.new_batch();
        for i in 0u64..4000 {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            let v = Sha256::hash(&[&(i * 7).to_be_bytes()]);
            batch = batch.write(k, Some(v));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        // Commit 2: update a third (inactivating their commit-1 ops) and delete a seventh.
        let mut batch = db.new_batch();
        for i in (0u64..4000).step_by(3) {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            let v = Sha256::hash(&[&((i + 1) * 11).to_be_bytes()]);
            batch = batch.write(k, Some(v));
        }
        for i in (1u64..4000).step_by(7) {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            batch = batch.write(k, None);
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        // Commit 3: reinsert a third of the deleted keys, so the replayed log contains
        // delete-then-reinsert sequences for the parallel build to resolve.
        let mut batch = db.new_batch();
        for i in (1u64..4000).step_by(21) {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            let v = Sha256::hash(&[&(i * 13).to_be_bytes()]);
            batch = batch.write(k, Some(v));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        let db = db.sync().await.unwrap();
        let root = db.root();
        let active_keys = db.active_keys;
        drop(db);

        // Reopen with a range of concurrency values. All rebuild from the same log and must
        // match the original root, the original active-key count (counted per actual key, so
        // translated-key collision chains contribute each of their members), and serve the
        // expected value for every key.
        for &concurrency in concurrency_sweep {
            let mut cfg = fixed_db_config_partitioned::<OneCap>(partition, &context);
            cfg.init_concurrency = NonZeroUsize::new(concurrency).unwrap();
            let ctx = context
                .child("reopen")
                .with_attribute("concurrency", concurrency);
            let db = PartDb::<P, Sequential>::init(ctx, cfg).await.unwrap();
            assert_eq!(
                db.root(),
                root,
                "root mismatch at P={P} concurrency={concurrency}"
            );
            assert_eq!(
                db.active_keys, active_keys,
                "active-key count mismatch at P={P} concurrency={concurrency}"
            );
            assert_expected_values(&db).await;
            drop(db);
        }
    }

    /// `P=2` allocates 65,536 hash sub-indexes per index instance (each pre-sizing its map), which
    /// is too memory-heavy for the default suite, and the range/offset arithmetic is shared with
    /// the ordered variant's P=2 coverage -- so the unordered sweep runs at P=1 only.
    #[test_traced("WARN")]
    fn test_unordered_partitioned_p1_parallel_init_equivalence() {
        deterministic::Runner::default().start(|context| async move {
            // Concurrency 201 (200 workers) rounds down to 128 equal two-partition ranges for
            // P=1 (count=256) and 301 exceeds the partition count and clamps. Both must
            // reconstruct the same root without panicking.
            check_parallel_init_equivalence::<1>(
                context,
                "unordered_parallel_equiv_p1",
                &[1, 2, 3, 5, 9, 201, 301],
            )
            .await;
        });
    }

    /// A fresh db's log holds only the auto-appended CommitFloor. A multi-worker reopen must
    /// handle the keyless single-op replay (every routed batch empty).
    #[test_traced("WARN")]
    fn test_unordered_partitioned_fresh_db_parallel_init() {
        deterministic::Runner::default().start(|context| async move {
            type FreshDb<S> =
                partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 1, S>;

            let cfg = fixed_db_config_partitioned::<OneCap>("unordered_parallel_fresh", &context);
            let db = FreshDb::<Sequential>::init(context.child("create"), cfg)
                .await
                .unwrap();
            let root = db.root();
            drop(db);

            let mut cfg =
                fixed_db_config_partitioned::<OneCap>("unordered_parallel_fresh", &context);
            cfg.init_concurrency = NZUsize!(4);
            let db = FreshDb::<Sequential>::init(context.child("reopen"), cfg)
                .await
                .unwrap();
            assert_eq!(db.root(), root);
        });
    }

    /// A replay failure during a parallel build must join every worker before surfacing the
    /// error: no worker may outlive the failed build, retaining a clone of the log and its
    /// partition-range allocation (the [crate::qmdb::SnapshotBuild] cleanup invariant).
    #[test_traced("WARN")]
    fn test_unordered_partitioned_parallel_init_replay_failure_drains_workers() {
        deterministic::Runner::default().start(|context| async move {
            type FailDb<S> =
                partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 1, S>;

            // Populate a db so the log has committed operations to replay.
            let cfg =
                fixed_db_config_partitioned::<OneCap>("unordered_parallel_replay_fail", &context);
            let db = FailDb::<Sequential>::init(context.child("populate"), cfg)
                .await
                .unwrap();
            let mut batch = db.new_batch();
            for i in 0u64..100 {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                let v = Sha256::hash(&[&(i * 7).to_be_bytes()]);
                batch = batch.write(k, Some(v));
            }
            let merkleized = batch.merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let db = db.commit().await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Reopen the op log directly (init's reads run before faults are enabled) and build
            // against a fresh index, mirroring init's parallel snapshot build.
            let cfg =
                fixed_db_config_partitioned::<OneCap>("unordered_parallel_replay_fail", &context);
            let log = Journal::<Context, Operation<mmr::Family, Digest, Digest>>::init(
                context.child("log"),
                cfg.journal_config,
            )
            .await
            .unwrap();
            let floor = Location::new(log.bounds().start);
            let log = Arc::new(log);
            let mut index = crate::index::partitioned::unordered::Index::<OneCap, Location, 1>::new(
                context.child("index"),
                OneCap,
            );

            // Every read now fails, and the failure necessarily surfaces through the replay
            // stream: the reopened journal's page cache is fresh (only the buffer pool is shared
            // across configs, never cached pages), so replay's first item forces a storage read,
            // and with far fewer ops than the routing batch size no batch reaches a worker, so
            // workers never read the log themselves.
            context.storage_fault_config().write().read_rate = Some(1.0);
            let result = index
                .build_snapshot(
                    context.child("build"),
                    floor,
                    &log,
                    NZUsize!(4),
                    NZUsize!(1 << 21),
                    None,
                )
                .await;
            assert!(result.is_err(), "replay must fail under read faults");

            // Every worker was joined before the error surfaced: nothing else may retain the log.
            assert_eq!(Arc::strong_count(&log), 1);

            context.storage_fault_config().write().read_rate = None;
        });
    }

    /// A read-only log view whose random-access reads always fail. During a parallel build only
    /// the workers read the log directly (collision resolution, with the init cache disabled), so
    /// this fails a worker's read while the router's replay stream succeeds.
    struct FailingReads<C>(C);

    impl<C: Contiguous<Item: Sync>> Contiguous for FailingReads<C> {
        type Item = C::Item;

        fn bounds(&self) -> std::ops::Range<u64> {
            self.0.bounds()
        }

        fn read(
            &self,
            position: u64,
        ) -> impl Future<Output = Result<Self::Item, JournalError>> + Send + Sync {
            ready(Err(JournalError::ItemPruned(position)))
        }

        fn read_many(
            &self,
            positions: &[u64],
        ) -> impl Future<Output = Result<Vec<Self::Item>, JournalError>> + Send {
            ready(Err(JournalError::ItemPruned(
                positions.first().copied().unwrap_or_default(),
            )))
        }

        fn try_read_sync(&self, _position: u64) -> Option<Self::Item> {
            None
        }

        fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<Self::Item>> {
            positions.iter().map(|_| None).collect()
        }

        fn replay(
            &self,
            start_pos: u64,
            buffer: NonZeroUsize,
        ) -> impl Future<
            Output = Result<
                impl Stream<Item = Result<(u64, Self::Item), JournalError>> + Send,
                JournalError,
            >,
        > + Send {
            self.0.replay(start_pos, buffer)
        }
    }

    /// A worker failure during a parallel build must surface through the worker join and leave
    /// no worker retaining the log: the failing worker's channel closes, routing stops, and the
    /// join returns the worker's error. This is the counterpart of the replay-failure test,
    /// which fails the router's stream before any worker reads.
    #[test_traced("WARN")]
    fn test_unordered_partitioned_parallel_init_worker_failure_drains_workers() {
        deterministic::Runner::default().start(|context| async move {
            type FailDb<S> =
                partitioned::Db<mmr::Family, Context, Digest, Digest, Sha256, OneCap, 1, S>;

            // Populate with two keys that share a partition and translated sub-key, so the
            // second key's replay resolves a collision by reading the first key's operation
            // from the log.
            let cfg =
                fixed_db_config_partitioned::<OneCap>("unordered_parallel_worker_fail", &context);
            let db = FailDb::<Sequential>::init(context.child("populate"), cfg)
                .await
                .unwrap();
            let merkleized = db
                .new_batch()
                .write(colliding_digest(0x10, 1), Some(Sha256::hash(&[b"v1"])))
                .write(colliding_digest(0x10, 2), Some(Sha256::hash(&[b"v2"])))
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            let db = db.commit().await.unwrap();
            let db = db.sync().await.unwrap();
            drop(db);

            // Reopen the op log behind a wrapper that fails every random-access read, and build
            // with the cache disabled so collision resolution must read the log.
            let cfg =
                fixed_db_config_partitioned::<OneCap>("unordered_parallel_worker_fail", &context);
            let log = Journal::<Context, Operation<mmr::Family, Digest, Digest>>::init(
                context.child("log"),
                cfg.journal_config,
            )
            .await
            .unwrap();
            let floor = Location::new(log.bounds().start);
            let log = Arc::new(FailingReads(log));
            let mut index = crate::index::partitioned::unordered::Index::<OneCap, Location, 1>::new(
                context.child("index"),
                OneCap,
            );
            let result = index
                .build_snapshot(
                    context.child("build"),
                    floor,
                    &log,
                    NZUsize!(4),
                    NZUsize!(1 << 21),
                    None,
                )
                .await;
            assert!(
                matches!(result, Err(Error::Journal(JournalError::ItemPruned(_)))),
                "worker read failure must surface through the join, got {result:?}"
            );

            // Every worker was joined before the error surfaced: nothing else may retain the log.
            assert_eq!(Arc::strong_count(&log), 1);
        });
    }

    /// A multi-worker build of an empty log must return the serial build's result (zero active
    /// keys, an empty bitmap) rather than panicking on the last-commit bit.
    #[test_traced("WARN")]
    fn test_unordered_partitioned_parallel_init_empty_log() {
        deterministic::Runner::default().start(|context| async move {
            let mut results = Vec::new();
            for concurrency in [1usize, 4] {
                let cfg =
                    fixed_db_config_partitioned::<OneCap>("unordered_parallel_empty", &context);
                let log = Journal::<Context, Operation<mmr::Family, Digest, Digest>>::init(
                    context
                        .child("log")
                        .with_attribute("concurrency", concurrency),
                    cfg.journal_config,
                )
                .await
                .unwrap();
                let log = Arc::new(log);
                let mut index =
                    crate::index::partitioned::unordered::Index::<OneCap, Location, 1>::new(
                        context
                            .child("index")
                            .with_attribute("concurrency", concurrency),
                        OneCap,
                    );
                let result = index
                    .build_snapshot(
                        context
                            .child("build")
                            .with_attribute("concurrency", concurrency),
                        Location::new(0),
                        &log,
                        NonZeroUsize::new(concurrency).unwrap(),
                        NZUsize!(1 << 21),
                        None,
                    )
                    .await
                    .unwrap();
                assert_eq!(result.0, 0);
                results.push(result);
            }
            assert_eq!(results[0], results[1]);
        });
    }

    #[test_traced("INFO")]
    fn test_any_unordered_fixed_metrics() {
        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db_generic::<mmr::Family>(ctx.child("db")).await;
            let k = key(1);
            let v = val(1);
            let batch = db
                .new_batch()
                .write(k, Some(v))
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            assert_eq!(db.get(&k).await.unwrap(), Some(v));
            assert_eq!(db.get_many(&[&k]).await.unwrap(), vec![Some(v)]);
            let db = db.commit().await.unwrap();
            let (db, handle) = db.start_commit().await.unwrap();
            handle.await.unwrap();
            let db = db.sync().await.unwrap();
            let _db = db.prune(Location::new(0)).await.unwrap();

            let metrics = ctx.encode();
            for expected in [
                "db_size 4",
                "db_pruning_boundary 0",
                "db_retained 4",
                "db_inactivity_floor 2",
                "db_last_commit 3",
                "db_get_calls_total 1",
                "db_get_many_calls_total 1",
                "db_lookups_requested_total 2",
                "db_apply_batch_calls_total 1",
                "db_operations_applied_total 3",
                "db_commit_calls_total 1",
                "db_start_commit_calls_total 1",
                "db_sync_calls_total 1",
                "db_prune_calls_total 1",
                "db_get_duration_count 1",
                "db_get_many_duration_count 1",
                "db_apply_batch_duration_count 1",
                "db_commit_duration_count 1",
                "db_sync_duration_count 1",
                "db_prune_duration_count 1",
            ] {
                assert!(metrics.contains(expected), "missing {expected}\n{metrics}");
            }
        });
    }

    /// Reads on a batch must not perturb `merkleize`: the root must be byte-identical to a
    /// write-only batch's `merkleize`, across updates/deletes/creates, both with the batch
    /// rooted directly at the DB (D=0) and through pending ancestors (D=1, D=2).
    #[test_traced("WARN")]
    fn test_unordered_fixed_read_merkleize_parity() {
        type ParentChain = Vec<
            std::sync::Arc<
                crate::qmdb::any::batch::MerkleizedBatch<
                    mmr::Family,
                    Digest,
                    crate::qmdb::any::operation::update::Unordered<Digest, FixedEncoding<Digest>>,
                    Sequential,
                >,
            >,
        >;

        deterministic::Runner::default().start(|ctx| async move {
            let db = create_test_db(ctx.child("db")).await;

            // Seed 2000 keys and commit so they live in the committed snapshot.
            let mut seed = db.new_batch();
            for i in 0..2000u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed = seed.merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

            // Build a mixed mutation set: updates of existing keys, deletes of existing keys,
            // and creates of fresh keys. `make` re-derives the set from a seed so both paths and
            // both depths see identical mutations.
            let make = |salt: u64| -> Vec<(Digest, Option<Digest>)> {
                let mut rng = TestRng::new(salt);
                let mut out = Vec::new();
                for _ in 0..600 {
                    let r = rng.next_u32() % 100;
                    if r < 60 {
                        out.push((key(rng.next_u64() % 2000), Some(val(rng.next_u64()))));
                    } else if r < 80 {
                        out.push((key(rng.next_u64() % 2000), None));
                    } else {
                        out.push((key(2000 + rng.next_u64() % 2000), Some(val(rng.next_u64()))));
                    }
                }
                // Dedup last-write-wins.
                let mut m: HashMap<Digest, Option<Digest>> = HashMap::new();
                for (k, v) in out {
                    m.insert(k, v);
                }
                m.into_iter().collect()
            };

            // D=0: batch rooted directly at the DB. D=N: through N pending ancestors.
            for depth in [0u64, 1, 2] {
                let mut chain: ParentChain = Vec::new();
                for d in 0..depth {
                    let mut p = chain
                        .last()
                        .map_or_else(|| db.new_batch(), |l| l.new_batch::<Sha256>());
                    for (k, v) in make(900 + d) {
                        p = p.write(k, v);
                    }
                    chain.push(p.merkleize(&db, None).await.unwrap());
                }

                let muts = make(depth + 1);
                let new_batch = || {
                    chain
                        .last()
                        .map_or_else(|| db.new_batch(), |p| p.new_batch::<Sha256>())
                };

                // Normal path.
                let mut nb = new_batch();
                for (k, v) in &muts {
                    nb = nb.write(*k, *v);
                }
                let normal_root = nb.merkleize(&db, None).await.unwrap().root();

                // Read-then-write on one batch. Values and root must match the write-only path.
                let keys: Vec<&Digest> = muts.iter().map(|(k, _)| k).collect();
                let mut fb = new_batch();
                // Duplicate keys in one read resolve identically per slot.
                let dup_values = fb.get_many(&[keys[0], keys[0]], &db).await.unwrap();
                assert_eq!(dup_values[0], dup_values[1]);
                // Keys read but never written must not affect the root.
                let unwritten: Vec<Digest> = (0..40u64)
                    .map(|i| key(i * 50))
                    .chain((0..5).map(|i| key(8000 + i)))
                    .collect();
                let unwritten_refs: Vec<&Digest> = unwritten.iter().collect();
                fb.get_many(&unwritten_refs, &db).await.unwrap();
                let values = fb.get_many(&keys, &db).await.unwrap();
                let plain = new_batch().get_many(&keys, &db).await.unwrap();
                assert_eq!(values, plain, "value mismatch at depth={depth}");
                for (k, v) in &muts {
                    fb = fb.write(*k, *v);
                }
                let fused_root = fb.merkleize(&db, None).await.unwrap().root();
                assert_eq!(normal_root, fused_root, "root mismatch at depth={depth}");

                // Reads after writes: written keys are answered by the pending mutations and the
                // root must still match.
                let half = muts.len() / 2;
                let mut mb = new_batch();
                for (k, v) in muts.iter().take(half) {
                    mb = mb.write(*k, *v);
                }
                let values = mb.get_many(&keys, &db).await.unwrap();
                for (i, (_, v)) in muts.iter().enumerate().take(half) {
                    assert_eq!(values[i], *v, "pending write not visible at depth={depth}");
                }
                assert_eq!(
                    values[half..],
                    plain[half..],
                    "unwritten value mismatch at depth={depth}"
                );
                for (k, v) in muts.iter().skip(half) {
                    mb = mb.write(*k, *v);
                }
                let mixed_root = mb.merkleize(&db, None).await.unwrap().root();
                assert_eq!(
                    normal_root, mixed_root,
                    "mixed root mismatch at depth={depth}"
                );

                // Multiple disjoint reads and single-key gets must not affect the root.
                let mut gb = new_batch();
                gb.get_many(&keys[..half], &db).await.unwrap();
                for key in &keys[half..] {
                    gb.get(key, &db).await.unwrap();
                }
                for (k, v) in &muts {
                    gb = gb.write(*k, *v);
                }
                let merged_root = gb.merkleize(&db, None).await.unwrap().root();
                assert_eq!(
                    normal_root, merged_root,
                    "merged root mismatch at depth={depth}"
                );
            }
        });
    }

    // -- Generic inner functions for parameterized batch tests --

    async fn batch_empty_inner<F: Family>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.child("db")).await;
        let root_before = db.root();

        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        assert_ne!(db.root(), root_before);

        // DB should still be functional.
        let (db, _) = commit_writes_generic(db, [(key(0), Some(val(0)))], None).await;
        assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

        db.destroy().await.unwrap();
    }

    async fn batch_metadata_inner<F: Family>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.child("db")).await;
        let metadata = val(42);

        let (db, _) = commit_writes_generic(db, [(key(0), Some(val(0)))], Some(metadata)).await;
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    async fn batch_get_read_through_inner<F: Family>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.child("db")).await;

        let ka = key(0);
        let va = val(0);
        let (db, _) = commit_writes_generic(db, [(ka, Some(va))], None).await;

        let kb = key(1);
        let vb = val(1);
        let kc = key(2);

        let mut batch = db.new_batch();
        assert_eq!(batch.get(&ka, &db).await.unwrap(), Some(va));

        batch = batch.write(kb, Some(vb));
        assert_eq!(batch.get(&kb, &db).await.unwrap(), Some(vb));
        assert_eq!(batch.get(&kc, &db).await.unwrap(), None);

        let va2 = val(100);
        batch = batch.write(ka, Some(va2));
        assert_eq!(batch.get(&ka, &db).await.unwrap(), Some(va2));

        batch = batch.write(ka, None);
        assert_eq!(batch.get(&ka, &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    async fn batch_get_on_merkleized_inner<F: Family>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.child("db")).await;

        let ka = key(0);
        let kb = key(1);
        let kc = key(2);
        let kd = key(3);

        let (db, _) =
            commit_writes_generic(db, [(ka, Some(val(0))), (kb, Some(val(1)))], None).await;

        let va2 = val(100);
        let vc = val(2);
        let merkleized = db
            .new_batch()
            .write(ka, Some(va2))
            .write(kb, None)
            .write(kc, Some(vc))
            .merkleize(&db, None)
            .await
            .unwrap();

        assert_eq!(merkleized.get(&ka, &db).await.unwrap(), Some(va2));
        assert_eq!(merkleized.get(&kb, &db).await.unwrap(), None);
        assert_eq!(merkleized.get(&kc, &db).await.unwrap(), Some(vc));
        assert_eq!(merkleized.get(&kd, &db).await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    async fn batch_stacked_get_inner<F: Family>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.child("db")).await;

        let ka = key(0);
        let kb = key(1);

        let merkleized = db
            .new_batch()
            .write(ka, Some(val(0)))
            .merkleize(&db, None)
            .await
            .unwrap();

        let mut child = merkleized.new_batch();
        assert_eq!(child.get(&ka, &db).await.unwrap(), Some(val(0)));

        child = child.write(ka, Some(val(100)));
        assert_eq!(child.get(&ka, &db).await.unwrap(), Some(val(100)));

        child = child.write(kb, Some(val(1)));
        assert_eq!(child.get(&kb, &db).await.unwrap(), Some(val(1)));

        child = child.write(ka, None);
        assert_eq!(child.get(&ka, &db).await.unwrap(), None);

        drop(child);
        drop(merkleized);
        db.destroy().await.unwrap();
    }

    async fn batch_stacked_delete_recreate_inner<F: Family>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.child("db")).await;
        let ka = key(0);

        let (db, _) = commit_writes_generic(db, [(ka, Some(val(0)))], None).await;

        let parent_m = db
            .new_batch()
            .write(ka, None)
            .merkleize(&db, None)
            .await
            .unwrap();
        assert_eq!(parent_m.get(&ka, &db).await.unwrap(), None);

        let child_m = parent_m
            .new_batch()
            .write(ka, Some(val(200)))
            .merkleize(&db, None)
            .await
            .unwrap();
        assert_eq!(child_m.get(&ka, &db).await.unwrap(), Some(val(200)));

        let (db, _) = db.apply_batch(child_m).await.unwrap();
        assert_eq!(db.get(&ka).await.unwrap(), Some(val(200)));

        db.destroy().await.unwrap();
    }

    async fn batch_apply_returns_range_inner<F: Family>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.child("db")).await;

        let writes: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
        let (db, range1) = commit_writes_generic(db, writes, None).await;

        assert_eq!(range1.start, GenericLocation::<F>::new(1));
        assert!(range1.end.saturating_sub(*range1.start) >= 6);

        let writes: Vec<_> = (5..10).map(|i| (key(i), Some(val(i)))).collect();
        let (db, range2) = commit_writes_generic(db, writes, None).await;
        assert_eq!(range2.start, range1.end);

        db.destroy().await.unwrap();
    }

    async fn batch_speculative_root_inner<F: Family>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.child("db")).await;

        let mut batch = db.new_batch();
        for i in 0..10 {
            batch = batch.write(key(i), Some(val(i)));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        let speculative_root = merkleized.root();

        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.root(), speculative_root);

        db.destroy().await.unwrap();
    }

    async fn log_replay_inner<F: Family>(context: deterministic::Context) {
        let db_context = context.child("db");
        let db = open_db_generic::<F>(db_context.child("db")).await;

        // Update the same key many times within a single batch.
        const UPDATES: u64 = 100;
        let k = Sha256::hash(&[&UPDATES.to_be_bytes()]);
        let mut batch = db.new_batch();
        for i in 0u64..UPDATES {
            let v = Sha256::hash(&[&(i * 1000).to_be_bytes()]);
            batch = batch.write(k, Some(v));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        let (db, _) = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();
        let root = db.root();

        // Simulate a failed commit and test that the log replay doesn't leave behind old data.
        drop(db);
        let db: AnyTestGeneric<F> = open_db_generic::<F>(db_context.child("reopened")).await;
        let iter = db.snapshot.get(&k);
        assert_eq!(iter.cloned().collect::<Vec<_>>().len(), 1);
        assert_eq!(db.root(), root);

        db.destroy().await.unwrap();
    }

    // -- MMR test wrappers --

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_empty() {
        let executor = deterministic::Runner::default();
        executor.start(batch_empty_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(batch_metadata_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_get_read_through() {
        let executor = deterministic::Runner::default();
        executor.start(batch_get_read_through_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_get_on_merkleized() {
        let executor = deterministic::Runner::default();
        executor.start(batch_get_on_merkleized_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_stacked_get() {
        let executor = deterministic::Runner::default();
        executor.start(batch_stacked_get_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_stacked_delete_recreate() {
        let executor = deterministic::Runner::default();
        executor.start(batch_stacked_delete_recreate_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_apply_returns_range() {
        let executor = deterministic::Runner::default();
        executor.start(batch_apply_returns_range_inner::<mmr::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_speculative_root() {
        let executor = deterministic::Runner::default();
        executor.start(batch_speculative_root_inner::<mmr::Family>);
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_log_replay() {
        let executor = deterministic::Runner::default();
        executor.start(log_replay_inner::<mmr::Family>);
    }

    // -- MMB test wrappers --

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_empty_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(batch_empty_inner::<crate::merkle::mmb::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_metadata_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(batch_metadata_inner::<crate::merkle::mmb::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_get_read_through_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(batch_get_read_through_inner::<crate::merkle::mmb::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_get_on_merkleized_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(batch_get_on_merkleized_inner::<crate::merkle::mmb::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_stacked_get_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(batch_stacked_get_inner::<crate::merkle::mmb::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_stacked_delete_recreate_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(batch_stacked_delete_recreate_inner::<crate::merkle::mmb::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_apply_returns_range_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(batch_apply_returns_range_inner::<crate::merkle::mmb::Family>);
    }

    #[test_traced("INFO")]
    fn test_unordered_fixed_batch_speculative_root_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(batch_speculative_root_inner::<crate::merkle::mmb::Family>);
    }

    #[test_traced("WARN")]
    fn test_any_fixed_db_log_replay_mmb() {
        let executor = deterministic::Runner::default();
        executor.start(log_replay_inner::<crate::merkle::mmb::Family>);
    }

    // -- MMR-only tests (use verify_proof / Position which are MMR-specific) --

    #[test]
    fn test_any_fixed_db_historical_proof_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let db = create_test_db(context.child("storage")).await;
            let ops = create_test_ops(20);
            let db = apply_ops(db, ops.clone()).await;
            let root_hash = db.root();
            let original_op_count = db.bounds().end;

            // Historical proof should match "regular" proof when historical size == current database size
            let max_ops = NZU64!(10);
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new(6), max_ops)
                .await
                .unwrap();
            let (regular_proof, regular_ops) = db.proof(Location::new(6), max_ops).await.unwrap();

            assert_eq!(historical_proof.leaves, regular_proof.leaves);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert!(verify_proof::<Sha256, _, _>(
                &historical_proof,
                Location::new(6),
                &historical_ops,
                &root_hash
            ));

            // Add more operations to the database
            // (use different seed to avoid key collisions)
            let more_ops = create_test_ops_seeded(5, 1);
            let db = apply_ops(db, more_ops.clone()).await;

            // Historical proof should remain the same even though database has grown
            let (historical_proof, historical_ops) = db
                .historical_proof(original_op_count, Location::new(6), NZU64!(10))
                .await
                .unwrap();
            assert_eq!(historical_proof.leaves, original_op_count);
            assert_eq!(historical_proof.leaves, regular_proof.leaves);
            assert_eq!(historical_ops.len(), 10);
            assert_eq!(historical_proof.digests, regular_proof.digests);
            assert_eq!(historical_ops, regular_ops);
            assert!(verify_proof::<Sha256, _, _>(
                &historical_proof,
                Location::new(6),
                &historical_ops,
                &root_hash
            ));

            // Try to get historical proof with op_count > number of operations and confirm it
            // returns RangeOutOfBounds error.
            assert!(matches!(
                db.historical_proof(db.bounds().end + 1, Location::new(6), NZU64!(10))
                    .await,
                Err(Error::Merkle(crate::mmr::Error::RangeOutOfBounds(_)))
            ));

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_edge_cases() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut db = create_test_db(context.child("first")).await;
            // Apply ops in multiple batches; each apply_ops ends in a commit, so the size
            // after each batch is a commit-boundary historical size.
            let mut commit_boundary_sizes: Vec<Location> = Vec::new();
            for _ in 0..5 {
                db = apply_ops(db, create_test_ops(10)).await;
                commit_boundary_sizes.push(db.bounds().end);
            }

            let root = db.root();
            let full_size = db.bounds().end;
            assert_eq!(full_size, *commit_boundary_sizes.last().unwrap());

            // Verify a single-op proof at the full commit size.
            let (proof, proof_ops) = db.proof(Location::new(1), NZU64!(1)).await.unwrap();
            assert_eq!(proof_ops.len(), 1);
            assert!(verify_proof::<Sha256, _, _>(
                &proof,
                Location::new(1),
                &proof_ops,
                &root
            ));

            // historical_proof at full size should match proof.
            let (hp, hp_ops) = db
                .historical_proof(full_size, Location::new(1), NZU64!(1))
                .await
                .unwrap();
            assert_eq!(hp.digests, proof.digests);
            assert_eq!(hp_ops, proof_ops);

            // Test requesting more operations than available in historical position. Use
            // the commit-boundary size after the first batch.
            let first_batch_size = commit_boundary_sizes[0];
            let (_proof, limited_ops) = db
                .historical_proof(first_batch_size, Location::new(6), NZU64!(1000))
                .await
                .unwrap();
            assert_eq!(limited_ops.len() as u64, *first_batch_size - 6);

            // Test proof at minimum historical position (just the initial commit).
            let (min_proof, min_ops) = db
                .historical_proof(Location::new(1), Location::new(0), NZU64!(3))
                .await
                .unwrap();
            assert_eq!(min_proof.leaves, Location::new(1));
            assert_eq!(min_ops.len(), 1);

            // Non-commit-boundary historical sizes are rejected.
            let result = db
                .historical_proof(Location::new(5), Location::new(1), NZU64!(3))
                .await;
            assert!(
                matches!(result, Err(crate::qmdb::Error::HistoricalFloorPruned(loc)) if loc == Location::new(5)),
                "expected HistoricalFloorPruned(5), got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_any_fixed_db_historical_proof_different_historical_sizes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let ops = create_test_ops(100);
            let start_loc = Location::new(2);
            let max_ops = NZU64!(10);

            // Build checkpoints only at commit points and record reference proofs/roots there.
            let mut db = create_test_db(context.child("main")).await;
            let mut offset = 0usize;
            let mut checkpoints = Vec::new();
            for chunk in [20usize, 15, 25, 30, 10] {
                db = apply_ops(db, ops[offset..offset + chunk].to_vec()).await;
                offset += chunk;

                let end_loc = db.bounds().end;
                let root = db.root();
                let (proof, proof_ops) = db.proof(start_loc, max_ops).await.unwrap();
                checkpoints.push((end_loc, root, proof, proof_ops));
            }

            // Grow state past the checkpoints with an empty batch and verify all
            // historical proofs from that later state.
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(merkleized).await.unwrap();
            for (historical_size, root, reference_proof, reference_ops) in checkpoints {
                let (historical_proof, historical_ops) = db
                    .historical_proof(historical_size, start_loc, max_ops)
                    .await
                    .unwrap();
                assert_eq!(historical_proof.leaves, reference_proof.leaves);
                assert_eq!(historical_proof.digests, reference_proof.digests);
                assert_eq!(historical_ops, reference_ops);
                assert!(verify_proof::<Sha256, _, _>(
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &root
                ));
            }

            // Verify the current full-size proof against the current root as a final sanity check.
            let full_root = db.root();
            let (full_proof, full_ops) = db.proof(start_loc, max_ops).await.unwrap();
            assert!(verify_proof::<Sha256, _, _>(
                &full_proof,
                start_loc,
                &full_ops,
                &full_root
            ));

            db.destroy().await.unwrap();
        });
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_non_trait_futures_are_send(db: &AnyTest, key: Digest, value: Digest) {
        let reader = db.new_batch();
        is_send(reader.get_many(&[&key], db));
        let batch = db.new_batch().write(key, Some(value));
        is_send(batch.merkleize(db, None));
        is_send(db.get_with_loc(&key));
    }

    // FromSyncTestable implementation for from_sync_result tests
    mod from_sync_testable {
        use super::*;
        use crate::{
            merkle::mmr::{self, full::Mmr},
            qmdb::any::sync::tests::FromSyncTestable,
        };
        use futures::future::join_all;

        type TestMmr = Mmr<deterministic::Context, Digest, Sequential>;

        impl FromSyncTestable for AnyTest {
            type Merkle = TestMmr;

            fn into_log_components(self) -> (Self::Merkle, Self::Journal) {
                (self.log.merkle, self.log.journal)
            }

            async fn pinned_nodes_at(&self, loc: Location) -> Vec<Digest> {
                join_all(mmr::Family::nodes_to_pin(loc).map(|p| self.log.merkle.get_node(p)))
                    .await
                    .into_iter()
                    .map(|n| n.unwrap().unwrap())
                    .collect()
            }
        }
    }
}

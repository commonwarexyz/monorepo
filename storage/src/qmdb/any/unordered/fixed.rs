//! An Any database implementation with an unordered key space and fixed-size values.

use crate::{
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    merkle::{Family, Location},
    qmdb::{
        any::{unordered, value::FixedEncoding, FixedConfig as Config, FixedValue},
        Error, RootSpec,
    },
    translator::Translator,
    Context,
};
use commonware_cryptography::Hasher;
use commonware_utils::Array;

pub type Update<K, V> = unordered::Update<K, FixedEncoding<V>>;
pub type Operation<F, K, V> = unordered::Operation<F, K, FixedEncoding<V>>;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Db<F, E, K, V, H, T> =
    super::Db<F, E, Journal<E, Operation<F, K, V>>, Index<T, Location<F>>, H, Update<K, V>>;

impl<F: Family + RootSpec, E: Context, K: Array, V: FixedValue, H: Hasher, T: Translator>
    Db<F, E, K, V, H, T>
{
    /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error<F>> {
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
        index::partitioned::unordered::Index,
        journal::contiguous::fixed::Journal,
        merkle::{Family, Location},
        qmdb::{
            any::{FixedConfig as Config, FixedValue},
            Error, RootSpec,
        },
        translator::Translator,
        Context,
    };
    use commonware_cryptography::Hasher;
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
    pub type Db<F, E, K, V, H, T, const P: usize> = crate::qmdb::any::unordered::Db<
        F,
        E,
        Journal<E, Operation<F, K, V>>,
        Index<T, Location<F>, P>,
        H,
        Update<K, V>,
    >;

    impl<
            F: Family + RootSpec,
            E: Context,
            K: Array,
            V: FixedValue,
            H: Hasher,
            T: Translator,
            const P: usize,
        > Db<F, E, K, V, H, T, P>
    {
        /// Returns a [Db] QMDB initialized from `cfg`. Uncommitted log operations will be
        /// discarded and the state of the db will be as of the last committed operation.
        pub async fn init(context: E, cfg: Config<T>) -> Result<Self, Error<F>> {
            crate::qmdb::any::init(context, cfg).await
        }
    }

    /// Convenience type aliases for 256 partitions (P=1).
    pub mod p256 {
        /// Fixed-value DB with 256 partitions.
        pub type Db<F, E, K, V, H, T> = super::Db<F, E, K, V, H, T, 1>;
    }

    /// Convenience type aliases for 65,536 partitions (P=2).
    pub mod p64k {
        /// Fixed-value DB with 65,536 partitions.
        pub type Db<F, E, K, V, H, T> = super::Db<F, E, K, V, H, T, 2>;
    }
}

// pub(crate) so helpers can be used by the sync module.
#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::{
        index::Unordered as _,
        merkle::{
            mmr::{self, Location, StandardHasher},
            Location as GenericLocation,
        },
        qmdb::{
            any::{
                test::fixed_db_config,
                unordered::{fixed::Operation, Update},
            },
            verify_proof, RootSpec,
        },
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_math::algebra::Random;
    use commonware_runtime::{
        deterministic::{self, Context},
        Metrics, Runner as _,
    };
    use commonware_utils::{test_rng_seeded, NZU64};
    use rand::RngCore;

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
    >;

    /// A type alias for the concrete [Db] type used in these unit tests.
    pub(crate) type AnyTest =
        Db<mmr::Family, deterministic::Context, Digest, Digest, Sha256, TwoCap>;

    /// Return an `Any` database initialized with a fixed config, generic over merkle family.
    async fn open_db_generic<F: Family + RootSpec>(
        context: deterministic::Context,
    ) -> AnyTestGeneric<F> {
        let cfg = fixed_db_config::<TwoCap>("partition", &context);
        crate::qmdb::any::init(context, cfg).await.unwrap()
    }

    /// Create a test database with unique partition names
    pub(crate) async fn create_test_db(mut context: Context) -> AnyTest {
        let seed = context.next_u64();
        let cfg = fixed_db_config::<TwoCap>(&seed.to_string(), &context);
        AnyTest::init(context, cfg).await.unwrap()
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
        let mut rng = test_rng_seeded(seed);
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
        db: &mut AnyTest,
        ops: Vec<Operation<mmr::Family, Digest, Digest>>,
    ) {
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
        let merkleized = batch.merkleize(db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
    }

    /// Helper: commit a batch of key-value writes and return the applied range (generic).
    async fn commit_writes_generic<F: Family + RootSpec>(
        db: &mut AnyTestGeneric<F>,
        writes: impl IntoIterator<Item = (Digest, Option<Digest>)>,
        metadata: Option<Digest>,
    ) -> std::ops::Range<GenericLocation<F>> {
        let mut batch = db.new_batch();
        for (k, v) in writes {
            batch = batch.write(k, v);
        }
        let merkleized = batch.merkleize(db, metadata).await.unwrap();
        let range = db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        range
    }

    fn key(i: u64) -> Digest {
        Sha256::hash(&i.to_be_bytes())
    }

    fn val(i: u64) -> Digest {
        Sha256::hash(&(i + 10000).to_be_bytes())
    }

    // -- Generic inner functions for parameterized batch tests --

    async fn batch_empty_inner<F: Family + RootSpec>(context: deterministic::Context) {
        let mut db = open_db_generic::<F>(context.with_label("db")).await;
        let root_before = db.root();

        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        assert_ne!(db.root(), root_before);

        // DB should still be functional.
        commit_writes_generic(&mut db, [(key(0), Some(val(0)))], None).await;
        assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(0)));

        db.destroy().await.unwrap();
    }

    async fn batch_metadata_inner<F: Family + RootSpec>(context: deterministic::Context) {
        let mut db = open_db_generic::<F>(context.with_label("db")).await;
        let metadata = val(42);

        commit_writes_generic(&mut db, [(key(0), Some(val(0)))], Some(metadata)).await;
        assert_eq!(db.get_metadata().await.unwrap(), Some(metadata));

        let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.get_metadata().await.unwrap(), None);

        db.destroy().await.unwrap();
    }

    async fn batch_get_read_through_inner<F: Family + RootSpec>(context: deterministic::Context) {
        let mut db = open_db_generic::<F>(context.with_label("db")).await;

        let ka = key(0);
        let va = val(0);
        commit_writes_generic(&mut db, [(ka, Some(va))], None).await;

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

    async fn batch_get_on_merkleized_inner<F: Family + RootSpec>(context: deterministic::Context) {
        let mut db = open_db_generic::<F>(context.with_label("db")).await;

        let ka = key(0);
        let kb = key(1);
        let kc = key(2);
        let kd = key(3);

        commit_writes_generic(&mut db, [(ka, Some(val(0))), (kb, Some(val(1)))], None).await;

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

    async fn batch_stacked_get_inner<F: Family + RootSpec>(context: deterministic::Context) {
        let db = open_db_generic::<F>(context.with_label("db")).await;

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

    async fn batch_stacked_delete_recreate_inner<F: Family + RootSpec>(
        context: deterministic::Context,
    ) {
        let mut db = open_db_generic::<F>(context.with_label("db")).await;
        let ka = key(0);

        commit_writes_generic(&mut db, [(ka, Some(val(0)))], None).await;

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

        db.apply_batch(child_m).await.unwrap();
        assert_eq!(db.get(&ka).await.unwrap(), Some(val(200)));

        db.destroy().await.unwrap();
    }

    async fn batch_apply_returns_range_inner<F: Family + RootSpec>(
        context: deterministic::Context,
    ) {
        let mut db = open_db_generic::<F>(context.with_label("db")).await;

        let writes: Vec<_> = (0..5).map(|i| (key(i), Some(val(i)))).collect();
        let range1 = commit_writes_generic(&mut db, writes, None).await;

        assert_eq!(range1.start, GenericLocation::<F>::new(1));
        assert!(range1.end.saturating_sub(*range1.start) >= 6);

        let writes: Vec<_> = (5..10).map(|i| (key(i), Some(val(i)))).collect();
        let range2 = commit_writes_generic(&mut db, writes, None).await;
        assert_eq!(range2.start, range1.end);

        db.destroy().await.unwrap();
    }

    async fn batch_speculative_root_inner<F: Family + RootSpec>(context: deterministic::Context) {
        let mut db = open_db_generic::<F>(context.with_label("db")).await;

        let mut batch = db.new_batch();
        for i in 0..10 {
            batch = batch.write(key(i), Some(val(i)));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        let speculative_root = merkleized.root();

        db.apply_batch(merkleized).await.unwrap();
        assert_eq!(db.root(), speculative_root);

        db.destroy().await.unwrap();
    }

    async fn log_replay_inner<F: Family + RootSpec>(context: deterministic::Context) {
        let db_context = context.with_label("db");
        let mut db = open_db_generic::<F>(db_context.clone()).await;

        // Update the same key many times within a single batch.
        const UPDATES: u64 = 100;
        let k = Sha256::hash(&UPDATES.to_be_bytes());
        let mut batch = db.new_batch();
        for i in 0u64..UPDATES {
            let v = Sha256::hash(&(i * 1000).to_be_bytes());
            batch = batch.write(k, Some(v));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        let root = db.root();

        // Simulate a failed commit and test that the log replay doesn't leave behind old data.
        drop(db);
        let db: AnyTestGeneric<F> = open_db_generic::<F>(db_context.with_label("reopened")).await;
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
            let mut db = create_test_db(context.clone()).await;
            let ops = create_test_ops(20);
            apply_ops(&mut db, ops.clone()).await;
            let root_hash = db.root();
            let original_op_count = db.bounds().await.end;

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
            let hasher = StandardHasher::<Sha256>::new();
            assert!(verify_proof(
                &hasher,
                &historical_proof,
                Location::new(6),
                &historical_ops,
                &root_hash,
                mmr::Family::root_spec(historical_proof.inactive_peaks),
            ));

            // Add more operations to the database
            // (use different seed to avoid key collisions)
            let more_ops = create_test_ops_seeded(5, 1);
            apply_ops(&mut db, more_ops.clone()).await;

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
            assert!(verify_proof(
                &hasher,
                &historical_proof,
                Location::new(6),
                &historical_ops,
                &root_hash,
                mmr::Family::root_spec(historical_proof.inactive_peaks),
            ));

            // Try to get historical proof with op_count > number of operations and confirm it
            // returns RangeOutOfBounds error.
            assert!(matches!(
                db.historical_proof(db.bounds().await.end + 1, Location::new(6), NZU64!(10))
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
            let hasher = StandardHasher::<Sha256>::new();

            let mut db = create_test_db(context.with_label("first")).await;
            // Apply ops in multiple batches; each apply_ops ends in a commit, so the size
            // after each batch is a commit-boundary historical size.
            let mut commit_boundary_sizes: Vec<Location> = Vec::new();
            for _ in 0..5 {
                apply_ops(&mut db, create_test_ops(10)).await;
                commit_boundary_sizes.push(db.bounds().await.end);
            }

            let root = db.root();
            let full_size = db.bounds().await.end;
            assert_eq!(full_size, *commit_boundary_sizes.last().unwrap());

            // Verify a single-op proof at the full commit size.
            let (proof, proof_ops) = db.proof(Location::new(1), NZU64!(1)).await.unwrap();
            assert_eq!(proof_ops.len(), 1);
            assert!(verify_proof(
                &hasher,
                &proof,
                Location::new(1),
                &proof_ops,
                &root,
                mmr::Family::root_spec(proof.inactive_peaks),
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
            let hasher = StandardHasher::<Sha256>::new();
            let start_loc = Location::new(2);
            let max_ops = NZU64!(10);

            // Build checkpoints only at commit points and record reference proofs/roots there.
            let mut db = create_test_db(context.with_label("main")).await;
            let mut offset = 0usize;
            let mut checkpoints = Vec::new();
            for chunk in [20usize, 15, 25, 30, 10] {
                apply_ops(&mut db, ops[offset..offset + chunk].to_vec()).await;
                offset += chunk;

                let end_loc = db.bounds().await.end;
                let root = db.root();
                let (proof, proof_ops) = db.proof(start_loc, max_ops).await.unwrap();
                checkpoints.push((end_loc, root, proof, proof_ops));
            }

            // Grow state past the checkpoints with an empty batch and verify all
            // historical proofs from that later state.
            let merkleized = db.new_batch().merkleize(&db, None).await.unwrap();
            db.apply_batch(merkleized).await.unwrap();
            for (historical_size, root, reference_proof, reference_ops) in checkpoints {
                let (historical_proof, historical_ops) = db
                    .historical_proof(historical_size, start_loc, max_ops)
                    .await
                    .unwrap();
                assert_eq!(historical_proof.leaves, reference_proof.leaves);
                assert_eq!(historical_proof.digests, reference_proof.digests);
                assert_eq!(historical_ops, reference_ops);
                assert!(verify_proof(
                    &hasher,
                    &historical_proof,
                    start_loc,
                    &historical_ops,
                    &root,
                    mmr::Family::root_spec(historical_proof.inactive_peaks),
                ));
            }

            // Verify the current full-size proof against the current root as a final sanity check.
            let full_root = db.root();
            let (full_proof, full_ops) = db.proof(start_loc, max_ops).await.unwrap();
            assert!(verify_proof(
                &hasher,
                &full_proof,
                start_loc,
                &full_ops,
                &full_root,
                mmr::Family::root_spec(full_proof.inactive_peaks),
            ));

            db.destroy().await.unwrap();
        });
    }

    fn is_send<T: Send>(_: T) {}

    #[allow(dead_code)]
    fn assert_non_trait_futures_are_send(db: &AnyTest, key: Digest, value: Digest) {
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

        type TestMmr = Mmr<deterministic::Context, Digest>;

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

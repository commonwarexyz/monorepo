//! An _ordered_ variant of a [crate::qmdb::current] authenticated database optimized for fixed-size
//! values.
//!
//! This variant maintains the lexicographic-next active key for each active key, enabling exclusion
//! proofs (proving a key is currently inactive). Use [crate::qmdb::current::unordered::fixed] if
//! exclusion proofs are not needed.
//!
//! See [Db] for the main database type and [super::ExclusionProof] for proving key inactivity.

pub use super::db::KeyValueProof;
use crate::{
    index::ordered::Index,
    journal::contiguous::fixed::Journal,
    merkle::{Graftable, Location},
    qmdb::{
        any::{ordered::fixed::Operation, value::FixedEncoding, FixedValue},
        current::FixedConfig as Config,
        Error,
    },
    translator::Translator,
    Context,
};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_runtime::Spawner;
use commonware_utils::Array;

pub type Db<F, E, K, V, H, T, const N: usize, S> = super::db::Db<
    F,
    E,
    Journal<E, Operation<F, K, V>>,
    K,
    FixedEncoding<V>,
    Index<T, Location<F>>,
    H,
    N,
    S,
>;

impl<
        F: Graftable,
        E: Context + Spawner + 'static,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: Translator,
        const N: usize,
        S: Strategy,
    > Db<F, E, K, V, H, T, N, S>
{
    /// Initializes a [Db] from the given `config`.
    /// The configured [`Strategy`] is used to parallelize merkleization.
    pub async fn init(context: E, config: Config<T, S>) -> Result<Self, Error<F>> {
        crate::qmdb::current::init(context, config).await
    }
}

pub mod partitioned {
    //! A variant of [super] that uses a partitioned index for the snapshot.

    use super::*;
    use crate::index::partitioned::ordered::Index;

    /// A partitioned variant of [super::Db].
    ///
    /// The const generic `P` specifies the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    /// - `P = 3`: ~16 million partitions
    pub type Db<F, E, K, V, H, T, const P: usize, const N: usize, S> =
        crate::qmdb::current::ordered::db::Db<
            F,
            E,
            Journal<E, Operation<F, K, V>>,
            K,
            FixedEncoding<V>,
            Index<T, Location<F>, P>,
            H,
            N,
            S,
        >;

    impl<
            F: Graftable,
            E: Context + Spawner + 'static,
            K: Array,
            V: FixedValue,
            H: Hasher,
            T: Translator,
            const P: usize,
            const N: usize,
            S: Strategy,
        > Db<F, E, K, V, H, T, P, N, S>
    {
        /// Initializes a [Db] authenticated database from the given `config`.
        /// The configured [`Strategy`] is used to parallelize merkleization.
        pub async fn init(context: E, config: Config<T, S>) -> Result<Self, Error<F>> {
            crate::qmdb::current::init(context, config).await
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        mmr,
        qmdb::{
            current::{ordered::tests as shared, tests::fixed_config},
            Error,
        },
        translator::OneCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};
    use commonware_utils::{
        bitmap::{Prunable as BitMap, Readable as _},
        NZU64,
    };

    /// A type alias for the concrete [Db] type used in these unit tests.
    type CurrentTest = Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        OneCap,
        32,
        commonware_parallel::Sequential,
    >;

    /// Return an [Db] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context, partition_prefix: String) -> CurrentTest {
        let cfg = fixed_config::<OneCap>(&partition_prefix, &context);
        CurrentTest::init(context, cfg).await.unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        shared::test_verify_proof_over_bits_in_uncommitted_chunk(open_db);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_range_proofs() {
        shared::test_range_proofs(open_db);
    }

    /// Regression test: requesting a range proof for a location in a pruned bitmap chunk
    /// must return `Error::OperationPruned`, not panic in the bitmap accessor.
    #[test_traced("DEBUG")]
    pub fn test_range_proof_returns_error_on_pruned_chunks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "range-proofs-pruned".to_string();
            let hasher = crate::qmdb::hasher::<Sha256>();
            let mut db = open_db(context.child("db"), partition).await;

            let chunk_bits = BitMap::<32>::CHUNK_SIZE_BITS;

            // Repeatedly update the same key to generate many inactive operations,
            // pushing the inactivity floor past at least one full bitmap chunk.
            let key = Sha256::fill(0x11);
            for i in 0..chunk_bits + 10 {
                let value = Sha256::hash(&i.to_be_bytes());
                let merkleized = db
                    .new_batch()
                    .write(key, Some(value))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                db.apply_batch(merkleized).await.unwrap();
            }

            // Prune the database
            db.prune(db.sync_boundary()).await.unwrap();

            assert!(
                db.any.bitmap.pruned_chunks() > 0,
                "expected at least one pruned chunk"
            );

            // Requesting a range proof at location 0 (in the pruned range) should return
            // OperationPruned, not panic.
            let result = db.range_proof(&hasher, Location::new(0), NZU64!(1)).await;
            assert!(
                matches!(result, Err(Error::OperationPruned(_))),
                "expected OperationPruned, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_key_value_proof() {
        shared::test_key_value_proof(open_db);
    }

    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        shared::test_proving_repeated_updates(open_db);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_exclusion_proofs() {
        shared::test_exclusion_proofs(open_db);
    }

    /// Build a `P`-partitioned current db with churny ops across two commits (so the second commit's
    /// updates and deletes inactivate locations from the first), then assert that reopening it at a
    /// range of worker counts all reconstruct the identical root. Unlike the `any` equivalence tests,
    /// the current root commits to the activity bitmap, so this exercises the parallel build's bitmap
    /// reconstruction (`for_each_value` + last-commit), not just the snapshot index and MMR.
    async fn check_current_parallel_init_equivalence<const P: usize>(
        context: deterministic::Context,
        partition: &'static str,
        parallelisms: &[usize],
    ) {
        type PartDb<const P: usize> = partitioned::Db<
            mmr::Family,
            deterministic::Context,
            Digest,
            Digest,
            Sha256,
            OneCap,
            P,
            32,
            commonware_parallel::Sequential,
        >;

        let cfg = fixed_config::<OneCap>(partition, &context);
        let mut db = PartDb::<P>::init(context.child("populate"), cfg)
            .await
            .unwrap();

        // Commit 1: insert.
        let mut batch = db.new_batch();
        for i in 0u64..2000 {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::hash(&(i * 7).to_be_bytes());
            batch = batch.write(k, Some(v));
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();

        // Commit 2: update a third (inactivating their commit-1 ops) and delete a seventh.
        let mut batch = db.new_batch();
        for i in (0u64..2000).step_by(3) {
            let k = Sha256::hash(&i.to_be_bytes());
            let v = Sha256::hash(&((i + 1) * 11).to_be_bytes());
            batch = batch.write(k, Some(v));
        }
        for i in (1u64..2000).step_by(7) {
            let k = Sha256::hash(&i.to_be_bytes());
            batch = batch.write(k, None);
        }
        let merkleized = batch.merkleize(&db, None).await.unwrap();
        db.apply_batch(merkleized).await.unwrap();
        db.commit().await.unwrap();
        db.sync().await.unwrap();
        let root = db.root();
        drop(db);

        // Reopen at each worker count; all rebuild (snapshot + bitmap) from the same log and must match.
        for &workers in parallelisms {
            let mut cfg = fixed_config::<OneCap>(partition, &context);
            cfg.init_parallelism = match workers {
                0 => crate::qmdb::InitParallelism::Serial,
                n => {
                    crate::qmdb::InitParallelism::Workers(core::num::NonZeroUsize::new(n).unwrap())
                }
            };
            let ctx = context
                .child("reopen")
                .with_attribute("parallelism", workers);
            let db = PartDb::<P>::init(ctx, cfg).await.unwrap();
            assert_eq!(
                db.root(),
                root,
                "current root mismatch at P={P} init_parallelism={workers}"
            );
            drop(db);
        }
    }

    #[test_traced("WARN")]
    fn test_current_ordered_partitioned_p1_parallel_init_equivalence() {
        deterministic::Runner::default().start(|context| async move {
            check_current_parallel_init_equivalence::<1>(
                context,
                "current_parallel_equiv_p1",
                &[0, 1, 2, 4],
            )
            .await;
        });
    }

    #[test_traced("WARN")]
    fn test_current_ordered_partitioned_p2_parallel_init_equivalence() {
        deterministic::Runner::default().start(|context| async move {
            check_current_parallel_init_equivalence::<2>(
                context,
                "current_parallel_equiv_p2",
                &[0, 1, 2, 4],
            )
            .await;
        });
    }

    /// P=3 allocates `2^24` partition slots per index, so it is too memory-heavy for the default
    /// suite; run explicitly with `--ignored` (and ideally `--release`). Only serial and one
    /// offset-parallel reopen are checked.
    #[test_traced("WARN")]
    #[ignore]
    fn test_current_ordered_partitioned_p3_parallel_init_equivalence() {
        deterministic::Runner::default().start(|context| async move {
            check_current_parallel_init_equivalence::<3>(
                context,
                "current_parallel_equiv_p3",
                &[0, 2],
            )
            .await;
        });
    }
}

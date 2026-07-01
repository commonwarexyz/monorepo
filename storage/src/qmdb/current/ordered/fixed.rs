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
        E: Context,
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
            E: Context,
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

    /// The staged path (`stage` + `Staged::merkleize`) must produce a root byte-identical to an explicit
    /// `get_many` + `write` + `merkleize` over the current ordered layer, across updates, deletes
    /// (which fall back to normal mutations and rewrite predecessors via a snapshot-bucket scan),
    /// upserts, duplicate read slots, missing keys, and prefix-then-suffix expansion, rooted at the
    /// DB (D=0) and through one or two pending ancestors (D=1/D=2). `OneCap` forces collisions,
    /// stressing predecessor rewrites.
    #[test_traced("WARN")]
    pub fn test_current_ordered_fixed_staged_merkleize_parity() {
        fn key(i: u64) -> Digest {
            Sha256::hash(&i.to_be_bytes())
        }
        fn val(i: u64) -> Digest {
            Sha256::hash(&(i + 10000).to_be_bytes())
        }

        deterministic::Runner::default().start(|ctx| async move {
            let mut db = open_db(ctx.child("current"), "staged-parity".to_string()).await;

            let mut seed = db.new_batch();
            for i in 0..2000u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed = seed.merkleize(&db, None).await.unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            for depth in [0u8, 1u8, 2u8] {
                // Keep every uncommitted ancestor alive until the child is merkleized; speculative
                // batch Merkle lookups walk weak parent links for in-memory ancestor nodes.
                let mut stack = Vec::new();
                match depth {
                    0 => {}
                    1 => {
                        let mut p = db.new_batch();
                        for i in 0..50u64 {
                            p = p.write(key(i), Some(val(i + 1_000)));
                        }
                        for i in 100..110u64 {
                            p = p.write(key(i), None);
                        }
                        stack.push(p.merkleize(&db, None).await.unwrap());
                    }
                    2 => {
                        let mut grandparent = db.new_batch();
                        for i in 0..10u64 {
                            grandparent = grandparent.write(key(i), Some(val(i + 1_000)));
                        }
                        for i in 100..110u64 {
                            grandparent = grandparent.write(key(i), None);
                        }
                        let grandparent = grandparent.merkleize(&db, None).await.unwrap();

                        let mut p = grandparent.new_batch::<Sha256>();
                        for i in 20..30u64 {
                            p = p.write(key(i), Some(val(i + 2_000)));
                        }
                        let p = p.merkleize(&db, None).await.unwrap();
                        stack.push(grandparent);
                        stack.push(p);
                    }
                    _ => unreachable!("covered depths"),
                };
                let new_batch = || {
                    stack
                        .last()
                        .map_or_else(|| db.new_batch(), |p| p.new_batch::<Sha256>())
                };

                let read_keys = [key(5), key(6), key(9000), key(5), key(0), key(20), key(105)];
                let keys: Vec<&Digest> = read_keys.iter().collect();
                let indexed_updates = vec![
                    (0, Some(val(5_000))),
                    (2, Some(val(5_001))),
                    (3, Some(val(5_002))),
                    (4, Some(val(5_003))),
                    (5, None),
                    (6, Some(val(5_004))),
                ];
                let upserts = vec![
                    (key(7000), Some(val(6_000))),
                    (key(30), Some(val(6_001))),
                    (key(5), Some(val(6_002))),
                    (key(31), None),
                ];

                let mut explicit = new_batch();
                let explicit_values = explicit.get_many(&keys, &db).await.unwrap();
                for (slot, value) in &indexed_updates {
                    explicit = explicit.write(read_keys[*slot], *value);
                }
                for (k, v) in &upserts {
                    explicit = explicit.write(*k, *v);
                }
                let explicit_root = explicit.merkleize(&db, None).await.unwrap().root();

                let (staged_values, mut staged) = new_batch().stage(&keys, &db).await.unwrap();
                for (slot, value) in &indexed_updates {
                    staged = staged.write(read_keys[*slot], *value);
                }
                for (k, v) in &upserts {
                    staged = staged.write(*k, *v);
                }
                let staged_root = staged.merkleize(&db, None).await.unwrap().root();

                assert_eq!(
                    explicit_values, staged_values,
                    "value mismatch at depth={depth}"
                );
                assert_eq!(explicit_root, staged_root, "root mismatch at depth={depth}");

                let split = 3;
                let (mut expanded_values, mut staged) =
                    new_batch().stage(&keys[..split], &db).await.unwrap();
                expanded_values.extend(staged.read(&keys[split..], &db).await.unwrap());
                for (slot, value) in &indexed_updates {
                    staged = staged.write(read_keys[*slot], *value);
                }
                for (k, v) in &upserts {
                    staged = staged.write(*k, *v);
                }
                let expanded_root = staged.merkleize(&db, None).await.unwrap().root();

                assert_eq!(
                    explicit_values, expanded_values,
                    "expanded value mismatch at depth={depth}"
                );
                assert_eq!(
                    explicit_root, expanded_root,
                    "expanded root mismatch at depth={depth}"
                );

                let planned = val(7_000);
                let duplicate_update = val(7_001);
                let (_, mut staged) = new_batch().stage(&keys[..1], &db).await.unwrap();
                staged = staged.write(read_keys[0], Some(planned));
                let reread_values = staged.read(&keys[..1], &db).await.unwrap();
                assert_eq!(
                    reread_values[0],
                    Some(planned),
                    "staged reads must observe pending writes"
                );

                let duplicate_root = staged
                    .write(read_keys[0], Some(duplicate_update))
                    .merkleize(&db, None)
                    .await
                    .unwrap()
                    .root();
                let expected_duplicate_root = new_batch()
                    .write(read_keys[0], Some(planned))
                    .write(read_keys[0], Some(duplicate_update))
                    .merkleize(&db, None)
                    .await
                    .unwrap()
                    .root();
                assert_eq!(
                    expected_duplicate_root, duplicate_root,
                    "re-read and re-written keys keep normal last-write-wins semantics"
                );
            }
        });
    }
}

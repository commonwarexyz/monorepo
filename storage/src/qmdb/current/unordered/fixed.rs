//! An _unordered_ variant of a [crate::qmdb::current] authenticated database optimized for
//! fixed-size values.
//!
//! This variant does not maintain key ordering, so it cannot generate exclusion proofs. Use
//! [crate::qmdb::current::ordered::fixed] if exclusion proofs are required.
//!
//! See [Db] for the main database type.

pub use super::db::KeyValueProof;
use crate::{
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    merkle::{Graftable, Location},
    qmdb::{
        any::{unordered::fixed::Operation, value::FixedEncoding, FixedValue},
        current::FixedConfig as Config,
        Error,
    },
    translator::Translator,
    Context,
};
use commonware_cryptography::Hasher;
use commonware_parallel::Strategy;
use commonware_utils::Array;

/// A specialization of [super::db::Db] for unordered key spaces and fixed-size values.
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
    /// Initializes a [Db] authenticated database from the given `config`.
    /// The configured [`Strategy`] is used to parallelize merkleization.
    pub async fn init(context: E, config: Config<T, S>) -> Result<Self, Error<F>> {
        crate::qmdb::current::init(context, config).await
    }
}

pub mod partitioned {
    //! A partitioned variant of [super] that uses a partitioned index for the snapshot.
    //!
    //! See [crate::qmdb::any::unordered::fixed::partitioned] for details on partitioned indices and
    //! when to use them.

    use super::*;
    use crate::index::partitioned::unordered::Index;

    /// A partitioned variant of [super::Db].
    ///
    /// The const generic `P` specifies the number of prefix bytes used for partitioning:
    /// - `P = 1`: 256 partitions
    /// - `P = 2`: 65,536 partitions
    /// - `P = 3`: ~16 million partitions
    pub type Db<F, E, K, V, H, T, const P: usize, const N: usize, S> =
        crate::qmdb::current::unordered::db::Db<
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
        qmdb::current::{tests::fixed_config, unordered::tests as shared},
        translator::TwoCap,
    };
    use commonware_cryptography::{sha256::Digest, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Metrics, Runner as _, Supervisor as _};
    use commonware_utils::test_rng_seeded;
    use rand::RngCore as _;
    use std::collections::HashMap;

    /// A type alias for the concrete [Db] type used in these unit tests.
    type CurrentTest = Db<
        mmr::Family,
        deterministic::Context,
        Digest,
        Digest,
        Sha256,
        TwoCap,
        32,
        commonware_parallel::Sequential,
    >;

    /// Return a [Db] database initialized with a fixed config.
    async fn open_db(context: deterministic::Context, partition_prefix: String) -> CurrentTest {
        let cfg = fixed_config::<TwoCap>(&partition_prefix, &context);
        CurrentTest::init(context, cfg).await.unwrap()
    }

    #[test_traced("INFO")]
    pub fn test_current_unordered_fixed_metrics() {
        deterministic::Runner::default().start(|ctx| async move {
            let mut db = open_db(ctx.child("current"), "metrics".to_string()).await;
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(2u8);
            let batch = db
                .new_batch()
                .write(key, Some(value))
                .merkleize(&db, None)
                .await
                .unwrap();
            db.apply_batch(batch).await.unwrap();
            assert_eq!(db.get(&key).await.unwrap(), Some(value));
            db.sync().await.unwrap();
            db.prune(db.sync_boundary()).await.unwrap();

            let metrics = ctx.encode();
            for expected in [
                "current_apply_batch_calls_total 1",
                "current_sync_calls_total 1",
                "current_prune_calls_total 1",
                "current_pruned_chunks 0",
                "current_sync_boundary 0",
                "current_apply_batch_duration_count 1",
                "current_sync_duration_count 1",
                "current_prune_duration_count 1",
                "current_any_get_calls_total 1",
                "current_any_apply_batch_calls_total 1",
            ] {
                assert!(metrics.contains(expected), "missing {expected}\n{metrics}");
            }
            assert!(!metrics.contains("current_get_calls_total"));
        });
    }

    /// Reads on a batch must not perturb `merkleize`: the root must match a write-only batch's
    /// `merkleize`, both rooted at the DB (D=0) and through one pending ancestor (D=1).
    #[test_traced("WARN")]
    pub fn test_current_unordered_fixed_read_merkleize_parity() {
        fn key(i: u64) -> Digest {
            Sha256::hash(&i.to_be_bytes())
        }
        fn val(i: u64) -> Digest {
            Sha256::hash(&(i + 10000).to_be_bytes())
        }

        deterministic::Runner::default().start(|ctx| async move {
            let mut db = open_db(ctx.child("current"), "fused-parity".to_string()).await;

            let mut seed = db.new_batch();
            for i in 0..2000u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed = seed.merkleize(&db, None).await.unwrap();
            db.apply_batch(seed).await.unwrap();
            db.commit().await.unwrap();

            let make = |salt: u64| -> Vec<(Digest, Option<Digest>)> {
                let mut rng = test_rng_seeded(salt);
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
                let mut m: HashMap<Digest, Option<Digest>> = HashMap::new();
                for (k, v) in out {
                    m.insert(k, v);
                }
                m.into_iter().collect()
            };

            for depth in [0u8, 1u8] {
                let parent = if depth == 1 {
                    let mut p = db.new_batch();
                    for (k, v) in make(900) {
                        p = p.write(k, v);
                    }
                    Some(p.merkleize(&db, None).await.unwrap())
                } else {
                    None
                };

                let muts = make(depth as u64 + 1);
                let new_batch = || {
                    parent
                        .as_ref()
                        .map_or_else(|| db.new_batch(), |p| p.new_batch::<Sha256>())
                };

                let mut nb = new_batch();
                for (k, v) in &muts {
                    nb = nb.write(*k, *v);
                }
                let normal_root = nb.merkleize(&db, None).await.unwrap().root();

                let keys: Vec<&Digest> = muts.iter().map(|(k, _)| k).collect();
                let mut fb = new_batch();
                let values = fb.get_many(&keys, &db).await.unwrap();
                let plain = new_batch().get_many(&keys, &db).await.unwrap();
                assert_eq!(values, plain, "value mismatch at depth={depth}");
                for (k, v) in &muts {
                    fb = fb.write(*k, *v);
                }
                let fused_root = fb.merkleize(&db, None).await.unwrap().root();
                assert_eq!(normal_root, fused_root, "root mismatch at depth={depth}");
            }
        });
    }

    /// The staged path (`stage` + `Staged::merkleize`) must produce a root byte-identical to an explicit
    /// `get_many` + `write` + `merkleize` over the current layer, across updates, deletes, upserts,
    /// duplicate read slots, missing keys, and prefix-then-suffix expansion, rooted at the DB
    /// (D=0) and through one or two pending ancestors (D=1/D=2). This guards the current-layer
    /// threading of `bitmap_parent`/`grafted_parent`, global read-index assignment across `expand`,
    /// and `compute_current_layer` for non-empty staged updates.
    #[test_traced("WARN")]
    pub fn test_current_unordered_fixed_staged_merkleize_parity() {
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

            // At D=1, one pending ancestor updates keys 0..50 and deletes 100..110. At D=2,
            // the grandparent updates keys 0..10 and deletes 100..110 while the parent updates
            // keys 20..30. The read set below then resolves through both ancestors, while
            // key(60) still falls through to the committed DB and exercises staged cache reuse
            // behind a stacked batch.
            // Keep every uncommitted ancestor alive until the child is merkleized; speculative
            // batch Merkle lookups walk weak parent links for in-memory ancestor nodes.
            for depth in [0u8, 1u8, 2u8] {
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

                // Read set: key(5) duplicated at slots 0/3, read-only key(6), missing key(9000),
                // key(60) that always remains committed, and keys 0/20/105 that resolve through
                // ancestors when depth > 0.
                let read_keys = [
                    key(5),
                    key(6),
                    key(9000),
                    key(5),
                    key(0),
                    key(20),
                    key(60),
                    key(105),
                ];
                let keys: Vec<&Digest> = read_keys.iter().collect();
                // (read_slot, Some=upsert | None=delete).
                let indexed_updates = vec![
                    (0, Some(val(5_000))),
                    (2, Some(val(5_001))),
                    (3, Some(val(5_002))),
                    (4, Some(val(5_003))),
                    (5, None),
                    (6, Some(val(5_004))),
                    (7, Some(val(5_005))),
                ];
                // Upserts for unread keys: create, update existing, override key(5), delete existing.
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

                let (staged_values, staged) = new_batch().stage(&keys, &db).await.unwrap();
                let staged_root = staged
                    .merkleize(indexed_updates.clone(), upserts.clone(), None, &db)
                    .await
                    .unwrap()
                    .root();

                assert_eq!(
                    explicit_values, staged_values,
                    "value mismatch at depth={depth}"
                );
                assert_eq!(explicit_root, staged_root, "root mismatch at depth={depth}");

                let split = 3;
                let (mut expanded_values, staged) =
                    new_batch().stage(&keys[..split], &db).await.unwrap();
                let (range, suffix_values, staged) =
                    staged.expand(&keys[split..], &db).await.unwrap();
                assert_eq!(range, split..keys.len());
                expanded_values.extend(suffix_values);
                let expanded_root = staged
                    .merkleize(indexed_updates.clone(), upserts.clone(), None, &db)
                    .await
                    .unwrap()
                    .root();

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
                let (first_values, staged) = new_batch().stage(&keys[..1], &db).await.unwrap();
                let (duplicate_range, duplicate_values, staged) =
                    staged.expand(&keys[..1], &db).await.unwrap();
                assert_eq!(duplicate_range, 1..2);
                assert_eq!(
                    first_values[0], duplicate_values[0],
                    "duplicate expansion must assign a new slot without changing the base read"
                );
                assert_ne!(
                    duplicate_values[0],
                    Some(planned),
                    "expand must not observe values computed for earlier staged slots"
                );

                let duplicate_root = staged
                    .merkleize(
                        vec![
                            (0, Some(planned)),
                            (duplicate_range.start, Some(duplicate_update)),
                        ],
                        Vec::new(),
                        None,
                        &db,
                    )
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
                    "duplicate expanded slots should use normal update-order semantics"
                );
            }
        });
    }

    /// The sync boundary recorded from a merkleized batch must match the boundary the database
    /// reports once that batch is applied. These can diverge if the batch boundary is derived from
    /// physical bitmap pruning rather than the batch's declared inactivity floor, because the floor
    /// can advance past a chunk even when pruning has not run. Reopening is exercised afterward as a
    /// persistence sanity check; it must not move the boundary.
    #[test_traced("INFO")]
    pub fn test_merkleized_batch_sync_boundary_matches_db() {
        deterministic::Runner::default().start(|ctx| async move {
            let partition = "batch-boundary-match".to_string();
            let mut db = open_db(ctx.child("current"), partition.clone()).await;

            let key = Sha256::fill(1u8);
            let mut last_batch_boundary = mmr::Location::new(0);
            for i in 0..300u64 {
                let value = Sha256::hash(&i.to_be_bytes());
                let batch = db
                    .new_batch()
                    .write(key, Some(value))
                    .merkleize(&db, None)
                    .await
                    .unwrap();
                last_batch_boundary = batch.sync_boundary();
                db.apply_batch(batch).await.unwrap();
            }
            db.sync().await.unwrap();

            // The boundary must have advanced, otherwise the inactivity floor never crossed a chunk
            // and the equality below would hold trivially.
            let db_boundary = db.sync_boundary();
            assert!(
                *db_boundary > 0,
                "inactivity floor never crossed a chunk; add more commits"
            );

            // The headline invariant: the boundary the batch advertised equals the boundary the DB
            // reports after applying that batch.
            assert_eq!(
                last_batch_boundary, db_boundary,
                "batch boundary diverged from applied db boundary"
            );

            // Reopening must not move the boundary.
            drop(db);
            let reopened = open_db(ctx.child("reopen"), partition).await;
            assert_eq!(
                reopened.sync_boundary(),
                last_batch_boundary,
                "reopened db boundary disagrees with the boundary recorded from the last merkleized batch"
            );
            reopened.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        shared::test_verify_proof_over_bits_in_uncommitted_chunk(open_db);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_range_proofs() {
        shared::test_range_proofs(open_db);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_key_value_proof() {
        shared::test_key_value_proof(open_db);
    }

    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        shared::test_proving_repeated_updates(open_db);
    }
}

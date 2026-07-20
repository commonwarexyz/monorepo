//! An _unordered_ variant of a [crate::qmdb::current] authenticated database optimized for
//! fixed-size values.
//!
//! This variant does not maintain key ordering, so it cannot generate exclusion proofs. Use
//! [crate::qmdb::current::ordered::fixed] if exclusion proofs are required.
//!
//! See [Db] for the main database type.

pub use super::db::KeyValueProof;
use crate::{
    Context,
    index::unordered::Index,
    journal::contiguous::fixed::Journal,
    merkle::{Graftable, Location},
    qmdb::{
        Error,
        any::{FixedValue, unordered::fixed::Operation, value::FixedEncoding},
        current::FixedConfig as Config,
    },
    translator::Translator,
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
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::test_traced;
    use commonware_runtime::{Metrics, Runner as _, Supervisor as _, deterministic};
    use commonware_utils::TestRng;
    use rand::Rng as _;
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
            let db = open_db(ctx.child("current"), "metrics".to_string()).await;
            let key = Sha256::fill(1u8);
            let value = Sha256::fill(2u8);
            let batch = db
                .new_batch()
                .write(key, Some(value))
                .merkleize(&db, None)
                .await
                .unwrap();
            let (db, _) = db.apply_batch(batch).await.unwrap();
            assert_eq!(db.get(&key).await.unwrap(), Some(value));
            let db = db.sync().await.unwrap();
            let boundary = db.sync_boundary();
            let _db = db.prune(boundary).await.unwrap();

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
            let db = open_db(ctx.child("current"), "fused-parity".to_string()).await;

            let mut seed = db.new_batch();
            for i in 0..2000u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed = seed.merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

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

    crate::qmdb::current::tests::staged_merkleize_parity_test!(
        test_current_unordered_fixed_staged_merkleize_parity,
        open_db
    );

    /// A staged read that resolved in a grandparent's diff must survive that grandparent
    /// committing and being freed before `Staged::merkleize`, through the current layer:
    /// the re-derived bases feed the grafted bitmap and `compute_current_layer`, so the
    /// staged root must match the explicit path's and the full lifecycle must read back.
    /// Mirrors the `any::unordered::variable` coverage of this interleaving (see
    /// `StagedLoc`).
    #[test_traced("WARN")]
    pub fn test_current_unordered_fixed_staged_ancestor_commit_before_merkleize() {
        fn key(i: u64) -> Digest {
            Sha256::hash(&i.to_be_bytes())
        }
        fn val(i: u64) -> Digest {
            Sha256::hash(&(i + 10000).to_be_bytes())
        }

        deterministic::Runner::default().start(|ctx| async move {
            let db = open_db(ctx.child("current"), "staged-ancestor".to_string()).await;

            // Committed base state, so the grandparent's write of key(0) supersedes a
            // committed location. Its create of key(100) supersedes none.
            let mut seed = db.new_batch();
            for i in 0..8u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed = seed.merkleize(&db, None).await.unwrap();
            let (db, _) = db.apply_batch(seed).await.unwrap();
            let db = db.commit().await.unwrap();

            // Grandparent -> parent chain. The parent touches neither staged key, so the
            // staged reads resolve in the grandparent's diff.
            let grandparent = db
                .new_batch()
                .write(key(0), Some(val(1_000)))
                .write(key(100), Some(val(1_001)))
                .merkleize(&db, None)
                .await
                .unwrap();
            let parent = grandparent
                .new_batch::<Sha256>()
                .write(key(1), Some(val(1_002)))
                .merkleize(&db, None)
                .await
                .unwrap();

            let read_keys = [key(0), key(100)];
            let keys: Vec<&Digest> = read_keys.iter().collect();
            let (values, staged) = parent
                .new_batch::<Sha256>()
                .stage(&keys, &db)
                .await
                .unwrap();
            assert_eq!(values, vec![Some(val(1_000)), Some(val(1_001))]);

            // Commit and free the grandparent: the staged resolutions' locations migrate
            // into the committed region, retiring their recorded bases.
            let (db, _) = db.apply_batch(grandparent).await.unwrap();

            let updates = vec![(0, Some(val(2_000))), (1, Some(val(2_001)))];
            let staged = staged
                .merkleize(updates, Vec::new(), None, &db)
                .await
                .unwrap();

            // The explicit path over the same post-commit state must agree.
            let explicit_root = parent
                .new_batch::<Sha256>()
                .write(key(0), Some(val(2_000)))
                .write(key(100), Some(val(2_001)))
                .merkleize(&db, None)
                .await
                .unwrap()
                .root();
            assert_eq!(staged.root(), explicit_root);

            let (db, _) = db.apply_batch(parent).await.unwrap();
            let (db, _) = db.apply_batch(staged).await.unwrap();
            let db = db.commit().await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(2_000)));
            assert_eq!(db.get(&key(100)).await.unwrap(), Some(val(2_001)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1_002)));
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
                (db, _) = db.apply_batch(batch).await.unwrap();
            }
            let db = db.sync().await.unwrap();

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

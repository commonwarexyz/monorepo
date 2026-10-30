//! An _ordered_ variant of a [crate::qmdb::current] authenticated database optimized for fixed-size
//! values.
//!
//! This variant maintains the lexicographic-next active key for each active key, enabling exclusion
//! proofs (proving a key is currently inactive). Use [crate::qmdb::current::unordered::fixed] if
//! exclusion proofs are not needed.
//!
//! See [Db] for the main database type and
//! [ExclusionProof](super::proof::constant::ExclusionProof) for proving key inactivity.

use crate::{
    Context,
    index::ordered::Index,
    journal::contiguous::fixed::Journal,
    merkle::{Graftable, Location},
    qmdb::{
        Error,
        any::{FixedValue, ordered::fixed::Operation, value::FixedEncoding},
        current::FixedConfig as Config,
    },
    translator::OrderedTranslator,
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
    E: Context + Spawner,
    K: Array,
    V: FixedValue,
    H: Hasher,
    T: OrderedTranslator,
    const N: usize,
    S: Strategy,
> Db<F, E, K, V, H, T, N, S>
{
    /// Initializes a [Db] from the given `config`.
    /// The configured [`Strategy`] is used to parallelize merkleization.
    /// `Some(max_size)` selects the latest retained commit with at most `max_size` operations,
    /// while `None` selects the latest retained state. Initialization fails with
    /// [Error::HistoricalFloorPruned] if the log or bitmap has pruned the commit's inactivity floor,
    /// and with [Error::Journal] ([`crate::journal::Error::ItemPruned`]) if the selected commit
    /// itself has been pruned.
    pub async fn init(
        context: E,
        config: Config<T, S>,
        max_size: Option<Location<F>>,
    ) -> Result<Self, Error<F>> {
        crate::qmdb::current::init(context, config, max_size).await
    }
}

pub mod partitioned {
    //! A variant of [super] that uses a partitioned key index.

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
        E: Context + Spawner,
        K: Array,
        V: FixedValue,
        H: Hasher,
        T: OrderedTranslator,
        const P: usize,
        const N: usize,
        S: Strategy,
    > Db<F, E, K, V, H, T, P, N, S>
    {
        /// Initializes a [Db] authenticated database from the given `config`.
        /// `Some(max_size)` selects the latest retained commit with at most `max_size` operations,
        /// while `None` selects the latest retained state. Initialization fails with
        /// [Error::HistoricalFloorPruned] if the log or bitmap has pruned the commit's inactivity
        /// floor, and with [Error::Journal] ([`crate::journal::Error::ItemPruned`]) if the selected
        /// commit itself has been pruned.
        pub async fn init(
            context: E,
            config: Config<T, S, core::num::NonZeroUsize>,
            max_size: Option<Location<F>>,
        ) -> Result<Self, Error<F>> {
            crate::qmdb::current::init(context, config, max_size).await
        }
    }
}

#[cfg(test)]
pub mod test {
    use super::*;
    use crate::{
        merkle::Graftable,
        mmb, mmr,
        qmdb::{
            Error,
            any::batch::{DiffEntry, Slot, StagedLoc, lookup_sorted},
            current::{
                ordered::tests as shared,
                tests::{fixed_config, fixed_config_partitioned},
            },
            floor::Proportional,
        },
        translator::OneCap,
    };
    use commonware_cryptography::{Sha256, sha256::Digest};
    use commonware_macros::{boxed, test_traced};
    use commonware_parallel::Sequential;
    use commonware_runtime::{Runner as _, Supervisor as _, deterministic};
    use commonware_utils::{
        NZU64,
        bitmap::{Prunable as BitMap, Readable as _},
    };

    /// A type alias for the concrete [Db] type used in these unit tests.
    type CurrentTest<F = mmr::Family> =
        Db<F, deterministic::Context, Digest, Digest, Sha256, OneCap, 32, Sequential>;

    /// Return an [Db] database initialized with a fixed config.
    async fn open_db<F: Graftable>(
        context: deterministic::Context,
        partition_prefix: String,
    ) -> CurrentTest<F> {
        let cfg = fixed_config::<OneCap>(&partition_prefix);
        CurrentTest::<F>::init(context, cfg, None).await.unwrap()
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_verify_proof_over_bits_in_uncommitted_chunk() {
        shared::test_verify_proof_over_bits_in_uncommitted_chunk(open_db::<mmr::Family>);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_range_proofs() {
        shared::test_range_proofs(open_db::<mmr::Family>);
    }

    /// Regression test: requesting a range proof for a location in a pruned bitmap chunk
    /// must return `Error::OperationPruned`, not panic in the bitmap accessor.
    #[test_traced("DEBUG")]
    pub fn test_range_proof_returns_error_on_pruned_chunks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let partition = "range-proofs-pruned".to_string();
            let mut db = open_db::<mmr::Family>(context.child("db"), partition).await;

            let chunk_bits = BitMap::<32>::CHUNK_SIZE_BITS;

            // Repeatedly update the same key to generate many inactive operations,
            // pushing the inactivity floor past at least one full bitmap chunk.
            let key = Sha256::fill(0x11);
            for i in 0..chunk_bits + 10 {
                let value = Sha256::hash(&[&i.to_be_bytes()]);
                let merkleized = db
                    .new_batch()
                    .write(key, Some(value))
                    .merkleize(&db, None, &mut Proportional)
                    .await
                    .unwrap();
                db = db.apply_batch(merkleized).await.unwrap();
            }

            // Prune the database
            let boundary = db.sync_boundary();
            let db = db.prune(boundary).await.unwrap();

            assert!(
                db.any.bitmap.pruned_chunks() > 0,
                "expected at least one pruned chunk"
            );

            // Requesting a range proof at location 0 (in the pruned range) should return
            // OperationPruned, not panic.
            let result = db.range_proof(Location::new(0), NZU64!(1)).await;
            assert!(
                matches!(result, Err(Error::OperationPruned(_))),
                "expected OperationPruned, got {result:?}"
            );

            db.destroy().await.unwrap();
        });
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_key_value_proof() {
        shared::test_key_value_proof(open_db::<mmr::Family>);
    }

    #[test_traced("DEBUG")]
    fn test_current_db_dynamic_key_value_proof_mmb() {
        shared::test_key_value_proof(open_db::<mmb::Family>);
    }

    #[test_traced("DEBUG")]
    fn test_current_db_dynamic_exclusion_proofs_mmb() {
        shared::test_exclusion_proofs(open_db::<mmb::Family>);
    }

    #[test_traced("DEBUG")]
    fn test_current_db_dynamic_inactive_proof_mmb() {
        shared::test_verify_proof_over_bits_in_uncommitted_chunk(open_db::<mmb::Family>);
    }

    #[test_traced("WARN")]
    pub fn test_current_db_proving_repeated_updates() {
        shared::test_proving_repeated_updates(open_db::<mmr::Family>);
    }

    #[test_traced("DEBUG")]
    pub fn test_current_db_exclusion_proofs() {
        shared::test_exclusion_proofs(open_db::<mmr::Family>);
    }

    crate::qmdb::current::tests::staged_merkleize_parity_test!(
        test_current_ordered_fixed_staged_merkleize_parity,
        open_db::<mmr::Family>
    );

    /// A staged read that resolved in a grandparent's diff must survive that grandparent being
    /// applied and dropped before `Staged::merkleize`, through the current layer. The re-derived
    /// bases feed the grafted bitmap and `compute_current_layer`, and the cached successors feed
    /// the rewritten links. The staged root must therefore match the explicit path's, and the full
    /// lifecycle must read back. Mirrors the `any::ordered::variable` coverage of this interleaving
    /// (see `StagedLoc`).
    #[test_traced("WARN")]
    pub fn test_current_ordered_fixed_staged_ancestor_applied_before_merkleize() {
        fn key(i: u64) -> Digest {
            Sha256::hash(&[&i.to_be_bytes()])
        }
        fn val(i: u64) -> Digest {
            Sha256::hash(&[&(i + 10000).to_be_bytes()])
        }

        deterministic::Runner::default().start(|ctx| async move {
            let db =
                open_db::<mmr::Family>(ctx.child("current"), "staged-ancestor".to_string()).await;

            // Committed base state, so the grandparent's write of key(0) supersedes a
            // committed location. Its create of key(100) supersedes none.
            let mut seed = db.new_batch();
            for i in 0..8u64 {
                seed = seed.write(key(i), Some(val(i)));
            }
            let seed = seed.merkleize(&db, None, &mut Proportional).await.unwrap();
            let db = db.apply_batch(seed).await.unwrap().commit().await.unwrap();

            // Grandparent -> parent chain. The parent touches neither staged key, so the
            // staged reads resolve in the grandparent's diff.
            let grandparent = db
                .new_batch()
                .write(key(0), Some(val(1_000)))
                .write(key(100), Some(val(1_001)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();
            let parent = grandparent
                .new_batch::<Sha256>()
                .write(key(1), Some(val(1_002)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap();

            // Stage both keys through the parent. Each must resolve in the grandparent's diff.
            let read_keys = [key(0), key(100)];
            let keys: Vec<&Digest> = read_keys.iter().collect();
            let (values, staged) = parent
                .new_batch::<Sha256>()
                .stage(&keys, &db)
                .await
                .unwrap();
            assert_eq!(values, vec![Some(val(1_000)), Some(val(1_001))]);
            for (resolved, key) in staged.resolved_locs().into_iter().zip(&read_keys) {
                let written =
                    lookup_sorted(grandparent.inner.diff.as_slice(), key).and_then(DiffEntry::loc);
                assert!(
                    matches!(
                        resolved,
                        Some(StagedLoc::Ancestor { loc, .. }) if Some(loc) == written
                    ),
                    "a staged read must resolve in the grandparent's diff"
                );
            }

            // Apply and drop the grandparent, so the staged resolutions' locations migrate
            // into the database region, retiring their recorded bases.
            let db = db.apply_batch(grandparent).await.unwrap();

            // Merkleize the staged writes over the applied state.
            let slots = vec![Slot::Put(val(2_000)), Slot::Put(val(2_001))];
            let staged = staged
                .merkleize(slots, Vec::new(), None, &db, &mut Proportional)
                .await
                .unwrap();

            // The explicit path over the same applied state must agree.
            let explicit_root = parent
                .new_batch::<Sha256>()
                .write(key(0), Some(val(2_000)))
                .write(key(100), Some(val(2_001)))
                .merkleize(&db, None, &mut Proportional)
                .await
                .unwrap()
                .root();
            assert_eq!(staged.root(), explicit_root);

            // Apply the rest of the chain and read the writes back.
            let db = db.apply_batch(parent).await.unwrap();
            let db = db.apply_batch(staged).await.unwrap();
            let db = db.commit().await.unwrap();

            assert_eq!(db.get(&key(0)).await.unwrap(), Some(val(2_000)));
            assert_eq!(db.get(&key(100)).await.unwrap(), Some(val(2_001)));
            assert_eq!(db.get(&key(1)).await.unwrap(), Some(val(1_002)));
        });
    }

    /// Build a `P`-partitioned current db with churny ops across two commits (so the second commit's
    /// updates and deletes inactivate locations from the first), prune it, then assert that
    /// reopening it at a range of worker counts reconstructs the identical root and key-value
    /// state. Unlike the `any` equivalence tests, the current root commits to the activity bitmap,
    /// so this exercises the parallel build's bitmap reconstruction (`for_each_value` +
    /// last-commit) over a pruned prefix, not just the key index and MMR.
    #[boxed]
    async fn check_current_parallel_init_equivalence<const P: usize>(
        context: deterministic::Context,
        partition: &'static str,
        concurrency_sweep: &[usize],
    ) {
        type PartDb<const P: usize, S> = partitioned::Db<
            mmr::Family,
            deterministic::Context,
            Digest,
            Digest,
            Sha256,
            OneCap,
            P,
            32,
            S,
        >;

        /// The value each key holds after the two commits below.
        fn expected_value(i: u64) -> Option<Digest> {
            if i % 7 == 1 {
                None
            } else if i.is_multiple_of(3) {
                Some(Sha256::hash(&[&((i + 1) * 11).to_be_bytes()]))
            } else {
                Some(Sha256::hash(&[&(i * 7).to_be_bytes()]))
            }
        }

        let cfg = fixed_config_partitioned::<OneCap>(partition);
        let db = PartDb::<P, Sequential>::init(context.child("populate"), cfg, None)
            .await
            .unwrap();

        // Commit 1: insert.
        let mut batch = db.new_batch();
        for i in 0u64..2000 {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            let v = Sha256::hash(&[&(i * 7).to_be_bytes()]);
            batch = batch.write(k, Some(v));
        }
        let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        let db = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        // Commit 2: update a third (inactivating their commit-1 ops) and delete a seventh.
        let mut batch = db.new_batch();
        for i in (0u64..2000).step_by(3) {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            let v = Sha256::hash(&[&((i + 1) * 11).to_be_bytes()]);
            batch = batch.write(k, Some(v));
        }
        for i in (1u64..2000).step_by(7) {
            let k = Sha256::hash(&[&i.to_be_bytes()]);
            batch = batch.write(k, None);
        }
        let merkleized = batch.merkleize(&db, None, &mut Proportional).await.unwrap();
        let db = db.apply_batch(merkleized).await.unwrap();
        let db = db.commit().await.unwrap();

        // Prune so the reopens rebuild the grafted root over a bitmap with a pruned prefix.
        let boundary = db.sync_boundary();
        let db = db.prune(boundary).await.unwrap();
        let db = db.sync().await.unwrap();
        let root = db.root();
        drop(db);

        // Reopen at each concurrency. All rebuild (index + bitmap) from the same log and must
        // match the original root and serve the expected value for every key.
        for &concurrency in concurrency_sweep {
            let mut cfg = fixed_config_partitioned::<OneCap>(partition);
            cfg.init_concurrency = core::num::NonZeroUsize::new(concurrency).unwrap();
            let ctx = context
                .child("reopen")
                .with_attribute("concurrency", concurrency);
            let db = PartDb::<P, Sequential>::init(ctx, cfg, None).await.unwrap();
            assert_eq!(
                db.root(),
                root,
                "current root mismatch at P={P} concurrency={concurrency}"
            );
            for i in 0u64..2000 {
                let k = Sha256::hash(&[&i.to_be_bytes()]);
                assert_eq!(
                    db.get(&k).await.unwrap(),
                    expected_value(i),
                    "value mismatch for key {i}"
                );
            }
            drop(db);
        }
    }

    #[test_traced("WARN")]
    fn test_current_ordered_partitioned_p1_parallel_init_equivalence() {
        deterministic::Runner::default().start(|context| async move {
            check_current_parallel_init_equivalence::<1>(
                context,
                "current_parallel_equiv_p1",
                &[1, 2, 3, 5],
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
                &[1, 2, 3, 5],
            )
            .await;
        });
    }

    /// P=3 allocates `2^24` partition slots per index, so it is too memory-heavy for the default
    /// suite. Run it explicitly with `--ignored` (and ideally `--release`). Only serial and one
    /// offset-parallel reopen are checked.
    #[test_traced("WARN")]
    #[ignore]
    fn test_current_ordered_partitioned_p3_parallel_init_equivalence() {
        deterministic::Runner::default().start(|context| async move {
            check_current_parallel_init_equivalence::<3>(
                context,
                "current_parallel_equiv_p3",
                &[1, 3],
            )
            .await;
        });
    }
}

//! An MMR backed by a fixed-item-length journal.
//!
//! A [crate::journal] is used to store all unpruned MMR nodes, and a [crate::metadata] store is
//! used to preserve digests required for root and proof generation that would have otherwise been
//! pruned.
//!
//! This module is a thin wrapper around the generic `Merkle` type, specialized for the
//! MMR [Family]. It re-exports [Config], [SyncConfig], and the append-only
//! [`UnmerkleizedBatch`] wrapper from `merkle::full`. Async proof methods (`proof`,
//! `range_proof`, `historical_proof`, `historical_range_proof`) and the `Storage<F>` impl are
//! provided by the generic `Merkle` in `merkle::full`.

/// Configuration for a journal-backed MMR.
pub use crate::merkle::full::Config;
pub use crate::merkle::full::UnmerkleizedBatch;
use crate::merkle::mmr::Family;
use commonware_parallel::Sequential;

/// Configuration for initializing a full MMR for synchronization.
pub type SyncConfig<D, S = Sequential> = crate::merkle::full::SyncConfig<Family, D, S>;

/// A MMR backed by a fixed-item-length journal.
pub type Mmr<E, D, S = Sequential> = crate::merkle::full::Merkle<Family, E, D, S>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        merkle::{conformance::build_test_mmr, Family as _},
        mmr::{mem, Error, Location, Position, StandardHasher as Standard},
    };
    use commonware_cryptography::{sha256::Digest, Hasher, Sha256};
    use commonware_macros::test_traced;
    use commonware_parallel::Sequential;
    use commonware_runtime::{
        buffer::paged::CacheRef, deterministic, BufferPooler, Metrics, Runner,
    };
    use commonware_utils::{non_empty_range, NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    fn test_digest(v: usize) -> Digest {
        Sha256::hash(&v.to_be_bytes())
    }

    const PAGE_SIZE: NonZeroU16 = NZU16!(111);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(5);

    fn test_config(pooler: &impl BufferPooler) -> Config {
        Config {
            journal_partition: "journal-partition".into(),
            metadata_partition: "metadata-partition".into(),
            items_per_blob: NZU64!(7),
            write_buffer: NZUsize!(1024),
            strategy: Sequential,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
        }
    }

    /// Test that the full MMR produces the same root as the in-memory reference.
    #[test]
    fn test_full_mmr_batched_root() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const NUM_ELEMENTS: u64 = 199;
            let hasher: Standard<Sha256> = Standard::new();
            let test_mmr = mem::Mmr::new();
            let test_mmr = build_test_mmr(&hasher, test_mmr, NUM_ELEMENTS);
            let expected_root = test_mmr.root(&hasher, 0).unwrap();

            let mut mmr = Mmr::init(
                context.clone(),
                &Standard::<Sha256>::new(),
                test_config(&context),
            )
            .await
            .unwrap();

            let mut batch = mmr.new_batch();
            for i in 0u64..NUM_ELEMENTS {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr.apply_batch(&batch).unwrap();
            assert_eq!(mmr.root(&hasher, 0).unwrap(), expected_root);

            mmr.destroy().await.unwrap();
        });
    }

    #[test]
    fn test_full_mmr_peek_root_empty_journal() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();
            let peek =
                Mmr::<_, Digest>::peek_root(context.clone(), test_config(&context), &hasher, 0)
                    .await
                    .unwrap();

            let empty_root = mem::Mmr::new().root(&hasher, 0).unwrap();
            assert_eq!(peek, Some((Location::new(0), Location::new(0), empty_root)));
        });
    }

    #[test_traced]
    fn test_full_mmr_pop() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            const NUM_ELEMENTS: u64 = 200;

            let hasher: Standard<Sha256> = Standard::new();
            let cfg = test_config(&context);
            let mut mmr = Mmr::init(context, &hasher, cfg).await.unwrap();

            let mut c_hasher = Sha256::new();
            let mut batch = mmr.new_batch();
            for i in 0u64..NUM_ELEMENTS {
                c_hasher.update(&i.to_be_bytes());
                let element = c_hasher.finalize();
                batch = batch.add(&hasher, &element);
            }
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr.apply_batch(&batch).unwrap();

            // Rewind one node at a time without syncing until empty, confirming the root matches.
            for i in (0..NUM_ELEMENTS).rev() {
                assert!(mmr.rewind(1).await.is_ok());
                let root = mmr.root(&hasher, 0).unwrap();
                let mut reference_mmr = mem::Mmr::new();
                let batch = {
                    let mut batch = reference_mmr.new_batch();
                    for j in 0..i {
                        c_hasher.update(&j.to_be_bytes());
                        let element = c_hasher.finalize();
                        batch = batch.add(&hasher, &element);
                    }
                    batch.merkleize(&reference_mmr, &hasher)
                };
                reference_mmr.apply_batch(&batch).unwrap();
                assert_eq!(
                    root,
                    reference_mmr.root(&hasher, 0).unwrap(),
                    "root mismatch after rewind at {i}"
                );
            }
            assert!(matches!(mmr.rewind(1).await, Err(Error::Empty)));
            assert!(mmr.rewind(0).await.is_ok());

            // Repeat the test though sync part of the way to tip to test crossing the boundary from
            // cached to uncached leaves, and rewind 2 at a time instead of just 1.
            {
                let mut batch = mmr.new_batch();
                for i in 0u64..NUM_ELEMENTS {
                    c_hasher.update(&i.to_be_bytes());
                    let element = c_hasher.finalize();
                    batch = batch.add(&hasher, &element);
                    if i == 101 {
                        // We can't sync mid-batch, so apply the first part,
                        // sync, then start a new batch for the rest.
                        break;
                    }
                }
                let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                mmr.apply_batch(&batch).unwrap();
                mmr.sync().await.unwrap();
                let mut batch = mmr.new_batch();
                for i in 102u64..NUM_ELEMENTS {
                    c_hasher.update(&i.to_be_bytes());
                    let element = c_hasher.finalize();
                    batch = batch.add(&hasher, &element);
                }
                let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                mmr.apply_batch(&batch).unwrap();
            }

            for i in (0..NUM_ELEMENTS - 1).rev().step_by(2) {
                assert!(mmr.rewind(2).await.is_ok(), "at position {i:?}");
                let root = mmr.root(&hasher, 0).unwrap();
                let reference_mmr = mem::Mmr::new();
                let reference_mmr = build_test_mmr(&hasher, reference_mmr, i);
                assert_eq!(
                    root,
                    reference_mmr.root(&hasher, 0).unwrap(),
                    "root mismatch at position {i:?}"
                );
            }
            assert!(matches!(mmr.rewind(99).await, Err(Error::Empty)));

            // Repeat one more time only after pruning the MMR first.
            {
                let mut batch = mmr.new_batch();
                for i in 0u64..102 {
                    c_hasher.update(&i.to_be_bytes());
                    let element = c_hasher.finalize();
                    batch = batch.add(&hasher, &element);
                }
                let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                mmr.apply_batch(&batch).unwrap();
                mmr.sync().await.unwrap();
                let mut batch = mmr.new_batch();
                for i in 102u64..NUM_ELEMENTS {
                    c_hasher.update(&i.to_be_bytes());
                    let element = c_hasher.finalize();
                    batch = batch.add(&hasher, &element);
                }
                let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
                mmr.apply_batch(&batch).unwrap();
            }
            let prune_loc = Location::new(50);
            let prune_pos = Position::try_from(prune_loc).unwrap();
            mmr.prune(prune_loc).await.unwrap();
            // Rewind enough nodes to cause the mem-mmr to be completely emptied, and then some.
            mmr.rewind(80).await.unwrap();
            // Make sure the pinned node boundary is valid by generating a proof for the oldest item.
            mmr.proof(&hasher, prune_loc, 0).await.unwrap();
            // prune all remaining leaves 1 at a time.
            while mmr.size() > prune_pos {
                assert!(mmr.rewind(1).await.is_ok());
            }
            assert!(matches!(mmr.rewind(1).await, Err(Error::ElementPruned(_))));

            // Make sure pruning to an older location is a no-op.
            assert!(mmr.prune(prune_loc - 1).await.is_ok());
            assert_eq!(mmr.bounds().start, prune_loc);

            mmr.destroy().await.unwrap();
        });
    }

    /// Create batch A, merkleize, create batch B via `merkleized_a.new_batch()`,
    /// merkleize, apply, and verify root matches a reference MMR.
    #[test_traced]
    fn test_full_mmr_batch_stacking() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher: Standard<Sha256> = Standard::new();

            // Build base full MMR with 10 elements.
            let mut mmr = Mmr::init(
                context.clone(),
                &Standard::<Sha256>::new(),
                test_config(&context),
            )
            .await
            .unwrap();

            let mut batch = mmr.new_batch();
            for i in 0u64..10 {
                let element = hasher.digest(&i.to_be_bytes());
                batch = batch.add(&hasher, &element);
            }
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr.apply_batch(&batch).unwrap();
            mmr.sync().await.unwrap();

            // Batch A: add 5 elements.
            let mut batch_a = mmr.new_batch();
            for i in 10u64..15 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_a = batch_a.add(&hasher, &element);
            }
            let merkleized_a = mmr.with_mem(|mem| batch_a.merkleize(mem, &hasher));

            // Batch B on merkleized A: add 5 more elements.
            let mut batch_b = merkleized_a.new_batch();
            for i in 15u64..20 {
                let element = hasher.digest(&i.to_be_bytes());
                batch_b = batch_b.add(&hasher, &element);
            }
            let merkleized_b = mmr.with_mem(|mem| batch_b.merkleize(mem, &hasher));
            let expected_root = mmr
                .with_mem(|mem| merkleized_b.root(mem, &hasher, 0))
                .unwrap();

            // Apply.
            mmr.apply_batch(&merkleized_b).unwrap();
            assert_eq!(mmr.root(&hasher, 0).unwrap(), expected_root);

            // Build a reference in-memory MMR with 20 elements to verify.
            let empty = mem::Mmr::new();
            let reference = build_test_mmr(&hasher, empty, 20);
            assert_eq!(
                mmr.root(&hasher, 0).unwrap(),
                reference.root(&hasher, 0).unwrap()
            );

            mmr.destroy().await.unwrap();
        });
    }

    /// Regression: init_sync's "fresh start" path (journal data entirely before sync range)
    /// calls clear_to_size which changes the journal size, but journal_size must be re-read
    /// afterward. Without the re-read, nodes_to_pin and the mem_mmr are initialized with a
    /// stale size, causing incorrect pinned nodes or init failure.
    #[test_traced]
    fn test_init_sync_fresh_start_updates_journal_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let hasher = Standard::<Sha256>::new();

            // Build an MMR with 5 leaves (size 8), sync, drop.
            let mut mmr =
                Mmr::<_, Digest>::init(context.with_label("init"), &hasher, test_config(&context))
                    .await
                    .unwrap();
            let mut batch = mmr.new_batch();
            for i in 0..5 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            mmr.apply_batch(&batch).unwrap();
            mmr.sync().await.unwrap();
            drop(mmr);

            // Build a reference MMR to 100 leaves to get valid pinned nodes for the
            // sync boundary.
            let ref_cfg = Config {
                journal_partition: "ref-journal".into(),
                metadata_partition: "ref-metadata".into(),
                items_per_blob: NZU64!(7),
                write_buffer: NZUsize!(1024),
                strategy: Sequential,
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            };
            let mut ref_mmr = Mmr::<_, Digest>::init(context.with_label("ref"), &hasher, ref_cfg)
                .await
                .unwrap();
            let mut batch = ref_mmr.new_batch();
            for i in 0..100 {
                batch = batch.add(&hasher, &test_digest(i));
            }
            let batch = ref_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            ref_mmr.apply_batch(&batch).unwrap();
            let expected_size = ref_mmr.size();
            let prune_loc = Location::new(100);
            let mut pinned = Vec::new();
            for pos in Family::nodes_to_pin(prune_loc) {
                pinned.push(ref_mmr.get_node(pos).await.unwrap().unwrap());
            }
            ref_mmr.destroy().await.unwrap();

            // init_sync with range starting beyond the existing data triggers the
            // "fresh start" path (clear_to_size).
            let sync_cfg = SyncConfig::<Digest> {
                config: test_config(&context),
                range: non_empty_range!(Location::new(100), Location::new(200)),
                pinned_nodes: Some(pinned),
            };
            let mut sync_mmr = Mmr::init_sync(context.with_label("sync"), sync_cfg)
                .await
                .unwrap();

            // The MMR should have size matching the prune boundary position.
            assert_eq!(sync_mmr.size(), expected_size);

            // Should be able to add new elements without panic.
            let batch = sync_mmr.new_batch().add(&hasher, &test_digest(999));
            let batch = sync_mmr.with_mem(|mem| batch.merkleize(mem, &hasher));
            sync_mmr.apply_batch(&batch).unwrap();

            sync_mmr.destroy().await.unwrap();
        });
    }
}

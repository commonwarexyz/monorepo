#![no_main]

//! Persisted Merkle (MMR and MMB) crash recovery under injected sync, write, and remove faults.
//!
//! The op phase interleaves appends with sync, flush, and abandoned start_sync barriers, plus
//! prune drives with remove faults armed so a prune can fail after removing only some blobs.
//! The oracle checks the recovered size, leaf count, and prune boundary against tracked
//! durable floors and attempted ceilings, then compares every readable node against an
//! independently rebuilt reference tree so a same-size corruption cannot pass. A sentinel
//! append, sync, and reopen prove the recovered instance still writes durably.

use arbitrary::Arbitrary;
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::merkle::{
    Bagging::ForwardFold, Family as MerkleFamily, Location, Position, full::Config,
    hasher::Standard as StandardHasher, mem::Mem, mmb, mmr,
};
use commonware_storage_fuzz::{
    bounded_buffer, bounded_entropy, bounded_items, bounded_nonzero_rate, bounded_page_cache_size,
    bounded_page_size, faulted_recovery,
};
use commonware_utils::{FuzzRng, NZU64, Probability, sync::RwLock};
use libfuzzer_sys::fuzz_target;
use std::{
    num::{NonZeroU16, NonZeroUsize},
    sync::Arc,
};

/// Data size for leaves.
const DATA_SIZE: usize = 32;

type Merkle<F> =
    commonware_storage::merkle::full::Merkle<F, deterministic::Context, Digest, Sequential>;

/// Operations that can be performed on the Merkle structure.
#[derive(Arbitrary, Debug, Clone)]
enum MerkleOperation {
    /// Add a leaf.
    Add { data: [u8; DATA_SIZE] },
    /// Sync to storage.
    Sync,
    /// Flush cached nodes to the journal without a durability barrier.
    Flush,
    /// Begin a durable sync and abandon its completion handle.
    StartSync,
    /// Prune leaves up to a location.
    PruneToLoc { loc: u64 },
    /// Prune all nodes.
    PruneAll,
}

/// Fuzz input containing fault injection parameters and operations.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Page size for buffer pool.
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    /// Number of pages in the buffer pool cache.
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    /// Items per blob.
    #[arbitrary(with = bounded_items)]
    items_per_blob: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_buffer)]
    write_buffer: usize,
    /// Replay buffer size.
    #[arbitrary(with = bounded_buffer)]
    replay_buffer: usize,
    /// Failure rate for sync operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    sync_failure_rate: Probability,
    /// Failure and byte-retention configuration for write operations.
    write_config: deterministic::WriteConfig,
    /// Remove failure rate (percent) armed only around each prune drive, sampled per blob
    /// removal so the journal prune inside can fail after removing only some blobs, leaving
    /// the durable metadata boundary ahead of a partially pruned journal.
    remove_failure: u8,
    /// Sequence of operations to execute.
    operations: Vec<MerkleOperation>,
    /// Byte stream driving the runtime rng: all in-run randomness, fault sampling, and the
    /// faulted recovery chain's depth and shapes.
    #[arbitrary(with = bounded_entropy)]
    entropy: Vec<u8>,
}

fn merkle_config(
    partition_suffix: &str,
    pooler: &impl BufferPooler,
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    items_per_blob: u64,
    write_buffer: NonZeroUsize,
    replay_buffer: NonZeroUsize,
) -> Config<Sequential> {
    Config {
        journal_partition: format!("journal-{partition_suffix}"),
        metadata_partition: format!("metadata-{partition_suffix}"),
        items_per_blob: NZU64!(items_per_blob),
        write_buffer,
        replay_buffer,
        strategy: Sequential,
        page_cache: CacheRef::from_pooler(pooler, page_size, page_cache_size),
    }
}

/// Conservative bounds on what a recovery may produce after an unclean shutdown:
/// - the recovered size is in `[min_size, max_size]`,
/// - the recovered leaf count is in `[min_leaves, max_leaves]`,
/// - the recovered prune boundary is in `[min_pruned, max_pruned]`.
struct ExpectedBounds {
    /// Guaranteed-durable size floor, raised only by completed barriers.
    min_size: u64,
    /// Ceiling on the recovered size, raised by every append.
    max_size: u64,
    /// Guaranteed-durable leaf floor, raised only by completed barriers.
    min_leaves: u64,
    /// Ceiling on the recovered leaf count, raised by every append.
    max_leaves: u64,
    /// Guaranteed prune floor, raised only by completed prunes.
    min_pruned: u64,
    /// Ceiling on the recovered prune boundary, including failed prune attempts.
    max_pruned: u64,
    /// Every leaf in append order, for rebuilding the reference tree.
    leaves: Vec<[u8; DATA_SIZE]>,
}

/// Drive the operation sequence under armed faults until one fails, tracking the durable
/// floors and attempted ceilings the recovery oracle asserts against.
async fn run_operations<F: MerkleFamily>(
    mut merkle: Merkle<F>,
    hasher: &StandardHasher<Sha256>,
    operations: &[MerkleOperation],
    faults: &Arc<RwLock<deterministic::FaultConfig>>,
    op_faults: &deterministic::FaultConfig,
    prune_faults: &deterministic::FaultConfig,
) -> ExpectedBounds {
    let mut min_size = 0u64;
    let mut max_size = merkle.size().as_u64();
    let mut min_leaves = 0u64;
    let mut max_leaves = merkle.leaves().as_u64();
    let mut min_pruned = 0u64;
    let mut max_pruned = merkle.bounds().start.as_u64();
    let mut leaves = Vec::new();

    // A failed operation breaks out of the loop.
    for op in operations.iter() {
        merkle = match op {
            MerkleOperation::Add { data } => {
                let batch = merkle.new_batch().add(hasher, data);
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, hasher));
                let merkle = merkle.apply_batch(&batch).unwrap();
                leaves.push(*data);
                max_size = max_size.max(merkle.size().as_u64());
                max_leaves = max_leaves.max(merkle.leaves().as_u64());
                merkle
            }

            MerkleOperation::Sync => match merkle.sync().await {
                Err(_) => break,
                Ok(merkle) => {
                    let size = merkle.size().as_u64();
                    let leaves = merkle.leaves().as_u64();
                    let pruned = merkle.bounds().start.as_u64();
                    min_size = size;
                    max_size = max_size.max(size);
                    min_leaves = leaves;
                    max_leaves = max_leaves.max(leaves);
                    min_pruned = pruned;
                    max_pruned = max_pruned.max(pruned);
                    merkle
                }
            },

            // Flushed nodes reach the journal without a durability barrier, so no
            // expectation changes: only a completed sync raises the floor.
            MerkleOperation::Flush => match merkle.flush().await {
                Err(_) => break,
                Ok(merkle) => merkle,
            },

            // The completion handle is dropped unobserved, so nothing is credited as
            // durable: the abandoned sync may or may not have completed by the crash.
            MerkleOperation::StartSync => match merkle.start_sync().await {
                Err(_) => break,
                Ok((merkle, handle)) => {
                    drop(handle);
                    merkle
                }
            },

            MerkleOperation::PruneToLoc { loc } => {
                let leaves = *merkle.leaves();
                let current_pruned = *merkle.bounds().start;
                let safe_loc = (*loc).min(leaves);

                if safe_loc > current_pruned {
                    // Remove faults are armed only around the prune drive, so the journal
                    // prune inside can fail after removing only some blobs.
                    *faults.write() = prune_faults.clone();
                    let result = merkle.prune(Location::new(safe_loc)).await;
                    *faults.write() = op_faults.clone();
                    match result {
                        Err(_) => {
                            // The error is opaque: the prune may have failed before its
                            // internal sync proved anything durable, so this ceiling is
                            // conservative and the size/leaves floors stay uncredited. A
                            // torn remove instead fails after the metadata durably recorded
                            // `safe_loc`, and recovery completes the journal prune to that
                            // boundary, so the recovered boundary can land anywhere up to
                            // this ceiling.
                            max_pruned = max_pruned.max(safe_loc);
                            break;
                        }
                        Ok(merkle) => {
                            let pruned = merkle.bounds().start.as_u64();
                            min_pruned = pruned;
                            max_pruned = pruned;

                            // Prune completes a full durable sync before touching
                            // metadata, so it is also a size/leaves barrier.
                            min_size = merkle.size().as_u64();
                            min_leaves = merkle.leaves().as_u64();
                            max_size = max_size.max(min_size);
                            max_leaves = max_leaves.max(min_leaves);
                            merkle
                        }
                    }
                } else {
                    merkle
                }
            }

            MerkleOperation::PruneAll => {
                let leaves = merkle.leaves().as_u64();
                let current_pruned = merkle.bounds().start.as_u64();

                if leaves != 0 && current_pruned < leaves {
                    // Same remove-fault window as PruneToLoc: prune_all is a prune to the
                    // current leaf count.
                    *faults.write() = prune_faults.clone();
                    let result = merkle.prune_all().await;
                    *faults.write() = op_faults.clone();
                    match result {
                        Err(_) => {
                            // The same conservative ceiling as PruneToLoc: a torn remove can
                            // leave the recovered boundary anywhere up to the leaf count.
                            max_pruned = max_pruned.max(leaves);
                            break;
                        }
                        Ok(merkle) => {
                            let pruned = merkle.bounds().start.as_u64();
                            min_pruned = pruned;
                            max_pruned = pruned;

                            // Prune completes a full durable sync before touching
                            // metadata, so it is also a size/leaves barrier.
                            min_size = merkle.size().as_u64();
                            min_leaves = merkle.leaves().as_u64();
                            max_size = max_size.max(min_size);
                            max_leaves = max_leaves.max(min_leaves);
                            merkle
                        }
                    }
                } else {
                    merkle
                }
            }
        };
    }

    ExpectedBounds {
        min_size,
        max_size,
        min_leaves,
        max_leaves,
        min_pruned,
        max_pruned,
        leaves,
    }
}

/// Rebuild an in-memory tree from the first `count` intended leaves.
fn build_reference<F: MerkleFamily>(
    hasher: &StandardHasher<Sha256>,
    leaves: &[[u8; DATA_SIZE]],
    count: u64,
) -> Mem<F, Digest> {
    let mut reference = Mem::new();
    let mut batch = reference.new_batch();
    for data in leaves.iter().take(count as usize) {
        batch = batch.add(hasher, data);
    }
    let batch = batch.merkleize(&reference, hasher);
    reference.apply_batch(&batch).unwrap();
    reference
}

/// Run one family through the faulted op phase, the faulted recovery chain, and a clean
/// recovery that verifies the oracle and post-recovery usability.
fn fuzz_family<F: MerkleFamily>(input: &FuzzInput, suffix: &str) {
    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_blob = input.items_per_blob;
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let replay_buffer = NonZeroUsize::new(input.replay_buffer).unwrap();
    let cfg =
        deterministic::Config::default().with_rng(Box::new(FuzzRng::new(input.entropy.clone())));
    let partition_suffix = format!("crash-{suffix}");
    let runner = deterministic::Runner::new(cfg);
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_config = input.write_config;
    let remove_rate = Probability::new(u64::from(input.remove_failure) % 101, 100).unwrap();

    // Phase 1: Execute operations with fault injection until crash
    let (bounds, checkpoint) = runner.start_and_recover(|ctx| {
        let partition_suffix = partition_suffix.clone();
        let operations = operations.clone();
        async move {
            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
            let merkle = Merkle::<F>::init(
                ctx.child("merkle"),
                &hasher,
                merkle_config(
                    &partition_suffix,
                    &ctx,
                    page_size,
                    page_cache_size,
                    items_per_blob,
                    write_buffer,
                    replay_buffer,
                ),
            )
            .await
            .expect("initial merkle init failed");

            let storage_fault_cfg = ctx.storage_fault_config();
            let op_faults = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_config),
                ..Default::default()
            };
            let prune_faults = deterministic::FaultConfig {
                remove_rate: Some(remove_rate),
                ..op_faults.clone()
            };
            *storage_fault_cfg.write() = op_faults.clone();

            run_operations(
                merkle,
                &hasher,
                &operations,
                &storage_fault_cfg,
                &op_faults,
                &prune_faults,
            )
            .await
        }
    });

    // A failed recovery instance is abandoned. Its crash checkpoint must remain recoverable by
    // the same ordinary initialization path with faults disabled.
    let recovery_partition_suffix = partition_suffix.clone();
    let checkpoint = faulted_recovery(checkpoint, move |ctx| {
        let recovery_partition_suffix = recovery_partition_suffix.clone();
        async move {
            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
            Merkle::<F>::init(
                ctx.child("faulted_recovery"),
                &hasher,
                merkle_config(
                    &recovery_partition_suffix,
                    &ctx,
                    page_size,
                    page_cache_size,
                    items_per_blob,
                    write_buffer,
                    replay_buffer,
                ),
            )
            .await
        }
    });

    // Phase 2: Recover and verify consistency
    let runner = deterministic::Runner::from(checkpoint);
    runner.start(|ctx| async move {
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();

        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let merkle = Merkle::<F>::init(
            ctx.child("recovered"),
            &hasher,
            merkle_config(
                &partition_suffix,
                &ctx,
                page_size,
                page_cache_size,
                items_per_blob,
                write_buffer,
                replay_buffer,
            ),
        )
        .await
        .expect("merkle recovery failed");

        // Verify recovered state is within expected bounds
        let size = merkle.size().as_u64();
        let leaves = merkle.leaves().as_u64();
        let pruned = merkle.bounds().start.as_u64();

        assert!(
            size <= bounds.max_size,
            "recovered size {size} exceeds the ceiling {} raised by appends",
            bounds.max_size
        );
        assert!(
            size >= bounds.min_size,
            "recovered size {size} lost nodes below the durable floor {}",
            bounds.min_size
        );
        assert!(
            leaves <= bounds.max_leaves,
            "recovered leaf count {leaves} exceeds the ceiling {} raised by appends",
            bounds.max_leaves
        );
        assert!(
            leaves >= bounds.min_leaves,
            "recovered leaf count {leaves} lost leaves below the durable floor {}",
            bounds.min_leaves
        );
        assert!(
            pruned <= bounds.max_pruned,
            "recovered prune boundary {pruned} exceeds the highest attempted prune {}",
            bounds.max_pruned
        );
        assert!(
            pruned >= bounds.min_pruned,
            "recovered prune boundary {pruned} resurrected nodes below the durable prune floor {}",
            bounds.min_pruned
        );

        // Scalar bounds select the allowed recovered prefix. Compare every readable node against
        // a separately rebuilt tree so a same-size corruption cannot satisfy the recovery oracle.
        let reference = build_reference::<F>(&hasher, &bounds.leaves, leaves);
        if leaves > 0 {
            assert_eq!(
                merkle.root(&hasher, 0).expect("recovered root missing"),
                reference.root(&hasher, 0).expect("reference root missing"),
                "recovered root does not match the intended leaf prefix",
            );
        }
        let prune_loc = Location::<F>::new(pruned);
        let prune_pos = F::location_to_position(prune_loc);
        let mut positions = F::nodes_to_pin(prune_loc).collect::<Vec<_>>();
        positions.extend((prune_pos.as_u64()..size).map(Position::<F>::new));
        positions.sort_unstable();
        positions.dedup();
        let expected_nodes = positions
            .iter()
            .map(|&position| {
                reference
                    .get_node(position)
                    .expect("reference node missing")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            merkle
                .get_nodes(&positions)
                .await
                .expect("recovered node read failed"),
            expected_nodes,
            "recovered nodes do not match the intended leaf prefix",
        );

        // Prove the recovered instance still writes durably: append a sentinel leaf, sync it,
        // and reopen to the same root.
        let test_data = [0xABu8; DATA_SIZE];
        let batch = merkle.new_batch().add(&hasher, &test_data);
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        let merkle = merkle.apply_batch(&batch).unwrap();
        let merkle = merkle.sync().await.expect("post-recovery sync failed");
        let root = merkle.root(&hasher, 0).expect("post-recovery root missing");
        drop(merkle);

        let reopened = Merkle::<F>::init(
            ctx.child("reopened"),
            &hasher,
            merkle_config(
                &partition_suffix,
                &ctx,
                page_size,
                page_cache_size,
                items_per_blob,
                write_buffer,
                replay_buffer,
            ),
        )
        .await
        .expect("reopen after sentinel sync failed");
        assert_eq!(
            reopened.root(&hasher, 0).expect("reopened root missing"),
            root,
            "sentinel leaf did not survive the reopen",
        );
        reopened.destroy().await.expect("destroy failed");
    });
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<mmr::Family>(&input, "mmr");
    fuzz_family::<mmb::Family>(&input, "mmb");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});

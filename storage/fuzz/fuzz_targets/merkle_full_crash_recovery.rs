#![no_main]

//! Fuzz test for Merkle Merkle crash recovery with fault injection.
//! Tests both MMR and MMB families.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_parallel::Sequential;
use commonware_runtime::{
    buffer::paged::CacheRef, deterministic, BufferPooler, Runner, Supervisor as _,
};
use commonware_storage::merkle::{
    full::Config, hasher::Standard as StandardHasher, mmb, mmr, Bagging::ForwardFold,
    Family as MerkleFamily, Location,
};
use commonware_utils::NZU64;
use libfuzzer_sys::fuzz_target;
use std::num::{NonZeroU16, NonZeroUsize};

/// Data size for leaves.
const DATA_SIZE: usize = 32;

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

type Merkle<F> =
    commonware_storage::merkle::full::Merkle<F, deterministic::Context, Digest, Sequential>;

fn bounded_page_size(u: &mut Unstructured<'_>) -> Result<u16> {
    u.int_in_range(1..=256)
}

fn bounded_page_cache_size(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=16)
}

fn bounded_items_per_blob(u: &mut Unstructured<'_>) -> Result<u64> {
    u.int_in_range(1..=64)
}

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=MAX_WRITE_BUF)
}

fn bounded_nonzero_rate(u: &mut Unstructured<'_>) -> Result<f64> {
    let percent: u8 = u.int_in_range(1..=100)?;
    Ok(f64::from(percent) / 100.0)
}

/// Operations that can be performed on the Merkle structure.
#[derive(Arbitrary, Debug, Clone)]
enum MerkleOperation {
    /// Add a leaf.
    Add { data: [u8; DATA_SIZE] },
    /// Sync to storage.
    Sync,
    /// Prune leaves up to a location.
    PruneToLoc { loc: u64 },
    /// Prune all nodes.
    PruneAll,
}

/// Fuzz input containing fault injection parameters and operations.
#[derive(Arbitrary, Debug)]
struct FuzzInput {
    /// Seed for deterministic execution.
    seed: u64,
    /// Page size for buffer pool.
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    /// Number of pages in the buffer pool cache.
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    /// Items per blob.
    #[arbitrary(with = bounded_items_per_blob)]
    items_per_blob: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_write_buffer)]
    write_buffer: usize,
    /// Failure rate for sync operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    sync_failure_rate: f64,
    /// Failure rate for write operations (0, 1].
    #[arbitrary(with = bounded_nonzero_rate)]
    write_failure_rate: f64,
    /// Sequence of operations to execute.
    operations: Vec<MerkleOperation>,
}

fn merkle_config(
    partition_suffix: &str,
    pooler: &impl BufferPooler,
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    items_per_blob: u64,
    write_buffer: NonZeroUsize,
) -> Config<Sequential> {
    Config {
        journal_partition: format!("journal-{partition_suffix}"),
        metadata_partition: format!("metadata-{partition_suffix}"),
        items_per_blob: NZU64!(items_per_blob),
        write_buffer,
        strategy: Sequential,
        page_cache: CacheRef::from_pooler(pooler, page_size, page_cache_size),
    }
}

/// Expected bounds for state after recovery.
struct ExpectedBounds {
    min_size: u64,
    max_size: u64,
    min_leaves: u64,
    max_leaves: u64,
    min_pruned: u64,
    max_pruned: u64,
}

async fn run_operations<F: MerkleFamily>(
    merkle: &mut Merkle<F>,
    hasher: &StandardHasher<Sha256>,
    operations: &[MerkleOperation],
) -> ExpectedBounds {
    let mut min_size = 0u64;
    let mut max_size = merkle.size().as_u64();
    let mut min_leaves = 0u64;
    let mut max_leaves = merkle.leaves().as_u64();
    let mut min_pruned = 0u64;
    let mut max_pruned = merkle.bounds().start.as_u64();

    for op in operations.iter() {
        let failed = match op {
            MerkleOperation::Add { data } => {
                let batch = merkle.new_batch().add(hasher, data);
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, hasher));
                merkle.apply_batch(&batch).unwrap();
                max_size = max_size.max(merkle.size().as_u64());
                max_leaves = max_leaves.max(merkle.leaves().as_u64());
                false
            }

            MerkleOperation::Sync => {
                if merkle.sync().await.is_err() {
                    true
                } else {
                    let size = merkle.size().as_u64();
                    let leaves = merkle.leaves().as_u64();
                    let pruned = merkle.bounds().start.as_u64();
                    min_size = size;
                    max_size = max_size.max(size);
                    min_leaves = leaves;
                    max_leaves = max_leaves.max(leaves);
                    min_pruned = pruned;
                    max_pruned = max_pruned.max(pruned);
                    false
                }
            }

            MerkleOperation::PruneToLoc { loc } => {
                let leaves = *merkle.leaves();
                let current_pruned = *merkle.bounds().start;
                let safe_loc = (*loc).min(leaves);

                if safe_loc <= current_pruned {
                    false
                } else {
                    match merkle.prune(Location::new(safe_loc)).await {
                        Err(_) => {
                            max_pruned = max_pruned.max(safe_loc);
                            true
                        }
                        Ok(_) => {
                            let pruned = merkle.bounds().start.as_u64();
                            min_pruned = pruned;
                            max_pruned = pruned;
                            false
                        }
                    }
                }
            }

            MerkleOperation::PruneAll => {
                let leaves = merkle.leaves().as_u64();
                let current_pruned = merkle.bounds().start.as_u64();

                if leaves == 0 || current_pruned >= leaves {
                    false
                } else {
                    match merkle.prune_all().await {
                        Err(_) => {
                            max_pruned = max_pruned.max(leaves);
                            true
                        }
                        Ok(_) => {
                            let pruned = merkle.bounds().start.as_u64();
                            min_pruned = pruned;
                            max_pruned = pruned;
                            false
                        }
                    }
                }
            }
        };

        if failed {
            break;
        }
    }

    ExpectedBounds {
        min_size,
        max_size,
        min_leaves,
        max_leaves,
        min_pruned,
        max_pruned,
    }
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput, suffix: &str) {
    if input.operations.is_empty() {
        return;
    }

    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_blob = input.items_per_blob;
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let cfg = deterministic::Config::default().with_seed(input.seed);
    let partition_suffix = format!("crash-{suffix}-{}", input.seed);
    let runner = deterministic::Runner::new(cfg);
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;

    // Phase 1: Execute operations with fault injection until crash
    let (bounds, checkpoint) = runner.start_and_recover(|ctx| {
        let partition_suffix = partition_suffix.clone();
        let operations = operations.clone();
        async move {
            let hasher = StandardHasher::<Sha256>::new(ForwardFold);
            let mut merkle = Merkle::<F>::init(
                ctx.child("merkle"),
                &hasher,
                merkle_config(
                    &partition_suffix,
                    &ctx,
                    page_size,
                    page_cache_size,
                    items_per_blob,
                    write_buffer,
                ),
            )
            .await
            .unwrap();

            let storage_fault_cfg = ctx.storage_fault_config();
            *storage_fault_cfg.write() = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_failure_rate),
                ..Default::default()
            };

            run_operations(&mut merkle, &hasher, &operations).await
        }
    });

    // Phase 2: Recover and verify consistency
    let runner = deterministic::Runner::from(checkpoint);
    runner.start(|ctx| async move {
        *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();

        let hasher = StandardHasher::<Sha256>::new(ForwardFold);
        let mut merkle = Merkle::<F>::init(
            ctx.child("recovered"),
            &hasher,
            merkle_config(
                &partition_suffix,
                &ctx,
                page_size,
                page_cache_size,
                items_per_blob,
                write_buffer,
            ),
        )
        .await
        .expect("recovery should succeed");

        // Verify recovered state is within expected bounds
        let size = merkle.size().as_u64();
        let leaves = merkle.leaves().as_u64();
        let pruned = merkle.bounds().start.as_u64();

        assert!(
            size <= bounds.max_size,
            "size {} > max_size {}",
            size,
            bounds.max_size
        );
        assert!(
            size >= bounds.min_size,
            "size {} < min_size {}",
            size,
            bounds.min_size
        );
        assert!(
            leaves <= bounds.max_leaves,
            "leaves {} > max_leaves {}",
            leaves,
            bounds.max_leaves
        );
        assert!(
            leaves >= bounds.min_leaves,
            "leaves {} < min_leaves {}",
            leaves,
            bounds.min_leaves
        );
        assert!(
            pruned <= bounds.max_pruned,
            "pruned {} > max_pruned {}",
            pruned,
            bounds.max_pruned
        );
        assert!(
            pruned >= bounds.min_pruned,
            "pruned {} < min_pruned {}",
            pruned,
            bounds.min_pruned
        );

        // Verify we can add new data after recovery
        let test_data = [0xABu8; DATA_SIZE];
        let batch = merkle.new_batch().add(&hasher, &test_data);
        let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
        merkle.apply_batch(&batch).unwrap();
        merkle.destroy().await.expect("should be able to destroy");
    });
}

fn fuzz(input: FuzzInput) {
    fuzz_family::<mmr::Family>(&input, "mmr");
    fuzz_family::<mmb::Family>(&input, "mmb");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});

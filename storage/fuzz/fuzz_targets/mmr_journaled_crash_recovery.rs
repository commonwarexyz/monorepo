#![no_main]

//! Fuzz test for MMR Journaled crash recovery with fault injection.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{sha256::Digest, Sha256};
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Metrics as _, Runner};
use commonware_storage::mmr::{
    journaled::{CleanMmr, Config},
    Location, Position, StandardHasher,
};
use commonware_utils::NZU64;
use libfuzzer_sys::fuzz_target;
use std::num::{NonZeroU16, NonZeroUsize};

/// Data size for MMR leaves.
const DATA_SIZE: usize = 32;

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

/// Type alias for the MMR we're testing.
type TestMmr = CleanMmr<deterministic::Context, Digest>;

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

/// Operations that can be performed on the MMR.
#[derive(Arbitrary, Debug, Clone)]
enum MmrOperation {
    /// Add a leaf to the MMR.
    Add { data: [u8; DATA_SIZE] },
    /// Pop leaves from the MMR.
    Pop { count: u8 },
    /// Sync the MMR to storage.
    Sync,
    /// Prune nodes up to a position.
    PruneToPos { pos: u64 },
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
    operations: Vec<MmrOperation>,
}

fn mmr_config(
    partition_suffix: &str,
    page_size: NonZeroU16,
    page_cache_size: NonZeroUsize,
    items_per_blob: u64,
    write_buffer: NonZeroUsize,
) -> Config {
    Config {
        journal_partition: format!("mmr_journal_{partition_suffix}"),
        metadata_partition: format!("mmr_metadata_{partition_suffix}"),
        items_per_blob: NZU64!(items_per_blob),
        write_buffer,
        thread_pool: None,
        page_cache: CacheRef::new(page_size, page_cache_size),
    }
}

/// Expected bounds for MMR state after recovery.
struct ExpectedBounds {
    min_size: u64,
    max_size: u64,
    min_leaves: u64,
    max_leaves: u64,
    min_pruned: u64,
    max_pruned: u64,
}

async fn run_operations(
    mmr: &mut TestMmr,
    hasher: &mut StandardHasher<Sha256>,
    operations: &[MmrOperation],
) -> ExpectedBounds {
    let mut min_size = 0u64;
    let mut max_size = mmr.size().as_u64();
    let mut min_leaves = 0u64;
    let mut max_leaves = mmr.leaves().as_u64();
    let mut min_pruned = 0u64;
    let mut max_pruned = mmr.pruned_to_pos().as_u64();

    for op in operations.iter() {
        let step_result: Result<(), ()> = match op {
            MmrOperation::Add { data } => {
                let leaves_before = mmr.leaves().as_u64();

                if mmr.add(hasher, data).await.is_err() {
                    // Partial write possible: max is size after one leaf added
                    max_size = max_size.max(
                        Position::try_from(Location::new(leaves_before).unwrap() + 1)
                            .unwrap()
                            .as_u64(),
                    );
                    max_leaves = max_leaves.max(leaves_before + 1);
                    Err(())
                } else {
                    max_size = max_size.max(mmr.size().as_u64());
                    max_leaves = max_leaves.max(mmr.leaves().as_u64());
                    Ok(())
                }
            }

            MmrOperation::Pop { count } => {
                let count = *count as usize;
                if count == 0 || count as u64 > mmr.leaves().as_u64() {
                    Ok(())
                } else {
                    let target_leaves = mmr.leaves().as_u64() - count as u64;

                    if mmr.pop(hasher, count).await.is_err() {
                        // Partial pop possible: min could be target
                        min_leaves = min_leaves.min(target_leaves);
                        if target_leaves > 0 {
                            let target_size =
                                Position::try_from(Location::new(target_leaves).unwrap())
                                    .unwrap()
                                    .as_u64();
                            min_size = min_size.min(target_size);
                        } else {
                            min_size = 0;
                        }
                        Err(())
                    } else {
                        // Pop decreases size: update min bounds
                        min_size = min_size.min(mmr.size().as_u64());
                        min_leaves = min_leaves.min(mmr.leaves().as_u64());
                        Ok(())
                    }
                }
            }

            MmrOperation::Sync => {
                if mmr.sync().await.is_err() {
                    Err(())
                } else {
                    // Sync commits state: update all bounds to current values
                    let size = mmr.size().as_u64();
                    let leaves = mmr.leaves().as_u64();
                    let pruned = mmr.pruned_to_pos().as_u64();
                    min_size = size;
                    max_size = max_size.max(size);
                    min_leaves = leaves;
                    max_leaves = max_leaves.max(leaves);
                    min_pruned = pruned;
                    max_pruned = max_pruned.max(pruned);
                    Ok(())
                }
            }

            MmrOperation::PruneToPos { pos } => {
                let size = mmr.size().as_u64();
                let current_pruned = mmr.pruned_to_pos().as_u64();
                let safe_pos = (*pos).min(size);

                if safe_pos <= current_pruned {
                    // No-op: already pruned past this point
                    Ok(())
                } else {
                    match mmr.prune_to_pos(Position::new(safe_pos)).await {
                        Err(_) => {
                            // Partial prune possible
                            max_pruned = max_pruned.max(safe_pos);
                            Err(())
                        }
                        Ok(_) => {
                            // Prune commits: update both bounds to actual value
                            let pruned = mmr.pruned_to_pos().as_u64();
                            min_pruned = pruned;
                            max_pruned = pruned;
                            Ok(())
                        }
                    }
                }
            }

            MmrOperation::PruneAll => {
                let size = mmr.size().as_u64();
                let current_pruned = mmr.pruned_to_pos().as_u64();

                if size == 0 || current_pruned >= size {
                    // No-op: nothing to prune
                    Ok(())
                } else {
                    match mmr.prune_all().await {
                        Err(_) => {
                            // Partial prune possible
                            max_pruned = max_pruned.max(size);
                            Err(())
                        }
                        Ok(_) => {
                            // Prune commits: update both bounds to actual value
                            let pruned = mmr.pruned_to_pos().as_u64();
                            min_pruned = pruned;
                            max_pruned = pruned;
                            Ok(())
                        }
                    }
                }
            }
        };

        if step_result.is_err() {
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

fn fuzz(input: FuzzInput) {
    if input.operations.is_empty() {
        return;
    }

    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_blob = input.items_per_blob;
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let cfg = deterministic::Config::default().with_seed(input.seed);
    let partition_suffix = format!("crash_recovery_{}", input.seed);
    let runner = deterministic::Runner::new(cfg);
    let operations = input.operations;
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;

    // Phase 1: Execute operations with fault injection until crash
    let (bounds, checkpoint) = runner.start_and_recover(|ctx| {
        let partition_suffix = partition_suffix.clone();
        let operations = operations.clone();
        async move {
            let mut hasher = StandardHasher::<Sha256>::new();
            let mut mmr = TestMmr::init(
                ctx.with_label("mmr"),
                &mut hasher,
                mmr_config(
                    &partition_suffix,
                    page_size,
                    page_cache_size,
                    items_per_blob,
                    write_buffer,
                ),
            )
            .await
            .unwrap();

            let faults = ctx.storage_faults();
            *faults.write().unwrap() = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_failure_rate),
                ..Default::default()
            };

            run_operations(&mut mmr, &mut hasher, &operations).await
        }
    });

    // Phase 2: Recover and verify consistency
    let runner = deterministic::Runner::from(checkpoint);
    runner.start(|ctx| async move {
        *ctx.storage_faults().write().unwrap() = deterministic::FaultConfig::default();

        let mut hasher = StandardHasher::<Sha256>::new();
        let mut mmr = TestMmr::init(
            ctx.with_label("recovered"),
            &mut hasher,
            mmr_config(
                &partition_suffix,
                page_size,
                page_cache_size,
                items_per_blob,
                write_buffer,
            ),
        )
        .await
        .expect("MMR recovery should succeed");

        // Verify recovered state is within expected bounds
        let size = mmr.size().as_u64();
        let leaves = mmr.leaves().as_u64();
        let pruned = mmr.pruned_to_pos().as_u64();

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
        mmr.add(&mut hasher, &test_data)
            .await
            .expect("Should be able to add after recovery");

        mmr.destroy().await.expect("Should be able to destroy MMR");
    });
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});

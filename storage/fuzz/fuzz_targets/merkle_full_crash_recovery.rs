#![no_main]

//! Fuzz test for Merkle crash recovery with fault injection.
//! Tests both MMR and MMB families.

use arbitrary::{Arbitrary, Result, Unstructured};
use commonware_cryptography::{Sha256, sha256::Digest};
use commonware_parallel::Sequential;
use commonware_runtime::{
    BufferPooler, Runner, Supervisor as _, buffer::paged::CacheRef, deterministic,
};
use commonware_storage::merkle::{
    Bagging, Family as MerkleFamily, Location, Position, full::Config,
    hasher::Standard as StandardHasher, mem::Mem, mmb, mmr,
};
use commonware_storage_fuzz::{
    RNG_BYTES, bounded_items_per_section, bounded_page_cache_size, bounded_page_size, bounded_rate,
    fuzz_runner,
};
use commonware_utils::NZU64;
use libfuzzer_sys::fuzz_target;
use std::{
    collections::BTreeSet,
    num::{NonZeroU16, NonZeroUsize},
};

/// Data size for leaves.
const DATA_SIZE: usize = 32;

/// Maximum write buffer size.
const MAX_WRITE_BUF: usize = 2048;

/// Maximum number of operations per fuzz input.
const MAX_OPERATIONS: usize = 64;

type Merkle<F> =
    commonware_storage::merkle::full::Merkle<F, deterministic::Context, Digest, Sequential>;

fn bounded_write_buffer(u: &mut Unstructured<'_>) -> Result<usize> {
    u.int_in_range(1..=MAX_WRITE_BUF)
}

fn bounded_operations(u: &mut Unstructured<'_>) -> Result<Vec<MerkleOperation>> {
    let count = u.int_in_range(0..=MAX_OPERATIONS)?;
    (0..count).map(|_| MerkleOperation::arbitrary(u)).collect()
}

#[derive(Arbitrary, Debug, Clone, Copy)]
enum FamilyType {
    Mmr,
    Mmb,
}

/// Operations that can be performed on the Merkle structure.
#[derive(Arbitrary, Debug, Clone)]
enum MerkleOperation {
    /// Add a leaf.
    Add { data: [u8; DATA_SIZE] },
    /// Flush to storage without making the write durable.
    Flush,
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
    /// Merkle family, kept independent of the deterministic-runtime choice bytes.
    family: FamilyType,
    /// Fuzzer-controlled randomness for deterministic runtime choices.
    raw_bytes: [u8; RNG_BYTES],
    /// Page size for buffer pool.
    #[arbitrary(with = bounded_page_size)]
    page_size: u16,
    /// Number of pages in the buffer pool cache.
    #[arbitrary(with = bounded_page_cache_size)]
    page_cache_size: usize,
    /// Items per blob.
    #[arbitrary(with = bounded_items_per_section)]
    items_per_blob: u64,
    /// Write buffer size.
    #[arbitrary(with = bounded_write_buffer)]
    write_buffer: usize,
    /// Failure rate for sync operations.
    #[arbitrary(with = bounded_rate)]
    sync_failure_rate: f64,
    /// Failure rate for write operations.
    #[arbitrary(with = bounded_rate)]
    write_failure_rate: f64,
    /// Sequence of operations to execute.
    #[arbitrary(with = bounded_operations)]
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
#[derive(Clone)]
struct ExpectedBounds {
    min_leaves: u64,
    max_leaves: u64,
    min_pruned: u64,
    max_pruned: u64,
    leaves_data: Vec<[u8; DATA_SIZE]>,
}

fn pin_durable<F: MerkleFamily>(expected: &mut ExpectedBounds, merkle: &Merkle<F>) {
    let leaves = merkle.leaves().as_u64();
    let pruned = merkle.bounds().start.as_u64();
    expected.min_leaves = leaves;
    expected.max_leaves = leaves;
    expected.min_pruned = pruned;
    expected.max_pruned = pruned;
}

/// Raise the recovery ceiling once an operation can have reached the journal. Applying a batch is
/// memory-only; flush, sync, and prune may make some current nodes recoverable even when they
/// return an error.
fn raise_storage_ceiling<F: MerkleFamily>(max_leaves: &mut u64, merkle: &Merkle<F>) {
    *max_leaves = (*max_leaves).max(merkle.leaves().as_u64());
}

fn mem_from_leaves<F: MerkleFamily>(
    leaves: &[[u8; DATA_SIZE]],
    hasher: &StandardHasher<Sha256>,
) -> Mem<F, Digest> {
    let mut mem = Mem::<F, Digest>::new();
    if !leaves.is_empty() {
        let mut batch = mem.new_batch();
        for data in leaves {
            batch = batch.add(hasher, data);
        }
        let batch = batch.merkleize(&mem, hasher);
        mem.apply_batch(&batch).unwrap();
    }
    mem
}

fn root_from_leaves<F: MerkleFamily>(
    leaves: &[[u8; DATA_SIZE]],
    hasher: &StandardHasher<Sha256>,
) -> Digest {
    mem_from_leaves::<F>(leaves, hasher)
        .root(hasher, 0)
        .unwrap()
}

async fn verify_recovery<F: MerkleFamily>(
    merkle: &Merkle<F>,
    hasher: &StandardHasher<Sha256>,
    expected: &ExpectedBounds,
    items_per_blob: u64,
) {
    let size = merkle.size().as_u64();
    let leaves = merkle.leaves().as_u64();
    let pruned = merkle.bounds().start.as_u64();
    assert!(
        leaves <= expected.max_leaves,
        "leaves {leaves} > {}",
        expected.max_leaves
    );
    assert!(
        leaves >= expected.min_leaves,
        "leaves {leaves} < {}",
        expected.min_leaves
    );
    assert!(
        pruned <= expected.max_pruned,
        "pruned {pruned} > {}",
        expected.max_pruned
    );
    assert!(
        pruned >= expected.min_pruned,
        "pruned {pruned} < {}",
        expected.min_pruned
    );
    assert!(pruned <= leaves && leaves <= expected.leaves_data.len() as u64);
    if pruned > expected.min_pruned {
        assert_eq!(
            pruned, expected.max_pruned,
            "an interrupted prune may recover only its old or target boundary"
        );
        assert_eq!(
            leaves, expected.max_leaves,
            "an advanced prune boundary requires every pre-prune leaf"
        );
    }

    // Recompute every node from the exact accepted leaf prefix. Non-pinned physical nodes must
    // match either the complete old blob cutoff or the complete committed prune cutoff.
    let oracle = mem_from_leaves::<F>(&expected.leaves_data[..leaves as usize], hasher);
    assert_eq!(
        oracle.size().as_u64(),
        size,
        "recovered size is inconsistent with its leaf count"
    );
    let root = merkle.root(hasher, 0).expect("recovered root");
    assert_eq!(
        root,
        oracle.root(hasher, 0).expect("oracle root"),
        "root mismatch for {leaves} recovered leaves"
    );

    let prune_loc = Location::<F>::new(pruned);
    let prune_pos = F::location_to_position(prune_loc);
    let physical_floor = *prune_pos / items_per_blob * items_per_blob;
    let required_pins: BTreeSet<_> = F::nodes_to_pin(prune_loc)
        .chain(F::peaks(oracle.size()).map(|(pos, _)| pos))
        .collect();
    for raw_pos in 0..size {
        let pos = Position::<F>::new(raw_pos);
        let expected_node = oracle
            .get_node(pos)
            .unwrap_or_else(|| panic!("oracle missing node {pos}"));
        let recovered_node = merkle
            .get_node(pos)
            .await
            .unwrap_or_else(|e| panic!("failed to read node {pos}: {e:?}"));
        if pos >= prune_pos || required_pins.contains(&pos) {
            assert!(recovered_node.is_some(), "required node {pos} is missing");
        }
        if !required_pins.contains(&pos) {
            assert_eq!(
                recovered_node.is_some(),
                raw_pos >= physical_floor,
                "physical node {pos} does not match the recovered atomic prune boundary"
            );
        }
        if let Some(recovered_node) = recovered_node {
            assert_eq!(
                recovered_node, expected_node,
                "recovered node {pos} diverged"
            );
        }
    }
    // Exercise both point and range proof construction against the recovered storage.
    if pruned < leaves {
        for leaf in pruned..leaves {
            let loc = Location::<F>::new(leaf);
            let proof = merkle
                .proof(hasher, loc, 0)
                .await
                .unwrap_or_else(|e| panic!("current proof for leaf {leaf} failed: {e:?}"));
            assert!(
                proof.verify_element_inclusion(
                    hasher,
                    &expected.leaves_data[leaf as usize],
                    loc,
                    &root,
                ),
                "current proof for leaf {leaf} did not verify"
            );
        }

        let current_start = Location::<F>::new(pruned);
        let current_end = Location::<F>::new(leaves);
        let proof = merkle
            .range_proof(hasher, current_start..current_end, 0)
            .await
            .expect("current retained range proof");
        assert!(
            proof.verify_range_inclusion(
                hasher,
                &expected.leaves_data[pruned as usize..leaves as usize],
                current_start,
                &root,
            ),
            "current retained range proof did not verify"
        );

        // Use a strictly smaller tree whenever at least two retained leaves exist, so this checks
        // the historical path rather than merely duplicating the current proof API.
        if leaves - pruned > 1 {
            let historical_count = leaves - 1;
            let historical_leaves = Location::<F>::new(historical_count);
            let historical_root =
                root_from_leaves::<F>(&expected.leaves_data[..historical_count as usize], hasher);
            let historical_loc = Location::<F>::new(historical_count - 1);
            let proof = merkle
                .historical_proof(hasher, historical_leaves, historical_loc, 0)
                .await
                .expect("historical point proof");
            assert!(
                proof.verify_element_inclusion(
                    hasher,
                    &expected.leaves_data[(historical_count - 1) as usize],
                    historical_loc,
                    &historical_root,
                ),
                "historical point proof did not verify"
            );

            let historical_start = Location::<F>::new(pruned);
            let proof = merkle
                .historical_range_proof(
                    hasher,
                    historical_leaves,
                    historical_start..historical_leaves,
                    0,
                )
                .await
                .expect("historical retained range proof");
            assert!(
                proof.verify_range_inclusion(
                    hasher,
                    &expected.leaves_data[pruned as usize..historical_count as usize],
                    historical_start,
                    &historical_root,
                ),
                "historical retained range proof did not verify"
            );
        }
    }
}

async fn run_operations<F: MerkleFamily>(
    mut merkle: Merkle<F>,
    hasher: &StandardHasher<Sha256>,
    operations: &[MerkleOperation],
) -> ExpectedBounds {
    let mut min_leaves = 0u64;
    let mut max_leaves = merkle.leaves().as_u64();
    let mut min_pruned = 0u64;
    let mut max_pruned = merkle.bounds().start.as_u64();
    let mut leaves_data = Vec::new();

    // A failed operation breaks out of the loop.
    for op in operations.iter() {
        merkle = match op {
            MerkleOperation::Add { data } => {
                let batch = merkle.new_batch().add(hasher, data);
                let batch = merkle.with_mem(|mem| batch.merkleize(mem, hasher));
                let merkle = merkle.apply_batch(&batch).unwrap();
                leaves_data.push(*data);
                merkle
            }

            MerkleOperation::Flush => {
                raise_storage_ceiling(&mut max_leaves, &merkle);
                match merkle.flush().await {
                    Ok(merkle) => merkle,
                    Err(_) => break,
                }
            }

            MerkleOperation::Sync => {
                raise_storage_ceiling(&mut max_leaves, &merkle);
                match merkle.sync().await {
                    Err(_) => break,
                    Ok(merkle) => {
                        min_leaves = merkle.leaves().as_u64();
                        max_leaves = min_leaves;
                        min_pruned = merkle.bounds().start.as_u64();
                        max_pruned = min_pruned;
                        merkle
                    }
                }
            }

            MerkleOperation::PruneToLoc { loc } => {
                let leaves = *merkle.leaves();
                let safe_loc = *loc % (leaves + 1);
                let target = Location::<F>::new(safe_loc);

                if target > merkle.bounds().start {
                    raise_storage_ceiling(&mut max_leaves, &merkle);
                    let merkle = match merkle.sync().await {
                        Err(_) => break,
                        Ok(merkle) => merkle,
                    };
                    min_leaves = merkle.leaves().as_u64();
                    max_leaves = min_leaves;
                    min_pruned = merkle.bounds().start.as_u64();
                    max_pruned = min_pruned;
                    match merkle.prune(target).await {
                        Err(_) => {
                            max_pruned = max_pruned.max(target.as_u64());
                            break;
                        }
                        Ok(merkle) => {
                            min_leaves = merkle.leaves().as_u64();
                            max_leaves = min_leaves;
                            min_pruned = merkle.bounds().start.as_u64();
                            max_pruned = min_pruned;
                            merkle
                        }
                    }
                } else {
                    merkle
                }
            }

            MerkleOperation::PruneAll => {
                let leaves = merkle.leaves();

                if leaves.as_u64() != 0 && merkle.bounds().start < *leaves {
                    raise_storage_ceiling(&mut max_leaves, &merkle);
                    let merkle = match merkle.sync().await {
                        Err(_) => break,
                        Ok(merkle) => merkle,
                    };
                    min_leaves = merkle.leaves().as_u64();
                    max_leaves = min_leaves;
                    min_pruned = merkle.bounds().start.as_u64();
                    max_pruned = min_pruned;
                    match merkle.prune_all().await {
                        Err(_) => {
                            max_pruned = max_pruned.max(leaves.as_u64());
                            break;
                        }
                        Ok(merkle) => {
                            min_leaves = merkle.leaves().as_u64();
                            max_leaves = min_leaves;
                            min_pruned = merkle.bounds().start.as_u64();
                            max_pruned = min_pruned;
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
        min_leaves,
        max_leaves,
        min_pruned,
        max_pruned,
        leaves_data,
    }
}

fn fuzz_family<F: MerkleFamily>(input: &FuzzInput, suffix: &str) {
    let page_size = NonZeroU16::new(input.page_size).unwrap();
    let page_cache_size = NonZeroUsize::new(input.page_cache_size).unwrap();
    let items_per_blob = input.items_per_blob;
    let write_buffer = NonZeroUsize::new(input.write_buffer).unwrap();
    let partition_suffix = format!("crash-{suffix}");
    let runner = fuzz_runner(&input.raw_bytes);
    let operations = input.operations.clone();
    let sync_failure_rate = input.sync_failure_rate;
    let write_failure_rate = input.write_failure_rate;

    // Phase 1: Execute operations with fault injection until crash
    let (mut expected, checkpoint) = runner.start_and_recover(|ctx| {
        let partition_suffix = partition_suffix.clone();
        let operations = operations.clone();
        async move {
            let hasher = StandardHasher::<Sha256>::new(Bagging::ForwardFold);
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
                ),
            )
            .await
            .unwrap();

            let storage_fault_cfg = ctx.storage_fault_config();
            *storage_fault_cfg.write() = deterministic::FaultConfig {
                sync_rate: Some(sync_failure_rate),
                write_rate: Some(write_failure_rate),
                partial_write_rate: Some(1.0),
                ..Default::default()
            };

            run_operations(merkle, &hasher, &operations).await
        }
    });

    // Recover and verify both structural bounds and the root for the recovered leaf prefix.
    let verify_suffix = partition_suffix.clone();
    let (expected, checkpoint) =
        deterministic::Runner::from(checkpoint).start_and_recover(|ctx| async move {
            *ctx.storage_fault_config().write() = deterministic::FaultConfig::default();

            let hasher = StandardHasher::<Sha256>::new(Bagging::ForwardFold);
            let merkle = Merkle::<F>::init(
                ctx.child("recovered"),
                &hasher,
                merkle_config(
                    &verify_suffix,
                    &ctx,
                    page_size,
                    page_cache_size,
                    items_per_blob,
                    write_buffer,
                ),
            )
            .await
            .expect("recovery should succeed");
            verify_recovery(&merkle, &hasher, &expected, items_per_blob).await;

            // Add and durably sync a sentinel after recovery.
            let sentinel = [0xABu8; DATA_SIZE];
            let batch = merkle.new_batch().add(&hasher, &sentinel);
            let batch = merkle.with_mem(|mem| batch.merkleize(mem, &hasher));
            let merkle = merkle.apply_batch(&batch).unwrap();
            let merkle = merkle.sync().await.expect("sentinel sync should succeed");
            expected
                .leaves_data
                .truncate((merkle.leaves().as_u64() - 1) as usize);
            expected.leaves_data.push(sentinel);
            pin_durable(&mut expected, &merkle);
            expected
        });

    deterministic::Runner::from(checkpoint).start(|ctx| async move {
        let hasher = StandardHasher::<Sha256>::new(Bagging::ForwardFold);
        let merkle = Merkle::<F>::init(
            ctx.child("sentinel"),
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
        .expect("sentinel recovery should succeed");
        verify_recovery(&merkle, &hasher, &expected, items_per_blob).await;
        merkle
            .destroy()
            .await
            .expect("cleanup destroy must succeed");
    });
}

fn fuzz(input: FuzzInput) {
    match input.family {
        FamilyType::Mmr => fuzz_family::<mmr::Family>(&input, "mmr"),
        FamilyType::Mmb => fuzz_family::<mmb::Family>(&input, "mmb"),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});

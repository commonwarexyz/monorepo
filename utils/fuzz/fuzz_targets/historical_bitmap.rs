#![no_main]

//! Fuzz test for Historical bitmap
//!
//! # Purpose
//! Verify Historical bitmap correctness via ground truth comparison. The fuzzer applies
//! random sequences of batch operations to both a Historical bitmap and a parallel Prunable
//! bitmap (ground truth), then verifies that historical reconstruction matches the saved
//! ground truth states.
//!
//! # Strategy
//! 1. Generate random sequence of commits, each containing multiple operations
//! 2. Apply operations in parallel to Historical (via batches) and Prunable (directly)
//! 3. Save ground truth snapshots after each commit
//! 4. Verify that `get_at_commit()` reconstruction matches ground truth for selected commits
//!
//! # Constraints
//! - Max 100 commits per fuzz input
//! - Max 100 operations per commit
//! - All commits are verified for correctness against ground truth
//! - Operations that would violate invariants are skipped (not an error)

use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::bitmap::{historical::BitMap, Prunable};
use libfuzzer_sys::fuzz_target;

/// Maximum number of commits in a single fuzz input
const MAX_COMMITS: usize = 100;
/// Maximum operations per commit
const MAX_OPS_PER_COMMIT: usize = 100;
/// Chunk size in bits for our test bitmap
const CHUNK_SIZE_BITS: u64 = 32; // Prunable::<4>::CHUNK_SIZE_BITS

/// A batch operation to apply to the bitmap
#[derive(Arbitrary, Debug, Clone)]
enum BatchOp {
    /// Push a bit to the end
    Push(bool),
    /// Pop the last bit
    Pop,
    /// Set a bit at a specific offset
    SetBit { bit: u64, value: bool },
    /// Prune chunks up to the specified chunk boundary
    PruneToChunk { chunk: u8 },
}

/// Fuzz input containing commits (each commit is a sequence of operations)
#[derive(Debug)]
struct FuzzInput {
    /// Commits to execute (each Vec<BatchOp> is one commit)
    commits: Vec<Vec<BatchOp>>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // Cap commits
        let num_commits = u.int_in_range(0..=MAX_COMMITS)?;
        let mut commits = Vec::with_capacity(num_commits);

        for _ in 0..num_commits {
            let num_ops = u.int_in_range(0..=MAX_OPS_PER_COMMIT)?;
            let mut operations = Vec::with_capacity(num_ops);
            for _ in 0..num_ops {
                operations.push(BatchOp::arbitrary(u)?);
            }
            commits.push(operations);
        }

        Ok(FuzzInput { commits })
    }
}

/// Apply a single operation to both batch and ground truth
fn apply_op(
    batch: &mut commonware_utils::bitmap::historical::BatchGuard<4>,
    ground_truth: &mut Prunable<4>,
    op: &BatchOp,
    current_len: &mut u64,
    current_pruned: &mut usize,
) {
    match op {
        BatchOp::Push(value) => {
            batch.push(*value);
            ground_truth.push(*value);
            *current_len += 1;
        }

        BatchOp::Pop => {
            // Can't pop from empty bitmap
            if *current_len == 0 {
                return;
            }

            // Can't pop into pruned region
            let chunk_idx = Prunable::<4>::unpruned_chunk(*current_len - 1);
            if chunk_idx < *current_pruned {
                return;
            }

            batch.pop();
            ground_truth.pop();
            *current_len -= 1;
        }

        BatchOp::SetBit { bit, value } => {
            // Bit must be within bounds
            if *bit >= *current_len {
                return;
            }

            // Bit's chunk must not be pruned
            let chunk_idx = Prunable::<4>::unpruned_chunk(*bit);
            if chunk_idx < *current_pruned {
                return;
            }

            batch.set_bit(*bit, *value);
            ground_truth.set_bit(*bit, *value);
        }

        BatchOp::PruneToChunk { chunk } => {
            let target_chunk = *chunk as usize;

            // Can't prune past current pruned point
            if target_chunk <= *current_pruned {
                return;
            }

            // Can't prune at or beyond the last chunk (must keep at least some data)
            let total_chunks = (*current_len / CHUNK_SIZE_BITS) as usize;
            if total_chunks == 0 || target_chunk >= total_chunks {
                return;
            }

            let prune_to_bit = (target_chunk as u64) * CHUNK_SIZE_BITS;
            batch.prune_to_bit(prune_to_bit);
            ground_truth.prune_to_bit(prune_to_bit);
            *current_pruned = target_chunk;
        }
    }
}

/// Main fuzzer function
fn fuzz(input: FuzzInput) {
    // Initialize Historical and ground truth storage
    let mut bitmap: BitMap<4> = BitMap::new();
    let mut commits: Vec<(u64, Prunable<4>)> = Vec::new();

    // Initialize ground truth bitmap
    let mut ground_truth = Prunable::<4>::new();

    // Process each commit
    for (commit_number, commit) in input.commits.iter().enumerate() {
        let commit_number = commit_number as u64;

        // Track state within this batch
        let mut current_len = ground_truth.len();
        let mut current_pruned = ground_truth.pruned_chunks();

        // Start batch
        let mut batch = bitmap.start_batch();

        // Apply operations
        for op in commit {
            apply_op(
                &mut batch,
                &mut ground_truth,
                op,
                &mut current_len,
                &mut current_pruned,
            );
        }

        // Commit the batch
        batch.commit(commit_number).unwrap();

        // Save checkpoint
        commits.push((commit_number, ground_truth.clone()));
    }

    // Verify all commits
    for (commit_num, expected) in &commits {
        // Reconstruct historical state
        // This should never fail since we committed successfully and never prune commit history
        let reconstructed = bitmap
            .get_at_commit(*commit_num)
            .expect("commit must exist in history");

        // Verify equality
        assert_eq!(
            reconstructed.len(),
            expected.len(),
            "Length mismatch at commit {commit_num}"
        );
        assert_eq!(
            reconstructed.pruned_chunks(),
            expected.pruned_chunks(),
            "Pruned chunks mismatch at commit {commit_num}"
        );

        let start_bit = reconstructed.pruned_chunks() as u64 * CHUNK_SIZE_BITS;
        for bit in start_bit..expected.len() {
            let expected_val = expected.get_bit(bit);
            let actual_val = reconstructed.get_bit(bit);
            assert_eq!(
                actual_val,
                expected_val,
                "Bit {bit} mismatch at commit {commit_num} (expected {expected_val}, got {actual_val})"
            );
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});

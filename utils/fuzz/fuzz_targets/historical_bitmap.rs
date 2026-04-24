#![no_main]

//! Fuzz test for Historical bitmap
//!
//! # Purpose
//! Verify Historical bitmap correctness via comparison with a reference Prunable bitmap.
//! The fuzzer applies random sequences of operations to both a Historical bitmap and a
//! parallel Prunable bitmap (the expected state), then verifies that historical
//! reconstruction matches the saved expected states.
//!
//! # Strategy
//! 1. Generate random sequence of commits, each containing multiple operations
//! 2. Apply operations in parallel to Historical and Prunable (expected)
//! 3. Save expected state snapshots after each commit
//! 4. Verify that `get_at_commit()` reconstruction matches expected for all commits
//!
//! # Constraints
//! - Max 100 commits per fuzz input
//! - Max 100 operations per commit
//! - All commits are verified for correctness against expected state
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

/// An operation to apply to the bitmap
#[derive(Arbitrary, Debug, Clone)]
enum Op {
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
    /// Commits to execute (each Vec<Op> is one commit)
    commits: Vec<Vec<Op>>,
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
                operations.push(Op::arbitrary(u)?);
            }
            commits.push(operations);
        }

        Ok(FuzzInput { commits })
    }
}

/// Apply a single operation to both dirty bitmap and expected bitmap.
fn apply_op(
    dirty: &mut commonware_utils::bitmap::historical::BitMap<
        4,
        commonware_utils::bitmap::historical::Dirty<4>,
    >,
    expected: &mut Prunable<4>,
    op: &Op,
    current_len: &mut u64,
    current_pruned: &mut usize,
) {
    match op {
        Op::Push(value) => {
            dirty.push(*value);
            expected.push(*value);
            *current_len += 1;
        }

        Op::Pop => {
            // Can't pop from empty bitmap
            if *current_len == 0 {
                return;
            }

            // Can't pop into pruned region
            let chunk_idx = Prunable::<4>::to_chunk_index(*current_len - 1);
            if chunk_idx < *current_pruned {
                return;
            }

            dirty.pop();
            expected.pop();
            *current_len -= 1;
        }

        Op::SetBit { bit, value } => {
            // Bit must be within bounds
            if *bit >= *current_len {
                return;
            }

            // Bit's chunk must not be pruned
            let chunk_idx = Prunable::<4>::to_chunk_index(*bit);
            if chunk_idx < *current_pruned {
                return;
            }

            dirty.set_bit(*bit, *value);
            expected.set_bit(*bit, *value);
        }

        Op::PruneToChunk { chunk } => {
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
            dirty.prune_to_bit(prune_to_bit);
            expected.prune_to_bit(prune_to_bit);
            *current_pruned = target_chunk;
        }
    }
}

/// Main fuzzer function
fn fuzz(input: FuzzInput) {
    // Initialize Historical bitmap and expected state storage
    let mut bitmap: BitMap<4> = BitMap::new();
    let mut commits: Vec<(u64, Prunable<4>)> = Vec::new();

    // Initialize expected state bitmap
    let mut expected = Prunable::<4>::new();

    // Process each commit
    for (commit_number, commit) in input.commits.iter().enumerate() {
        let commit_number = commit_number as u64;

        // Track state within this dirty state
        let mut current_len = expected.len();
        let mut current_pruned = expected.pruned_chunks();

        // Transition to dirty state
        let mut dirty = bitmap.into_dirty();

        // Apply operations
        for op in commit {
            apply_op(
                &mut dirty,
                &mut expected,
                op,
                &mut current_len,
                &mut current_pruned,
            );
        }

        // Commit and transition back to clean state
        bitmap = dirty.commit(commit_number).unwrap();

        // Save checkpoint
        commits.push((commit_number, expected.clone()));
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

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
    /// Push a full byte (8 bits) to the end
    PushByte(u8),
    /// Push a full chunk (N bytes) to the end
    PushChunk([u8; 4]),
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
    /// Chunks to pre-prune when constructing the subject: zero exercises `Default`,
    /// non-zero exercises `new_with_pruned_chunks`.
    initial_pruned_chunks: u8,
    /// Commits to execute (each Vec<Op> is one commit)
    commits: Vec<Vec<Op>>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let initial_pruned_chunks = u8::arbitrary(u)?;

        // At least one commit, each with at least one op (never an empty stream).
        let num_commits = u.int_in_range(1..=MAX_COMMITS)?;
        let mut commits = Vec::with_capacity(num_commits);
        for _ in 0..num_commits {
            let num_ops = u.int_in_range(1..=MAX_OPS_PER_COMMIT)?;
            let mut operations = Vec::with_capacity(num_ops);
            for _ in 0..num_ops {
                operations.push(Op::arbitrary(u)?);
            }
            commits.push(operations);
        }

        Ok(FuzzInput {
            initial_pruned_chunks,
            commits,
        })
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

            // Read-through getter: appended bit must reflect the pushed value.
            assert_eq!(
                dirty.get_bit(*current_len - 1),
                *value,
                "dirty.get_bit on freshly pushed bit"
            );
            // Projected length must track the expected bitmap exactly.
            assert_eq!(dirty.len(), *current_len, "dirty.len after push");
            assert_eq!(
                dirty.is_empty(),
                *current_len == 0,
                "dirty.is_empty after push"
            );
        }

        Op::PushByte(byte) => {
            // The reference Prunable::push_byte requires byte alignment; mirror only then.
            if !current_len.is_multiple_of(8) {
                return;
            }
            dirty.push_byte(*byte);
            expected.push_byte(*byte);
            *current_len += 8;

            // Each appended bit must read back per the byte's bit layout.
            for i in 0..8u64 {
                let expected_bit = (*byte >> i) & 1 == 1;
                assert_eq!(
                    dirty.get_bit(*current_len - 8 + i),
                    expected_bit,
                    "dirty.get_bit on bit {i} of pushed byte"
                );
            }
            assert_eq!(dirty.len(), *current_len, "dirty.len after push_byte");
        }

        Op::PushChunk(chunk) => {
            // The reference Prunable::push_chunk requires chunk alignment; mirror only then.
            if !current_len.is_multiple_of(CHUNK_SIZE_BITS) {
                return;
            }
            dirty.push_chunk(chunk);
            expected.push_chunk(chunk);
            *current_len += CHUNK_SIZE_BITS;

            // The newly appended chunk must reconstruct to the pushed bytes via get_chunk.
            let chunk_start = *current_len - CHUNK_SIZE_BITS;
            assert_eq!(
                dirty.get_chunk(chunk_start),
                *chunk,
                "dirty.get_chunk on freshly pushed chunk"
            );
            assert_eq!(dirty.len(), *current_len, "dirty.len after push_chunk");
            assert_eq!(
                dirty.pruned_chunks(),
                *current_pruned,
                "dirty.pruned_chunks after push_chunk"
            );
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

            // Read-through getter must observe the modification immediately.
            assert_eq!(dirty.get_bit(*bit), *value, "dirty.get_bit after set_bit");
            // The chunk containing the modified bit must reconstruct to match expected.
            assert_eq!(
                dirty.get_chunk(*bit),
                *expected.get_chunk_containing(*bit),
                "dirty.get_chunk after set_bit"
            );
        }

        Op::PruneToChunk { chunk } => {
            let target_chunk = *chunk as usize;

            // Can't prune past current pruned point
            if target_chunk <= *current_pruned {
                // Pruning to an already-pruned chunk is a no-op; exercise that branch
                // and assert it leaves the projected length and pruned count untouched.
                let len_before = dirty.len();
                let pruned_before = dirty.pruned_chunks();
                dirty.prune_to_bit((target_chunk as u64) * CHUNK_SIZE_BITS);
                assert_eq!(dirty.len(), len_before, "prune no-op changed len");
                assert_eq!(
                    dirty.pruned_chunks(),
                    pruned_before,
                    "prune no-op changed pruned_chunks"
                );
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
    // Construct the subject pre-pruned (or empty) per the fuzzer input: a zero count
    // exercises `Default`, a non-zero count exercises `new_with_pruned_chunks`.
    let pruned = (input.initial_pruned_chunks % 8) as usize;
    let (mut bitmap, mut expected): (BitMap<4>, Prunable<4>) = if pruned == 0 {
        (BitMap::default(), Prunable::new())
    } else {
        (
            BitMap::new_with_pruned_chunks(pruned).unwrap(),
            Prunable::new_with_pruned_chunks(pruned).unwrap(),
        )
    };
    let mut commits: Vec<(u64, Prunable<4>)> = Vec::new();

    // Process each commit, alternating between the explicit dirty/commit path and the
    // closure-based `apply_batch` path so both commit APIs ride on the same op stream.
    for (commit_number, commit) in input.commits.iter().enumerate() {
        let commit_number = commit_number as u64;
        let mut current_len = expected.len();
        let mut current_pruned = expected.pruned_chunks();

        if commit_number.is_multiple_of(2) {
            let mut dirty = bitmap.into_dirty();
            for op in commit {
                apply_op(
                    &mut dirty,
                    &mut expected,
                    op,
                    &mut current_len,
                    &mut current_pruned,
                );
            }
            bitmap = dirty.commit(commit_number).unwrap();
        } else {
            bitmap = bitmap
                .apply_batch(commit_number, |dirty| {
                    for op in commit {
                        apply_op(
                            dirty,
                            &mut expected,
                            op,
                            &mut current_len,
                            &mut current_pruned,
                        );
                    }
                })
                .unwrap();
        }

        commits.push((commit_number, expected.clone()));
    }

    // Re-committing the latest number is non-monotonic and must be rejected.
    let latest = bitmap.latest_commit().expect("at least one commit");
    let mut stale = bitmap.clone().into_dirty();
    stale.push(true);
    match stale.commit(latest).unwrap_err() {
        commonware_utils::bitmap::historical::Error::NonMonotonicCommit {
            previous,
            attempted,
        } => {
            assert_eq!(previous, latest, "non-monotonic previous commit");
            assert_eq!(attempted, latest, "non-monotonic attempted commit");
        }
        other => panic!("expected NonMonotonicCommit, got {other:?}"),
    }

    // Aborting pending mutations must leave HEAD unchanged.
    let len_before = bitmap.len();
    let pruned_before = bitmap.pruned_chunks();
    let mut dirty = bitmap.into_dirty();
    dirty.push(true);
    dirty.push(false);
    bitmap = dirty.abort();
    assert_eq!(bitmap.len(), len_before, "abort changed HEAD len");
    assert_eq!(
        bitmap.pruned_chunks(),
        pruned_before,
        "abort changed HEAD pruned_chunks"
    );

    // The final clean bitmap's HEAD getters must match the final expected bitmap.
    assert_eq!(bitmap.len(), expected.len(), "clean len mismatch");
    assert_eq!(
        bitmap.is_empty(),
        expected.is_empty(),
        "clean is_empty mismatch"
    );
    assert_eq!(
        bitmap.pruned_chunks(),
        expected.pruned_chunks(),
        "clean pruned_chunks mismatch"
    );
    // current() exposes the HEAD Prunable; its length must match the model.
    let head = bitmap.current();
    assert_eq!(head.len(), expected.len(), "clean current() len mismatch");
    let head_start = bitmap.pruned_chunks() as u64 * CHUNK_SIZE_BITS;
    for bit in head_start..bitmap.len() {
        assert_eq!(
            bitmap.get_bit(bit),
            expected.get_bit(bit),
            "clean get_bit mismatch at {bit}"
        );
        assert_eq!(
            bitmap.get_chunk_containing(bit),
            expected.get_chunk_containing(bit),
            "clean get_chunk_containing mismatch at {bit}"
        );
    }

    // Commit-set queries must agree with the committed model.
    let model_commits: Vec<u64> = commits.iter().map(|(c, _)| *c).collect();
    assert_eq!(
        bitmap.commits().collect::<Vec<u64>>(),
        model_commits,
        "commits() must list every commit in ascending order"
    );
    assert_eq!(
        bitmap.latest_commit(),
        model_commits.last().copied(),
        "latest_commit mismatch"
    );
    assert_eq!(
        bitmap.earliest_commit(),
        model_commits.first().copied(),
        "earliest_commit mismatch"
    );
    // The reserved commit number and any commit one-past-the-end never exist.
    assert!(
        !bitmap.commit_exists(u64::MAX),
        "u64::MAX must never be a commit"
    );
    assert!(
        bitmap.get_at_commit(u64::MAX).is_none(),
        "get_at_commit(u64::MAX) must be None"
    );
    let absent = commits.len() as u64;
    assert!(
        !bitmap.commit_exists(absent),
        "uncommitted number must not exist"
    );
    assert!(
        bitmap.get_at_commit(absent).is_none(),
        "get_at_commit on absent commit must be None"
    );

    // Verify all commits
    for (commit_num, expected) in &commits {
        // Each committed number must report as existing.
        assert!(
            bitmap.commit_exists(*commit_num),
            "commit_exists must be true for committed number {commit_num}"
        );

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

    // History management: prune the earliest half, then clear the remainder.
    if let Some(&(boundary, _)) = commits.get(commits.len() / 2) {
        let total = commits.len();
        let removed = bitmap.prune_commits_before(boundary);
        let expected_removed = commits.iter().filter(|(c, _)| *c < boundary).count();
        assert_eq!(
            removed, expected_removed,
            "prune_commits_before returned wrong removed count"
        );
        assert_eq!(
            bitmap.commits().count(),
            total - expected_removed,
            "remaining commit count after prune mismatch"
        );
        assert!(
            !bitmap.commit_exists(boundary.wrapping_sub(1)),
            "pruned commit must no longer exist"
        );
    }
    bitmap.clear_history();
    assert_eq!(
        bitmap.commits().count(),
        0,
        "clear_history must remove all commits"
    );
    assert!(bitmap.latest_commit().is_none(), "no commits after clear");
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});

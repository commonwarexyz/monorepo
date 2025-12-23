use super::*;
use crate::{bitmap::Prunable, hex};

/// Test basic batch lifecycle: creation, operations, commit, and abort.
#[test]
fn test_batch_lifecycle_and_operations() {
    // Empty initialization
    let mut bitmap: BitMap<4> = BitMap::new();
    assert_eq!(bitmap.len(), 0);
    assert!(bitmap.is_empty());
    assert_eq!(bitmap.commits().count(), 0);

    // Basic push and commit
    bitmap
        .with_batch(1, |batch| {
            batch.push(true).push(false).push(true);
        })
        .unwrap();
    assert_eq!(bitmap.len(), 3);
    assert!(bitmap.get_bit(0));
    assert!(!bitmap.get_bit(1));
    assert!(bitmap.get_bit(2));
    assert_eq!(bitmap.commits().count(), 1);

    // Batch abort (drop without commit)
    {
        let mut batch = bitmap.start_batch();
        batch.push(true).push(true);
        // Drop here - should abort
    }
    assert_eq!(bitmap.len(), 3); // Unchanged

    // Read-through semantics
    let mut batch = bitmap.start_batch();
    assert!(batch.get_bit(0)); // Read unmodified
    batch.set_bit(1, true); // Modify
    assert!(batch.get_bit(1)); // See modification in batch
    batch.push(false); // Append
    assert!(!batch.get_bit(3)); // See appended bit
    batch.commit(2).unwrap();

    // After commit, changes persisted
    assert_eq!(bitmap.len(), 4);
    assert!(bitmap.get_bit(1));
    assert!(!bitmap.get_bit(3));

    // Empty batch commit
    bitmap.with_batch(3, |_batch| {}).unwrap();
    assert_eq!(bitmap.len(), 4);
    assert!(bitmap.commit_exists(3));

    // Method chaining with batch.set_bit()
    bitmap
        .with_batch(4, |batch| {
            batch.set_bit(0, false).push_byte(0xAA);
        })
        .unwrap();
    assert_eq!(bitmap.len(), 12); // 4 + 8 bits
    assert!(!bitmap.get_bit(0)); // Modified
}

/// Test that only one batch can be active at a time.
#[test]
#[should_panic(expected = "batch already active")]
fn test_cannot_start_batch_when_active() {
    let mut bitmap: BitMap<4> = BitMap::new();
    let _batch1 = bitmap.start_batch();
    // This should panic because a batch is already active
    // We need to use core::mem::forget to prevent drop from clearing the batch
    core::mem::forget(_batch1);
    let _batch2 = bitmap.start_batch();
}

/// Test batch operations: push, pop, prune, push_byte, push_chunk, and get_chunk.
#[test]
fn test_batch_operations_push_pop_prune() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Push, modify, and append operations
    bitmap
        .with_batch(1, |batch| {
            batch.push(false).push(false).push(false);
        })
        .unwrap();

    bitmap
        .with_batch(2, |batch| {
            batch.set_bit(0, true); // Modify
            batch.set_bit(1, true); // Modify
            batch.push(true); // Append
            batch.push(true); // Append
        })
        .unwrap();

    assert_eq!(bitmap.len(), 5);
    assert!(bitmap.get_bit(0));
    assert!(bitmap.get_bit(1));
    assert!(!bitmap.get_bit(2));

    // Pop operations
    bitmap
        .with_batch(3, |batch| {
            batch.push(false); // Add bit 5
            let popped = batch.pop(); // Remove it
            assert!(!popped);
            assert_eq!(batch.len(), 5); // Back to original
        })
        .unwrap();

    // Bulk push operations (push_chunk, push_byte)
    // Start fresh with 32 bits so chunks align cleanly
    let mut bitmap: BitMap<4> = BitMap::new();
    bitmap
        .with_batch(1, |b| {
            b.push_chunk(&hex!("0x00000000"));
        })
        .unwrap();

    bitmap
        .with_batch(2, |batch| {
            batch.push_chunk(&hex!("0xAABBCCDD")); // 32 bits at offset 32
            batch.push_byte(0xFF); // 8 bits at offset 64
        })
        .unwrap();

    assert_eq!(bitmap.len(), 72); // 32 + 32 + 8
    let chunk = bitmap.get_chunk_containing(32); // Read second chunk
    assert_eq!(chunk, &hex!("0xAABBCCDD"));
    for i in 64..72 {
        assert!(bitmap.get_bit(i)); // Verify pushed byte
    }

    // get_chunk with modifications in batch
    let mut batch = bitmap.start_batch();
    batch.set_bit(32, true); // First bit of second chunk
    batch.set_bit(39, true); // 8th bit of second chunk
    let chunk = batch.get_chunk(32);
    assert_eq!(chunk[0] & 0x01, 0x01); // bit 32 (0 in chunk) set
    assert_eq!(chunk[0] & 0x80, 0x80); // bit 39 (7 in chunk) set
    batch.commit(3).unwrap();

    // Prune operations
    bitmap
        .with_batch(4, |batch| {
            batch.prune_to_bit(32);
        })
        .unwrap();

    assert_eq!(bitmap.len(), 72); // Length unchanged
    assert_eq!(bitmap.pruned_chunks(), 1); // First chunk pruned
}

/// Test commit history management.
#[test]
fn test_commit_history_management() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Validate monotonic commit numbers
    bitmap
        .with_batch(5, |b| {
            b.push(true);
        })
        .unwrap();

    let err = bitmap
        .with_batch(5, |b| {
            b.push(false);
        })
        .unwrap_err();
    match err {
        Error::NonMonotonicCommit {
            previous,
            attempted,
        } => {
            assert_eq!(previous, 5);
            assert_eq!(attempted, 5);
        }
        _ => panic!("Expected NonMonotonicCommit error"),
    }

    let err = bitmap
        .with_batch(3, |b| {
            b.push(false);
        })
        .unwrap_err();
    match err {
        Error::NonMonotonicCommit {
            previous,
            attempted,
        } => {
            assert_eq!(previous, 5);
            assert_eq!(attempted, 3);
        }
        _ => panic!("Expected NonMonotonicCommit error"),
    }

    bitmap
        .with_batch(10, |b| {
            b.push(false);
        })
        .unwrap(); // Should succeed

    // Commit queries (need fresh instance)
    let mut bitmap: BitMap<4> = BitMap::new();
    assert!(bitmap.earliest_commit().is_none());
    assert!(bitmap.latest_commit().is_none());
    for i in 1..=5 {
        bitmap
            .with_batch(i * 10, |b| {
                b.push(true);
            })
            .unwrap();
    }

    assert_eq!(bitmap.earliest_commit(), Some(10));
    assert_eq!(bitmap.latest_commit(), Some(50));
    assert!(bitmap.commit_exists(30));
    assert!(!bitmap.commit_exists(25));

    let commits: Vec<u64> = bitmap.commits().collect();
    assert_eq!(commits, vec![10, 20, 30, 40, 50]);

    // Prune commits
    let removed = bitmap.prune_commits_before(30);
    assert_eq!(removed, 2);
    assert_eq!(bitmap.commits().count(), 3);

    // Clear history
    bitmap.clear_history();
    assert_eq!(bitmap.commits().count(), 0);
    assert!(bitmap.earliest_commit().is_none());
    assert!(bitmap.latest_commit().is_none());
    assert_eq!(bitmap.len(), 5); // Current state preserved
}

/// Test historical reconstruction with bit modifications across multiple commits.
#[test]
fn test_historical_reconstruction_with_modifications() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Simple modification scenario
    bitmap
        .with_batch(1, |b| {
            b.push(true).push(false).push(true);
        })
        .unwrap();
    bitmap
        .with_batch(2, |b| {
            b.set_bit(0, false);
            b.push(false);
        })
        .unwrap();

    let state_at_1 = bitmap.get_at_commit(1).unwrap();
    assert_eq!(state_at_1.len(), 3);
    assert!(state_at_1.get_bit(0)); // Original true
    assert!(!state_at_1.get_bit(1));

    let state_at_2 = bitmap.get_at_commit(2).unwrap();
    assert_eq!(state_at_2.len(), 4);
    assert!(!state_at_2.get_bit(0)); // Modified to false
    assert!(!state_at_2.get_bit(3)); // Appended

    // Multiple successive modifications
    let mut bitmap: BitMap<4> = BitMap::new();
    bitmap
        .with_batch(1, |b| {
            b.push_chunk(&hex!("0xFF00FF00"));
        })
        .unwrap();
    bitmap
        .with_batch(2, |b| {
            b.set_bit(0, false);
            b.set_bit(8, true);
        })
        .unwrap();
    bitmap
        .with_batch(3, |b| {
            b.set_bit(16, false);
            b.set_bit(24, true);
        })
        .unwrap();

    let state_at_1 = bitmap.get_at_commit(1).unwrap();
    assert!(state_at_1.get_bit(0));
    assert!(!state_at_1.get_bit(8));

    let state_at_2 = bitmap.get_at_commit(2).unwrap();
    assert!(!state_at_2.get_bit(0)); // Modified
    assert!(state_at_2.get_bit(8)); // Modified
    assert!(state_at_2.get_bit(16)); // Not yet modified

    let state_at_3 = bitmap.get_at_commit(3).unwrap();
    assert!(!state_at_3.get_bit(16)); // Modified
    assert!(state_at_3.get_bit(24)); // Modified

    // Modifications combined with appends
    let mut bitmap: BitMap<4> = BitMap::new();
    bitmap
        .with_batch(1, |b| {
            for _ in 0..4 {
                b.push(true);
            }
        })
        .unwrap();
    bitmap
        .with_batch(2, |b| {
            b.set_bit(0, false).set_bit(2, false);
            b.push(false).push(false);
        })
        .unwrap();
    bitmap
        .with_batch(3, |b| {
            b.set_bit(1, false).set_bit(3, false);
            b.push(true).push(true);
        })
        .unwrap();

    let state_at_1 = bitmap.get_at_commit(1).unwrap();
    assert_eq!(state_at_1.len(), 4);
    for i in 0..4 {
        assert!(state_at_1.get_bit(i)); // All true
    }

    let state_at_2 = bitmap.get_at_commit(2).unwrap();
    assert_eq!(state_at_2.len(), 6);
    assert!(!state_at_2.get_bit(0)); // Modified
    assert!(state_at_2.get_bit(1)); // Unchanged
    assert!(!state_at_2.get_bit(4)); // Appended false

    let state_at_3 = bitmap.get_at_commit(3).unwrap();
    assert_eq!(state_at_3.len(), 8);
    assert!(!state_at_3.get_bit(1)); // Modified in commit 3
    assert!(state_at_3.get_bit(6)); // Appended in commit 3
}

/// Test historical reconstruction with length-changing operations (appends and pops).
#[test]
fn test_historical_reconstruction_with_length_changes() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Pure append operations
    bitmap
        .with_batch(1, |b| {
            b.push(true).push(false);
        })
        .unwrap();
    bitmap
        .with_batch(2, |b| {
            b.push(true).push(true);
        })
        .unwrap();
    bitmap
        .with_batch(3, |b| {
            b.push(false).push(false);
        })
        .unwrap();

    assert_eq!(bitmap.get_at_commit(1).unwrap().len(), 2);
    assert_eq!(bitmap.get_at_commit(2).unwrap().len(), 4);
    assert_eq!(bitmap.get_at_commit(3).unwrap().len(), 6);

    // Pops followed by appends
    let mut bitmap: BitMap<4> = BitMap::new();
    bitmap
        .with_batch(1, |b| {
            for i in 0..5 {
                b.push(i % 2 == 0);
            }
        })
        .unwrap();
    bitmap
        .with_batch(2, |b| {
            b.pop();
            b.pop();
        })
        .unwrap();
    bitmap
        .with_batch(3, |b| {
            b.push(true).push(true).push(true);
        })
        .unwrap();

    let state_1 = bitmap.get_at_commit(1).unwrap();
    assert_eq!(state_1.len(), 5);
    assert!(state_1.get_bit(0)); // true
    assert!(!state_1.get_bit(1)); // false
    assert!(state_1.get_bit(4)); // true

    let state_2 = bitmap.get_at_commit(2).unwrap();
    assert_eq!(state_2.len(), 3);

    let state_3 = bitmap.get_at_commit(3).unwrap();
    assert_eq!(state_3.len(), 6);
    assert!(state_3.get_bit(3));
    assert!(state_3.get_bit(5));
}

/// Test historical reconstruction with bitmap chunk pruning.
#[test]
fn test_historical_reconstruction_with_pruning() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Commit 1: Create 64 bits (2 chunks), no pruning
    bitmap
        .with_batch(1, |b| {
            b.push_chunk(&hex!("0xAABBCCDD"));
            b.push_chunk(&hex!("0x11223344"));
        })
        .unwrap();

    // Commit 2: Prune first chunk
    bitmap
        .with_batch(2, |b| {
            b.prune_to_bit(32);
        })
        .unwrap();
    assert_eq!(bitmap.pruned_chunks(), 1);

    // Reconstruct state before pruning
    let state_at_1 = bitmap.get_at_commit(1).unwrap();
    assert_eq!(state_at_1.len(), 64);
    assert_eq!(state_at_1.pruned_chunks(), 0); // No pruning
    assert_eq!(state_at_1.get_chunk_containing(0), &hex!("0xAABBCCDD")); // Restored
    assert_eq!(state_at_1.get_chunk_containing(32), &hex!("0x11223344"));

    // Reconstruct state after pruning
    let state_at_2 = bitmap.get_at_commit(2).unwrap();
    assert_eq!(state_at_2.len(), 64);
    assert_eq!(state_at_2.pruned_chunks(), 1); // Pruning preserved
    assert_eq!(state_at_2.get_chunk_containing(32), &hex!("0x11223344"));
}

/// Test edge cases in historical reconstruction.
#[test]
fn test_historical_reconstruction_edge_cases() {
    let mut bitmap: BitMap<4> = BitMap::new();

    bitmap
        .with_batch(10, |b| {
            b.push(true);
        })
        .unwrap();

    // Nonexistent commits
    assert!(bitmap.get_at_commit(5).is_none());
    assert!(bitmap.get_at_commit(15).is_none());
    assert!(bitmap.get_at_commit(10).is_some());

    // After pruning commit history
    let mut bitmap: BitMap<4> = BitMap::new();
    for i in 1..=5 {
        bitmap
            .with_batch(i, |b| {
                for _ in 0..i {
                    b.push(true);
                }
            })
            .unwrap();
    }

    bitmap.prune_commits_before(3);

    // Cannot reconstruct pruned commits
    assert!(bitmap.get_at_commit(1).is_none());
    assert!(bitmap.get_at_commit(2).is_none());

    // Can reconstruct remaining commits
    assert!(bitmap.get_at_commit(3).is_some());
    assert!(bitmap.get_at_commit(4).is_some());
    assert_eq!(bitmap.get_at_commit(3).unwrap().len(), 6); // 1+2+3 bits
}

/// Test batch modifications on appended bits (regression tests).
#[test]
fn test_batch_modifications_on_appended_bits() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Modify appended bit in same batch
    bitmap
        .with_batch(1, |batch| {
            batch.push(true); // Append bit 0
            batch.set_bit(0, false); // Modify that appended bit
        })
        .unwrap();
    assert_eq!(bitmap.len(), 1);
    assert!(!bitmap.get_bit(0)); // Should be false after modification

    // Push, modify, then pop (should cancel out cleanly)
    bitmap
        .with_batch(2, |batch| {
            batch.push(true); // Append bit 1
            batch.set_bit(1, false); // Modify that appended bit
            batch.pop(); // Remove bit 1
        })
        .unwrap();
    assert_eq!(bitmap.len(), 1); // Only bit 0 remains
}

/// Test pop() behavior with batch modifications (regression tests).
#[test]
fn test_pop_behavior_with_modifications() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Create initial bits
    bitmap
        .with_batch(1, |b| {
            for _ in 0..10 {
                b.push(true);
            }
        })
        .unwrap();

    // pop() should return modified value
    let mut popped_value = true;
    bitmap
        .with_batch(2, |batch| {
            batch.set_bit(9, false); // Modify bit 9 in batch
            popped_value = batch.pop(); // Should return false (modified)
        })
        .unwrap();
    assert!(
        !popped_value,
        "pop() should return modified value, not original"
    );
}

/// Test reading popped bits should fail.
#[test]
#[should_panic(expected = "out of bounds")]
fn test_read_popped_bit_panics() {
    let mut bitmap: BitMap<4> = BitMap::new();
    bitmap
        .with_batch(1, |b| {
            for _ in 0..10 {
                b.push(true);
            }
        })
        .unwrap();

    let mut batch = bitmap.start_batch();
    batch.pop();
    batch.pop();
    batch.get_bit(8); // Should panic - bit 8 is now out of bounds
}

/// Test pruning beyond bitmap length should fail.
#[test]
#[should_panic(expected = "beyond projected length")]
fn test_prune_beyond_length_panics() {
    let mut bitmap: BitMap<4> = BitMap::new();
    bitmap
        .with_batch(1, |b| {
            for _ in 0..10 {
                b.push(true);
            }
        })
        .unwrap();

    let mut batch = bitmap.start_batch();
    batch.pop(); // projected_len = 9
    batch.prune_to_bit(100); // Should panic - bit 100 is beyond projected length
}

/// Test that get_chunk can read entirely appended chunks.
///
/// This tests the scenario where:
/// 1. We start with an empty (or short) bitmap
/// 2. We append bits that create a chunk entirely in the appended region
/// 3. We call get_chunk on that chunk
///
/// The bug is that when a chunk is entirely appended (chunk_start >= base_len),
/// the range_end calculation (chunk_end.min(base_len)) creates an empty range,
/// so all checks return false and we fall back to current.get_chunk(), which
/// panics because that chunk doesn't exist in current.
#[test]
fn test_get_chunk_on_appended_only_chunk() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Start with empty bitmap
    let mut batch = bitmap.start_batch();

    // Push 32 bits (fills chunk 0 entirely)
    for i in 0..32 {
        batch.push(i % 2 == 0); // Alternating pattern: true, false, true, false...
    }

    // Now try to read chunk 0 - this chunk is entirely appended
    let chunk = batch.get_chunk(0);

    // Verify the alternating pattern: true, false, true, false...
    assert_ne!(chunk[0] & 0x01, 0, "bit 0 should be true");
    assert_eq!(chunk[0] & 0x02, 0, "bit 1 should be false");
    assert_ne!(chunk[0] & 0x04, 0, "bit 2 should be true");
    assert_eq!(chunk[0] & 0x08, 0, "bit 3 should be false");

    // Overall pattern should be 0x55 (binary 01010101)
    assert_eq!(chunk[0], 0x55, "byte 0 should be 0x55");
}

/// Test that get_chunk zeros out bits beyond projected_len after pops.
///
/// This tests the scenario where:
/// 1. We have a chunk with all bits set
/// 2. We pop some bits from the end of that chunk
/// 3. We call get_chunk on that chunk
///
/// The bug is that get_chunk would return the full chunk from current without
/// zeroing out the popped bits, so readers see stale data that will be zeroed
/// after commit.
#[test]
fn test_pop_zeros_chunk_tail() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Setup: Create 33 bits (chunk 0 has bits 0-31 all true, chunk 1 has bit 32 true)
    bitmap
        .with_batch(1, |b| {
            for _ in 0..33 {
                b.push(true);
            }
        })
        .unwrap();

    // Start a new batch and pop 2 bits
    let mut batch = bitmap.start_batch();
    batch.pop(); // projected_len = 32
    batch.pop(); // projected_len = 31

    // Now bit 31 is out of bounds (projected_len = 31)
    // get_chunk(0) returns chunk 0, which contains bits 0-31
    let chunk = batch.get_chunk(0);

    // Bit 31 should be zeroed since it's >= projected_len
    let byte_31 = chunk[31 / 8]; // byte 3
    let bit_31_in_byte = 31 % 8; // bit 7
    let bit_31_set = (byte_31 >> bit_31_in_byte) & 1 == 1;

    assert!(!bit_31_set);
}

/// Test pruning a chunk that was just appended in the same batch.
///
/// This tests the scenario where:
/// 1. We have a bitmap with some bits (not chunk-aligned)
/// 2. We append enough bits to create a NEW chunk beyond what exists in current
/// 3. We immediately prune that new chunk
///
/// The bug is that prune_to_bit tries to capture chunk data from current,
/// but the new chunk only exists in appended_bits, causing a panic.
#[test]
fn test_prune_freshly_appended_chunk() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Start with 10 bits (chunk 0 is partial, no chunk 1)
    bitmap
        .with_batch(1, |b| {
            for _ in 0..10 {
                b.push(true);
            }
        })
        .unwrap();

    assert_eq!(bitmap.current().chunks_len(), 1); // Only chunk 0 exists

    // Now in a new batch, append 54 more bits
    // This creates chunk 1 (bits 32-63) entirely within the batch
    let mut batch = bitmap.start_batch();
    for _ in 0..54 {
        batch.push(true);
    }

    // projected_len = 64, we now have chunks 0 and 1
    // But chunk 1 is ONLY in appended_bits, not in current
    assert_eq!(batch.len(), 64);

    // Try to prune to bit 64 (prune chunks 0 and 1)
    // This should capture chunk 0 from current (OK)
    // But chunk 1 doesn't exist in current yet!
    batch.prune_to_bit(64);

    // Should commit successfully
    batch.commit(2).unwrap();
}

/// Test that batch reads correctly see appended bits after pops.
///
/// This tests the scenario where:
/// 1. We start with a bitmap of length N
/// 2. Pop some bits (reducing length to M < N)
/// 3. Push new bits (growing length back toward N)
/// 4. Read those newly pushed bits within the same batch
///
/// The bug was that `get_bit` and `get_chunk_containing` checked `bit >= base_len`
/// to identify appended bits, but after net pops, the appended region actually
/// starts at `projected_len - appended_bits.len()`, which is less than `base_len`.
/// This caused reads to fall through to the stale underlying bitmap instead of
/// reading from the batch's `appended_bits` vector.
#[test]
fn test_read_appended_bits_after_pops() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Setup: Create bitmap with 10 bits, all set to true
    bitmap
        .with_batch(1, |b| {
            for _ in 0..10 {
                b.push(true);
            }
        })
        .unwrap();

    // Start batch: pop 3 bits, then push 2 bits with value false
    let mut batch = bitmap.start_batch();
    batch.pop(); // projected_len = 9
    batch.pop(); // projected_len = 8
    batch.pop(); // projected_len = 7
    batch.push(false); // projected_len = 8, appended_bits = [false]
    batch.push(false); // projected_len = 9, appended_bits = [false, false]

    // The appended region is now [7, 9), not [10, 12)
    // Verify get_bit sees the new false values, not the old true values
    assert!(!batch.get_bit(7));
    assert!(!batch.get_bit(8));

    // Verify get_chunk also reconstructs correctly
    let chunk = batch.get_chunk(0); // Chunk containing bits 0..31
    assert_eq!(chunk[0] & 0x80, 0, "bit 7 should be false in chunk");
    assert_eq!(chunk[1] & 0x01, 0, "bit 8 should be false in chunk");

    // Also verify we can modify appended bits
    batch.set_bit(7, true);
    assert!(batch.get_bit(7));

    // Commit and verify the final state
    batch.commit(2).unwrap();
    assert_eq!(bitmap.len(), 9);
    assert!(bitmap.get_bit(7));
    assert!(!bitmap.get_bit(8));
}

/// Test historical reconstruction when current state has MORE pruning than target.
///
/// This tests the scenario where:
/// 1. We commit a state with some unpruned data
/// 2. We prune that data in a later commit
/// 3. We try to reconstruct the earlier state (which needs the now-pruned data)
///
/// The diff system should have captured the pruned chunk data as `ChunkDiff::Pruned`,
/// allowing reconstruction even though that chunk no longer exists in current state.
#[test]
fn test_reconstruct_less_pruned_from_more_pruned() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Commit 1: Create 64 bits (2 chunks) with pattern
    bitmap
        .with_batch(1, |b| {
            for i in 0..64 {
                b.push(i < 32); // First chunk all true, second chunk all false
            }
        })
        .unwrap();
    assert_eq!(bitmap.len(), 64);
    assert_eq!(bitmap.pruned_chunks(), 0);

    // Commit 2: Prune first chunk
    bitmap
        .with_batch(2, |b| {
            b.prune_to_bit(32); // Prune chunk 0
        })
        .unwrap();
    assert_eq!(bitmap.len(), 64);
    assert_eq!(bitmap.pruned_chunks(), 1);

    // Now reconstruct commit 1 (which has chunk 0 unpruned)
    // This requires getting chunk 0 from the diff, not from current state
    let reconstructed = bitmap
        .get_at_commit(1)
        .expect("should be able to reconstruct less-pruned state");

    assert_eq!(reconstructed.len(), 64);
    assert_eq!(reconstructed.pruned_chunks(), 0, "commit 1 had no pruning");

    // Verify the data is correct
    for i in 0..32 {
        assert!(reconstructed.get_bit(i));
    }
    for i in 32..64 {
        assert!(!reconstructed.get_bit(i));
    }
}

/// Test historical reconstruction when all non-pruned bits are in pruned chunks.
///
/// This tests the scenario where:
/// 1. We have a bitmap with some bits (e.g., 32 bits = 1 chunk)
/// 2. We prune all chunks (e.g., prune chunk 0, so only pruned metadata remains)
/// 3. We commit this state
/// 4. We try to reconstruct this historical state via `get_at_commit`
///
/// The bug was that `apply_reverse_diff` always computed `raw_last_chunk` from
/// `target_len - 1`, but when `target_len <= target_pruned * CHUNK_SIZE_BITS`,
/// this gives a chunk index that's less than `raw_first_chunk` (the first
/// unpruned chunk). The code then tried to access this pruned chunk from
/// `newer_state`, causing a panic. The fix is to detect this case early and
/// return an empty bitmap with the correct pruning metadata.
#[test]
fn test_reconstruct_fully_pruned_commit() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Commit 1: Create 32 bits (1 complete chunk)
    bitmap
        .with_batch(1, |b| {
            for i in 0..32 {
                b.push(i % 2 == 0); // Alternating pattern
            }
        })
        .unwrap();
    assert_eq!(bitmap.len(), 32);
    assert_eq!(bitmap.pruned_chunks(), 0);

    // Commit 2: Prune the entire chunk
    bitmap
        .with_batch(2, |b| {
            b.prune_to_bit(32); // Prune chunk 0 (bits 0..32)
        })
        .unwrap();
    assert_eq!(bitmap.len(), 32);
    assert_eq!(bitmap.pruned_chunks(), 1);

    // The bitmap now has 32 bits but they're all in pruned chunks
    // Try to reconstruct commit 2 - this should not panic
    let reconstructed = bitmap
        .get_at_commit(2)
        .expect("should be able to reconstruct fully pruned commit");

    assert_eq!(reconstructed.len(), 32, "length should match");
    assert_eq!(
        reconstructed.pruned_chunks(),
        1,
        "should have 1 pruned chunk"
    );

    // Also test reconstruction of commit 1 (before pruning)
    let before_prune = bitmap
        .get_at_commit(1)
        .expect("should be able to reconstruct pre-prune state");

    assert_eq!(before_prune.len(), 32);
    assert_eq!(before_prune.pruned_chunks(), 0);
    // Verify the alternating pattern
    for i in 0..32 {
        assert_eq!(before_prune.get_bit(i), i % 2 == 0);
    }
}

/// Verify historical bitmap reconstruction correctness by comparing to another bitmap.
///
/// This test creates a "ground truth" (`Prunable`) bitmap alongside the `Historical` bitmap.
/// Both bitmaps receive the same random operations. After each commit, we save the ground
/// truth state. At the end, we reconstruct each commit from the `Historical` bitmap and
/// verify it matches the saved ground truth state bit-for-bit.
fn test_randomized_helper<R: rand::Rng>(rng: &mut R) {
    // Test configuration
    const NUM_COMMITS: u64 = 20;
    const OPERATIONS_PER_COMMIT: usize = 32;
    const CHUNK_SIZE_BITS: u64 = Prunable::<4>::CHUNK_SIZE_BITS;

    // Operation probability thresholds (out of 100)
    // These define a probability distribution over different operations
    const PROB_PUSH: u64 = 55; // 0-54: 55% chance to push a new bit
    const PROB_MODIFY: u64 = 75; // 55-74: 20% chance to modify existing bit
    const PROB_POP: u64 = 90; // 75-89: 15% chance to pop last bit
    const PROB_PRUNE: u64 = 100; // 90-99: 10% chance to prune (if possible)

    let mut bitmap: BitMap<4> = BitMap::new();
    let mut ground_truth = Prunable::<4>::new();
    let mut checkpoints: Vec<(u64, Prunable<4>)> = Vec::new();

    // Perform random operations across multiple commits
    for commit_num in 0..NUM_COMMITS {
        let initial_len = ground_truth.len();
        let initial_pruned = ground_truth.pruned_chunks();

        bitmap
            .with_batch(commit_num, |batch| {
                // Track current state within this batch (changes as we apply operations)
                let mut current_len = initial_len;
                let mut current_pruned = initial_pruned;

                for _ in 0..OPERATIONS_PER_COMMIT {
                    // Pick a random operation based on probability distribution
                    let op_choice = rng.gen_range(0..100);

                    // Special case: if bitmap is empty, we can only push
                    if current_len == 0 {
                        let bit_value = rng.gen_bool(0.5);
                        batch.push(bit_value);
                        ground_truth.push(bit_value);
                        current_len += 1;
                        continue;
                    }

                    // Operation: PUSH (55% probability)
                    if op_choice < PROB_PUSH {
                        let bit_value = rng.gen_bool(0.5);
                        batch.push(bit_value);
                        ground_truth.push(bit_value);
                        current_len += 1;
                    }
                    // Operation: MODIFY existing bit (20% probability)
                    else if op_choice < PROB_MODIFY {
                        let bit = rng.gen_range(0..current_len);
                        let new_value = rng.gen_bool(0.5);

                        // Safety: Only modify bits that aren't pruned
                        let chunk_idx = Prunable::<4>::unpruned_chunk(bit);
                        if chunk_idx >= current_pruned {
                            batch.set_bit(bit, new_value);
                            ground_truth.set_bit(bit, new_value);
                        }
                    }
                    // Operation: POP last bit (15% probability)
                    else if op_choice < PROB_POP {
                        batch.pop();
                        ground_truth.pop();
                        current_len -= 1;
                    }
                    // Operation: PRUNE to random chunk boundary (10% probability)
                    else if op_choice < PROB_PRUNE {
                        // Calculate the maximum chunk we can prune to (keep at least 1 chunk of data)
                        let total_chunks = (current_len / CHUNK_SIZE_BITS) as usize;
                        let max_prune_chunk = total_chunks.saturating_sub(1);

                        // Only prune if there's at least one unpruned complete chunk we can prune
                        if max_prune_chunk > current_pruned {
                            // Randomly pick a chunk boundary to prune to (between current_pruned+1 and max)
                            let prune_chunk = rng.gen_range((current_pruned + 1)..=max_prune_chunk);
                            let prune_to = (prune_chunk as u64) * CHUNK_SIZE_BITS;

                            batch.prune_to_bit(prune_to);
                            ground_truth.prune_to_bit(prune_to);
                            current_pruned = prune_chunk;
                        }
                    }
                }
            })
            .unwrap();

        // Save checkpoint for verification
        checkpoints.push((commit_num, ground_truth.clone()));
    }

    // Verify all checkpoints match reconstructed states
    for (commit_num, checkpoint) in &checkpoints {
        let reconstructed = bitmap.get_at_commit(*commit_num).unwrap();

        assert_eq!(
            reconstructed.len(),
            checkpoint.len(),
            "Length mismatch at commit {commit_num}"
        );
        assert_eq!(
            reconstructed.pruned_chunks(),
            checkpoint.pruned_chunks(),
            "Pruned chunks mismatch at commit {commit_num}"
        );

        // Verify all accessible bits
        let start_bit = reconstructed.pruned_chunks() as u64 * Prunable::<4>::CHUNK_SIZE_BITS;
        for i in start_bit..checkpoint.len() {
            let expected = checkpoint.get_bit(i);
            let actual = reconstructed.get_bit(i);
            assert_eq!(
                actual, expected,
                "Bit {i} mismatch at commit {commit_num} (expected {expected}, got {actual})"
            );
        }
    }
}

/// Run property-based tests with multiple seeds to explore the state space.
///
/// Tests 101 different random operation sequences (seeds 0-100) to ensure
/// historical reconstruction works correctly across a wide variety of scenarios.
#[test]
fn test_randomized_with_multiple_seeds() {
    use rand::{rngs::StdRng, SeedableRng};
    for seed in 0..=100 {
        let mut rng = StdRng::seed_from_u64(seed);
        test_randomized_helper(&mut rng);
    }
}

#[test]
#[should_panic(expected = "bit pruned: 31")]
fn test_pop_into_pruned_region_panics() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Create a bitmap with 64 bits (2 chunks), then prune first chunk
    bitmap
        .with_batch(1, |b| {
            b.push_chunk(&[0xFF; 4]);
            b.push_chunk(&[0xFF; 4]);
        })
        .unwrap();

    bitmap
        .with_batch(2, |b| {
            b.prune_to_bit(32);
        })
        .unwrap();

    // Now we have: len=64, pruned_chunks=1 (32 pruned bits, 32 live bits)
    assert_eq!(bitmap.len(), 64);
    assert_eq!(bitmap.pruned_chunks(), 1);

    // Try to pop past the prune boundary
    // This should panic with "cannot pop into pruned region"
    let mut batch = bitmap.start_batch();
    for _ in 0..33 {
        // Pop 33 times (32 live bits + 1 pruned bit)
        batch.pop();
    }
}

#[test]
fn test_commit_u64_max_is_reserved() {
    let mut bitmap: BitMap<4> = BitMap::new();

    // Verify that u64::MAX cannot be used as a commit number
    let result = bitmap.with_batch(u64::MAX, |b| {
        b.push(true);
    });

    assert!(matches!(result, Err(Error::ReservedCommitNumber)));
    assert_eq!(bitmap.len(), 0); // Batch was rejected

    // Verify that u64::MAX - 1 can be used
    let result = bitmap.with_batch(u64::MAX - 1, |b| {
        b.push(true);
    });

    assert!(result.is_ok());
    assert_eq!(bitmap.len(), 1);

    // Verify get_at_commit returns None for u64::MAX
    assert!(bitmap.get_at_commit(u64::MAX).is_none());

    // But works for u64::MAX - 1
    assert!(bitmap.get_at_commit(u64::MAX - 1).is_some());
}

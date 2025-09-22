//! A historical wrapper around Prunable that maintains snapshots at user-defined keys.

use super::Prunable;
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
use core::ops::{Deref, DerefMut};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Represents a change to a single chunk in the bitmap.
#[derive(Clone, Debug)]
struct ChunkDiff<const N: usize> {
    /// Index of the chunk in the bitmap.
    chunk_index: usize,
    /// The chunk data at this snapshot.
    chunk_data: [u8; N],
}

/// Represents a reverse diff between two snapshots.
#[derive(Clone, Debug)]
struct BitmapDiff<const N: usize> {
    /// Length of the target (older) bitmap.
    len: usize,
    /// Number of pruned chunks in the target (older) bitmap.
    pruned_chunks: usize,
    /// Changed chunks needed to transform from newer snapshot to older snapshot.
    changed_chunks: Vec<ChunkDiff<N>>,
}

/// Storage type for snapshots - either a full bitmap or a reverse diff.
#[derive(Clone, Debug)]
enum SnapshotStorage<const N: usize> {
    /// Full bitmap snapshot (used for the newest/base snapshot).
    Full(Prunable<N>),
    /// Reverse diff showing how to get from a newer snapshot to this older snapshot.
    Diff(BitmapDiff<N>),
}

/// A historical bitmap that maintains snapshots of bitmap states at user-defined keys.
///
/// This wrapper around [Prunable] allows storing and retrieving historical states of the bitmap,
/// which is useful for generating historical range proofs or maintaining audit trails.
#[derive(Clone, Debug)]
pub struct Historical<const N: usize> {
    /// The current/active prunable bitmap.
    current: Prunable<N>,

    /// Historical snapshots: key -> snapshot storage (full or diff).
    /// The BTreeMap maintains key order, with the NEWEST snapshot being the full base.
    /// Older snapshots are stored as reverse diffs from newer snapshots.
    /// Keys must be monotonically increasing for the diff-chain approach to work correctly.
    snapshots: BTreeMap<u64, SnapshotStorage<N>>,
}

impl<const N: usize> Historical<N> {
    /// Create a new empty historical bitmap.
    pub fn new() -> Self {
        Self {
            current: Prunable::new(),
            snapshots: BTreeMap::new(),
        }
    }

    /// Create a new historical bitmap with the given number of pruned chunks.
    pub fn new_with_pruned_chunks(pruned_chunks: usize) -> Self {
        Self {
            current: Prunable::new_with_pruned_chunks(pruned_chunks),
            snapshots: BTreeMap::new(),
        }
    }

    /// Create a snapshot of the current bitmap state at the given key.
    ///
    /// Note: Keys must be monotonically increasing for the diff-chain approach to work correctly.
    pub fn create_snapshot(&mut self, key: u64) {
        if self.snapshots.is_empty() {
            // First snapshot is always a full snapshot
            let full_snapshot = self.current.clone();
            self.snapshots
                .insert(key, SnapshotStorage::Full(full_snapshot));
        } else {
            // Convert the current newest snapshot to a reverse diff
            let newest_key = *self.snapshots.keys().next_back().unwrap();
            let newest_snapshot = self.get_snapshot(newest_key).unwrap();

            // Create reverse diff: how to get from NEW snapshot (current) to OLD snapshot (newest)
            let reverse_diff = self
                .create_diff_between(&self.current, &newest_snapshot)
                .expect("reverse diff creation should never fail with monotonic keys");

            // Replace the old newest with the reverse diff
            self.snapshots
                .insert(newest_key, SnapshotStorage::Diff(reverse_diff));

            // Store the new snapshot as the full base
            self.snapshots
                .insert(key, SnapshotStorage::Full(self.current.clone()));
        }
    }

    /// Retrieve a historical snapshot by key.
    ///
    /// Note: This method may need to reconstruct the snapshot from diffs,
    /// so it returns an owned `Prunable<N>` rather than a reference.
    pub fn get_snapshot(&self, key: u64) -> Option<Prunable<N>> {
        // Find the target snapshot
        self.snapshots.get(&key)?;

        // Reconstruct by following the reverse diff chain from the newest base
        self.reconstruct_snapshot_chain(key)
    }

    /// Remove all snapshots with keys below the given threshold.
    ///
    /// Returns the number of snapshots removed.
    pub fn remove_snapshots_below(&mut self, threshold: u64) -> usize {
        let keys_to_remove: Vec<u64> = self.snapshots.range(..threshold).map(|(k, _)| *k).collect();

        if keys_to_remove.is_empty() {
            return 0;
        }

        // Handle newest snapshot removal if needed
        self.handle_newest_removal_if_needed(&keys_to_remove);

        // Remove the old snapshots
        let count = keys_to_remove.len();
        for key in keys_to_remove {
            self.snapshots.remove(&key);
        }
        count
    }

    /// Remove all snapshots with keys at or below the given threshold.
    ///
    /// Returns the number of snapshots removed.
    pub fn remove_snapshots_at_or_below(&mut self, threshold: u64) -> usize {
        let keys_to_remove: Vec<u64> = self
            .snapshots
            .range(..=threshold)
            .map(|(k, _)| *k)
            .collect();

        if keys_to_remove.is_empty() {
            return 0;
        }

        // Handle newest snapshot removal if needed
        self.handle_newest_removal_if_needed(&keys_to_remove);

        // Remove the old snapshots
        let count = keys_to_remove.len();
        for key in keys_to_remove {
            self.snapshots.remove(&key);
        }
        count
    }

    /// Remove a specific snapshot by key.
    ///
    /// Returns true if the snapshot existed and was removed, false otherwise.
    pub fn remove_snapshot(&mut self, key: u64) -> bool {
        if !self.snapshots.contains_key(&key) {
            return false;
        }

        // Handle newest snapshot removal if needed
        self.handle_newest_removal_if_needed(&[key]);

        // Remove the snapshot
        self.snapshots.remove(&key).is_some()
    }

    /// Get the number of stored snapshots.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Get an iterator over all snapshot keys in ascending order.
    pub fn snapshot_keys(&self) -> impl Iterator<Item = u64> + '_ {
        self.snapshots.keys().copied()
    }

    /// Get the smallest snapshot key, if any snapshots exist.
    pub fn min_snapshot_key(&self) -> Option<u64> {
        self.snapshots.keys().next().copied()
    }

    /// Get the largest snapshot key, if any snapshots exist.
    pub fn max_snapshot_key(&self) -> Option<u64> {
        self.snapshots.keys().next_back().copied()
    }

    /// Clear all snapshots.
    pub fn clear_snapshots(&mut self) {
        self.snapshots.clear();
    }

    /// Get a reference to the current bitmap state.
    pub fn current(&self) -> &Prunable<N> {
        &self.current
    }

    /// Get a mutable reference to the current bitmap state.
    pub fn current_mut(&mut self) -> &mut Prunable<N> {
        &mut self.current
    }

    /// Check if we're removing the newest snapshot and handle it appropriately.
    /// With reverse diff approach, we need to promote the next newest to full if we remove the current newest.
    fn handle_newest_removal_if_needed(&mut self, keys_to_remove: &[u64]) {
        if keys_to_remove.is_empty() || self.snapshots.is_empty() {
            return;
        }

        let newest_key = *self.snapshots.keys().next_back().unwrap();
        let removing_newest = keys_to_remove.contains(&newest_key);

        if removing_newest && keys_to_remove.len() < self.snapshots.len() {
            // Find the next newest snapshot that will remain
            let next_newest_key = self
                .snapshots
                .keys()
                .rev()
                .find(|&&k| !keys_to_remove.contains(&k))
                .copied();

            if let Some(next_newest_key) = next_newest_key {
                // Reconstruct it as a full snapshot to become the new base
                if let Some(reconstructed) = self.reconstruct_snapshot_chain(next_newest_key) {
                    self.snapshots
                        .insert(next_newest_key, SnapshotStorage::Full(reconstructed));
                }
            }
        }
    }

    /// Create a diff between two bitmaps.
    fn create_diff_between(&self, from: &Prunable<N>, to: &Prunable<N>) -> Option<BitmapDiff<N>> {
        let mut changed_chunks = Vec::new();

        // Compare chunk by chunk
        let max_chunks = from.chunks_len().max(to.chunks_len());

        for chunk_idx in 0..max_chunks {
            let from_chunk = if chunk_idx < from.chunks_len() {
                Some(from.get_chunk_by_index(chunk_idx))
            } else {
                None
            };

            let to_chunk = if chunk_idx < to.chunks_len() {
                Some(to.get_chunk_by_index(chunk_idx))
            } else {
                None
            };

            // Check if chunks are different
            let chunks_differ = match (from_chunk, to_chunk) {
                (Some(a), Some(b)) => a != b,
                (None, Some(_)) => true, // New chunk added
                (Some(_), None) => true, // Chunk removed (shouldn't happen with prunable)
                (None, None) => false,   // Both don't exist
            };

            if chunks_differ {
                if let Some(chunk) = to_chunk {
                    changed_chunks.push(ChunkDiff {
                        chunk_index: chunk_idx,
                        chunk_data: *chunk,
                    });
                }
            }
        }

        Some(BitmapDiff {
            len: to.len(),
            pruned_chunks: to.pruned_chunks(),
            changed_chunks,
        })
    }

    /// Reconstruct a snapshot by following the reverse diff chain from the newest base.
    fn reconstruct_snapshot_chain(&self, target_key: u64) -> Option<Prunable<N>> {
        // Find the newest (highest key) snapshot - this is our base
        let newest_key = *self.snapshots.keys().next_back()?;

        // If we're asking for the newest snapshot, it should be full
        if target_key == newest_key {
            let newest_storage = self.snapshots.get(&newest_key)?;
            return match newest_storage {
                SnapshotStorage::Full(bitmap) => Some(bitmap.clone()),
                SnapshotStorage::Diff(_) => None, // Newest should always be full
            };
        }

        // Start from the newest full snapshot and work backward
        let newest_storage = self.snapshots.get(&newest_key)?;
        let mut result = match newest_storage {
            SnapshotStorage::Full(bitmap) => bitmap.clone(),
            SnapshotStorage::Diff(_) => return None, // Newest should always be full
        };

        // Apply reverse diffs going backward from newest to target
        for (&key, storage) in self.snapshots.range(target_key..newest_key).rev() {
            // Apply this reverse diff to continue going backward
            match storage {
                SnapshotStorage::Full(bitmap) => {
                    // If we encounter another full snapshot, use it as new base
                    result = bitmap.clone();
                }
                SnapshotStorage::Diff(diff) => {
                    // Apply the reverse diff to go further back in time
                    result = self.apply_reverse_diff_to_bitmap(&result, diff)?;
                }
            }

            // Check if we've reached our target after applying the diff
            if key == target_key {
                return Some(result);
            }
        }

        None
    }

    /// Apply a reverse diff to a bitmap to get the previous (older) state.
    fn apply_reverse_diff_to_bitmap(
        &self,
        newer_bitmap: &Prunable<N>,
        reverse_diff: &BitmapDiff<N>,
    ) -> Option<Prunable<N>> {
        // Create a new bitmap with the target properties
        let mut result = Prunable::new_with_pruned_chunks(reverse_diff.pruned_chunks);

        // Calculate how many complete chunks we need
        let complete_chunks = reverse_diff.len / Prunable::<N>::CHUNK_SIZE_BITS;
        let remaining_bits = reverse_diff.len % Prunable::<N>::CHUNK_SIZE_BITS;

        // Add complete chunks
        for chunk_idx in 0..complete_chunks {
            let chunk_data = if let Some(chunk_diff) = reverse_diff
                .changed_chunks
                .iter()
                .find(|cd| cd.chunk_index == chunk_idx)
            {
                // Use the modified chunk from the reverse diff
                chunk_diff.chunk_data
            } else {
                // Use the chunk from the newer bitmap
                if chunk_idx < newer_bitmap.chunks_len() {
                    *newer_bitmap.get_chunk_by_index(chunk_idx)
                } else {
                    // This chunk didn't exist in newer bitmap, use empty chunk
                    [0u8; N]
                }
            };

            result.push_chunk(&chunk_data);
        }

        // Handle the partial last chunk if there are remaining bits
        if remaining_bits > 0 {
            let chunk_idx = complete_chunks;
            let chunk_data = if let Some(chunk_diff) = reverse_diff
                .changed_chunks
                .iter()
                .find(|cd| cd.chunk_index == chunk_idx)
            {
                chunk_diff.chunk_data
            } else {
                if chunk_idx < newer_bitmap.chunks_len() {
                    *newer_bitmap.get_chunk_by_index(chunk_idx)
                } else {
                    [0u8; N]
                }
            };

            // Add bits from this chunk one by one until we reach the target length
            for bit_idx in 0..remaining_bits {
                let byte_idx = bit_idx / 8;
                let bit_in_byte = bit_idx % 8;
                let bit_value = (chunk_data[byte_idx] >> bit_in_byte) & 1 == 1;
                result.push(bit_value);
            }
        }

        Some(result)
    }
}

impl<const N: usize> Default for Historical<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Deref for Historical<N> {
    type Target = Prunable<N>;

    fn deref(&self) -> &Self::Target {
        &self.current
    }
}

impl<const N: usize> DerefMut for Historical<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let historical: Historical<4> = Historical::new();
        assert_eq!(historical.len(), 0);
        assert_eq!(historical.snapshot_count(), 0);
        assert!(historical.is_empty());
    }

    #[test]
    fn test_new_with_pruned_chunks() {
        let historical: Historical<4> = Historical::new_with_pruned_chunks(2);
        assert_eq!(historical.len(), 64); // 2 chunks * 32 bits
        assert_eq!(historical.pruned_chunks(), 2);
        assert_eq!(historical.snapshot_count(), 0);
    }

    #[test]
    fn test_create_and_get_snapshot() {
        let mut historical: Historical<4> = Historical::new();

        // Add some data to current state
        historical.push(true);
        historical.push(false);
        historical.push(true);

        // Create a snapshot
        historical.create_snapshot(100);
        assert_eq!(historical.snapshot_count(), 1);

        // Modify current state
        historical.push(false);
        historical.push(true);

        // Current state should have 5 bits
        assert_eq!(historical.len(), 5);

        // Snapshot should have the original 3 bits
        let snapshot = historical.get_snapshot(100).unwrap();
        assert_eq!(snapshot.len(), 3);
        assert!(snapshot.get_bit(0));
        assert!(!snapshot.get_bit(1));
        assert!(snapshot.get_bit(2));
    }

    #[test]
    fn test_get_snapshot_not_found() {
        let historical: Historical<4> = Historical::new();
        assert!(historical.get_snapshot(100).is_none());
    }

    #[test]
    fn test_remove_snapshots_below() {
        let mut historical: Historical<4> = Historical::new();

        // Create multiple snapshots
        for i in [10, 20, 30, 40, 50] {
            historical.push(true);
            historical.create_snapshot(i);
        }

        assert_eq!(historical.snapshot_count(), 5);

        // Remove snapshots below 30
        let removed = historical.remove_snapshots_below(30);
        assert_eq!(removed, 2); // 10 and 20
        assert_eq!(historical.snapshot_count(), 3);

        // Verify remaining snapshots
        assert!(historical.get_snapshot(10).is_none());
        assert!(historical.get_snapshot(20).is_none());
        assert!(historical.get_snapshot(30).is_some());
        assert!(historical.get_snapshot(40).is_some());
        assert!(historical.get_snapshot(50).is_some());
    }

    #[test]
    fn test_remove_snapshots_at_or_below() {
        let mut historical: Historical<4> = Historical::new();

        // Create multiple snapshots
        for i in [10, 20, 30, 40, 50] {
            historical.push(true);
            historical.create_snapshot(i);
        }

        // Remove snapshots at or below 30
        let removed = historical.remove_snapshots_at_or_below(30);
        assert_eq!(removed, 3); // 10, 20, and 30
        assert_eq!(historical.snapshot_count(), 2);

        // Verify remaining snapshots
        assert!(historical.get_snapshot(30).is_none());
        assert!(historical.get_snapshot(40).is_some());
        assert!(historical.get_snapshot(50).is_some());
    }

    #[test]
    fn test_remove_snapshot() {
        let mut historical: Historical<4> = Historical::new();
        historical.push(true);
        historical.create_snapshot(100);

        assert!(historical.remove_snapshot(100));
        assert_eq!(historical.snapshot_count(), 0);
        assert!(!historical.remove_snapshot(100)); // Already removed
    }

    #[test]
    fn test_snapshot_keys_and_bounds() {
        let mut historical: Historical<4> = Historical::new();

        // Empty case
        assert_eq!(historical.snapshot_count(), 0);
        assert!(historical.min_snapshot_key().is_none());
        assert!(historical.max_snapshot_key().is_none());

        // Add snapshots with monotonic keys
        for i in [10, 20, 30, 40, 50] {
            historical.push(true);
            historical.create_snapshot(i);
        }

        // Check keys are sorted
        let keys: Vec<u64> = historical.snapshot_keys().collect();
        assert_eq!(keys, vec![10, 20, 30, 40, 50]);

        assert_eq!(historical.min_snapshot_key(), Some(10));
        assert_eq!(historical.max_snapshot_key(), Some(50));
    }

    #[test]
    fn test_clear_snapshots() {
        let mut historical: Historical<4> = Historical::new();

        // Add snapshots
        for i in 0..5 {
            historical.push(true);
            historical.create_snapshot(i);
        }

        assert_eq!(historical.snapshot_count(), 5);
        historical.clear_snapshots();
        assert_eq!(historical.snapshot_count(), 0);
    }

    #[test]
    fn test_transparent_access() {
        let mut historical: Historical<4> = Historical::new();

        // Test that we can use Historical like a Prunable
        historical.push(true);
        historical.push(false);
        historical.push(true);

        assert_eq!(historical.len(), 3);
        assert!(historical.get_bit(0));
        assert!(!historical.get_bit(1));
        assert!(historical.get_bit(2));

        // Test set_bit
        historical.set_bit(1, true);
        assert!(historical.get_bit(1));
    }

    #[test]
    fn test_current_access() {
        let mut historical: Historical<4> = Historical::new();
        historical.push(true);

        // Test immutable access
        let current = historical.current();
        assert_eq!(current.len(), 1);
        assert!(current.get_bit(0));

        // Test mutable access
        let current_mut = historical.current_mut();
        current_mut.push(false);
        assert_eq!(historical.len(), 2);
    }

    #[test]
    fn test_pruning_with_snapshots() {
        let mut historical: Historical<4> = Historical::new();

        // Add multiple chunks
        let chunk1 = [0x01, 0x02, 0x03, 0x04];
        let chunk2 = [0x05, 0x06, 0x07, 0x08];
        let chunk3 = [0x09, 0x0A, 0x0B, 0x0C];

        historical.push_chunk(&chunk1);
        historical.push_chunk(&chunk2);
        historical.create_snapshot(100); // Snapshot with 2 chunks

        historical.push_chunk(&chunk3);
        historical.create_snapshot(200); // Snapshot with 3 chunks

        // Prune current state
        historical.prune_to_bit(64); // Prune to third chunk
        assert_eq!(historical.pruned_chunks(), 2);

        // Snapshots should be unaffected by pruning of current state
        let snapshot1 = historical.get_snapshot(100).unwrap();
        assert_eq!(snapshot1.len(), 64);
        assert_eq!(snapshot1.pruned_chunks(), 0);
        assert_eq!(snapshot1.get_chunk(0), &chunk1);

        let snapshot2 = historical.get_snapshot(200).unwrap();
        assert_eq!(snapshot2.len(), 96);
        assert_eq!(snapshot2.pruned_chunks(), 0);
        assert_eq!(snapshot2.get_chunk(0), &chunk1);
        assert_eq!(snapshot2.get_chunk(32), &chunk2);
    }

    #[test]
    fn test_multiple_snapshots_different_states() {
        let mut historical: Historical<4> = Historical::new();

        // Create snapshots at different stages
        historical.create_snapshot(0); // Empty state

        historical.push(true);
        historical.create_snapshot(1); // 1 bit

        historical.push(false);
        historical.push(true);
        historical.create_snapshot(2); // 3 bits

        // Verify each snapshot has the correct state
        let snapshot0 = historical.get_snapshot(0).unwrap();
        assert_eq!(snapshot0.len(), 0);

        let snapshot1 = historical.get_snapshot(1).unwrap();
        assert_eq!(snapshot1.len(), 1);
        assert!(snapshot1.get_bit(0));

        let snapshot2 = historical.get_snapshot(2).unwrap();
        assert_eq!(snapshot2.len(), 3);
        assert!(snapshot2.get_bit(0));
        assert!(!snapshot2.get_bit(1));
        assert!(snapshot2.get_bit(2));

        // Current state should have 3 bits
        assert_eq!(historical.len(), 3);
    }

    #[test]
    fn test_diff_based_snapshots() {
        // Test diff-based storage with reverse diff approach
        let mut historical: Historical<4> = Historical::new();

        // Create initial base snapshot
        historical.push(true);
        historical.push(false);
        historical.create_snapshot(100); // This should be a full snapshot (base)

        // Modify slightly and create another snapshot
        historical.push(true);
        historical.create_snapshot(200); // This should be a diff

        // Verify both snapshots work
        let snapshot100 = historical.get_snapshot(100).unwrap();
        assert_eq!(snapshot100.len(), 2);
        assert!(snapshot100.get_bit(0));
        assert!(!snapshot100.get_bit(1));

        let snapshot200 = historical.get_snapshot(200).unwrap();
        assert_eq!(snapshot200.len(), 3);
        assert!(snapshot200.get_bit(0));
        assert!(!snapshot200.get_bit(1));
        assert!(snapshot200.get_bit(2));
    }
}

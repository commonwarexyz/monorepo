//! A historical wrapper around Prunable that maintains snapshots at user-defined keys.

use super::Prunable;
#[cfg(not(feature = "std"))]
use alloc::collections::BTreeMap;
use core::ops::{Deref, DerefMut};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// A historical bitmap that maintains snapshots of bitmap states at user-defined keys.
///
/// This wrapper around [Prunable] allows storing and retrieving historical states of the bitmap,
/// which is useful for generating historical range proofs or maintaining audit trails.
#[derive(Clone, Debug)]
pub struct Historical<const N: usize> {
    /// The current/active prunable bitmap.
    current: Prunable<N>,

    /// Historical snapshots: key -> bitmap state at that point.
    snapshots: BTreeMap<u64, Prunable<N>>,
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
    /// # Errors
    ///
    /// Returns `HistoricalError::DuplicateKey` if a snapshot already exists at the given key.
    pub fn create_snapshot(&mut self, key: u64) {
        let snapshot = self.current.clone();
        self.snapshots.insert(key, snapshot);
    }

    /// Create a snapshot of the current bitmap state at the given key, overwriting any existing snapshot.
    pub fn create_snapshot_overwrite(&mut self, key: u64) {
        let snapshot = self.current.clone();
        self.snapshots.insert(key, snapshot);
    }

    /// Retrieve a historical snapshot by key.
    ///
    /// # Errors
    ///
    /// Returns `HistoricalError::SnapshotNotFound` if no snapshot exists at the given key.
    pub fn get_snapshot(&self, key: u64) -> Option<&Prunable<N>> {
        self.snapshots.get(&key)
    }

    /// Remove all snapshots with keys below the given threshold.
    ///
    /// Returns the number of snapshots removed.
    pub fn remove_snapshots_below(&mut self, threshold: u64) -> usize {
        let keys_to_remove: Vec<u64> = self.snapshots.range(..threshold).map(|(k, _)| *k).collect();

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
    fn test_create_snapshot_overwrite() {
        let mut historical: Historical<4> = Historical::new();
        historical.push(true);
        historical.create_snapshot_overwrite(100);

        // Modify and overwrite
        historical.push(false);
        historical.create_snapshot_overwrite(100);

        // Should have the updated snapshot
        let snapshot = historical.get_snapshot(100).unwrap();
        assert_eq!(snapshot.len(), 2);
        assert!(snapshot.get_bit(0));
        assert!(!snapshot.get_bit(1));
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

        // Add snapshots
        for i in [30, 10, 50, 20, 40] {
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
}

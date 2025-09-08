//! Historical bitmap that maintains a cache of recent bitmap states
//! for generating historical range proofs.

use crate::mmr::{bitmap::Bitmap, storage::Storage, Error as MmrError};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics, Storage as RStorage};
use std::collections::BTreeMap;

/// Identifies a historical bitmap state.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StateKey {
    /// The inactivity floor of the database when the bitmap state was cached.
    pub inactivity_floor: u64,
    /// The size of the database when the bitmap state was cached.
    pub size: u64,
}

/// A [Bitmap] wrapper that maintains a cache of recent states.
/// Each stored bitmap state is associated with a [StateKey] which identifies the state.
pub(super) struct HistoricalBitmap<H: Hasher, const N: usize> {
    /// The current bitmap state
    bitmap: Bitmap<H, N>,
    /// StateKey -> Bitmap State at that key (inactivity_floor, size)
    cached_states: BTreeMap<StateKey, Bitmap<H, N>>,
}

impl<H: Hasher, const N: usize> HistoricalBitmap<H, N> {
    /// Create a new historical bitmap
    pub fn new() -> Self {
        Self {
            bitmap: Bitmap::new(),
            cached_states: BTreeMap::new(),
        }
    }

    /// Get a reference to the current bitmap (for testing)
    #[cfg(test)]
    pub(crate) fn current(&self) -> &Bitmap<H, N> {
        &self.bitmap
    }

    /// Get a mutable reference to the current bitmap
    pub(crate) fn current_mut(&mut self) -> &mut Bitmap<H, N> {
        &mut self.bitmap
    }

    /// Get the current bit count
    pub fn bit_count(&self) -> u64 {
        self.bitmap.bit_count()
    }

    /// Get the last chunk of the bitmap and its size in bits
    pub fn last_chunk(&self) -> (&[u8; N], u64) {
        self.bitmap.last_chunk()
    }

    /// Get a chunk containing the specified bit
    pub fn get_chunk(&self, bit_offset: u64) -> &[u8; N] {
        self.bitmap.get_chunk(bit_offset)
    }

    /// Get the value of a bit
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        self.bitmap.get_bit(bit_offset)
    }

    /// Returns a root digest that incorporates bits that aren't part of the MMR yet
    pub fn partial_chunk_root(
        hasher: &mut H,
        mmr_root: &H::Digest,
        next_bit: u64,
        last_chunk_digest: &H::Digest,
    ) -> H::Digest {
        Bitmap::<H, N>::partial_chunk_root(hasher, mmr_root, next_bit, last_chunk_digest)
    }

    /// Get the number of cached states (for testing)
    #[cfg(test)]
    pub(crate) fn cached_count(&self) -> usize {
        self.cached_states.len()
    }

    /// Cache the current bitmap state with the specified inactivity floor and size
    pub fn cache_state(&mut self, inactivity_floor: u64, size: u64) {
        // Copy and cache the current state
        let bitmap_copy = self.bitmap.clone();
        let key = StateKey {
            inactivity_floor,
            size,
        };
        self.cached_states.insert(key, bitmap_copy);
    }

    /// Append a bit to the bitmap and cache the previous state
    pub fn append(&mut self, value: bool) {
        self.bitmap.append(value);
    }

    /// Set a bit at a specific offset and cache the previous state
    pub fn set_bit(&mut self, bit_offset: u64, value: bool) {
        self.bitmap.set_bit(bit_offset, value);
    }

    /// Prune the bitmap to the specified bit offset. Does NOT affect cached states.
    /// Use prune_cached_states() separately to remove cached states.
    pub fn prune_to_bit(&mut self, bit_offset: u64) {
        self.bitmap.prune_to_bit(bit_offset);
    }

    /// Remove cached states based on inactivity floor - only remove states where the
    /// inactivity_floor is below the prune boundary (meaning the data is no longer accessible)
    pub fn prune_cached_states(&mut self, prune_boundary: u64) {
        self.cached_states
            .retain(|key, _| key.inactivity_floor >= prune_boundary);
    }

    /// Get a historical bitmap state by the size of the database when the state was cached.
    pub fn get_state(&self, requested_size: u64) -> Option<&Bitmap<H, N>> {
        self.cached_states
            .iter()
            .find(|(key, _)| key.size == requested_size)
            .map(|(_, bitmap)| bitmap)
    }

    /// Get all available cached states in ascending order (for testing)
    #[cfg(test)]
    pub(crate) fn available_sizes(&self) -> Vec<u64> {
        let mut sizes: Vec<u64> = self.cached_states.keys().map(|key| key.size).collect();
        sizes.sort();
        sizes.dedup();
        sizes
    }

    /// Check if a state is available (for testing)
    #[cfg(test)]
    pub(crate) fn has_state(&self, requested_size: u64) -> bool {
        self.cached_states
            .keys()
            .any(|key| key.size == requested_size)
    }

    /// Get the dirty chunks from the current bitmap
    pub fn dirty_chunks(&self) -> Vec<u64> {
        self.bitmap.dirty_chunks()
    }

    /// Sync the current bitmap with the given hasher
    pub(crate) async fn sync<G>(&mut self, grafter: &mut G) -> Result<(), crate::mmr::Error>
    where
        G: crate::mmr::hasher::Hasher<H>,
    {
        self.bitmap.sync(grafter).await
    }

    /// Write the pruned bitmap to storage
    pub(crate) async fn write_pruned<E>(
        &mut self,
        context: E,
        partition: &str,
    ) -> Result<(), MmrError>
    where
        E: RStorage + Metrics + Clock,
    {
        self.bitmap.write_pruned(context, partition).await
    }

    /// Check if the bitmap is dirty
    pub(crate) fn is_dirty(&self) -> bool {
        self.bitmap.is_dirty()
    }

    /// Get the bitmap from another bitmap
    pub fn from_bitmap(bitmap: Bitmap<H, N>) -> Self {
        Self {
            bitmap,
            cached_states: BTreeMap::new(),
        }
    }
}

/// Implement the Storage trait for HistoricalBitmap to delegate to the underlying bitmap
impl<H: Hasher, const N: usize> Storage<H::Digest> for HistoricalBitmap<H, N> {
    fn size(&self) -> u64 {
        self.bitmap.size()
    }

    fn get_node(
        &self,
        position: u64,
    ) -> impl std::future::Future<Output = Result<Option<H::Digest>, MmrError>> + Send {
        async move { Ok(self.bitmap.get_node(position)) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::hasher::Standard;
    use commonware_cryptography::Sha256;
    use commonware_runtime::{deterministic, Runner};

    type TestHistoricalBitmap = HistoricalBitmap<Sha256, 32>;

    #[test]
    fn test_new() {
        let hb = TestHistoricalBitmap::new();
        assert_eq!(hb.bit_count(), 0);
        assert_eq!(hb.cached_count(), 0);
    }

    #[test]
    fn test_from_bitmap() {
        let mut bitmap = crate::mmr::bitmap::Bitmap::<Sha256, 32>::new();
        bitmap.append(true);
        bitmap.append(false);

        let hb = TestHistoricalBitmap::from_bitmap(bitmap);
        assert_eq!(hb.bit_count(), 2);
        assert_eq!(hb.cached_count(), 0);
        assert!(hb.current().get_bit(0));
        assert!(!hb.current().get_bit(1));
    }

    #[test]
    fn test_cache_state() {
        // Tests that cache_state() stores bitmap snapshots that can be retrieved later
        let mut hb = TestHistoricalBitmap::new();

        hb.cache_state(0, 0);
        assert!(hb.has_state(0));
        assert_eq!(hb.cached_count(), 1);
        assert_eq!(hb.available_sizes(), vec![0]);

        hb.append(true);
        hb.cache_state(0, 1);
        assert!(hb.has_state(1));
        assert_eq!(hb.cached_count(), 2);
        assert_eq!(hb.available_sizes(), vec![0, 1]);

        hb.append(false);
        hb.cache_state(0, 2);
        assert!(hb.has_state(2));
        assert_eq!(hb.cached_count(), 3);
        assert_eq!(hb.available_sizes(), vec![0, 1, 2]);

        // Add one more bit and cache that state
        hb.append(true);
        hb.cache_state(0, 3);
        assert!(hb.has_state(3));
        assert_eq!(hb.cached_count(), 4);
        assert_eq!(hb.available_sizes(), vec![0, 1, 2, 3]);

        // Verify cached state contents match expected snapshots
        let state_0 = hb.get_state(0).unwrap();
        assert_eq!(state_0.bit_count(), 0);

        let state_1 = hb.get_state(1).unwrap();
        assert_eq!(state_1.bit_count(), 1);
        assert!(state_1.get_bit(0));

        let state_2 = hb.get_state(2).unwrap();
        assert_eq!(state_2.bit_count(), 2);
        assert!(state_2.get_bit(0));
        assert!(!state_2.get_bit(1));

        let state_3 = hb.get_state(3).unwrap();
        assert_eq!(state_3.bit_count(), 3);
        assert!(state_3.get_bit(0));
        assert!(!state_3.get_bit(1));
        assert!(state_3.get_bit(2));
    }

    #[test]
    fn test_prune_to_bit() {
        // Tests comprehensive prune_to_bit behavior with operations between cached states
        // and multiple pruning calls
        let mut hb = TestHistoricalBitmap::new();

        // Phase 1: Build up bitmap with operations and cache states

        // Cache initial empty state
        // Bitmap: (empty)
        // Cached: [(inactivity_floor=0, size=0)]
        hb.cache_state(0, 0);
        assert_eq!(hb.bit_count(), 0);
        assert_eq!(hb.cached_count(), 1);

        // Add some bits and cache intermediate states
        hb.append(true); // bit_count = 1
        hb.append(false); // bit_count = 2
                          // Bitmap: [1, 0]
                          // Cached: [(0,0), (1,2)]
        hb.cache_state(1, 2);

        hb.append(true); // bit_count = 3
        hb.append(true); // bit_count = 4
        hb.append(false); // bit_count = 5
                          // Bitmap: [1, 0, 1, 1, 0]
                          // Cached: [(0,0), (1,2), (2,5)]
        hb.cache_state(2, 5);

        hb.append(false); // bit_count = 6
        hb.append(true); // bit_count = 7
        hb.append(false); // bit_count = 8
                          // Bitmap: [1, 0, 1, 1, 0, 0, 1, 0]
                          // Cached: [(0,0), (1,2), (2,5), (4,8)]
        hb.cache_state(4, 8);

        // Use set_bit to modify an earlier bit (simulates an operation becoming inactive)
        hb.set_bit(1, true); // Change bit 1 from 0 to 1
                             // Bitmap: [1, 1, 1, 1, 0, 0, 1, 0]
                             //            ^  (bit 1 changed from 0 to 1)

        // Verify that previously cached states are NOT affected by set_bit
        let cached_state_2 = hb.get_state(2).unwrap();
        assert!(!cached_state_2.get_bit(1)); // Should still be false (cached before set_bit)

        // But current bitmap should reflect the change
        assert!(hb.current().get_bit(1)); // Should now be true (after set_bit)

        hb.append(true); // bit_count = 9
        hb.append(false); // bit_count = 10
                          // Bitmap: [1, 1, 1, 1, 0, 0, 1, 0, 1, 0]
                          // Cached: [(0,0), (1,2), (2,5), (4,8), (5,10)]
        hb.cache_state(5, 10);

        // Verify initial state
        assert_eq!(hb.bit_count(), 10);
        assert_eq!(hb.cached_count(), 5); // States at 0, 2, 5, 8, 10
        assert!(hb.has_state(0));
        assert!(hb.has_state(2));
        assert!(hb.has_state(5));
        assert!(hb.has_state(8));
        assert!(hb.has_state(10));

        // Verify cached state contents are correct
        let state_0 = hb.get_state(0).unwrap();
        assert_eq!(state_0.bit_count(), 0);

        let state_2 = hb.get_state(2).unwrap();
        assert_eq!(state_2.bit_count(), 2);
        assert!(state_2.get_bit(0)); // true
        assert!(!state_2.get_bit(1)); // false (this was cached before set_bit changed it)

        let state_5 = hb.get_state(5).unwrap();
        assert_eq!(state_5.bit_count(), 5);
        assert!(state_5.get_bit(0)); // true
        assert!(!state_5.get_bit(1)); // false
        assert!(state_5.get_bit(2)); // true
        assert!(state_5.get_bit(3)); // true
        assert!(!state_5.get_bit(4)); // false

        // Phase 2: First pruning - prune bitmap but keep all cached states
        // Before: Bitmap: [1, 0, 1, 1, 0, 0, 1, 0, 1, 0]
        //         Cached: [0, 2, 5, 8, 10]
        hb.prune_to_bit(3);
        // After:  Bitmap: [X, X, X, 1, 0, 0, 1, 0, 1, 0] (bits 0-2 pruned)
        //         Cached: [0, 2, 5, 8, 10] (cached states PRESERVED)

        // All cached states should remain (prune_to_bit doesn't affect cached_states)
        assert_eq!(hb.cached_count(), 5); // All states still present
        assert!(hb.has_state(0)); // Still present
        assert!(hb.has_state(2)); // Still present
        assert!(hb.has_state(5)); // Still present
        assert!(hb.has_state(8)); // Still present
        assert!(hb.has_state(10)); // Still present

        // Now separately prune cached states
        hb.prune_cached_states(3);
        // After:  Cached: [(4,8), (5,10)] (states with inactivity_floor < 3 removed)

        // Now states with inactivity_floor < 3 should be removed
        assert_eq!(hb.cached_count(), 2); // States at 8, 10 remain
        assert!(!hb.has_state(0)); // Removed (inactivity_floor=0 < 3)
        assert!(!hb.has_state(2)); // Removed (inactivity_floor=1 < 3)
        assert!(!hb.has_state(5)); // Removed (inactivity_floor=2 < 3)
        assert!(hb.has_state(8)); // Kept (inactivity_floor=4 >= 3)
        assert!(hb.has_state(10)); // Kept (inactivity_floor=5 >= 3)

        // Phase 3: Add operations with set_bit modifications
        hb.append(false); // bit_count = 11
        hb.append(true); // bit_count = 12
                         // Bitmap: [X, X, X, 1, 1, 1, 1, 0, 1, 0, 0, 1]
                         // Cached: [(4,8), (5,10), (6,12)]
        hb.cache_state(6, 12);

        // Use set_bit to modify existing bits (simulates operations becoming inactive)
        hb.set_bit(9, true); // Change bit 9 from 0 to 1
        hb.set_bit(10, true); // Change bit 10 from 0 to 1
                              // Bitmap: [X, X, X, 1, 1, 1, 1, 0, 1, 1, 1, 1]
                              //                              ^  ^  (bits 9,10 changed)

        // Verify that set_bit doesn't affect previously cached states
        // This is essential for historical range proofs - cached states must be immutable snapshots
        let cached_state_10 = hb.get_state(10).unwrap();
        assert_eq!(cached_state_10.bit_count(), 10);
        assert!(!cached_state_10.get_bit(9)); // Should still be false (cached before set_bit)

        // But current bitmap should reflect the set_bit change
        assert!(hb.current().get_bit(9)); // Should now be true (after set_bit)

        // Verify state before pruning
        assert_eq!(hb.bit_count(), 12);
        assert_eq!(hb.cached_count(), 3); // States at 8, 10, 12

        // Phase 4: Prune bitmap and then cached states
        // Before: Bitmap: [X, X, X, 1, 1, 1, 1, 0, 1, 1, 1, 1]
        //         Cached: [(4,8), (5,10), (6,12)]
        hb.prune_to_bit(9);
        // After:  Bitmap: [X, X, X, X, X, X, X, X, X, 1, 1, 1] (bits 0-8 pruned)
        //         Cached: [(4,8), (5,10), (6,12)] (cached states unchanged)

        // Cached states should still be there after bitmap pruning
        assert_eq!(hb.cached_count(), 3);
        assert!(hb.has_state(8)); // Still present
        assert!(hb.has_state(10)); // Still present
        assert!(hb.has_state(12)); // Still present

        // Now prune cached states based on inactivity floor
        hb.prune_cached_states(6);
        // After:  Cached: [(6,12)] (states with inactivity_floor < 6 removed)

        assert_eq!(hb.cached_count(), 1);
        assert!(!hb.has_state(8)); // Removed (inactivity_floor=4 < 6)
        assert!(!hb.has_state(10)); // Removed (inactivity_floor=5 < 6)
        assert!(hb.has_state(12)); // Kept (inactivity_floor=6 >= 6)

        // Phase 5: Final pruning beyond all cached states
        hb.prune_cached_states(10);
        // After:  Cached: [] (all states removed since 6 < 10)

        assert_eq!(hb.cached_count(), 0);
        assert!(!hb.has_state(12)); // Removed (inactivity_floor=6 < 10)

        // Current bitmap should still be accessible
        assert_eq!(hb.bit_count(), 12);
    }

    // Tests that cached bitmap states preserve their MMR roots correctly
    #[test]
    fn test_cached_states_preserve_mmr_roots() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hb = TestHistoricalBitmap::new();
            let mut hasher = Standard::new();

            // Cache state and capture its root
            hb.cache_state(0, 0);
            let root_0 = hb.current().root(&mut hasher).await.unwrap();

            // Modify bitmap and cache new state
            hb.append(true);
            hb.cache_state(0, 1);
            let root_1 = hb.current().root(&mut hasher).await.unwrap();

            // Verify cached states have preserved their original roots
            let cached_0 = hb.get_state(0).unwrap();
            assert_eq!(cached_0.root(&mut hasher).await.unwrap(), root_0);

            let cached_1 = hb.get_state(1).unwrap();
            assert_eq!(cached_1.root(&mut hasher).await.unwrap(), root_1);
        });
    }

    #[test]
    fn test_prune_empty() {
        let mut hb = TestHistoricalBitmap::new();

        hb.prune_to_bit(10);
        assert_eq!(hb.cached_count(), 0);
        assert_eq!(hb.available_sizes(), Vec::<u64>::new());
    }
}

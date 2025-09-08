//! Historical bitmap that maintains a cache of recent bitmap states.
//!
//! This implementation stores the current bitmap and caches the last N complete
//! bitmap states for fast retrieval, which is needed for implementing
//! the sync database trait.

use crate::mmr::bitmap::Bitmap;
use commonware_cryptography::Hasher;
use std::collections::BTreeMap;

/// A [Bitmap] wrapper that maintains a cache of recent states.
/// Each stored bitmap state is associated with an index which identifies the state.
pub struct HistoricalBitmap<H: Hasher, const N: usize> {
    /// The current bitmap state
    bitmap: Bitmap<H, N>,
    /// Index -> Bitmap State at that index
    cached_states: BTreeMap<u64, Bitmap<H, N>>,
}

impl<H: Hasher, const N: usize> HistoricalBitmap<H, N> {
    /// The size of a chunk in bytes.
    pub const CHUNK_SIZE: usize = N;

    /// The size of a chunk in bits.
    pub const CHUNK_SIZE_BITS: u64 = N as u64 * 8;

    /// Create a new historical bitmap
    pub fn new() -> Self {
        Self {
            bitmap: Bitmap::new(),
            cached_states: BTreeMap::new(),
        }
    }

    /// Get a reference to the current bitmap
    pub fn current(&self) -> &Bitmap<H, N> {
        &self.bitmap
    }

    /// Get a mutable reference to the current bitmap
    pub fn current_mut(&mut self) -> &mut Bitmap<H, N> {
        &mut self.bitmap
    }

    /// Get the current bitmap bit count
    pub fn current_bit_count(&self) -> u64 {
        self.bitmap.bit_count()
    }

    /// Get the number of cached states
    pub fn cached_count(&self) -> usize {
        self.cached_states.len()
    }

    /// Cache the current bitmap state at the specified index
    pub fn cache_state(&mut self, index: u64) {
        // Copy and cache the current state
        let bitmap_copy = self.bitmap.clone();
        self.cached_states.insert(index, bitmap_copy);
    }

    /// Append a bit to the bitmap and cache the previous state
    pub fn append(&mut self, value: bool) {
        self.bitmap.append(value);
    }

    /// Set a bit at a specific offset and cache the previous state
    pub fn set_bit(&mut self, bit_offset: u64, value: bool) {
        self.bitmap.set_bit(bit_offset, value);
    }

    /// Append a byte to the bitmap and cache the previous state
    pub fn append_byte_unchecked(&mut self, byte: u8) {
        self.bitmap.append_byte_unchecked(byte);
    }

    /// Append a chunk to the bitmap and cache the previous state
    pub fn append_chunk_unchecked(&mut self, chunk: &[u8; N]) {
        self.bitmap.append_chunk_unchecked(chunk);
    }

    /// Prune the bitmap to the specified bit offset and remove cached states with indices below
    /// this offset.
    pub fn prune_to_bit(&mut self, bit_offset: u64) {
        self.bitmap.prune_to_bit(bit_offset);
        self.cached_states.retain(|&index, _| index >= bit_offset);
    }

    /// Get a bitmap state by index
    pub fn get_state(&self, index: u64) -> Option<&Bitmap<H, N>> {
        self.cached_states.get(&index)
    }

    /// Get all available cached indices in ascending order
    pub fn available_indices(&self) -> Vec<u64> {
        self.cached_states.keys().into_iter().copied().collect()
    }

    /// Check if a state is available (either current or cached)
    pub fn has_state(&self, index: u64) -> bool {
        self.cached_states.contains_key(&index)
    }

    /// Get the dirty chunks from the current bitmap
    pub fn dirty_chunks(&self) -> Vec<u64> {
        self.bitmap.dirty_chunks()
    }

    /// Check if the current bitmap is dirty
    pub fn is_dirty(&self) -> bool {
        self.bitmap.is_dirty()
    }

    /// Get the last chunk from the current bitmap
    pub fn last_chunk(&self) -> (&[u8; N], u64) {
        self.bitmap.last_chunk()
    }

    /// Get a chunk from the current bitmap
    pub fn get_chunk(&self, bit_offset: u64) -> &[u8; N] {
        self.bitmap.get_chunk(bit_offset)
    }

    /// Sync the current bitmap
    pub async fn sync(
        &mut self,
        hasher: &mut impl crate::mmr::Hasher<H>,
    ) -> Result<(), crate::mmr::Error> {
        self.bitmap.sync(hasher).await
    }

    /// Get the bit count from the current bitmap
    pub fn bit_count(&self) -> u64 {
        self.bitmap.bit_count()
    }

    /// Get the pruned bits from the current bitmap
    pub fn pruned_bits(&self) -> u64 {
        self.bitmap.pruned_bits()
    }

    /// Get a bit from the current bitmap
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        self.bitmap.get_bit(bit_offset)
    }

    /// Write the pruned state of the current bitmap
    pub async fn write_pruned<
        C: commonware_runtime::Storage + commonware_runtime::Metrics + commonware_runtime::Clock,
    >(
        &self,
        context: C,
        partition: &str,
    ) -> Result<(), crate::mmr::Error> {
        self.bitmap.write_pruned(context, partition).await
    }

    /// Get the size from the current bitmap
    pub fn size(&self) -> u64 {
        self.bitmap.size()
    }

    /// Get a node from the current bitmap
    pub fn get_node(&self, position: u64) -> Option<H::Digest> {
        self.bitmap.get_node(position)
    }

    /// Returns a root digest that incorporates bits that aren't part of the MMR yet because they
    /// belong to the last (unfilled) chunk.
    pub fn partial_chunk_root(
        hasher: &mut H,
        mmr_root: &H::Digest,
        next_bit: u64,
        last_chunk_digest: &H::Digest,
    ) -> H::Digest {
        Bitmap::<H, N>::partial_chunk_root(hasher, mmr_root, next_bit, last_chunk_digest)
    }
}

impl<H: Hasher, const N: usize> Default for HistoricalBitmap<H, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<H: Hasher, const N: usize> From<Bitmap<H, N>> for HistoricalBitmap<H, N> {
    fn from(bitmap: Bitmap<H, N>) -> Self {
        Self {
            bitmap,
            cached_states: BTreeMap::new(),
        }
    }
}

// Implement the Storage trait for HistoricalBitmap
impl<H: Hasher, const N: usize> crate::mmr::storage::Storage<H::Digest> for HistoricalBitmap<H, N> {
    fn size(&self) -> u64 {
        self.size()
    }

    async fn get_node(&self, position: u64) -> Result<Option<H::Digest>, crate::mmr::Error> {
        Ok(self.get_node(position))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::mmr::hasher::Standard;
    use commonware_cryptography::Sha256;
    use commonware_runtime::{deterministic, Runner as _};

    type TestHistoricalBitmap = HistoricalBitmap<Sha256, 32>;

    #[test]
    fn test_new() {
        // Tests that new() creates an empty HistoricalBitmap with no cached states
        let hb = TestHistoricalBitmap::new();
        assert_eq!(hb.current().bit_count(), 0);
        assert_eq!(hb.cached_count(), 0);
        assert_eq!(hb.current_bit_count(), 0);
    }

    #[test]
    fn test_from_bitmap() {
        // Tests that From<Bitmap<H, N>> creates a HistoricalBitmap that preserves the existing bitmap's state
        let mut bitmap = crate::mmr::bitmap::Bitmap::new();
        bitmap.append(true);
        bitmap.append(false);

        let hb = TestHistoricalBitmap::from(bitmap);
        assert_eq!(hb.current().bit_count(), 2);
        assert_eq!(hb.cached_count(), 0);
        assert!(hb.current().get_bit(0));
        assert!(!hb.current().get_bit(1));
    }

    #[test]
    fn test_cache_state() {
        // Tests that cache_state() stores bitmap snapshots that can be retrieved later
        let mut hb = TestHistoricalBitmap::new();

        hb.cache_state(0);
        assert!(hb.has_state(0));
        assert_eq!(hb.cached_count(), 1);
        assert_eq!(hb.available_indices(), vec![0]);

        hb.append(true);
        hb.cache_state(1);
        assert!(hb.has_state(1));
        assert_eq!(hb.cached_count(), 2);
        assert_eq!(hb.available_indices(), vec![0, 1]);

        hb.append(false);
        hb.cache_state(2);
        assert!(hb.has_state(2));
        assert_eq!(hb.cached_count(), 3);
        assert_eq!(hb.available_indices(), vec![0, 1, 2]);

        hb.set_bit(1, true);
        hb.cache_state(3);
        assert!(hb.has_state(3));
        assert_eq!(hb.cached_count(), 4);
        assert_eq!(hb.available_indices(), vec![0, 1, 2, 3]);

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
        assert_eq!(state_3.bit_count(), 2);
        assert!(state_3.get_bit(0));
        assert!(state_3.get_bit(1));
    }

    #[test]
    fn test_prune_to_bit() {
        // Tests comprehensive prune_to_bit behavior with operations between cached states
        // and multiple pruning calls
        let mut hb = TestHistoricalBitmap::new();

        // Phase 1: Build up bitmap with operations and cache states

        // Cache initial empty state
        // Bitmap: (empty)
        // Cached: [0]
        hb.cache_state(0);
        assert_eq!(hb.current_bit_count(), 0);
        assert_eq!(hb.cached_count(), 1);

        // Add some bits and cache intermediate states
        hb.append(true); // bit_count = 1
        hb.append(false); // bit_count = 2
                          // Bitmap: [1, 0]
                          // Cached: [0, 2]
        hb.cache_state(2);

        hb.append(true); // bit_count = 3
        hb.append(true); // bit_count = 4
        hb.append(false); // bit_count = 5
                          // Bitmap: [1, 0, 1, 1, 0]
                          // Cached: [0, 2, 5]
        hb.cache_state(5);

        hb.append(false); // bit_count = 6
        hb.append(true); // bit_count = 7
        hb.append(false); // bit_count = 8
                          // Bitmap: [1, 0, 1, 1, 0, 0, 1, 0]
                          // Cached: [0, 2, 5, 8]
        hb.cache_state(8);

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
                          // Cached: [0, 2, 5, 8, 10]
        hb.cache_state(10);

        // Verify initial state
        assert_eq!(hb.current_bit_count(), 10);
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

        // Phase 2: First pruning - remove states below bit 3
        // Before: Bitmap: [1, 0, 1, 1, 0, 0, 1, 0, 1, 0]
        //         Cached: [0, 2, 5, 8, 10]
        //         Prune:   ^  ^  ^  (remove states < 3)
        hb.prune_to_bit(3);
        // After:  Bitmap: [X, X, X, 1, 0, 0, 1, 0, 1, 0] (bits 0-2 pruned)
        //         Cached: [5, 8, 10] (states 0,2 removed)

        // States with index >= 3 should remain, others should be removed
        assert_eq!(hb.cached_count(), 3); // States at 5, 8, 10 remain
        assert!(!hb.has_state(0)); // Removed (0 < 3)
        assert!(!hb.has_state(2)); // Removed (2 < 3)
        assert!(hb.has_state(5)); // Kept (5 >= 3)
        assert!(hb.has_state(8)); // Kept (8 >= 3)
        assert!(hb.has_state(10)); // Kept (10 >= 3)

        // Phase 3: Add operations with set_bit modifications
        hb.append(false); // bit_count = 11
        hb.append(true); // bit_count = 12
                         // Bitmap: [X, X, X, 1, 1, 1, 1, 0, 1, 0, 0, 1]
                         // Cached: [5, 8, 10, 12]
        hb.cache_state(12);

        // Use set_bit to modify existing bits (simulates operations becoming inactive)
        hb.set_bit(9, true); // Change bit 9 from 0 to 1
        hb.set_bit(10, true); // Change bit 10 from 0 to 1
                              // Bitmap: [X, X, X, 1, 1, 1, 1, 0, 1, 1, 1, 1]
                              //                              ^  ^  (bits 9,10 changed)

        // Verify that set_bit doesn't affect previously cached states
        let cached_state_10 = hb.get_state(10).unwrap();
        assert_eq!(cached_state_10.bit_count(), 10);
        assert!(!cached_state_10.get_bit(9)); // Should still be false (cached before set_bit)

        // But current bitmap should reflect the set_bit change
        assert!(hb.current().get_bit(9)); // Should now be true (after set_bit)

        // Verify state before pruning
        assert_eq!(hb.current_bit_count(), 12);
        assert_eq!(hb.cached_count(), 4); // States at 5, 8, 10, 12

        // Phase 4: Prune to remove some cached states
        // Before: Bitmap: [X, X, X, 1, 1, 1, 1, 0, 1, 1, 1, 1]
        //         Cached: [5, 8, 10, 12]
        //         Prune:   ^  ^  (remove states < 9)
        hb.prune_to_bit(9);
        // After:  Bitmap: [X, X, X, X, X, X, X, X, X, 1, 1, 1] (bits 0-8 pruned)
        //         Cached: [10, 12] (states 5,8 removed)

        assert_eq!(hb.cached_count(), 2);
        assert!(!hb.has_state(5)); // Removed (5 < 9)
        assert!(!hb.has_state(8)); // Removed (8 < 9)
        assert!(hb.has_state(10)); // Kept (10 >= 9)
        assert!(hb.has_state(12)); // Kept (12 >= 9)

        // Phase 5: Final pruning beyond all cached states
        // Before: Bitmap: [X, X, X, X, X, X, X, X, X, 1, 1, 1]
        //         Cached: [10, 12]
        //         Prune:   ^   ^  (remove states < 15)
        hb.prune_to_bit(15);
        // After:  Bitmap: [X, X, X, X, X, X, X, X, X, X, X, X, X, X, X] (all bits pruned)
        //         Cached: [] (all states removed)

        assert_eq!(hb.cached_count(), 0);
        assert!(!hb.has_state(10)); // Removed (10 < 15)
        assert!(!hb.has_state(12)); // Removed (12 < 15)

        // Current bitmap should still be accessible
        assert_eq!(hb.current_bit_count(), 12);
    }

    // Tests that cached bitmap states preserve their MMR roots correctly
    #[test]
    fn test_cached_states_preserve_mmr_roots() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            let mut hb = TestHistoricalBitmap::new();
            let mut hasher = Standard::new();

            // Cache state and capture its root
            hb.cache_state(0);
            let root_0 = hb.current().root(&mut hasher).await.unwrap();

            // Modify bitmap and cache new state
            hb.append(true);
            hb.cache_state(1);
            let root_1 = hb.current().root(&mut hasher).await.unwrap();

            // Verify cached states have preserved their original roots
            let cached_0 = hb.get_state(0).unwrap();
            assert_eq!(cached_0.root(&mut hasher).await.unwrap(), root_0);

            let cached_1 = hb.get_state(1).unwrap();
            assert_eq!(cached_1.root(&mut hasher).await.unwrap(), root_1);
        });
    }

    #[test]
    fn test_cached_state_unmodified() {
        let mut hb = TestHistoricalBitmap::new();

        hb.append(true);
        hb.append(false);
        hb.append(true);
        hb.cache_state(3);

        // Setting should not modify the cached state
        hb.set_bit(1, true);

        // Verify cached state preserves original bit value
        let cached_3 = hb.get_state(3).unwrap();
        assert!(!cached_3.get_bit(1));

        // Verify current state has modified bit value
        assert!(hb.current().get_bit(1));
    }

    #[test]
    fn test_prune_empty() {
        let mut hb = TestHistoricalBitmap::new();

        hb.prune_to_bit(10);
        assert_eq!(hb.cached_count(), 0);
        assert_eq!(hb.available_indices(), Vec::<u64>::new());
    }
}

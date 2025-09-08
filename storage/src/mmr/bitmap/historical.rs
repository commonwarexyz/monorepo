//! Historical bitmap that maintains a cache of recent bitmap states.
//!
//! This implementation stores the current bitmap and caches the last N complete
//! bitmap states for fast retrieval, which is needed for implementing
//! the sync database trait.

use crate::mmr::bitmap::Bitmap;
use commonware_cryptography::Hasher;
use std::collections::HashMap;

/// A bitmap wrapper that maintains a cache of recent bitmap states.
///
/// Cached states are automatically pruned when the underlying bitmap is pruned.
pub struct HistoricalBitmap<H: Hasher, const N: usize> {
    /// The current bitmap state
    bitmap: Bitmap<H, N>,
    /// Cache of bitmap states keyed by index (log size)
    cached_states: HashMap<u64, Bitmap<H, N>>,
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
            cached_states: HashMap::new(),
        }
    }

    /// Create a new historical bitmap from an existing bitmap
    pub fn from_bitmap(bitmap: Bitmap<H, N>) -> Self {
        Self {
            bitmap,
            cached_states: HashMap::new(),
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

    /// Cache the current bitmap state at the specified index (log size)
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

    /// Prune the bitmap to the specified bit offset and remove cached states below this offset.
    pub fn prune_to_bit(&mut self, bit_offset: u64) {
        self.bitmap.prune_to_bit(bit_offset);
        self.cached_states.retain(|&index, _| index >= bit_offset);
    }

    /// Get a cached bitmap state by index
    /// Returns None if the index is not in the cache
    pub fn get_cached_state(&self, index: u64) -> Option<&Bitmap<H, N>> {
        self.cached_states.get(&index)
    }

    /// Get a bitmap state by index
    pub fn get_state(&self, index: u64) -> Option<&Bitmap<H, N>> {
        self.cached_states.get(&index)
    }

    /// Get all available cached indices in sorted order
    pub fn available_indices(&self) -> Vec<u64> {
        let mut indices: Vec<u64> = self.cached_states.keys().copied().collect();
        indices.sort_unstable();
        indices
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
        // Tests that from_bitmap() creates a HistoricalBitmap that preserves the existing bitmap's state
        let mut bitmap = crate::mmr::bitmap::Bitmap::new();
        bitmap.append(true);
        bitmap.append(false);

        let hb = TestHistoricalBitmap::from_bitmap(bitmap);
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
        hb.append(true);
        hb.cache_state(1);
        hb.append(false);
        hb.cache_state(2);

        assert_eq!(hb.cached_count(), 3);

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
    }

    #[test]
    fn test_available_indices() {
        // Tests that available_indices() returns all cached indices in sorted order
        let mut hb = TestHistoricalBitmap::new();

        // Cache states in non-sequential order
        hb.cache_state(10);
        hb.cache_state(5);
        hb.cache_state(15);
        hb.cache_state(1);

        let indices = hb.available_indices();
        assert_eq!(indices, vec![1, 5, 10, 15]); // Should be sorted
    }

    #[test]
    fn test_prune_to_bit() {
        // Tests that prune_to_bit() removes cached states with index < bit_offset
        let mut hb = TestHistoricalBitmap::new();

        hb.cache_state(0);
        hb.cache_state(1);
        hb.cache_state(2);
        hb.cache_state(3);
        hb.cache_state(4);

        hb.prune_to_bit(2);

        // States with index >= 2 should remain
        assert_eq!(hb.cached_count(), 3);
        assert!(!hb.has_state(0));
        assert!(!hb.has_state(1));
        assert!(hb.has_state(2));
        assert!(hb.has_state(3));
        assert!(hb.has_state(4));
    }

    #[test]
    fn test_cached_states_preserve_mmr_roots() {
        // Tests that cached bitmap states preserve their MMR roots correctly
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

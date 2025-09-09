//! A prunable wrapper around BitVec that tracks pruned chunks.
//!
//! This provides the same interface as the Bitmap type in storage/mmr/bitmap.rs
//! but built on top of the BitVec implementation.

use super::BitVec;

/// A prunable bitmap that stores data in chunks of N bytes.
#[derive(Clone, Debug)]
pub struct Prunable<const N: usize> {
    /// The underlying BitVec storing the actual bits.
    bitvec: BitVec<N>,

    /// The number of bitmap chunks that have been pruned.
    pruned_chunks: usize,
}

impl<const N: usize> Prunable<N> {
    /// The size of a chunk in bits.
    const CHUNK_SIZE_BITS: u64 = N as u64 * 8;

    /// Create a new empty prunable bitmap.
    pub fn new() -> Self {
        Self {
            bitvec: BitVec::new(),
            pruned_chunks: 0,
        }
    }

    /// Create a new empty prunable bitmap with the given number of pruned chunks.
    pub fn new_with_pruned_chunks(pruned_chunks: usize) -> Self {
        Self {
            bitvec: BitVec::new(),
            pruned_chunks,
        }
    }

    /// Return the number of bits in the bitmap, irrespective of any pruning.
    #[inline]
    pub fn len(&self) -> u64 {
        self.pruned_chunks as u64 * Self::CHUNK_SIZE_BITS + self.bitvec.len()
    }

    /// Returns true if the bitmap is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the number of bits that have been pruned from this bitmap.
    #[inline]
    pub fn pruned_bits(&self) -> u64 {
        self.pruned_chunks as u64 * Self::CHUNK_SIZE_BITS
    }

    /// Return the last chunk of the bitmap and its size in bits.
    #[inline]
    pub fn last_chunk(&self) -> (&[u8; N], u64) {
        self.bitvec.last_chunk()
    }

    /// Returns the bitmap chunk containing the specified bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_chunk(&self, bit_offset: u64) -> &[u8; N] {
        let chunk_num = Self::chunk_num(bit_offset);
        assert!(chunk_num >= self.pruned_chunks, "bit pruned: {bit_offset}");

        // Adjust bit_offset to account for pruning
        let adjusted_offset = bit_offset - self.pruned_bits();
        self.bitvec.get_chunk(adjusted_offset)
    }

    /// Get the value of a bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        let chunk_num = Self::chunk_num(bit_offset);
        assert!(chunk_num >= self.pruned_chunks, "bit pruned: {bit_offset}");

        // Adjust bit_offset to account for pruning
        let adjusted_offset = bit_offset - self.pruned_bits();
        self.bitvec.get_bit(adjusted_offset)
    }

    /// Get the value of a bit from its chunk.
    #[inline]
    pub fn get_bit_from_chunk(chunk: &[u8; N], bit_offset: u64) -> bool {
        BitVec::<N>::get_bit_from_chunk(chunk, bit_offset)
    }

    /// Add a single bit to the bitmap.
    pub fn append(&mut self, bit: bool) {
        self.bitvec.append(bit);
    }

    /// Efficiently add a byte to the bitmap.
    ///
    /// # Warning
    ///
    /// Assumes self.next_bit is currently byte aligned, and panics otherwise.
    pub fn append_byte_unchecked(&mut self, byte: u8) {
        self.bitvec.append_byte_unchecked(byte);
    }

    /// Efficiently add a chunk of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// Assumes we are at a chunk boundary (that is, `self.next_bit` is 0) and panics otherwise.
    pub fn append_chunk_unchecked(&mut self, chunk: &[u8; N]) {
        self.bitvec.append_chunk_unchecked(chunk);
    }

    /// Set the value of the given bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    pub fn set_bit(&mut self, bit_offset: u64, bit: bool) {
        let chunk_num = Self::chunk_num(bit_offset);
        assert!(chunk_num >= self.pruned_chunks, "bit pruned: {bit_offset}");

        // Adjust bit_offset to account for pruning
        let adjusted_offset = bit_offset - self.pruned_bits();
        self.bitvec.set(adjusted_offset, bit);
    }

    /// Prune the bitmap to the most recent chunk boundary that contains the referenced bit.
    ///
    /// # Warning
    ///
    /// Panics if the referenced bit is greater than the number of bits in the bitmap.
    pub fn prune_to_bit(&mut self, bit_offset: u64) {
        let chunk_num = Self::chunk_num(bit_offset);
        if chunk_num < self.pruned_chunks {
            return;
        }

        let chunks_to_prune = chunk_num - self.pruned_chunks;
        self.bitvec.prune_chunks(chunks_to_prune);
        self.pruned_chunks = chunk_num;
    }

    /// Convert a bit offset into a bitmask for the byte containing that bit.
    #[inline]
    pub fn chunk_byte_bitmask(bit_offset: u64) -> u8 {
        BitVec::<N>::chunk_byte_bitmask(bit_offset)
    }

    /// Convert a bit offset into the offset of the byte within a chunk containing the bit.
    #[inline]
    pub fn chunk_byte_offset(bit_offset: u64) -> usize {
        BitVec::<N>::chunk_byte_offset(bit_offset)
    }

    /// Convert a bit offset into the index of the chunk it belongs to within the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn chunk_index(&self, bit_offset: u64) -> usize {
        assert!(bit_offset < self.len(), "out of bounds: {bit_offset}");
        let chunk_num = Self::chunk_num(bit_offset);
        assert!(chunk_num >= self.pruned_chunks, "bit pruned: {bit_offset}");

        chunk_num - self.pruned_chunks
    }

    /// Convert a bit offset into the number of the chunk it belongs to.
    #[inline]
    pub fn chunk_num(bit_offset: u64) -> usize {
        BitVec::<N>::chunk_index(bit_offset)
    }

    /// Get the number of chunks in the bitmap
    pub fn chunks_len(&self) -> usize {
        self.bitvec.chunks_len()
    }

    /// Get a reference to a chunk by its index in the current bitmap
    pub fn get_chunk_by_index(&self, index: usize) -> &[u8; N] {
        self.bitvec.get_chunk_by_index(index)
    }

    /// Get the number of pruned chunks
    pub fn pruned_chunks(&self) -> usize {
        self.pruned_chunks
    }
}

impl<const N: usize> Default for Prunable<N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_empty() {
        let prunable: Prunable<32> = Prunable::new();
        assert_eq!(prunable.len(), 0);
        assert_eq!(prunable.pruned_bits(), 0);
        assert_eq!(prunable.pruned_chunks(), 0);
        assert!(prunable.is_empty());
        assert_eq!(prunable.chunks_len(), 1); // Always has at least one chunk
    }

    #[test]
    fn test_append_and_get_bits() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add some bits
        prunable.append(true);
        prunable.append(false);
        prunable.append(true);

        assert_eq!(prunable.len(), 3);
        assert!(!prunable.is_empty());
        assert!(prunable.get_bit(0));
        assert!(!prunable.get_bit(1));
        assert!(prunable.get_bit(2));
    }

    #[test]
    fn test_append_byte() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add a byte
        prunable.append_byte_unchecked(0xFF);
        assert_eq!(prunable.len(), 8);

        // All bits should be set
        for i in 0..8 {
            assert!(prunable.get_bit(i));
        }

        prunable.append_byte_unchecked(0x00);
        assert_eq!(prunable.len(), 16);

        // Next 8 bits should be clear
        for i in 8..16 {
            assert!(!prunable.get_bit(i));
        }
    }

    #[test]
    fn test_append_chunk() {
        let mut prunable: Prunable<4> = Prunable::new();
        let chunk = [0xAA, 0xBB, 0xCC, 0xDD];

        prunable.append_chunk_unchecked(&chunk);
        assert_eq!(prunable.len(), 32); // 4 bytes * 8 bits

        let retrieved_chunk = prunable.get_chunk(0);
        assert_eq!(retrieved_chunk, &chunk);
    }

    #[test]
    fn test_set_bit() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add some bits
        prunable.append(false);
        prunable.append(false);
        prunable.append(false);

        assert!(!prunable.get_bit(1));

        // Set a bit
        prunable.set_bit(1, true);
        assert!(prunable.get_bit(1));

        // Set it back
        prunable.set_bit(1, false);
        assert!(!prunable.get_bit(1));
    }

    #[test]
    fn test_pruning_basic() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add multiple chunks (4 bytes each)
        let chunk1 = [0x01, 0x02, 0x03, 0x04];
        let chunk2 = [0x05, 0x06, 0x07, 0x08];
        let chunk3 = [0x09, 0x0A, 0x0B, 0x0C];

        prunable.append_chunk_unchecked(&chunk1);
        prunable.append_chunk_unchecked(&chunk2);
        prunable.append_chunk_unchecked(&chunk3);

        assert_eq!(prunable.len(), 96); // 3 chunks * 32 bits
        assert_eq!(prunable.pruned_chunks(), 0);

        // Prune to second chunk (bit 32 is start of second chunk)
        prunable.prune_to_bit(32);
        assert_eq!(prunable.pruned_chunks(), 1);
        assert_eq!(prunable.pruned_bits(), 32);
        assert_eq!(prunable.len(), 96); // Total count unchanged

        // Can still access non-pruned bits
        assert_eq!(prunable.get_chunk(32), &chunk2);
        assert_eq!(prunable.get_chunk(64), &chunk3);

        // Prune to third chunk
        prunable.prune_to_bit(64);
        assert_eq!(prunable.pruned_chunks(), 2);
        assert_eq!(prunable.pruned_bits(), 64);
        assert_eq!(prunable.len(), 96);

        // Can still access the third chunk
        assert_eq!(prunable.get_chunk(64), &chunk3);
    }

    #[test]
    #[should_panic(expected = "bit pruned")]
    fn test_get_pruned_bit_panics() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add two chunks
        prunable.append_chunk_unchecked(&[1, 2, 3, 4]);
        prunable.append_chunk_unchecked(&[5, 6, 7, 8]);

        // Prune first chunk
        prunable.prune_to_bit(32);

        // Try to access pruned bit - should panic
        prunable.get_bit(0);
    }

    #[test]
    #[should_panic(expected = "bit pruned")]
    fn test_get_pruned_chunk_panics() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add two chunks
        prunable.append_chunk_unchecked(&[1, 2, 3, 4]);
        prunable.append_chunk_unchecked(&[5, 6, 7, 8]);

        // Prune first chunk
        prunable.prune_to_bit(32);

        // Try to access pruned chunk - should panic
        prunable.get_chunk(0);
    }

    #[test]
    #[should_panic(expected = "bit pruned")]
    fn test_set_pruned_bit_panics() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add two chunks
        prunable.append_chunk_unchecked(&[1, 2, 3, 4]);
        prunable.append_chunk_unchecked(&[5, 6, 7, 8]);

        // Prune first chunk
        prunable.prune_to_bit(32);

        // Try to set pruned bit - should panic
        prunable.set_bit(0, true);
    }

    #[test]
    fn test_pruning_with_partial_chunk() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add two full chunks and some partial bits
        prunable.append_chunk_unchecked(&[0xFF; 4]);
        prunable.append_chunk_unchecked(&[0xAA; 4]);
        prunable.append(true);
        prunable.append(false);
        prunable.append(true);

        assert_eq!(prunable.len(), 67); // 64 + 3 bits

        // Prune to second chunk
        prunable.prune_to_bit(32);
        assert_eq!(prunable.pruned_chunks(), 1);
        assert_eq!(prunable.len(), 67);

        // Can still access the partial bits
        assert!(prunable.get_bit(64));
        assert!(!prunable.get_bit(65));
        assert!(prunable.get_bit(66));
    }

    #[test]
    fn test_prune_idempotent() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add chunks
        prunable.append_chunk_unchecked(&[1, 2, 3, 4]);
        prunable.append_chunk_unchecked(&[5, 6, 7, 8]);

        // Prune to bit 32
        prunable.prune_to_bit(32);
        assert_eq!(prunable.pruned_chunks(), 1);

        // Pruning to same or earlier point should be no-op
        prunable.prune_to_bit(32);
        assert_eq!(prunable.pruned_chunks(), 1);

        prunable.prune_to_bit(16);
        assert_eq!(prunable.pruned_chunks(), 1);
    }

    #[test]
    fn test_append_after_pruning() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add initial chunks
        prunable.append_chunk_unchecked(&[1, 2, 3, 4]);
        prunable.append_chunk_unchecked(&[5, 6, 7, 8]);

        // Prune first chunk
        prunable.prune_to_bit(32);
        assert_eq!(prunable.len(), 64);
        assert_eq!(prunable.pruned_chunks(), 1);

        // Add more data
        prunable.append_chunk_unchecked(&[9, 10, 11, 12]);
        assert_eq!(prunable.len(), 96); // 32 pruned + 64 active

        // New chunk should be accessible
        assert_eq!(prunable.get_chunk(64), &[9, 10, 11, 12]);
    }

    #[test]
    fn test_chunk_calculations() {
        // Test chunk_num calculation
        assert_eq!(Prunable::<4>::chunk_num(0), 0);
        assert_eq!(Prunable::<4>::chunk_num(31), 0);
        assert_eq!(Prunable::<4>::chunk_num(32), 1);
        assert_eq!(Prunable::<4>::chunk_num(63), 1);
        assert_eq!(Prunable::<4>::chunk_num(64), 2);

        // Test chunk_byte_offset
        assert_eq!(Prunable::<4>::chunk_byte_offset(0), 0);
        assert_eq!(Prunable::<4>::chunk_byte_offset(8), 1);
        assert_eq!(Prunable::<4>::chunk_byte_offset(16), 2);
        assert_eq!(Prunable::<4>::chunk_byte_offset(24), 3);
        assert_eq!(Prunable::<4>::chunk_byte_offset(32), 0); // Wraps to next chunk

        // Test chunk_byte_bitmask
        assert_eq!(Prunable::<4>::chunk_byte_bitmask(0), 0b00000001);
        assert_eq!(Prunable::<4>::chunk_byte_bitmask(1), 0b00000010);
        assert_eq!(Prunable::<4>::chunk_byte_bitmask(7), 0b10000000);
        assert_eq!(Prunable::<4>::chunk_byte_bitmask(8), 0b00000001); // Next byte
    }

    #[test]
    fn test_chunk_index_with_pruning() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add three chunks
        for i in 0..3 {
            let chunk = [
                (i * 4) as u8,
                (i * 4 + 1) as u8,
                (i * 4 + 2) as u8,
                (i * 4 + 3) as u8,
            ];
            prunable.append_chunk_unchecked(&chunk);
        }

        // Before pruning
        assert_eq!(prunable.chunk_index(0), 0);
        assert_eq!(prunable.chunk_index(32), 1);
        assert_eq!(prunable.chunk_index(64), 2);

        // After pruning first chunk
        prunable.prune_to_bit(32);
        assert_eq!(prunable.chunk_index(32), 0); // Now at index 0
        assert_eq!(prunable.chunk_index(64), 1); // Now at index 1
    }

    #[test]
    fn test_last_chunk_with_pruning() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add chunks
        prunable.append_chunk_unchecked(&[1, 2, 3, 4]);
        prunable.append_chunk_unchecked(&[5, 6, 7, 8]);
        prunable.append(true);
        prunable.append(false);

        let (_, next_bit) = prunable.last_chunk();
        assert_eq!(next_bit, 2);

        // Store the chunk data for comparison
        let chunk_data = *prunable.last_chunk().0;

        // Pruning shouldn't affect last_chunk
        prunable.prune_to_bit(32);
        let (chunk2, next_bit2) = prunable.last_chunk();
        assert_eq!(next_bit2, 2);
        assert_eq!(&chunk_data, chunk2);
    }

    #[test]
    fn test_different_chunk_sizes() {
        // Test with different chunk sizes
        let mut p8: Prunable<8> = Prunable::new();
        let mut p16: Prunable<16> = Prunable::new();
        let mut p32: Prunable<32> = Prunable::new();

        // Add same pattern to each
        for i in 0..10 {
            p8.append(i % 2 == 0);
            p16.append(i % 2 == 0);
            p32.append(i % 2 == 0);
        }

        // All should have same bit count
        assert_eq!(p8.len(), 10);
        assert_eq!(p16.len(), 10);
        assert_eq!(p32.len(), 10);

        // All should have same bit values
        for i in 0..10 {
            let expected = i % 2 == 0;
            if expected {
                assert!(p8.get_bit(i));
                assert!(p16.get_bit(i));
                assert!(p32.get_bit(i));
            } else {
                assert!(!p8.get_bit(i));
                assert!(!p16.get_bit(i));
                assert!(!p32.get_bit(i));
            }
        }
    }

    #[test]
    fn test_get_bit_from_chunk() {
        let chunk: [u8; 4] = [0b10101010, 0b11001100, 0b11110000, 0b00001111];

        // Test first byte
        assert!(!Prunable::<4>::get_bit_from_chunk(&chunk, 0));
        assert!(Prunable::<4>::get_bit_from_chunk(&chunk, 1));
        assert!(!Prunable::<4>::get_bit_from_chunk(&chunk, 2));
        assert!(Prunable::<4>::get_bit_from_chunk(&chunk, 3));

        // Test second byte
        assert!(!Prunable::<4>::get_bit_from_chunk(&chunk, 8));
        assert!(!Prunable::<4>::get_bit_from_chunk(&chunk, 9));
        assert!(Prunable::<4>::get_bit_from_chunk(&chunk, 10));
        assert!(Prunable::<4>::get_bit_from_chunk(&chunk, 11));
    }

    #[test]
    fn test_get_chunk_by_index() {
        let mut prunable: Prunable<4> = Prunable::new();
        let chunk1 = [0x11, 0x22, 0x33, 0x44];
        let chunk2 = [0x55, 0x66, 0x77, 0x88];
        let chunk3 = [0x99, 0xAA, 0xBB, 0xCC];

        prunable.append_chunk_unchecked(&chunk1);
        prunable.append_chunk_unchecked(&chunk2);
        prunable.append_chunk_unchecked(&chunk3);

        // Before pruning
        assert_eq!(prunable.get_chunk_by_index(0), &chunk1);
        assert_eq!(prunable.get_chunk_by_index(1), &chunk2);
        assert_eq!(prunable.get_chunk_by_index(2), &chunk3);

        // After pruning
        prunable.prune_to_bit(32);
        assert_eq!(prunable.get_chunk_by_index(0), &chunk2);
        assert_eq!(prunable.get_chunk_by_index(1), &chunk3);
    }
}

//! A prunable wrapper around BitMap that tracks pruned chunks.

use super::BitMap;
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadExt, Write};
use thiserror::Error;

/// Errors that can occur when working with a prunable bitmap.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum Error {
    /// The provided pruned_chunks value would overflow.
    #[error("pruned_chunks * CHUNK_SIZE_BITS overflows u64")]
    PrunedChunksOverflow,
}

/// A prunable bitmap that stores data in chunks of N bytes.
///
/// # Panics
///
/// Operations panic if `bit / CHUNK_SIZE_BITS > usize::MAX`. On 32-bit systems
/// with N=32, this occurs at bit >= 1,099,511,627,776.
#[derive(Clone, Debug)]
pub struct Prunable<const N: usize> {
    /// The underlying BitMap storing the actual bits.
    bitmap: BitMap<N>,

    /// The number of bitmap chunks that have been pruned.
    ///
    /// # Invariant
    ///
    /// Must satisfy: `pruned_chunks as u64 * CHUNK_SIZE_BITS + bitmap.len() <= u64::MAX`
    pruned_chunks: usize,
}

impl<const N: usize> Prunable<N> {
    /// The size of a chunk in bits.
    pub const CHUNK_SIZE_BITS: u64 = BitMap::<N>::CHUNK_SIZE_BITS;

    /* Constructors */

    /// Create a new empty prunable bitmap.
    pub const fn new() -> Self {
        Self {
            bitmap: BitMap::new(),
            pruned_chunks: 0,
        }
    }

    /// Create a new empty prunable bitmap with the given number of pruned chunks.
    ///
    /// # Errors
    ///
    /// Returns an error if `pruned_chunks` violates the invariant that
    /// `pruned_chunks as u64 * CHUNK_SIZE_BITS` must not overflow u64.
    pub fn new_with_pruned_chunks(pruned_chunks: usize) -> Result<Self, Error> {
        // Validate the invariant: pruned_chunks * CHUNK_SIZE_BITS must fit in u64
        let pruned_chunks_u64 = pruned_chunks as u64;
        pruned_chunks_u64
            .checked_mul(Self::CHUNK_SIZE_BITS)
            .ok_or(Error::PrunedChunksOverflow)?;

        Ok(Self {
            bitmap: BitMap::new(),
            pruned_chunks,
        })
    }

    /* Length */

    /// Return the number of bits in the bitmap, irrespective of any pruning.
    #[inline]
    pub const fn len(&self) -> u64 {
        let pruned_bits = (self.pruned_chunks as u64)
            .checked_mul(Self::CHUNK_SIZE_BITS)
            .expect("invariant violated: pruned_chunks * CHUNK_SIZE_BITS overflows u64");

        pruned_bits
            .checked_add(self.bitmap.len())
            .expect("invariant violated: pruned_bits + bitmap.len() overflows u64")
    }

    /// Return true if the bitmap is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if the bitmap length is aligned to a chunk boundary.
    #[inline]
    pub const fn is_chunk_aligned(&self) -> bool {
        self.len().is_multiple_of(Self::CHUNK_SIZE_BITS)
    }

    /// Return the number of unpruned chunks in the bitmap.
    #[inline]
    pub fn chunks_len(&self) -> usize {
        self.bitmap.chunks_len()
    }

    /// Return the number of pruned chunks.
    #[inline]
    pub const fn pruned_chunks(&self) -> usize {
        self.pruned_chunks
    }

    /// Return the number of pruned bits.
    #[inline]
    pub const fn pruned_bits(&self) -> u64 {
        (self.pruned_chunks as u64)
            .checked_mul(Self::CHUNK_SIZE_BITS)
            .expect("invariant violated: pruned_chunks * CHUNK_SIZE_BITS overflows u64")
    }

    /* Getters */

    /// Get the value of a bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_bit(&self, bit: u64) -> bool {
        let chunk_num = Self::unpruned_chunk(bit);
        assert!(chunk_num >= self.pruned_chunks, "bit pruned: {bit}");

        // Adjust bit to account for pruning
        self.bitmap.get(bit - self.pruned_bits())
    }

    /// Returns the bitmap chunk containing the specified bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_chunk_containing(&self, bit: u64) -> &[u8; N] {
        let chunk_num = Self::unpruned_chunk(bit);
        assert!(chunk_num >= self.pruned_chunks, "bit pruned: {bit}");

        // Adjust bit to account for pruning
        self.bitmap.get_chunk_containing(bit - self.pruned_bits())
    }

    /// Get the value of a bit from its chunk.
    /// `bit` is an index into the entire bitmap, not just the chunk.
    #[inline]
    pub const fn get_bit_from_chunk(chunk: &[u8; N], bit: u64) -> bool {
        BitMap::<N>::get_from_chunk(chunk, bit)
    }

    /// Return the last chunk of the bitmap and its size in bits.
    #[inline]
    pub fn last_chunk(&self) -> (&[u8; N], u64) {
        self.bitmap.last_chunk()
    }

    /* Setters */

    /// Set the value of the given bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    pub fn set_bit(&mut self, bit: u64, value: bool) {
        let chunk_num = Self::unpruned_chunk(bit);
        assert!(chunk_num >= self.pruned_chunks, "bit pruned: {bit}");

        // Adjust bit to account for pruning
        self.bitmap.set(bit - self.pruned_bits(), value);
    }

    /// Add a single bit to the end of the bitmap.
    pub fn push(&mut self, bit: bool) {
        self.bitmap.push(bit);
    }

    /// Remove and return the last bit from the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bitmap is empty.
    pub fn pop(&mut self) -> bool {
        self.bitmap.pop()
    }

    /// Add a byte to the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if self.next_bit is not byte aligned.
    pub fn push_byte(&mut self, byte: u8) {
        self.bitmap.push_byte(byte);
    }

    /// Add a chunk of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if self.next_bit is not chunk aligned.
    pub fn push_chunk(&mut self, chunk: &[u8; N]) {
        self.bitmap.push_chunk(chunk);
    }

    /// Remove and return the last complete chunk from the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bitmap has fewer than `CHUNK_SIZE_BITS` bits or if not chunk-aligned.
    pub fn pop_chunk(&mut self) -> [u8; N] {
        self.bitmap.pop_chunk()
    }

    /* Pruning */

    /// Prune all complete chunks before the chunk containing the given bit.
    ///
    /// The chunk containing `bit` and all subsequent chunks are retained. All chunks
    /// before it are pruned.
    ///
    /// If `bit` equals the bitmap length, this prunes all complete chunks while retaining
    /// the empty trailing chunk, preparing the bitmap for appending new data.
    ///
    /// # Warning
    ///
    /// Panics if `bit` is greater than the bitmap length.
    pub fn prune_to_bit(&mut self, bit: u64) {
        assert!(
            bit <= self.len(),
            "bit {} out of bounds (len: {})",
            bit,
            self.len()
        );

        let chunk = Self::unpruned_chunk(bit);
        if chunk < self.pruned_chunks {
            return;
        }

        let chunks_to_prune = chunk - self.pruned_chunks;
        self.bitmap.prune_chunks(chunks_to_prune);
        self.pruned_chunks = chunk;
    }

    /* Indexing Helpers */

    /// Convert a bit into a bitmask for the byte containing that bit.
    #[inline]
    pub const fn chunk_byte_bitmask(bit: u64) -> u8 {
        BitMap::<N>::chunk_byte_bitmask(bit)
    }

    /// Convert a bit into the index of the byte within a chunk containing the bit.
    #[inline]
    pub const fn chunk_byte_offset(bit: u64) -> usize {
        BitMap::<N>::chunk_byte_offset(bit)
    }

    /// Convert a bit into the index of the chunk it belongs to within the bitmap,
    /// taking pruned chunks into account. That is, the returned value is a valid index into
    /// the inner bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn pruned_chunk(&self, bit: u64) -> usize {
        assert!(bit < self.len(), "out of bounds: {bit}");
        let chunk = Self::unpruned_chunk(bit);
        assert!(chunk >= self.pruned_chunks, "bit pruned: {bit}");

        chunk - self.pruned_chunks
    }

    /// Convert a bit into the number of the chunk it belongs to,
    /// ignoring any pruning.
    ///
    /// # Panics
    ///
    /// Panics if `bit / CHUNK_SIZE_BITS > usize::MAX`.
    #[inline]
    pub fn unpruned_chunk(bit: u64) -> usize {
        BitMap::<N>::chunk(bit)
    }

    /// Get a reference to a chunk by its index in the current bitmap
    /// Note this is an index into the chunks, not a bit.
    #[inline]
    pub fn get_chunk(&self, chunk: usize) -> &[u8; N] {
        self.bitmap.get_chunk(chunk)
    }

    /// Overwrite a chunk's data by its raw (unpruned) chunk index.
    ///
    /// # Panics
    ///
    /// Panics if the chunk is pruned or out of bounds.
    pub(super) fn set_chunk_by_index(&mut self, chunk_index: usize, chunk_data: &[u8; N]) {
        assert!(
            chunk_index >= self.pruned_chunks,
            "cannot set pruned chunk {chunk_index} (pruned_chunks: {})",
            self.pruned_chunks
        );
        let bitmap_chunk_idx = chunk_index - self.pruned_chunks;
        self.bitmap.set_chunk_by_index(bitmap_chunk_idx, chunk_data);
    }

    /// Unprune chunks by prepending them back to the front of the bitmap.
    ///
    /// The caller must provide chunks in **reverse** order: to restore chunks with
    /// indices [0, 1, 2], pass them as [2, 1, 0]. This is necessary because each chunk
    /// is prepended to the front, so the last chunk provided becomes the first chunk
    /// in the bitmap.
    ///
    /// # Panics
    ///
    /// Panics if chunks.len() > self.pruned_chunks.
    pub(super) fn unprune_chunks(&mut self, chunks: &[[u8; N]]) {
        assert!(
            chunks.len() <= self.pruned_chunks,
            "cannot unprune {} chunks (only {} pruned)",
            chunks.len(),
            self.pruned_chunks
        );

        for chunk in chunks.iter() {
            self.bitmap.prepend_chunk(chunk);
        }

        self.pruned_chunks -= chunks.len();
    }
}

impl<const N: usize> Default for Prunable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Write for Prunable<N> {
    fn write(&self, buf: &mut impl BufMut) {
        (self.pruned_chunks as u64).write(buf);
        self.bitmap.write(buf);
    }
}

impl<const N: usize> Read for Prunable<N> {
    // Max length for the unpruned portion of the bitmap.
    type Cfg = u64;

    fn read_cfg(buf: &mut impl Buf, max_len: &Self::Cfg) -> Result<Self, CodecError> {
        let pruned_chunks_u64 = u64::read(buf)?;

        // Validate that pruned_chunks * CHUNK_SIZE_BITS doesn't overflow u64
        let pruned_bits =
            pruned_chunks_u64
                .checked_mul(Self::CHUNK_SIZE_BITS)
                .ok_or(CodecError::Invalid(
                    "Prunable",
                    "pruned_chunks would overflow when computing pruned_bits",
                ))?;

        let pruned_chunks = usize::try_from(pruned_chunks_u64)
            .map_err(|_| CodecError::Invalid("Prunable", "pruned_chunks doesn't fit in usize"))?;

        let bitmap = BitMap::<N>::read_cfg(buf, max_len)?;

        // Validate that total length (pruned_bits + bitmap.len()) doesn't overflow u64
        pruned_bits
            .checked_add(bitmap.len())
            .ok_or(CodecError::Invalid(
                "Prunable",
                "total bitmap length (pruned + unpruned) would overflow u64",
            ))?;

        Ok(Self {
            bitmap,
            pruned_chunks,
        })
    }
}

impl<const N: usize> EncodeSize for Prunable<N> {
    fn encode_size(&self) -> usize {
        (self.pruned_chunks as u64).encode_size() + self.bitmap.encode_size()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hex;
    use bytes::BytesMut;
    use commonware_codec::Encode;

    #[test]
    fn test_new() {
        let prunable: Prunable<32> = Prunable::new();
        assert_eq!(prunable.len(), 0);
        assert_eq!(prunable.pruned_bits(), 0);
        assert_eq!(prunable.pruned_chunks(), 0);
        assert!(prunable.is_empty());
        assert_eq!(prunable.chunks_len(), 0); // No chunks when empty
    }

    #[test]
    fn test_new_with_pruned_chunks() {
        let prunable: Prunable<2> = Prunable::new_with_pruned_chunks(1).unwrap();
        assert_eq!(prunable.len(), 16);
        assert_eq!(prunable.pruned_bits(), 16);
        assert_eq!(prunable.pruned_chunks(), 1);
        assert_eq!(prunable.chunks_len(), 0);
    }

    #[test]
    fn test_new_with_pruned_chunks_overflow() {
        // Try to create a Prunable with pruned_chunks that would overflow
        let overflowing_pruned_chunks = (u64::MAX / Prunable::<4>::CHUNK_SIZE_BITS) as usize + 1;
        let result = Prunable::<4>::new_with_pruned_chunks(overflowing_pruned_chunks);

        assert!(matches!(result, Err(Error::PrunedChunksOverflow)));
    }

    #[test]
    fn test_push_and_get_bits() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add some bits
        prunable.push(true);
        prunable.push(false);
        prunable.push(true);

        assert_eq!(prunable.len(), 3);
        assert!(!prunable.is_empty());
        assert!(prunable.get_bit(0));
        assert!(!prunable.get_bit(1));
        assert!(prunable.get_bit(2));
    }

    #[test]
    fn test_push_byte() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add a byte
        prunable.push_byte(0xFF);
        assert_eq!(prunable.len(), 8);

        // All bits should be set
        for i in 0..8 {
            assert!(prunable.get_bit(i as u64));
        }

        prunable.push_byte(0x00);
        assert_eq!(prunable.len(), 16);

        // Next 8 bits should be clear
        for i in 8..16 {
            assert!(!prunable.get_bit(i as u64));
        }
    }

    #[test]
    fn test_push_chunk() {
        let mut prunable: Prunable<4> = Prunable::new();
        let chunk = hex!("0xAABBCCDD");

        prunable.push_chunk(&chunk);
        assert_eq!(prunable.len(), 32); // 4 bytes * 8 bits

        let retrieved_chunk = prunable.get_chunk_containing(0);
        assert_eq!(retrieved_chunk, &chunk);
    }

    #[test]
    fn test_set_bit() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add some bits
        prunable.push(false);
        prunable.push(false);
        prunable.push(false);

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
        let chunk1 = hex!("0x01020304");
        let chunk2 = hex!("0x05060708");
        let chunk3 = hex!("0x090A0B0C");

        prunable.push_chunk(&chunk1);
        prunable.push_chunk(&chunk2);
        prunable.push_chunk(&chunk3);

        assert_eq!(prunable.len(), 96); // 3 chunks * 32 bits
        assert_eq!(prunable.pruned_chunks(), 0);

        // Prune to second chunk (bit 32 is start of second chunk)
        prunable.prune_to_bit(32);
        assert_eq!(prunable.pruned_chunks(), 1);
        assert_eq!(prunable.pruned_bits(), 32);
        assert_eq!(prunable.len(), 96); // Total count unchanged

        // Can still access non-pruned bits
        assert_eq!(prunable.get_chunk_containing(32), &chunk2);
        assert_eq!(prunable.get_chunk_containing(64), &chunk3);

        // Prune to third chunk
        prunable.prune_to_bit(64);
        assert_eq!(prunable.pruned_chunks(), 2);
        assert_eq!(prunable.pruned_bits(), 64);
        assert_eq!(prunable.len(), 96);

        // Can still access the third chunk
        assert_eq!(prunable.get_chunk_containing(64), &chunk3);
    }

    #[test]
    #[should_panic(expected = "bit pruned")]
    fn test_get_pruned_bit_panics() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add two chunks
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);

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
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);

        // Prune first chunk
        prunable.prune_to_bit(32);

        // Try to access pruned chunk - should panic
        prunable.get_chunk_containing(0);
    }

    #[test]
    #[should_panic(expected = "bit pruned")]
    fn test_set_pruned_bit_panics() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add two chunks
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);

        // Prune first chunk
        prunable.prune_to_bit(32);

        // Try to set pruned bit - should panic
        prunable.set_bit(0, true);
    }

    #[test]
    #[should_panic(expected = "bit 25 out of bounds (len: 24)")]
    fn test_prune_to_bit_out_of_bounds() {
        let mut prunable: Prunable<1> = Prunable::new();

        // Add 3 bytes (24 bits total)
        prunable.push_byte(1);
        prunable.push_byte(2);
        prunable.push_byte(3);

        // Try to prune to a bit beyond the bitmap
        prunable.prune_to_bit(25);
    }

    #[test]
    fn test_pruning_with_partial_chunk() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add two full chunks and some partial bits
        prunable.push_chunk(&[0xFF; 4]);
        prunable.push_chunk(&[0xAA; 4]);
        prunable.push(true);
        prunable.push(false);
        prunable.push(true);

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
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);

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
    fn test_push_after_pruning() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add initial chunks
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);

        // Prune first chunk
        prunable.prune_to_bit(32);
        assert_eq!(prunable.len(), 64);
        assert_eq!(prunable.pruned_chunks(), 1);

        // Add more data
        prunable.push_chunk(&[9, 10, 11, 12]);
        assert_eq!(prunable.len(), 96); // 32 pruned + 64 active

        // New chunk should be accessible
        assert_eq!(prunable.get_chunk_containing(64), &[9, 10, 11, 12]);
    }

    #[test]
    fn test_chunk_calculations() {
        // Test chunk_num calculation
        assert_eq!(Prunable::<4>::unpruned_chunk(0), 0);
        assert_eq!(Prunable::<4>::unpruned_chunk(31), 0);
        assert_eq!(Prunable::<4>::unpruned_chunk(32), 1);
        assert_eq!(Prunable::<4>::unpruned_chunk(63), 1);
        assert_eq!(Prunable::<4>::unpruned_chunk(64), 2);

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
    fn test_pruned_chunk() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add three chunks
        for i in 0..3 {
            let chunk = [
                (i * 4) as u8,
                (i * 4 + 1) as u8,
                (i * 4 + 2) as u8,
                (i * 4 + 3) as u8,
            ];
            prunable.push_chunk(&chunk);
        }

        // Before pruning
        assert_eq!(prunable.pruned_chunk(0), 0);
        assert_eq!(prunable.pruned_chunk(32), 1);
        assert_eq!(prunable.pruned_chunk(64), 2);

        // After pruning first chunk
        prunable.prune_to_bit(32);
        assert_eq!(prunable.pruned_chunk(32), 0); // Now at index 0
        assert_eq!(prunable.pruned_chunk(64), 1); // Now at index 1
    }

    #[test]
    fn test_last_chunk_with_pruning() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Add chunks
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);
        prunable.push(true);
        prunable.push(false);

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
            p8.push(i % 2 == 0);
            p16.push(i % 2 == 0);
            p32.push(i % 2 == 0);
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
    fn test_get_chunk() {
        let mut prunable: Prunable<4> = Prunable::new();
        let chunk1 = hex!("0x11223344");
        let chunk2 = hex!("0x55667788");
        let chunk3 = hex!("0x99AABBCC");

        prunable.push_chunk(&chunk1);
        prunable.push_chunk(&chunk2);
        prunable.push_chunk(&chunk3);

        // Before pruning
        assert_eq!(prunable.get_chunk(0), &chunk1);
        assert_eq!(prunable.get_chunk(1), &chunk2);
        assert_eq!(prunable.get_chunk(2), &chunk3);

        // After pruning
        prunable.prune_to_bit(32);
        assert_eq!(prunable.get_chunk(0), &chunk2);
        assert_eq!(prunable.get_chunk(1), &chunk3);
    }

    #[test]
    fn test_pop() {
        let mut prunable: Prunable<4> = Prunable::new();

        prunable.push(true);
        prunable.push(false);
        prunable.push(true);
        assert_eq!(prunable.len(), 3);

        assert!(prunable.pop());
        assert_eq!(prunable.len(), 2);

        assert!(!prunable.pop());
        assert_eq!(prunable.len(), 1);

        assert!(prunable.pop());
        assert_eq!(prunable.len(), 0);
        assert!(prunable.is_empty());

        for i in 0..100 {
            prunable.push(i % 3 == 0);
        }
        assert_eq!(prunable.len(), 100);

        for i in (0..100).rev() {
            let expected = i % 3 == 0;
            assert_eq!(prunable.pop(), expected);
            assert_eq!(prunable.len(), i);
        }

        assert!(prunable.is_empty());
    }

    #[test]
    fn test_pop_chunk() {
        let mut prunable: Prunable<4> = Prunable::new();
        const CHUNK_SIZE: u64 = Prunable::<4>::CHUNK_SIZE_BITS;

        // Test 1: Pop a single chunk and verify it returns the correct data
        let chunk1 = hex!("0xAABBCCDD");
        prunable.push_chunk(&chunk1);
        assert_eq!(prunable.len(), CHUNK_SIZE);
        let popped = prunable.pop_chunk();
        assert_eq!(popped, chunk1);
        assert_eq!(prunable.len(), 0);
        assert!(prunable.is_empty());

        // Test 2: Pop multiple chunks in reverse order
        let chunk2 = hex!("0x11223344");
        let chunk3 = hex!("0x55667788");
        let chunk4 = hex!("0x99AABBCC");

        prunable.push_chunk(&chunk2);
        prunable.push_chunk(&chunk3);
        prunable.push_chunk(&chunk4);
        assert_eq!(prunable.len(), CHUNK_SIZE * 3);

        assert_eq!(prunable.pop_chunk(), chunk4);
        assert_eq!(prunable.len(), CHUNK_SIZE * 2);

        assert_eq!(prunable.pop_chunk(), chunk3);
        assert_eq!(prunable.len(), CHUNK_SIZE);

        assert_eq!(prunable.pop_chunk(), chunk2);
        assert_eq!(prunable.len(), 0);

        // Test 3: Verify data integrity when popping chunks
        prunable = Prunable::new();
        let first_chunk = hex!("0xAABBCCDD");
        let second_chunk = hex!("0x11223344");
        prunable.push_chunk(&first_chunk);
        prunable.push_chunk(&second_chunk);

        // Pop the second chunk, verify it and that first chunk is intact
        assert_eq!(prunable.pop_chunk(), second_chunk);
        assert_eq!(prunable.len(), CHUNK_SIZE);

        for i in 0..CHUNK_SIZE {
            let byte_idx = (i / 8) as usize;
            let bit_idx = i % 8;
            let expected = (first_chunk[byte_idx] >> bit_idx) & 1 == 1;
            assert_eq!(prunable.get_bit(i), expected);
        }

        assert_eq!(prunable.pop_chunk(), first_chunk);
        assert_eq!(prunable.len(), 0);
    }

    #[test]
    #[should_panic(expected = "cannot pop chunk when not chunk aligned")]
    fn test_pop_chunk_not_aligned() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Push a full chunk plus one bit
        prunable.push_chunk(&[0xFF; 4]);
        prunable.push(true);

        // Should panic because not chunk-aligned
        prunable.pop_chunk();
    }

    #[test]
    #[should_panic(expected = "cannot pop chunk: bitmap has fewer than CHUNK_SIZE_BITS bits")]
    fn test_pop_chunk_insufficient_bits() {
        let mut prunable: Prunable<4> = Prunable::new();

        // Push only a few bits (less than a full chunk)
        prunable.push(true);
        prunable.push(false);

        // Should panic because we don't have a full chunk to pop
        prunable.pop_chunk();
    }

    #[test]
    fn test_write_read_empty() {
        let original: Prunable<4> = Prunable::new();
        let encoded = original.encode();

        let decoded = Prunable::<4>::read_cfg(&mut encoded.as_ref(), &u64::MAX).unwrap();
        assert_eq!(decoded.len(), original.len());
        assert_eq!(decoded.pruned_chunks(), original.pruned_chunks());
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_write_read_non_empty() {
        let mut original: Prunable<4> = Prunable::new();
        original.push_chunk(&hex!("0xAABBCCDD"));
        original.push_chunk(&hex!("0x11223344"));
        original.push(true);
        original.push(false);
        original.push(true);

        let encoded = original.encode();
        let decoded = Prunable::<4>::read_cfg(&mut encoded.as_ref(), &u64::MAX).unwrap();

        assert_eq!(decoded.len(), original.len());
        assert_eq!(decoded.pruned_chunks(), original.pruned_chunks());
        assert_eq!(decoded.len(), 67);

        // Verify all bits match
        for i in 0..original.len() {
            assert_eq!(decoded.get_bit(i), original.get_bit(i));
        }
    }

    #[test]
    fn test_write_read_with_pruning() {
        let mut original: Prunable<4> = Prunable::new();
        original.push_chunk(&hex!("0x01020304"));
        original.push_chunk(&hex!("0x05060708"));
        original.push_chunk(&hex!("0x090A0B0C"));

        // Prune first chunk
        original.prune_to_bit(32);
        assert_eq!(original.pruned_chunks(), 1);
        assert_eq!(original.len(), 96);

        let encoded = original.encode();
        let decoded = Prunable::<4>::read_cfg(&mut encoded.as_ref(), &u64::MAX).unwrap();

        assert_eq!(decoded.len(), original.len());
        assert_eq!(decoded.pruned_chunks(), original.pruned_chunks());
        assert_eq!(decoded.pruned_chunks(), 1);
        assert_eq!(decoded.len(), 96);

        // Verify remaining chunks match
        assert_eq!(decoded.get_chunk_containing(32), &hex!("0x05060708"));
        assert_eq!(decoded.get_chunk_containing(64), &hex!("0x090A0B0C"));
    }

    #[test]
    fn test_write_read_with_pruning_2() {
        let mut original: Prunable<4> = Prunable::new();

        // Add several chunks
        for i in 0..5 {
            let chunk = [
                (i * 4) as u8,
                (i * 4 + 1) as u8,
                (i * 4 + 2) as u8,
                (i * 4 + 3) as u8,
            ];
            original.push_chunk(&chunk);
        }

        // Keep only last two chunks
        original.prune_to_bit(96); // Prune first 3 chunks
        assert_eq!(original.pruned_chunks(), 3);
        assert_eq!(original.len(), 160);

        let encoded = original.encode();
        let decoded = Prunable::<4>::read_cfg(&mut encoded.as_ref(), &u64::MAX).unwrap();

        assert_eq!(decoded.len(), original.len());
        assert_eq!(decoded.pruned_chunks(), 3);

        // Verify remaining accessible bits match
        for i in 96..original.len() {
            assert_eq!(decoded.get_bit(i), original.get_bit(i));
        }
    }

    #[test]
    fn test_encode_size_matches() {
        let mut prunable: Prunable<4> = Prunable::new();
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);
        prunable.push(true);

        let size = prunable.encode_size();
        let encoded = prunable.encode();

        assert_eq!(size, encoded.len());
    }

    #[test]
    fn test_encode_size_with_pruning() {
        let mut prunable: Prunable<4> = Prunable::new();
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);
        prunable.push_chunk(&[9, 10, 11, 12]);

        prunable.prune_to_bit(32);

        let size = prunable.encode_size();
        let encoded = prunable.encode();

        assert_eq!(size, encoded.len());
    }

    #[test]
    fn test_read_max_len_validation() {
        let mut original: Prunable<4> = Prunable::new();
        for _ in 0..10 {
            original.push(true);
        }

        let encoded = original.encode();

        // Should succeed with sufficient max_len
        assert!(Prunable::<4>::read_cfg(&mut encoded.as_ref(), &100).is_ok());

        // Should fail with insufficient max_len
        let result = Prunable::<4>::read_cfg(&mut encoded.as_ref(), &5);
        assert!(result.is_err());
    }

    #[test]
    fn test_codec_roundtrip_different_chunk_sizes() {
        // Test with different chunk sizes
        let mut p8: Prunable<8> = Prunable::new();
        let mut p16: Prunable<16> = Prunable::new();
        let mut p32: Prunable<32> = Prunable::new();

        for i in 0..100 {
            let bit = i % 3 == 0;
            p8.push(bit);
            p16.push(bit);
            p32.push(bit);
        }

        // Roundtrip each
        let encoded8 = p8.encode();
        let decoded8 = Prunable::<8>::read_cfg(&mut encoded8.as_ref(), &u64::MAX).unwrap();
        assert_eq!(decoded8.len(), p8.len());

        let encoded16 = p16.encode();
        let decoded16 = Prunable::<16>::read_cfg(&mut encoded16.as_ref(), &u64::MAX).unwrap();
        assert_eq!(decoded16.len(), p16.len());

        let encoded32 = p32.encode();
        let decoded32 = Prunable::<32>::read_cfg(&mut encoded32.as_ref(), &u64::MAX).unwrap();
        assert_eq!(decoded32.len(), p32.len());
    }

    #[test]
    fn test_read_pruned_chunks_overflow() {
        let mut buf = BytesMut::new();

        // Write a pruned_chunks value that would overflow when multiplied by CHUNK_SIZE_BITS
        let overflowing_pruned_chunks = (u64::MAX / Prunable::<4>::CHUNK_SIZE_BITS) + 1;
        overflowing_pruned_chunks.write(&mut buf);

        // Write a valid bitmap (empty)
        0u64.write(&mut buf); // len = 0

        // Try to read - should fail with overflow error
        let result = Prunable::<4>::read_cfg(&mut buf.as_ref(), &u64::MAX);
        match result {
            Err(CodecError::Invalid(type_name, msg)) => {
                assert_eq!(type_name, "Prunable");
                assert_eq!(
                    msg,
                    "pruned_chunks would overflow when computing pruned_bits"
                );
            }
            Ok(_) => panic!("Expected error but got Ok"),
            Err(e) => panic!("Expected Invalid error for pruned_bits overflow, got: {e:?}"),
        }
    }

    #[test]
    fn test_read_total_length_overflow() {
        let mut buf = BytesMut::new();

        // Make pruned_bits as large as possible without overflowing
        let max_safe_pruned_chunks = u64::MAX / Prunable::<4>::CHUNK_SIZE_BITS;
        let pruned_bits = max_safe_pruned_chunks * Prunable::<4>::CHUNK_SIZE_BITS;

        // Make bitmap_len large enough that adding it overflows
        let remaining_space = u64::MAX - pruned_bits;
        let bitmap_len = remaining_space + 1; // Go over by 1 to trigger overflow

        // Write the serialized data
        max_safe_pruned_chunks.write(&mut buf);
        bitmap_len.write(&mut buf);

        // Write bitmap chunk data
        let num_chunks = bitmap_len.div_ceil(Prunable::<4>::CHUNK_SIZE_BITS);
        for _ in 0..(num_chunks * 4) {
            0u8.write(&mut buf);
        }

        // Try to read - should fail because pruned_bits + bitmap_len overflows u64
        let result = Prunable::<4>::read_cfg(&mut buf.as_ref(), &u64::MAX);
        match result {
            Err(CodecError::Invalid(type_name, msg)) => {
                assert_eq!(type_name, "Prunable");
                assert_eq!(
                    msg,
                    "total bitmap length (pruned + unpruned) would overflow u64"
                );
            }
            Ok(_) => panic!("Expected error but got Ok"),
            Err(e) => panic!("Expected Invalid error for total length overflow, got: {e:?}"),
        }
    }

    #[test]
    fn test_is_chunk_aligned() {
        // Empty bitmap is chunk aligned
        let prunable: Prunable<4> = Prunable::new();
        assert!(prunable.is_chunk_aligned());

        // Add bits one at a time and check alignment
        let mut prunable: Prunable<4> = Prunable::new();
        for i in 1..=32 {
            prunable.push(i % 2 == 0);
            if i == 32 {
                assert!(prunable.is_chunk_aligned()); // Exactly one chunk
            } else {
                assert!(!prunable.is_chunk_aligned()); // Partial chunk
            }
        }

        // Add another full chunk
        for i in 33..=64 {
            prunable.push(i % 2 == 0);
            if i == 64 {
                assert!(prunable.is_chunk_aligned()); // Exactly two chunks
            } else {
                assert!(!prunable.is_chunk_aligned()); // Partial chunk
            }
        }

        // Test with push_chunk
        let mut prunable: Prunable<4> = Prunable::new();
        assert!(prunable.is_chunk_aligned());
        prunable.push_chunk(&[1, 2, 3, 4]);
        assert!(prunable.is_chunk_aligned()); // 32 bits = 1 chunk
        prunable.push_chunk(&[5, 6, 7, 8]);
        assert!(prunable.is_chunk_aligned()); // 64 bits = 2 chunks
        prunable.push(true);
        assert!(!prunable.is_chunk_aligned()); // 65 bits = partial chunk

        // Test alignment with pruning
        let mut prunable: Prunable<4> = Prunable::new();
        prunable.push_chunk(&[1, 2, 3, 4]);
        prunable.push_chunk(&[5, 6, 7, 8]);
        prunable.push_chunk(&[9, 10, 11, 12]);
        assert!(prunable.is_chunk_aligned()); // 96 bits = 3 chunks

        // Prune first chunk - still aligned (64 bits remaining)
        prunable.prune_to_bit(32);
        assert!(prunable.is_chunk_aligned());
        assert_eq!(prunable.len(), 96);

        // Add a partial chunk
        prunable.push(true);
        prunable.push(false);
        assert!(!prunable.is_chunk_aligned()); // 98 bits total

        // Prune to align again
        prunable.prune_to_bit(64);
        assert!(!prunable.is_chunk_aligned()); // 98 bits total (34 bits remaining)

        // Test with new_with_pruned_chunks
        let prunable: Prunable<4> = Prunable::new_with_pruned_chunks(2).unwrap();
        assert!(prunable.is_chunk_aligned()); // 64 bits pruned, 0 bits in bitmap

        let mut prunable: Prunable<4> = Prunable::new_with_pruned_chunks(1).unwrap();
        assert!(prunable.is_chunk_aligned()); // 32 bits pruned, 0 bits in bitmap
        prunable.push(true);
        assert!(!prunable.is_chunk_aligned()); // 33 bits total

        // Test with push_byte
        let mut prunable: Prunable<4> = Prunable::new();
        for _ in 0..4 {
            prunable.push_byte(0xFF);
        }
        assert!(prunable.is_chunk_aligned()); // 32 bits = 1 chunk

        // Test after pop
        prunable.pop();
        assert!(!prunable.is_chunk_aligned()); // 31 bits

        // Pop back to alignment
        for _ in 0..31 {
            prunable.pop();
        }
        assert!(prunable.is_chunk_aligned()); // 0 bits
    }
}

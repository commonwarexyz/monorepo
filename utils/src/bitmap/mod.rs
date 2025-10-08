//! Bitmap implementation
//!
//! The bitmap is a compact representation of a sequence of bits, using chunks of bytes for a
//! more-efficient memory layout than doing [`Vec<bool>`].

use crate::NZUsize;
#[cfg(not(feature = "std"))]
use alloc::{collections::VecDeque, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{util::at_least, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use core::{
    fmt::{self, Formatter, Write as _},
    num::NonZeroUsize,
    ops::{BitAnd, BitOr, BitXor, Index},
};
#[cfg(feature = "std")]
use std::collections::VecDeque;

mod prunable;
pub use prunable::Prunable;

/// The default [BitMap] chunk size in bytes.
pub const DEFAULT_CHUNK_SIZE: usize = 8;

/// A bitmap that stores data in chunks of N bytes.
///
/// # Panics
///
/// Operations panic if `bit / CHUNK_SIZE_BITS > usize::MAX`. On 32-bit systems
/// with N=32, this occurs at bit >= 1,099,511,627,776.
#[derive(Clone, PartialEq, Eq)]
pub struct BitMap<const N: usize = DEFAULT_CHUNK_SIZE> {
    /// The bitmap itself, in chunks of size N bytes. The number of valid bits in the last chunk is
    /// given by `self.next_bit`. Within each byte, lowest order bits are treated as coming before
    /// higher order bits in the bit ordering.
    ///
    /// Invariant: The last chunk in the bitmap always has room for at least one more bit.
    /// This implies that !chunks.is_empty() always holds.
    ///
    /// Invariant: All bits in the last chunk >= `self.next_bit` are 0.
    chunks: VecDeque<[u8; N]>,

    /// The position within the last chunk where the next bit is to be appended.
    ///
    /// Invariant: This value is always in the range [0, N * 8).
    next_bit: u64,
}

impl<const N: usize> BitMap<N> {
    const _CHUNK_SIZE_NON_ZERO_ASSERT: () = assert!(N > 0, "chunk size must be > 0");

    /// The size of a chunk in bits.
    pub const CHUNK_SIZE_BITS: u64 = (N * 8) as u64;

    /// A chunk of all 0s.
    const EMPTY_CHUNK: [u8; N] = [0u8; N];

    /// A chunk of all 1s.
    const FULL_CHUNK: [u8; N] = [u8::MAX; N];

    /* Constructors */

    /// Create a new empty bitmap.
    pub fn new() -> Self {
        #[allow(path_statements)]
        Self::_CHUNK_SIZE_NON_ZERO_ASSERT; // Prevent compilation for N == 0

        let bitmap = VecDeque::from([Self::EMPTY_CHUNK]);
        Self {
            chunks: bitmap,
            next_bit: 0,
        }
    }

    // Create a new empty bitmap with the capacity to hold `size` bits without reallocating.
    pub fn with_capacity(size: u64) -> Self {
        #[allow(path_statements)]
        Self::_CHUNK_SIZE_NON_ZERO_ASSERT; // Prevent compilation for N == 0

        let num_chunks = Self::num_chunks_at_size(size).get();
        let mut chunks = VecDeque::with_capacity(num_chunks);
        // Invariant: chunks is never empty
        chunks.push_back(Self::EMPTY_CHUNK);
        Self {
            chunks,
            next_bit: 0,
        }
    }

    /// Create a new bitmap with `size` bits, with all bits set to 0.
    pub fn zeroes(size: u64) -> Self {
        #[allow(path_statements)]
        Self::_CHUNK_SIZE_NON_ZERO_ASSERT; // Prevent compilation for N == 0

        let num_chunks = Self::num_chunks_at_size(size).get();
        let mut chunks = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            chunks.push_back(Self::EMPTY_CHUNK);
        }
        Self {
            chunks,
            next_bit: size % Self::CHUNK_SIZE_BITS,
        }
    }

    /// Create a new bitmap with `size` bits, with all bits set to 1.
    pub fn ones(size: u64) -> Self {
        #[allow(path_statements)]
        Self::_CHUNK_SIZE_NON_ZERO_ASSERT; // Prevent compilation for N == 0

        let num_chunks = Self::num_chunks_at_size(size).get();
        let mut chunks = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            chunks.push_back(Self::FULL_CHUNK);
        }
        let mut result = Self {
            chunks,
            next_bit: size % Self::CHUNK_SIZE_BITS,
        };
        // Clear trailing bits to maintain invariant
        result.clear_trailing_bits();
        result
    }

    /* Length */

    /// Return the number of bits currently stored in the bitmap.
    #[inline]
    pub fn len(&self) -> u64 {
        ((self.chunks.len() as u64 - 1) * Self::CHUNK_SIZE_BITS) + self.next_bit
    }

    /// Returns true if the bitmap is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    // Get the number of chunks currently in the bitmap.
    fn chunks_len(&self) -> usize {
        self.chunks.len()
    }

    /* Getters */

    /// Get the value of the bit at the given index.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    #[inline]
    pub fn get(&self, bit: u64) -> bool {
        let chunk = self.get_chunk_containing(bit);
        Self::get_from_chunk(chunk, bit)
    }

    /// Returns the bitmap chunk containing the given bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    #[inline]
    fn get_chunk_containing(&self, bit: u64) -> &[u8; N] {
        assert!(
            bit < self.len(),
            "bit {} out of bounds (len: {})",
            bit,
            self.len()
        );
        &self.chunks[Self::chunk(bit)]
    }

    /// Get a reference to a chunk by its index in the current bitmap.
    /// Note this is an index into the chunks, not a bit.
    #[inline]
    pub(super) fn get_chunk(&self, chunk: usize) -> &[u8; N] {
        assert!(
            chunk < self.chunks.len(),
            "chunk {} out of bounds (chunks: {})",
            chunk,
            self.chunks.len()
        );
        &self.chunks[chunk]
    }

    /// Get the value at the given `bit` from the `chunk`.
    /// `bit` is an index into the entire bitmap, not just the chunk.
    #[inline]
    fn get_from_chunk(chunk: &[u8; N], bit: u64) -> bool {
        let byte = Self::chunk_byte_offset(bit);
        let byte = chunk[byte];
        let mask = Self::chunk_byte_bitmask(bit);
        (byte & mask) != 0
    }

    // Return the last chunk of the bitmap and its size in bits.
    // The size can be 0 (meaning the last chunk is empty).
    #[inline]
    fn last_chunk(&self) -> (&[u8; N], u64) {
        (self.chunks.back().unwrap(), self.next_bit)
    }

    // Return the last chunk of the bitmap.
    #[inline]
    fn last_chunk_mut(&mut self) -> &mut [u8; N] {
        self.chunks.back_mut().unwrap()
    }

    /* Setters */

    /// Add a single bit to the bitmap.
    pub fn push(&mut self, bit: bool) {
        let chunk_byte = (self.next_bit / 8) as usize;
        let next_bit = self.next_bit;
        let last_chunk = self.last_chunk_mut();
        if bit {
            last_chunk[chunk_byte] |= Self::chunk_byte_bitmask(next_bit);
        }
        // If bit is false, just advance the next_bit -- the bit is already 0
        self.next_bit += 1;
        assert!(self.next_bit <= Self::CHUNK_SIZE_BITS);

        if self.next_bit == Self::CHUNK_SIZE_BITS {
            self.prepare_next_chunk();
        }
    }

    /// Remove and return the last bit from the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bitmap is empty.
    pub fn pop(&mut self) -> bool {
        assert!(!self.is_empty(), "Cannot pop from empty bitmap");

        if self.next_bit == 0 {
            // Remove the last (empty) chunk
            self.chunks.pop_back();
            self.next_bit = Self::CHUNK_SIZE_BITS - 1;
        } else {
            self.next_bit -= 1;
        }
        let bit = Self::get_from_chunk(self.last_chunk().0, self.next_bit);

        // Clear trailing bits to maintain the invariant
        if bit {
            assert!(self.clear_trailing_bits());
        }

        bit
    }

    /// Flips the given bit.
    ///
    /// # Panics
    ///
    /// Panics if `bit` is out of bounds.
    #[inline]
    pub fn flip(&mut self, bit: u64) {
        self.assert_bit(bit);
        let chunk = Self::chunk(bit);
        let byte = Self::chunk_byte_offset(bit);
        let mask = Self::chunk_byte_bitmask(bit);
        self.chunks[chunk][byte] ^= mask;
    }

    /// Flips all bits (1s become 0s and vice versa).
    pub fn flip_all(&mut self) {
        for chunk in &mut self.chunks {
            for byte in chunk {
                *byte = !*byte;
            }
        }
        // Clear trailing bits to maintain invariant
        self.clear_trailing_bits();
    }

    /// Set the value of the referenced bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    pub fn set(&mut self, bit: u64, value: bool) {
        assert!(
            bit < self.len(),
            "bit {} out of bounds (len: {})",
            bit,
            self.len()
        );

        let chunk = &mut self.chunks[Self::chunk(bit)];
        let byte = Self::chunk_byte_offset(bit);
        let mask = Self::chunk_byte_bitmask(bit);
        if value {
            chunk[byte] |= mask;
        } else {
            chunk[byte] &= !mask;
        }
    }

    /// Sets all bits to the specified value.
    #[inline]
    pub fn set_all(&mut self, bit: bool) {
        let value = if bit { u8::MAX } else { 0 };
        for chunk in &mut self.chunks {
            chunk.fill(value);
        }
        // Clear trailing bits to maintain invariant when setting to true
        if value != 0 {
            self.clear_trailing_bits();
        }
    }

    // Add a byte's worth of bits to the bitmap.
    //
    // # Warning
    //
    // Panics if self.next_bit is not byte aligned.
    fn push_byte(&mut self, byte: u8) {
        assert!(
            self.next_bit.is_multiple_of(8),
            "cannot add byte when not byte aligned"
        );

        let chunk_byte = (self.next_bit / 8) as usize;
        self.last_chunk_mut()[chunk_byte] = byte;
        self.next_bit += 8;
        assert!(self.next_bit <= Self::CHUNK_SIZE_BITS);

        if self.next_bit == Self::CHUNK_SIZE_BITS {
            self.prepare_next_chunk();
        }
    }

    /// Add a chunk of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if self.next_bit is not chunk aligned.
    pub(super) fn push_chunk(&mut self, chunk: &[u8; N]) {
        assert_eq!(self.next_bit, 0, "cannot add chunk when not chunk aligned");
        self.last_chunk_mut().copy_from_slice(chunk.as_ref());
        self.prepare_next_chunk();
    }

    /* Invariant Maintenance */

    /// Prepares the next chunk of the bitmap to preserve the invariant that there is always room
    /// for one more bit.
    fn prepare_next_chunk(&mut self) {
        self.next_bit = 0;
        self.chunks.push_back(Self::EMPTY_CHUNK);
    }

    /// Clear all bits in the last chunk that are >= self.next_bit to maintain the invariant.
    /// Returns true if any bits were flipped from 1 to 0.
    fn clear_trailing_bits(&mut self) -> bool {
        let next_bit = self.next_bit;
        let mut flipped_any = false;
        let last_chunk = self.last_chunk_mut();

        if next_bit == 0 {
            // If next_bit is 0, the entire last chunk should be clear (it's empty)
            let was_empty = *last_chunk == Self::EMPTY_CHUNK;
            *last_chunk = Self::EMPTY_CHUNK;
            return !was_empty;
        }

        // Clear whole bytes after the last valid bit
        let last_byte_index = ((next_bit - 1) / 8) as usize;
        for byte in last_chunk.iter_mut().skip(last_byte_index + 1) {
            if *byte != 0 {
                flipped_any = true;
                *byte = 0;
            }
        }

        // Clear the trailing bits in the last partial byte
        let bits_in_last_byte = ((next_bit - 1) % 8) + 1;
        if bits_in_last_byte < 8 {
            let mask = (1u8 << bits_in_last_byte) - 1;
            let old_byte = last_chunk[last_byte_index];
            let new_byte = old_byte & mask;
            if old_byte != new_byte {
                flipped_any = true;
                last_chunk[last_byte_index] = new_byte;
            }
        }

        flipped_any
    }

    /* Pruning */

    // Remove the first `n` chunks from the bitmap.
    //
    // # Warning
    //
    // Panics if trying to prune more chunks than exist.
    fn prune_chunks(&mut self, chunks: usize) {
        assert!(
            chunks <= self.chunks.len(),
            "cannot prune {chunks} chunks, only {} available",
            self.chunks.len()
        );
        self.chunks.drain(..chunks);
        // Invariant: chunks is never empty
        if self.chunks.is_empty() {
            self.chunks.push_back(Self::EMPTY_CHUNK);
            self.next_bit = 0;
        }
    }

    /* Counting */

    /// Returns the number of bits set to 1.
    #[inline]
    pub fn count_ones(&self) -> u64 {
        // Thanks to the invariant that trailing bits are always 0,
        // we can simply count all set bits in all chunks
        self.chunks
            .iter()
            .flat_map(|chunk| chunk.iter())
            .map(|byte| byte.count_ones() as u64)
            .sum()
    }

    /// Returns the number of bits set to 0.
    #[inline]
    pub fn count_zeros(&self) -> u64 {
        self.len() - self.count_ones()
    }

    /* Indexing Helpers */

    // Returns the number of chunks in a bitmap with `size` bits.
    #[inline]
    fn num_chunks_at_size(size: u64) -> NonZeroUsize {
        NZUsize!(((size / Self::CHUNK_SIZE_BITS) + 1) as usize)
    }

    /// Convert a bit into a bitmask for the byte containing that bit.
    #[inline]
    pub(super) fn chunk_byte_bitmask(bit: u64) -> u8 {
        1 << (bit % 8)
    }

    /// Convert a bit into the index of the byte within a chunk containing the bit.
    #[inline]
    pub(super) fn chunk_byte_offset(bit: u64) -> usize {
        ((bit / 8) % N as u64) as usize
    }

    /// Convert a bit into the index of the chunk it belongs to.
    ///
    /// # Panics
    ///
    /// Panics if the chunk index overflows `usize`.
    #[inline]
    pub(super) fn chunk(bit: u64) -> usize {
        let chunk = bit / Self::CHUNK_SIZE_BITS;
        assert!(
            chunk <= usize::MAX as u64,
            "chunk overflow: {chunk} exceeds usize::MAX",
        );
        chunk as usize
    }

    /* Iterator */

    /// Creates an iterator over the bits.
    pub fn iter(&self) -> Iterator<'_, N> {
        Iterator {
            bitmap: self,
            pos: 0,
        }
    }

    /* Bitwise Operations */

    /// Helper for binary operations
    #[inline]
    fn binary_op<F: Fn(u8, u8) -> u8>(&mut self, other: &BitMap<N>, op: F) {
        self.assert_eq_len(other);
        for (a_chunk, b_chunk) in self.chunks.iter_mut().zip(other.chunks.iter()) {
            for (a_byte, b_byte) in a_chunk.iter_mut().zip(b_chunk.iter()) {
                *a_byte = op(*a_byte, *b_byte);
            }
        }
        // Clear trailing bits to maintain invariant
        self.clear_trailing_bits();
    }

    /// Performs a bitwise AND with another BitMap.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn and(&mut self, other: &BitMap<N>) {
        self.binary_op(other, |a, b| a & b);
    }

    /// Performs a bitwise OR with another BitMap.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn or(&mut self, other: &BitMap<N>) {
        self.binary_op(other, |a, b| a | b);
    }

    /// Performs a bitwise XOR with another BitMap.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn xor(&mut self, other: &BitMap<N>) {
        self.binary_op(other, |a, b| a ^ b);
    }

    /* Assertions */

    /// Asserts that the bit is within bounds.
    #[inline(always)]
    fn assert_bit(&self, bit: u64) {
        assert!(
            bit < self.len(),
            "bit {} out of bounds (len: {})",
            bit,
            self.len()
        );
    }

    /// Asserts that the lengths of two [BitMap]s match.
    #[inline(always)]
    fn assert_eq_len(&self, other: &BitMap<N>) {
        assert_eq!(
            self.len(),
            other.len(),
            "BitMap lengths don't match: {} vs {}",
            self.len(),
            other.len()
        );
    }
}

impl<const N: usize> Default for BitMap<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: AsRef<[bool]>, const N: usize> From<T> for BitMap<N> {
    fn from(t: T) -> Self {
        let bools = t.as_ref();
        let mut bv = Self::new();
        for &b in bools {
            bv.push(b);
        }
        bv
    }
}

impl<const N: usize> From<BitMap<N>> for Vec<bool> {
    fn from(bv: BitMap<N>) -> Self {
        bv.iter().collect()
    }
}

impl<const N: usize> fmt::Debug for BitMap<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // For very large BitMaps, only show a preview
        const MAX_DISPLAY: u64 = 64;
        const HALF_DISPLAY: u64 = MAX_DISPLAY / 2;

        // Closure for writing a bit
        let write_bit = |formatter: &mut Formatter<'_>, bit: u64| -> core::fmt::Result {
            formatter.write_char(if self.get(bit) { '1' } else { '0' })
        };

        f.write_str("BitMap[")?;
        let len = self.len();
        if len <= MAX_DISPLAY {
            // Show all bits
            for i in 0..len {
                write_bit(f, i)?;
            }
        } else {
            // Show first and last bits with ellipsis
            for i in 0..HALF_DISPLAY {
                write_bit(f, i)?;
            }

            f.write_str("...")?;

            for i in (len - HALF_DISPLAY)..len {
                write_bit(f, i)?;
            }
        }
        f.write_str("]")
    }
}

impl<const N: usize> Index<u64> for BitMap<N> {
    type Output = bool;

    /// Allows accessing bits using the `[]` operator.
    ///
    /// Panics if out of bounds.
    #[inline]
    fn index(&self, bit: u64) -> &Self::Output {
        self.assert_bit(bit);
        let value = self.get(bit);
        if value {
            &true
        } else {
            &false
        }
    }
}

impl<const N: usize> BitAnd for &BitMap<N> {
    type Output = BitMap<N>;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.and(rhs);
        result
    }
}

impl<const N: usize> BitOr for &BitMap<N> {
    type Output = BitMap<N>;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.or(rhs);
        result
    }
}

impl<const N: usize> BitXor for &BitMap<N> {
    type Output = BitMap<N>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.xor(rhs);
        result
    }
}

impl<const N: usize> Write for BitMap<N> {
    fn write(&self, buf: &mut impl BufMut) {
        // Prefix with the number of bits
        self.len().write(buf);

        // Write chunks, omitting the last chunk if it's empty
        let num_chunks_to_write = if self.next_bit == 0 {
            self.chunks.len() - 1
        } else {
            self.chunks.len()
        };

        for chunk in self.chunks.iter().take(num_chunks_to_write) {
            for &byte in chunk {
                byte.write(buf);
            }
        }
    }
}

impl<const N: usize> Read for BitMap<N> {
    type Cfg = u64; // Max bitmap length

    fn read_cfg(buf: &mut impl Buf, max_len: &Self::Cfg) -> Result<Self, CodecError> {
        // Parse length in bits
        let len = u64::read(buf)?;
        if len > *max_len {
            return Err(CodecError::InvalidLength(len as usize));
        }

        // If next_bit == 0, the last chunk is empty and was omitted during serialization
        let num_chunks_needed = Self::num_chunks_at_size(len).get();
        let next_bit = len % Self::CHUNK_SIZE_BITS;
        let last_chunk_omitted = next_bit == 0;
        let num_chunks_to_read = if last_chunk_omitted {
            num_chunks_needed - 1
        } else {
            num_chunks_needed
        };

        // Parse chunks
        let mut chunks = VecDeque::with_capacity(num_chunks_needed);
        for _ in 0..num_chunks_to_read {
            at_least(buf, N)?;
            let mut chunk = [0u8; N];
            buf.copy_to_slice(&mut chunk);
            chunks.push_back(chunk);
        }

        // Add back the omitted empty chunk if necessary
        if last_chunk_omitted {
            chunks.push_back(Self::EMPTY_CHUNK);
        }

        let mut result = BitMap { chunks, next_bit };

        // Verify trailing bits are zero (maintain invariant)
        if result.clear_trailing_bits() {
            return Err(CodecError::Invalid(
                "BitMap",
                "Invalid trailing bits in encoded data",
            ));
        }

        Ok(result)
    }
}

impl<const N: usize> EncodeSize for BitMap<N> {
    fn encode_size(&self) -> usize {
        // Size of length prefix + serialized chunks
        let num_chunks_to_write = if self.next_bit == 0 {
            self.chunks.len() - 1
        } else {
            self.chunks.len()
        };
        self.len().encode_size() + (num_chunks_to_write * N)
    }
}

/// Iterator over bits in a [BitMap].
pub struct Iterator<'a, const N: usize> {
    /// Reference to the BitMap being iterated over
    bitmap: &'a BitMap<N>,

    /// Current index in the BitMap
    pos: u64,
}

impl<const N: usize> core::iter::Iterator for Iterator<'_, N> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.bitmap.len() {
            return None;
        }

        let bit = self.bitmap.get(self.pos);
        self.pos += 1;
        Some(bit)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.bitmap.len().saturating_sub(self.pos);
        let capped = remaining.min(usize::MAX as u64) as usize;
        (capped, Some(capped))
    }
}

impl<const N: usize> ExactSizeIterator for Iterator<'_, N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_constructors() {
        // Test new()
        let bv: BitMap<4> = BitMap::new();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test default()
        let bv: BitMap<4> = Default::default();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test with_capacity()
        let bv: BitMap<4> = BitMap::with_capacity(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        let bv: BitMap<4> = BitMap::with_capacity(10);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
    }

    #[test]
    fn test_zeroes() {
        let bv: BitMap<1> = BitMap::zeroes(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 0);

        let bv: BitMap<1> = BitMap::zeroes(1);
        assert_eq!(bv.len(), 1);
        assert!(!bv.is_empty());
        assert_eq!(bv.len(), 1);
        assert!(!bv.get(0));
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 1);

        let bv: BitMap<1> = BitMap::zeroes(10);
        assert_eq!(bv.len(), 10);
        assert!(!bv.is_empty());
        assert_eq!(bv.len(), 10);
        for i in 0..10 {
            assert!(!bv.get(i as u64));
        }
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 10);
    }

    #[test]
    fn test_ones() {
        let bv: BitMap<1> = BitMap::ones(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 0);

        let bv: BitMap<1> = BitMap::ones(1);
        assert_eq!(bv.len(), 1);
        assert!(!bv.is_empty());
        assert_eq!(bv.len(), 1);
        assert!(bv.get(0));
        assert_eq!(bv.count_ones(), 1);
        assert_eq!(bv.count_zeros(), 0);

        let bv: BitMap<1> = BitMap::ones(10);
        assert_eq!(bv.len(), 10);
        assert!(!bv.is_empty());
        assert_eq!(bv.len(), 10);
        for i in 0..10 {
            assert!(bv.get(i as u64));
        }
        assert_eq!(bv.count_ones(), 10);
        assert_eq!(bv.count_zeros(), 0);
    }

    #[test]
    fn test_invariant_trailing_bits_are_zero() {
        // Helper function to check the invariant
        fn check_trailing_bits_zero<const N: usize>(bitmap: &BitMap<N>) {
            let (last_chunk, next_bit) = bitmap.last_chunk();

            // Check that all bits >= next_bit in the last chunk are 0
            for bit_idx in next_bit..((N * 8) as u64) {
                let byte_idx = (bit_idx / 8) as usize;
                let bit_in_byte = bit_idx % 8;
                let mask = 1u8 << bit_in_byte;
                assert_eq!(last_chunk[byte_idx] & mask, 0);
            }
        }

        // Test ones() constructor
        let bv: BitMap<4> = BitMap::ones(15);
        check_trailing_bits_zero(&bv);

        let bv: BitMap<4> = BitMap::ones(33);
        check_trailing_bits_zero(&bv);

        // Test after push operations
        let mut bv: BitMap<4> = BitMap::new();
        for i in 0..37 {
            bv.push(i % 2 == 0);
            check_trailing_bits_zero(&bv);
        }

        // Test after pop operations
        let mut bv: BitMap<4> = BitMap::ones(40);
        check_trailing_bits_zero(&bv);
        for _ in 0..15 {
            bv.pop();
            check_trailing_bits_zero(&bv);
        }

        // Test after flip_all
        let mut bv: BitMap<4> = BitMap::ones(25);
        bv.flip_all();
        check_trailing_bits_zero(&bv);

        // Test after binary operations
        let bv1: BitMap<4> = BitMap::ones(20);
        let bv2: BitMap<4> = BitMap::zeroes(20);

        let mut bv_and = bv1.clone();
        bv_and.and(&bv2);
        check_trailing_bits_zero(&bv_and);

        let mut bv_or = bv1.clone();
        bv_or.or(&bv2);
        check_trailing_bits_zero(&bv_or);

        let mut bv_xor = bv1.clone();
        bv_xor.xor(&bv2);
        check_trailing_bits_zero(&bv_xor);

        // Test after deserialization
        let original: BitMap<4> = BitMap::ones(27);
        let encoded = original.encode();
        let decoded: BitMap<4> =
            BitMap::decode_cfg(&mut encoded.as_ref(), &(usize::MAX as u64)).unwrap();
        check_trailing_bits_zero(&decoded);

        // Test clear_trailing_bits return value
        let mut bv_clean: BitMap<4> = BitMap::ones(20);
        // Should return false since ones() already clears trailing bits
        assert!(!bv_clean.clear_trailing_bits());

        // Create a bitmap with invalid trailing bits by manually setting them
        let mut bv_dirty: BitMap<4> = BitMap::ones(20);
        // Manually corrupt the last chunk to have trailing bits set
        let last_chunk = bv_dirty.last_chunk_mut();
        last_chunk[3] |= 0xF0; // Set some high bits in the last byte
                               // Should return true since we had invalid trailing bits
        assert!(bv_dirty.clear_trailing_bits());
        // After clearing, should return false
        assert!(!bv_dirty.clear_trailing_bits());
        check_trailing_bits_zero(&bv_dirty);
    }

    #[test]
    fn test_get_set() {
        let mut bv: BitMap<4> = BitMap::new();

        // Test initial state
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test push
        bv.push(true);
        bv.push(false);
        bv.push(true);
        assert_eq!(bv.len(), 3);
        assert!(!bv.is_empty());

        // Test get
        assert!(bv.get(0));
        assert!(!bv.get(1));
        assert!(bv.get(2));

        bv.set(1, true);
        assert!(bv.get(1));
        bv.set(2, false);
        assert!(!bv.get(2));

        // Test flip
        bv.flip(0); // true -> false
        assert!(!bv.get(0));
        bv.flip(0); // false -> true
        assert!(bv.get(0));
    }

    #[test]
    fn test_chunk_operations() {
        let mut bv: BitMap<4> = BitMap::new();
        let test_chunk = [0xAB, 0xCD, 0xEF, 0x12];

        // Test push_chunk
        bv.push_chunk(&test_chunk);
        assert_eq!(bv.len(), 32); // 4 bytes * 8 bits

        // Test get_chunk
        let chunk = bv.get_chunk(0);
        assert_eq!(chunk, &test_chunk);

        // Test get_chunk_containing
        let chunk = bv.get_chunk_containing(0);
        assert_eq!(chunk, &test_chunk);

        // Test last_chunk
        let (last_chunk, next_bit) = bv.last_chunk();
        assert_eq!(next_bit, 0); // Should be at chunk boundary
        assert_eq!(last_chunk, &[0u8; 4]); // Empty next chunk
    }

    #[test]
    fn test_pop() {
        let mut bv: BitMap<3> = BitMap::new();
        bv.push(true);
        assert!(bv.pop());
        assert_eq!(bv.len(), 0);

        bv.push(false);
        assert!(!bv.pop());
        assert_eq!(bv.len(), 0);

        bv.push(true);
        bv.push(false);
        bv.push(true);
        assert!(bv.pop());
        assert_eq!(bv.len(), 2);
        assert!(!bv.pop());
        assert_eq!(bv.len(), 1);
        assert!(bv.pop());
        assert_eq!(bv.len(), 0);

        for i in 0..100 {
            bv.push(i % 2 == 0);
        }
        assert_eq!(bv.len(), 100);
        for i in (0..100).rev() {
            assert_eq!(bv.pop(), i % 2 == 0);
        }
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
    }

    #[test]
    fn test_byte_operations() {
        let mut bv: BitMap<4> = BitMap::new();

        // Test push_byte
        bv.push_byte(0xFF);
        assert_eq!(bv.len(), 8);

        // All bits in the byte should be set
        for i in 0..8 {
            assert!(bv.get(i as u64));
        }

        bv.push_byte(0x00);
        assert_eq!(bv.len(), 16);

        // All bits in the second byte should be clear
        for i in 8..16 {
            assert!(!bv.get(i as u64));
        }
    }

    #[test]
    fn test_count_operations() {
        let mut bv: BitMap<4> = BitMap::new();

        // Empty bitmap
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 0);

        // Add some bits
        bv.push(true);
        bv.push(false);
        bv.push(true);
        bv.push(true);
        bv.push(false);

        assert_eq!(bv.count_ones(), 3);
        assert_eq!(bv.count_zeros(), 2);
        assert_eq!(bv.len(), 5);

        // Test with full bytes
        let mut bv2: BitMap<4> = BitMap::new();
        bv2.push_byte(0xFF); // 8 ones
        bv2.push_byte(0x00); // 8 zeros
        bv2.push_byte(0xAA); // 4 ones, 4 zeros (10101010)

        assert_eq!(bv2.count_ones(), 12);
        assert_eq!(bv2.count_zeros(), 12);
        assert_eq!(bv2.len(), 24);
    }

    #[test]
    fn test_set_all() {
        let mut bv: BitMap<1> = BitMap::new();

        // Add some bits
        bv.push(true);
        bv.push(false);
        bv.push(true);
        bv.push(false);
        bv.push(true);
        bv.push(false);
        bv.push(true);
        bv.push(false);
        bv.push(true);
        bv.push(false);

        assert_eq!(bv.len(), 10);
        assert_eq!(bv.count_ones(), 5);
        assert_eq!(bv.count_zeros(), 5);

        // Test set_all(true)
        bv.set_all(true);
        assert_eq!(bv.len(), 10);
        assert_eq!(bv.count_ones(), 10);
        assert_eq!(bv.count_zeros(), 0);

        // Test set_all(false)
        bv.set_all(false);
        assert_eq!(bv.len(), 10);
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 10);
    }

    #[test]
    fn test_flip_all() {
        let mut bv: BitMap<4> = BitMap::new();

        bv.push(true);
        bv.push(false);
        bv.push(true);
        bv.push(false);
        bv.push(true);

        let original_ones = bv.count_ones();
        let original_zeros = bv.count_zeros();
        let original_len = bv.len();

        bv.flip_all();

        // Length should not change
        assert_eq!(bv.len(), original_len);

        // Ones and zeros should be swapped
        assert_eq!(bv.count_ones(), original_zeros);
        assert_eq!(bv.count_zeros(), original_ones);

        // Check bits
        assert!(!bv.get(0));
        assert!(bv.get(1));
        assert!(!bv.get(2));
        assert!(bv.get(3));
        assert!(!bv.get(4));
    }

    #[test]
    fn test_bitwise_and() {
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();

        // Create test patterns: 10110 & 11010 = 10010
        let pattern1 = [true, false, true, true, false];
        let pattern2 = [true, true, false, true, false];
        let expected = [true, false, false, true, false];

        for &bit in &pattern1 {
            bv1.push(bit);
        }
        for &bit in &pattern2 {
            bv2.push(bit);
        }

        bv1.and(&bv2);

        assert_eq!(bv1.len(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get(i as u64), expected_bit);
        }
    }

    #[test]
    fn test_bitwise_or() {
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();

        // Create test patterns: 10110 | 11010 = 11110
        let pattern1 = [true, false, true, true, false];
        let pattern2 = [true, true, false, true, false];
        let expected = [true, true, true, true, false];

        for &bit in &pattern1 {
            bv1.push(bit);
        }
        for &bit in &pattern2 {
            bv2.push(bit);
        }

        bv1.or(&bv2);

        assert_eq!(bv1.len(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get(i as u64), expected_bit);
        }
    }

    #[test]
    fn test_bitwise_xor() {
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();

        // Create test patterns: 10110 ^ 11010 = 01100
        let pattern1 = [true, false, true, true, false];
        let pattern2 = [true, true, false, true, false];
        let expected = [false, true, true, false, false];

        for &bit in &pattern1 {
            bv1.push(bit);
        }
        for &bit in &pattern2 {
            bv2.push(bit);
        }

        bv1.xor(&bv2);

        assert_eq!(bv1.len(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get(i as u64), expected_bit);
        }
    }

    #[test]
    fn test_multi_chunk_operations() {
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();

        // Fill multiple chunks
        let chunk1 = [0xAA, 0xBB, 0xCC, 0xDD]; // 10101010 10111011 11001100 11011101
        let chunk2 = [0x55, 0x66, 0x77, 0x88]; // 01010101 01100110 01110111 10001000

        bv1.push_chunk(&chunk1);
        bv1.push_chunk(&chunk1);
        bv2.push_chunk(&chunk2);
        bv2.push_chunk(&chunk2);

        assert_eq!(bv1.len(), 64);
        assert_eq!(bv2.len(), 64);

        // Test AND operation
        let mut bv_and = bv1.clone();
        bv_and.and(&bv2);

        // Test OR operation
        let mut bv_or = bv1.clone();
        bv_or.or(&bv2);

        // Test XOR operation
        let mut bv_xor = bv1.clone();
        bv_xor.xor(&bv2);

        // Verify results make sense
        assert_eq!(bv_and.len(), 64);
        assert_eq!(bv_or.len(), 64);
        assert_eq!(bv_xor.len(), 64);

        // AND should have fewer or equal ones than either operand
        assert!(bv_and.count_ones() <= bv1.count_ones());
        assert!(bv_and.count_ones() <= bv2.count_ones());

        // OR should have more or equal ones than either operand
        assert!(bv_or.count_ones() >= bv1.count_ones());
        assert!(bv_or.count_ones() >= bv2.count_ones());
    }

    #[test]
    fn test_partial_chunk_operations() {
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();

        // Add partial chunks (not aligned to chunk boundaries)
        for i in 0..35 {
            // 35 bits = 4 bytes + 3 bits
            bv1.push(i % 2 == 0);
            bv2.push(i % 3 == 0);
        }

        assert_eq!(bv1.len(), 35);
        assert_eq!(bv2.len(), 35);

        // Test operations with partial chunks
        let mut bv_and = bv1.clone();
        bv_and.and(&bv2);

        let mut bv_or = bv1.clone();
        bv_or.or(&bv2);

        let mut bv_xor = bv1.clone();
        bv_xor.xor(&bv2);

        // All should maintain the same length
        assert_eq!(bv_and.len(), 35);
        assert_eq!(bv_or.len(), 35);
        assert_eq!(bv_xor.len(), 35);

        // Test flip_all with partial chunk
        let mut bv_inv = bv1.clone();
        let original_ones = bv_inv.count_ones();
        let original_zeros = bv_inv.count_zeros();
        bv_inv.flip_all();
        assert_eq!(bv_inv.count_ones(), original_zeros);
        assert_eq!(bv_inv.count_zeros(), original_ones);
    }

    #[test]
    #[should_panic(expected = "bit 1 out of bounds (len: 1)")]
    fn test_flip_out_of_bounds() {
        let mut bv: BitMap<4> = BitMap::new();
        bv.push(true);
        bv.flip(1); // Only bit 0 exists
    }

    #[test]
    #[should_panic(expected = "BitMap lengths don't match: 2 vs 1")]
    fn test_and_length_mismatch() {
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();

        bv1.push(true);
        bv1.push(false);
        bv2.push(true); // Different length

        bv1.and(&bv2);
    }

    #[test]
    #[should_panic(expected = "BitMap lengths don't match: 1 vs 2")]
    fn test_or_length_mismatch() {
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();

        bv1.push(true);
        bv2.push(true);
        bv2.push(false); // Different length

        bv1.or(&bv2);
    }

    #[test]
    #[should_panic(expected = "BitMap lengths don't match: 3 vs 2")]
    fn test_xor_length_mismatch() {
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();

        bv1.push(true);
        bv1.push(false);
        bv1.push(true);
        bv2.push(true);
        bv2.push(false); // Different length

        bv1.xor(&bv2);
    }

    #[test]
    fn test_equality() {
        // Test empty bitmaps
        assert_eq!(BitMap::<4>::new(), BitMap::<4>::new());
        assert_eq!(BitMap::<8>::new(), BitMap::<8>::new());

        // Test non-empty bitmaps from constructors
        let pattern = [true, false, true, true, false, false, true, false, true];
        let bv4: BitMap<4> = pattern.as_ref().into();
        assert_eq!(bv4, BitMap::<4>::from(pattern.as_ref()));
        let bv8: BitMap<8> = pattern.as_ref().into();
        assert_eq!(bv8, BitMap::<8>::from(pattern.as_ref()));

        // Test non-empty bitmaps from push operations
        let mut bv1: BitMap<4> = BitMap::new();
        let mut bv2: BitMap<4> = BitMap::new();
        for i in 0..33 {
            let bit = i % 3 == 0;
            bv1.push(bit);
            bv2.push(bit);
        }
        assert_eq!(bv1, bv2);

        // Test inequality: different lengths
        bv1.push(true);
        assert_ne!(bv1, bv2);
        bv1.pop(); // Restore equality
        assert_eq!(bv1, bv2);

        // Test inequality: different content
        bv1.flip(15);
        assert_ne!(bv1, bv2);
        bv1.flip(15); // Restore equality
        assert_eq!(bv1, bv2);

        // Test equality after operations
        let mut bv_ops1 = BitMap::<16>::ones(25);
        let mut bv_ops2 = BitMap::<16>::ones(25);
        bv_ops1.flip_all();
        bv_ops2.flip_all();
        assert_eq!(bv_ops1, bv_ops2);

        let mask_bits: Vec<bool> = (0..33).map(|i| i % 3 == 0).collect();
        let mask = BitMap::<4>::from(mask_bits);
        bv1.and(&mask);
        bv2.and(&mask);
        assert_eq!(bv1, bv2);
    }

    #[test]
    fn test_different_chunk_sizes() {
        // Test with different chunk sizes
        let mut bv8: BitMap<8> = BitMap::new();
        let mut bv16: BitMap<16> = BitMap::new();
        let mut bv32: BitMap<32> = BitMap::new();

        // Test chunk operations first (must be chunk-aligned)
        let chunk8 = [0xFF; 8];
        let chunk16 = [0xAA; 16];
        let chunk32 = [0x55; 32];

        bv8.push_chunk(&chunk8);
        bv16.push_chunk(&chunk16);
        bv32.push_chunk(&chunk32);

        // Test basic operations work with different sizes
        bv8.push(true);
        bv8.push(false);
        assert_eq!(bv8.len(), 64 + 2);
        assert_eq!(bv8.count_ones(), 64 + 1); // chunk8 is all 0xFF + 1 true bit
        assert_eq!(bv8.count_zeros(), 1);

        bv16.push(true);
        bv16.push(false);
        assert_eq!(bv16.len(), 128 + 2);
        assert_eq!(bv16.count_ones(), 64 + 1); // chunk16 is 0xAA pattern + 1 true bit
        assert_eq!(bv16.count_zeros(), 64 + 1);

        bv32.push(true);
        bv32.push(false);
        assert_eq!(bv32.len(), 256 + 2);
        assert_eq!(bv32.count_ones(), 128 + 1); // chunk32 is 0x55 pattern + 1 true bit
        assert_eq!(bv32.count_zeros(), 128 + 1);
    }

    #[test]
    fn test_iterator() {
        // Test empty iterator
        let bv: BitMap<4> = BitMap::new();
        let mut iter = bv.iter();
        assert_eq!(iter.next(), None);
        assert_eq!(iter.size_hint(), (0, Some(0)));

        // Test iterator with some bits
        let pattern = [true, false, true, false, true];
        let bv: BitMap<4> = pattern.as_ref().into();

        // Collect all bits via iterator
        let collected: Vec<bool> = bv.iter().collect();
        assert_eq!(collected, pattern);

        // Test size_hint
        let mut iter = bv.iter();
        assert_eq!(iter.size_hint(), (5, Some(5)));

        // Consume one element and check size_hint again
        assert_eq!(iter.next(), Some(true));
        assert_eq!(iter.size_hint(), (4, Some(4)));

        // Test ExactSizeIterator
        let iter = bv.iter();
        assert_eq!(iter.len(), 5);

        // Test iterator with larger bitmap
        let mut large_bv: BitMap<8> = BitMap::new();
        for i in 0..100 {
            large_bv.push(i % 3 == 0);
        }

        let collected: Vec<bool> = large_bv.iter().collect();
        assert_eq!(collected.len(), 100);
        for (i, &bit) in collected.iter().enumerate() {
            assert_eq!(bit, i % 3 == 0);
        }
    }

    #[test]
    fn test_iterator_edge_cases() {
        // Test iterator with single bit
        let mut bv: BitMap<4> = BitMap::new();
        bv.push(true);

        let collected: Vec<bool> = bv.iter().collect();
        assert_eq!(collected, vec![true]);

        // Test iterator across chunk boundaries
        let mut bv: BitMap<4> = BitMap::new();
        // Fill exactly one chunk (32 bits)
        for i in 0..32 {
            bv.push(i % 2 == 0);
        }
        // Add a few more bits in the next chunk
        bv.push(true);
        bv.push(false);
        bv.push(true);

        let collected: Vec<bool> = bv.iter().collect();
        assert_eq!(collected.len(), 35);

        // Verify the pattern
        for (i, &bit) in collected.iter().enumerate().take(32) {
            assert_eq!(bit, i % 2 == 0);
        }
        assert!(collected[32]);
        assert!(!collected[33]);
        assert!(collected[34]);
    }

    #[test]
    fn test_codec_roundtrip() {
        // Test empty bitmap
        let original: BitMap<4> = BitMap::new();
        let encoded = original.encode();
        let decoded = BitMap::decode_cfg(&mut encoded.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(original, decoded);

        // Test small bitmap
        let pattern = [true, false, true, false, true];
        let original: BitMap<4> = pattern.as_ref().into();
        let encoded = original.encode();
        let decoded = BitMap::decode_cfg(&mut encoded.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(original, decoded);

        // Verify the decoded bitmap has the same bits
        for (i, &expected) in pattern.iter().enumerate() {
            assert_eq!(decoded.get(i as u64), expected);
        }

        // Test larger bitmap across multiple chunks
        let mut large_original: BitMap<8> = BitMap::new();
        for i in 0..100 {
            large_original.push(i % 7 == 0);
        }

        let encoded = large_original.encode();
        let decoded = BitMap::decode_cfg(&mut encoded.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(large_original, decoded);

        // Verify all bits match
        assert_eq!(decoded.len(), 100);
        for i in 0..100 {
            assert_eq!(decoded.get(i as u64), i % 7 == 0);
        }
    }

    #[test]
    fn test_codec_different_chunk_sizes() {
        let pattern = [true, false, true, true, false, false, true];

        // Test with different chunk sizes
        let bv4: BitMap<4> = pattern.as_ref().into();
        let bv8: BitMap<8> = pattern.as_ref().into();
        let bv16: BitMap<16> = pattern.as_ref().into();

        // Encode and decode each
        let encoded4 = bv4.encode();
        let decoded4 = BitMap::decode_cfg(&mut encoded4.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv4, decoded4);

        let encoded8 = bv8.encode();
        let decoded8 = BitMap::decode_cfg(&mut encoded8.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv8, decoded8);

        let encoded16 = bv16.encode();
        let decoded16 = BitMap::decode_cfg(&mut encoded16.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv16, decoded16);

        // All should have the same logical content
        for (i, &expected) in pattern.iter().enumerate() {
            let i = i as u64;
            assert_eq!(decoded4.get(i), expected);
            assert_eq!(decoded8.get(i), expected);
            assert_eq!(decoded16.get(i), expected);
        }
    }

    #[test]
    fn test_codec_edge_cases() {
        // Test bitmap with exactly one chunk filled
        let mut bv: BitMap<4> = BitMap::new();
        for i in 0..32 {
            bv.push(i % 2 == 0);
        }

        let encoded = bv.encode();
        let decoded = BitMap::decode_cfg(&mut encoded.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv, decoded);
        assert_eq!(decoded.len(), 32);

        // Test bitmap with partial chunk
        let mut bv2: BitMap<4> = BitMap::new();
        for i in 0..35 {
            // 32 + 3 bits
            bv2.push(i % 3 == 0);
        }

        let encoded2 = bv2.encode();
        let decoded2 = BitMap::decode_cfg(&mut encoded2.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv2, decoded2);
        assert_eq!(decoded2.len(), 35);
    }

    #[test]
    fn test_encode_size() {
        // Test encode size calculation
        let bv: BitMap<4> = BitMap::new();
        let encoded = bv.encode();
        assert_eq!(bv.encode_size(), encoded.len());

        // Test with some data
        let pattern = [true, false, true, false, true];
        let bv: BitMap<4> = pattern.as_ref().into();
        let encoded = bv.encode();
        assert_eq!(bv.encode_size(), encoded.len());

        // Test with larger data
        let mut large_bv: BitMap<8> = BitMap::new();
        for i in 0..100 {
            large_bv.push(i % 2 == 0);
        }
        let encoded = large_bv.encode();
        assert_eq!(large_bv.encode_size(), encoded.len());
    }

    #[test]
    fn test_codec_empty_chunk_optimization() {
        // Test that empty last chunks are not serialized

        // Case 1: Empty bitmap (omits the only empty chunk)
        let bv_empty: BitMap<4> = BitMap::new();
        let encoded_empty = bv_empty.encode();
        let decoded_empty: BitMap<4> =
            BitMap::decode_cfg(&mut encoded_empty.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv_empty, decoded_empty);
        assert_eq!(bv_empty.len(), decoded_empty.len());
        // Should only encode the length, no chunks
        assert_eq!(encoded_empty.len(), bv_empty.len().encode_size());

        // Case 2: Bitmap ending exactly at chunk boundary (omits empty last chunk)
        let mut bv_exact: BitMap<4> = BitMap::new();
        for _ in 0..32 {
            bv_exact.push(true);
        }
        let encoded_exact = bv_exact.encode();
        let decoded_exact: BitMap<4> =
            BitMap::decode_cfg(&mut encoded_exact.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv_exact, decoded_exact);

        // Case 3: Bitmap with partial last chunk (includes last chunk)
        let mut bv_partial: BitMap<4> = BitMap::new();
        for _ in 0..35 {
            bv_partial.push(true);
        }
        let encoded_partial = bv_partial.encode();
        let decoded_partial: BitMap<4> =
            BitMap::decode_cfg(&mut encoded_partial.as_ref(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv_partial, decoded_partial);
        assert_eq!(bv_partial.len(), decoded_partial.len());

        // Verify optimization works correctly
        assert!(encoded_exact.len() < encoded_partial.len());
        assert_eq!(encoded_exact.len(), bv_exact.len().encode_size() + 4); // length + 1 chunk
        assert_eq!(encoded_partial.len(), bv_partial.len().encode_size() + 8); // length + 2 chunks
    }

    #[test]
    fn test_codec_error_cases() {
        // Test invalid length with range check
        let mut buf = BytesMut::new();
        100u64.write(&mut buf); // bits length

        // 100 bits requires 4 chunks (3 full + partially filled)
        for _ in 0..4 {
            [0u8; 4].write(&mut buf);
        }

        // Test with a restricted range that excludes 100
        let result = BitMap::<4>::decode_cfg(&mut buf, &99);
        assert!(matches!(result, Err(CodecError::InvalidLength(100))));

        // Test truncated buffer (not enough chunks)
        let mut buf = BytesMut::new();
        100u64.write(&mut buf); // bits length requiring 4 chunks (3 full + partially filled)
                                // Only write 3 chunks
        [0u8; 4].write(&mut buf);
        [0u8; 4].write(&mut buf);
        [0u8; 4].write(&mut buf);

        let result = BitMap::<4>::decode_cfg(&mut buf, &(usize::MAX as u64));
        // Should fail when trying to read missing chunks
        assert!(result.is_err());

        // Test invalid trailing bits

        // Create a valid bitmap and encode it
        let original: BitMap<4> = BitMap::ones(20);
        let mut buf = BytesMut::new();
        original.write(&mut buf);

        // Manually corrupt the encoded data by setting trailing bits
        let corrupted_data = buf.freeze();
        let mut corrupted_bytes = corrupted_data.to_vec();

        // The last byte should have some trailing bits set to 1
        // For 20 bits with 4-byte chunks: 20 bits = 2.5 bytes, so last byte should have 4 valid bits
        // Set the high 4 bits of the last byte to 1 (these should be 0)
        let last_byte_idx = corrupted_bytes.len() - 1;
        corrupted_bytes[last_byte_idx] |= 0xF0;

        // Read should fail
        let result = BitMap::<4>::read_cfg(&mut corrupted_bytes.as_slice(), &(usize::MAX as u64));
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "BitMap",
                "Invalid trailing bits in encoded data"
            ))
        ));
    }

    #[test]
    fn test_codec_range_config() {
        // Test RangeCfg validation in read_cfg

        // Create a bitmap with 100 bits
        let mut original: BitMap<4> = BitMap::new();
        for i in 0..100 {
            original.push(i % 3 == 0);
        }

        // Write to a buffer
        let mut buf = BytesMut::new();
        original.write(&mut buf);

        // Test with max length < actual size (should fail)
        let result = BitMap::<4>::decode_cfg(&mut buf.as_ref(), &50);
        assert!(matches!(result, Err(CodecError::InvalidLength(100))));

        // Test with max length == actual size (should succeed)
        let decoded = BitMap::<4>::decode_cfg(&mut buf.as_ref(), &100).unwrap();
        assert_eq!(decoded.len(), 100);
        assert_eq!(decoded, original);

        // Test with max length > actual size (should succeed)
        let decoded = BitMap::<4>::decode_cfg(&mut buf.as_ref(), &101).unwrap();
        assert_eq!(decoded.len(), 100);
        assert_eq!(decoded, original);

        // Test empty bitmap
        let empty = BitMap::<4>::new();
        let mut buf = BytesMut::new();
        empty.write(&mut buf);

        // Empty bitmap should work with max length 0
        let decoded = BitMap::<4>::decode_cfg(&mut buf.as_ref(), &0).unwrap();
        assert_eq!(decoded.len(), 0);
        assert!(decoded.is_empty());

        // Empty bitmap should work with max length > 0
        let decoded = BitMap::<4>::decode_cfg(&mut buf.as_ref(), &1).unwrap();
        assert_eq!(decoded.len(), 0);
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_from() {
        // Test From trait with different input types

        // Test with Vec<bool>
        let vec_bool = vec![true, false, true, false, true];
        let bv: BitMap<4> = vec_bool.into();
        assert_eq!(bv.len(), 5);
        assert_eq!(bv.count_ones(), 3);
        assert_eq!(bv.count_zeros(), 2);
        for (i, &expected) in [true, false, true, false, true].iter().enumerate() {
            assert_eq!(bv.get(i as u64), expected);
        }

        // Test with array slice
        let array = [false, true, true, false];
        let bv: BitMap<4> = (&array).into();
        assert_eq!(bv.len(), 4);
        assert_eq!(bv.count_ones(), 2);
        assert_eq!(bv.count_zeros(), 2);
        for (i, &expected) in array.iter().enumerate() {
            assert_eq!(bv.get(i as u64), expected);
        }

        // Test with empty slice
        let empty: Vec<bool> = vec![];
        let bv: BitMap<4> = empty.into();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test with large slice
        let large: Vec<bool> = (0..100).map(|i| i % 3 == 0).collect();
        let bv: BitMap<8> = large.clone().into();
        assert_eq!(bv.len(), 100);
        for (i, &expected) in large.iter().enumerate() {
            assert_eq!(bv.get(i as u64), expected);
        }
    }

    #[test]
    fn test_debug_formatting() {
        // Test Debug formatting for different sizes

        // Test empty bitmap
        let bv: BitMap<4> = BitMap::new();
        let debug_str = format!("{bv:?}");
        assert_eq!(debug_str, "BitMap[]");

        // Test small bitmap (should show all bits)
        let bv: BitMap<4> = [true, false, true, false, true].as_ref().into();
        let debug_str = format!("{bv:?}");
        assert_eq!(debug_str, "BitMap[10101]");

        // Test bitmap at the display limit (64 bits)
        let pattern: Vec<bool> = (0..64).map(|i| i % 2 == 0).collect();
        let bv: BitMap<8> = pattern.into();
        let debug_str = format!("{bv:?}");
        let expected_pattern = "1010".repeat(16); // 64 bits alternating
        assert_eq!(debug_str, format!("BitMap[{expected_pattern}]"));

        // Test large bitmap (should show ellipsis)
        let large_pattern: Vec<bool> = (0..100).map(|i| i % 2 == 0).collect();
        let bv: BitMap<16> = large_pattern.into();
        let debug_str = format!("{bv:?}");

        // Should show first 32 bits + "..." + last 32 bits
        let first_32 = "10".repeat(16); // First 32 bits: 1010...
        let last_32 = "10".repeat(16); // Last 32 bits: ...1010
        let expected = format!("BitMap[{first_32}...{last_32}]");
        assert_eq!(debug_str, expected);

        // Test single bit
        let bv: BitMap<4> = [true].as_ref().into();
        assert_eq!(format!("{bv:?}"), "BitMap[1]");

        let bv: BitMap<4> = [false].as_ref().into();
        assert_eq!(format!("{bv:?}"), "BitMap[0]");

        // Test exactly at boundary (65 bits - should show ellipsis)
        let pattern: Vec<bool> = (0..65).map(|i| i == 0 || i == 64).collect(); // First and last bits are true
        let bv: BitMap<16> = pattern.into();
        let debug_str = format!("{bv:?}");

        // Should show first 32 bits (100000...) + "..." + last 32 bits (...000001)
        let first_32 = "1".to_string() + &"0".repeat(31);
        let last_32 = "0".repeat(31) + "1";
        let expected = format!("BitMap[{first_32}...{last_32}]");
        assert_eq!(debug_str, expected);
    }

    #[test]
    fn test_from_different_chunk_sizes() {
        // Test From trait works with different chunk sizes
        let pattern = [true, false, true, true, false, false, true];

        let bv4: BitMap<4> = pattern.as_ref().into();
        let bv8: BitMap<8> = pattern.as_ref().into();
        let bv16: BitMap<16> = pattern.as_ref().into();

        // All should have the same content regardless of chunk size
        // Test each bitmap separately since they have different types
        for bv in [&bv4] {
            assert_eq!(bv.len(), 7);
            assert_eq!(bv.count_ones(), 4);
            assert_eq!(bv.count_zeros(), 3);
            for (i, &expected) in pattern.iter().enumerate() {
                assert_eq!(bv.get(i as u64), expected);
            }
        }

        assert_eq!(bv8.len(), 7);
        assert_eq!(bv8.count_ones(), 4);
        assert_eq!(bv8.count_zeros(), 3);
        for (i, &expected) in pattern.iter().enumerate() {
            assert_eq!(bv8.get(i as u64), expected);
        }

        assert_eq!(bv16.len(), 7);
        assert_eq!(bv16.count_ones(), 4);
        assert_eq!(bv16.count_zeros(), 3);
        for (i, &expected) in pattern.iter().enumerate() {
            assert_eq!(bv16.get(i as u64), expected);
        }
    }

    #[test]
    fn test_prune_chunks() {
        let mut bv: BitMap<4> = BitMap::new();
        bv.push_chunk(&[1, 2, 3, 4]);
        bv.push_chunk(&[5, 6, 7, 8]);
        bv.push_chunk(&[9, 10, 11, 12]);

        assert_eq!(bv.len(), 96);
        assert_eq!(bv.get_chunk(0), &[1, 2, 3, 4]);

        // Prune first chunk
        bv.prune_chunks(1);
        assert_eq!(bv.len(), 64);
        assert_eq!(bv.get_chunk(0), &[5, 6, 7, 8]);
        assert_eq!(bv.get_chunk(1), &[9, 10, 11, 12]);

        // Prune another chunk
        bv.prune_chunks(1);
        assert_eq!(bv.len(), 32);
        assert_eq!(bv.get_chunk(0), &[9, 10, 11, 12]);
    }

    #[test]
    #[should_panic(expected = "cannot prune")]
    fn test_prune_too_many_chunks() {
        let mut bv: BitMap<4> = BitMap::new();
        bv.push_chunk(&[1, 2, 3, 4]);
        bv.push_chunk(&[5, 6, 7, 8]);
        bv.push(true);

        // Try to prune 4 chunks when only 3 are available
        bv.prune_chunks(4);
    }

    #[test]
    fn test_prune_with_partial_last_chunk() {
        let mut bv: BitMap<4> = BitMap::new();
        bv.push_chunk(&[1, 2, 3, 4]);
        bv.push_chunk(&[5, 6, 7, 8]);
        bv.push(true);
        bv.push(false);

        assert_eq!(bv.len(), 66);

        // Can prune first chunk
        bv.prune_chunks(1);
        assert_eq!(bv.len(), 34);
        assert_eq!(bv.get_chunk(0), &[5, 6, 7, 8]);

        // Last partial chunk still has the appended bits
        assert!(bv.get(32));
        assert!(!bv.get(33));
    }

    #[test]
    fn test_prune_all_chunks_resets_next_bit() {
        let mut bv: BitMap<4> = BitMap::new();
        bv.push_chunk(&[1, 2, 3, 4]);
        bv.push_chunk(&[5, 6, 7, 8]);
        bv.push(true);
        bv.push(false);
        bv.push(true);

        // Bitmap has 2 full chunks + 3 bits in partial chunk
        assert_eq!(bv.len(), 67);

        // Prune all chunks (this leaves chunks empty, triggering the reset path)
        bv.prune_chunks(3);

        // Regression test: len() should be 0, not the old next_bit value (3)
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Bitmap should behave as freshly created
        bv.push(true);
        assert_eq!(bv.len(), 1);
        assert!(bv.get(0));
    }

    #[test]
    fn test_chunks_needed() {
        // Test with different chunk sizes
        assert_eq!(BitMap::<1>::num_chunks_at_size(0).get(), 1);
        assert_eq!(BitMap::<1>::num_chunks_at_size(1).get(), 1);
        assert_eq!(BitMap::<1>::num_chunks_at_size(8).get(), 2);
        assert_eq!(BitMap::<1>::num_chunks_at_size(9).get(), 2);
        assert_eq!(BitMap::<1>::num_chunks_at_size(16).get(), 3);
        assert_eq!(BitMap::<1>::num_chunks_at_size(17).get(), 3);

        assert_eq!(BitMap::<3>::num_chunks_at_size(0).get(), 1);
        assert_eq!(BitMap::<3>::num_chunks_at_size(1).get(), 1);
        assert_eq!(BitMap::<3>::num_chunks_at_size(23).get(), 1);
        assert_eq!(BitMap::<3>::num_chunks_at_size(24).get(), 2);
        assert_eq!(BitMap::<3>::num_chunks_at_size(25).get(), 2);
        assert_eq!(BitMap::<3>::num_chunks_at_size(48).get(), 3);
        assert_eq!(BitMap::<3>::num_chunks_at_size(49).get(), 3);

        assert_eq!(BitMap::<4>::num_chunks_at_size(0).get(), 1);
        assert_eq!(BitMap::<4>::num_chunks_at_size(1).get(), 1);
        assert_eq!(BitMap::<4>::num_chunks_at_size(31).get(), 1);
        assert_eq!(BitMap::<4>::num_chunks_at_size(32).get(), 2);
        assert_eq!(BitMap::<4>::num_chunks_at_size(33).get(), 2);
        assert_eq!(BitMap::<4>::num_chunks_at_size(63).get(), 2);
        assert_eq!(BitMap::<4>::num_chunks_at_size(64).get(), 3);
        assert_eq!(BitMap::<4>::num_chunks_at_size(65).get(), 3);
    }
}

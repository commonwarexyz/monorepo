//! Bit-vector implementation
//!
//! The bit-vector is a compact representation of a sequence of bits, using "chunks" of bytes for a
//! more-efficient memory layout than doing a [`Vec<bool>`].

use crate::NZUsize;
#[cfg(not(feature = "std"))]
use alloc::{collections::VecDeque, vec, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadExt, Write};
use core::{
    fmt::{self, Formatter, Write as _},
    num::NonZeroUsize,
    ops::{BitAnd, BitOr, BitXor, Index},
};
#[cfg(feature = "std")]
use std::collections::VecDeque;

pub mod prunable;
pub use prunable::Prunable;

/// A bitmap that stores data in chunks of N bytes.
#[derive(Clone)]
pub struct BitVec<const N: usize> {
    /// The bitmap itself, in chunks of size N bytes. The number of valid bits in the last chunk is
    /// given by `self.next_bit`. Within each byte, lowest order bits are treated as coming before
    /// higher order bits in the bit ordering.
    ///
    /// Invariant: The last chunk in the bitmap always has room for at least one more bit.
    /// This implies that !chunks.is_empty() always holds.
    chunks: VecDeque<[u8; N]>,

    /// The position within the last chunk where the next bit is to be appended.
    ///
    /// Invariant: This value is always in the range [0, N * 8).
    next_bit: u64,
}

impl<const N: usize> BitVec<N> {
    /// The size of a chunk in bytes.
    const CHUNK_SIZE: usize = N;

    /// The size of a chunk in bits.
    const CHUNK_SIZE_BITS: u64 = N as u64 * 8;

    /// A chunk of all 0s.
    const EMPTY_CHUNK: [u8; N] = [0u8; N];

    /// A chunk of all 1s.
    const FULL_CHUNK: [u8; N] = [u8::MAX; N];

    /// Create a new empty bitmap.
    pub fn new() -> Self {
        // Invariant: chunks is never empty
        let bitmap = VecDeque::from([Self::EMPTY_CHUNK]);
        Self {
            chunks: bitmap,
            next_bit: 0,
        }
    }

    // Create a new empty bitmap with the capacity to hold `size` bits without reallocating.
    pub fn with_capacity(size: u64) -> Self {
        let num_chunks = Self::num_chunks_at_size(size).get();
        let mut bitmap = VecDeque::with_capacity(num_chunks);
        // Invariant: chunks is never empty
        bitmap.push_back(Self::EMPTY_CHUNK);
        Self {
            chunks: bitmap,
            next_bit: 0,
        }
    }

    // Returns the number of chunks in a bitvec with `size` bits.
    // Recall the invariant that the last chunk always has room for at least one more bit.
    fn num_chunks_at_size(size: u64) -> NonZeroUsize {
        NZUsize!((size / Self::CHUNK_SIZE_BITS) as usize + 1)
    }

    /// Create a new bitmap with `size` bits, with all bits set to 0.
    pub fn zeroes(size: u64) -> Self {
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
        let num_chunks = Self::num_chunks_at_size(size).get();
        let mut chunks = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            chunks.push_back(Self::FULL_CHUNK);
        }
        Self {
            chunks,
            next_bit: size % Self::CHUNK_SIZE_BITS,
        }
    }

    /// Return the number of bits currently stored in the bitmap.
    #[inline]
    pub fn len(&self) -> u64 {
        (self.chunks.len() as u64 - 1) * Self::CHUNK_SIZE_BITS + self.next_bit
    }

    /// Return the last chunk of the bitmap and its size in bits.
    /// The size can be 0 (meaning the last chunk is empty).
    #[inline]
    fn last_chunk(&self) -> (&[u8; N], u64) {
        (self.chunks.back().unwrap(), self.next_bit)
    }

    /// Return the last chunk of the bitmap and its size in bits.
    /// The size can be 0 (meaning the last chunk is empty).
    #[inline]
    fn last_chunk_mut(&mut self) -> &mut [u8; N] {
        self.chunks.back_mut().unwrap()
    }

    /// Returns the bitmap chunk containing the specified bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    #[inline]
    fn get_chunk(&self, bit_offset: u64) -> &[u8; N] {
        assert!(bit_offset < self.len(), "out of bounds: {bit_offset}");
        &self.chunks[Self::chunk_index(bit_offset)]
    }

    /// Get the value of a bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    #[inline]
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        let chunk = self.get_chunk(bit_offset);
        Self::get_bit_from_chunk(chunk, bit_offset)
    }

    /// Get the value at the given global `bit_offset` from the `chunk`.
    #[inline]
    fn get_bit_from_chunk(chunk: &[u8; N], bit_offset: u64) -> bool {
        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let byte = chunk[byte_offset];
        let mask = Self::chunk_byte_bitmask(bit_offset);
        (byte & mask) != 0
    }

    /// Add a single bit to the bitmap.
    pub fn append(&mut self, bit: bool) {
        let chunk_byte = (self.next_bit / 8) as usize;
        let next_bit = self.next_bit;
        let last_chunk = self.last_chunk_mut();
        // Ensure the bit is set correctly
        if bit {
            last_chunk[chunk_byte] |= Self::chunk_byte_bitmask(next_bit);
        } else {
            last_chunk[chunk_byte] &= !Self::chunk_byte_bitmask(next_bit);
        }
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
        if self.next_bit == 0 {
            // Remove the last (empty) chunk
            self.chunks.pop_back();
            self.next_bit = Self::CHUNK_SIZE_BITS - 1;
        } else {
            self.next_bit -= 1;
        }
        Self::get_bit_from_chunk(self.last_chunk().0, self.next_bit)
    }

    /// Remove the first `n` chunks from the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if trying to prune more chunks than exist.
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
        }
    }

    /// Get the number of chunks currently in the bitmap.
    fn chunks_len(&self) -> usize {
        self.chunks.len()
    }

    /// Efficiently add a byte's worth of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// Assumes self.next_bit is currently byte aligned, and panics otherwise.
    fn append_byte_unchecked(&mut self, byte: u8) {
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

    /// Efficiently add a chunk of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if we're not at a chunk boundary.
    pub(super) fn append_chunk_unchecked(&mut self, chunk: &[u8; N]) {
        assert_eq!(self.next_bit, 0, "cannot add chunk when not chunk aligned");
        self.last_chunk_mut().copy_from_slice(chunk.as_ref());
        self.prepare_next_chunk();
    }

    /// Set the value of the referenced bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    pub fn set(&mut self, bit_offset: u64, bit: bool) {
        let chunk_index = Self::chunk_index(bit_offset);
        let chunk = &mut self.chunks[chunk_index];

        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let mask = Self::chunk_byte_bitmask(bit_offset);

        if bit {
            chunk[byte_offset] |= mask;
        } else {
            chunk[byte_offset] &= !mask;
        }
    }

    /// Prepares the next chunk of the bitmap to preserve the invariant that there is always room
    /// for one more bit.
    fn prepare_next_chunk(&mut self) {
        self.next_bit = 0;
        self.chunks.push_back([0u8; N]);
    }

    /// Convert a bit offset into a bitmask for the byte containing that bit.
    #[inline]
    pub(super) fn chunk_byte_bitmask(bit_offset: u64) -> u8 {
        1 << (bit_offset % 8)
    }

    /// Convert a bit offset into the offset of the byte within a chunk containing the bit.
    #[inline]
    pub(super) fn chunk_byte_offset(bit_offset: u64) -> usize {
        (bit_offset / 8) as usize % Self::CHUNK_SIZE
    }

    /// Convert a bit offset into the index of the chunk it belongs to.
    #[inline]
    pub(super) fn chunk_index(bit_offset: u64) -> usize {
        (bit_offset / Self::CHUNK_SIZE_BITS) as usize
    }

    /// Returns true if the bitmap is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get a reference to a chunk by its index in the current bitmap
    pub fn get_chunk_by_index(&self, index: usize) -> &[u8; N] {
        &self.chunks[index]
    }

    /// Flips the bit at `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn toggle(&mut self, index: u64) {
        self.assert_index(index);
        let chunk_index = Self::chunk_index(index);
        let byte_offset = Self::chunk_byte_offset(index);
        let mask = Self::chunk_byte_bitmask(index);
        self.chunks[chunk_index][byte_offset] ^= mask;
    }

    /// Sets all bits to 0.
    #[inline]
    pub fn clear_all(&mut self) {
        for chunk in &mut self.chunks {
            chunk.fill(0u8);
        }
    }

    /// Sets all bits to 1.
    #[inline]
    pub fn set_all(&mut self) {
        for chunk in &mut self.chunks {
            chunk.fill(u8::MAX);
        }
    }

    /// Returns the number of bits set to 1.
    #[inline]
    pub fn count_ones(&self) -> u64 {
        let mut count: u64 = 0;
        for (i, chunk) in self.chunks.iter().enumerate() {
            if i == self.chunks.len() - 1 {
                // For the last chunk, only count bits up to next_bit
                let bytes_to_count = self.next_bit.div_ceil(8) as usize; // Round up to nearest byte
                for (byte_idx, byte) in chunk.iter().enumerate().take(bytes_to_count) {
                    if byte_idx == (bytes_to_count - 1) && self.next_bit % 8 != 0 {
                        // For the last byte, only count bits up to next_bit % 8
                        let bits_in_last_byte = self.next_bit % 8;
                        let mask = (1u8 << bits_in_last_byte) - 1;
                        count += (byte & mask).count_ones() as u64;
                    } else {
                        count += byte.count_ones() as u64;
                    }
                }
            } else {
                // For all other chunks, count all bits
                for byte in chunk {
                    count += byte.count_ones() as u64;
                }
            }
        }
        count
    }

    /// Returns the number of bits set to 0.
    #[inline]
    pub fn count_zeros(&self) -> u64 {
        self.len() - self.count_ones()
    }

    /// Performs a bitwise AND with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn and(&mut self, other: &BitVec<N>) {
        self.binary_op(other, |a, b| a & b);
    }

    /// Performs a bitwise OR with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn or(&mut self, other: &BitVec<N>) {
        self.binary_op(other, |a, b| a | b);
    }

    /// Performs a bitwise XOR with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn xor(&mut self, other: &BitVec<N>) {
        self.binary_op(other, |a, b| a ^ b);
    }

    /// Flips all bits (1s become 0s and vice versa).
    pub fn invert(&mut self) {
        for chunk in &mut self.chunks {
            for byte in chunk {
                *byte = !*byte;
            }
        }
    }

    /// Asserts that the index is within bounds.
    #[inline(always)]
    fn assert_index(&self, index: u64) {
        assert!(index < self.len(), "Index out of bounds");
    }

    /// Asserts that the lengths of two [BitVec]s match.
    #[inline(always)]
    fn assert_eq_len(&self, other: &BitVec<N>) {
        assert_eq!(self.len(), other.len(), "BitVec lengths don't match");
    }

    /// Creates an iterator over the bits.
    pub fn iter(&self) -> Iterator<'_, N> {
        Iterator { vec: self, pos: 0 }
    }

    /// Helper for binary operations (AND, OR, XOR)
    #[inline]
    fn binary_op<F: Fn(u8, u8) -> u8>(&mut self, other: &BitVec<N>, op: F) {
        self.assert_eq_len(other);
        for (a_chunk, b_chunk) in self.chunks.iter_mut().zip(other.chunks.iter()) {
            for (a_byte, b_byte) in a_chunk.iter_mut().zip(b_chunk.iter()) {
                *a_byte = op(*a_byte, *b_byte);
            }
        }
    }
}

impl<const N: usize> Default for BitVec<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PartialEq for BitVec<N> {
    fn eq(&self, other: &Self) -> bool {
        // First check if bit counts match
        if self.len() != other.len() {
            return false;
        }

        // If both are empty, they're equal
        if self.is_empty() {
            return true;
        }

        // Compare each valid bit
        for i in 0..self.len() {
            if self.get_bit(i) != other.get_bit(i) {
                return false;
            }
        }

        true
    }
}

impl<const N: usize> Eq for BitVec<N> {}

impl<T: AsRef<[bool]>, const N: usize> From<T> for BitVec<N> {
    fn from(t: T) -> Self {
        let bools = t.as_ref();
        let mut bv = Self::new();
        for &b in bools {
            bv.append(b);
        }
        bv
    }
}

impl<const N: usize> From<BitVec<N>> for Vec<bool> {
    fn from(bv: BitVec<N>) -> Self {
        bv.iter().collect()
    }
}

impl<const N: usize> fmt::Debug for BitVec<N> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // For very large BitVecs, only show a preview
        const MAX_DISPLAY: usize = 64;
        const HALF_DISPLAY: usize = MAX_DISPLAY / 2;

        // Closure for writing a bit
        let write_bit = |formatter: &mut Formatter<'_>, index: u64| -> core::fmt::Result {
            formatter.write_char(if self.get_bit(index) { '1' } else { '0' })
        };

        f.write_str("BitVec[")?;
        let len = self.len();
        if len <= MAX_DISPLAY as u64 {
            // Show all bits
            for i in 0..len {
                write_bit(f, i)?;
            }
        } else {
            // Show first and last bits with ellipsis
            for i in 0..HALF_DISPLAY as u64 {
                write_bit(f, i)?;
            }

            f.write_str("...")?;

            for i in (len - HALF_DISPLAY as u64)..len {
                write_bit(f, i)?;
            }
        }
        f.write_str("]")
    }
}

impl<const N: usize> Index<usize> for BitVec<N> {
    type Output = bool;

    /// Allows accessing bits using the `[]` operator.
    ///
    /// Panics if out of bounds.
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.assert_index(index as u64);
        let value = self.get_bit(index as u64);
        if value {
            &true
        } else {
            &false
        }
    }
}

impl<const N: usize> BitAnd for &BitVec<N> {
    type Output = BitVec<N>;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.and(rhs);
        result
    }
}

impl<const N: usize> BitOr for &BitVec<N> {
    type Output = BitVec<N>;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.or(rhs);
        result
    }
}

impl<const N: usize> BitXor for &BitVec<N> {
    type Output = BitVec<N>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.xor(rhs);
        result
    }
}

impl<const N: usize> Write for BitVec<N> {
    fn write(&self, buf: &mut impl BufMut) {
        // Prefix with the number of bits
        self.len().write(buf);

        // Write the next_bit position
        self.next_bit.write(buf);

        // Write all chunks
        for chunk in &self.chunks {
            for &byte in chunk {
                byte.write(buf);
            }
        }
    }
}

impl<const N: usize> Read for BitVec<N> {
    type Cfg = RangeCfg;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        // Parse length in bits
        let len = u64::read(buf)?;
        if !range.contains(&(len as usize)) {
            return Err(CodecError::InvalidLength(len as usize));
        }

        // Parse next_bit position
        let next_bit = u64::read(buf)?;

        // Validate next_bit is within chunk bounds
        if next_bit >= Self::CHUNK_SIZE_BITS {
            return Err(CodecError::Invalid("BitVec", "next_bit out of bounds"));
        }

        // Parse chunks
        let num_chunks = Self::num_chunks_at_size(len).get();
        let mut bitmap = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            let mut chunk = [0u8; N];
            for byte in &mut chunk {
                *byte = u8::read(buf)?;
            }
            bitmap.push_back(chunk);
        }

        // Validate the length and next_bit are consistent
        let expected_len = if bitmap.len() == 1 && next_bit == 0 {
            0 // Empty bitvec
        } else {
            (bitmap.len() - 1) as u64 * Self::CHUNK_SIZE_BITS + next_bit
        };

        if len != expected_len {
            return Err(CodecError::Invalid(
                "BitVec",
                "inconsistent length and next_bit",
            ));
        }

        Ok(BitVec {
            chunks: bitmap,
            next_bit,
        })
    }
}

impl<const N: usize> EncodeSize for BitVec<N> {
    fn encode_size(&self) -> usize {
        // Size of length (u64) + next_bit (u64) + all chunks
        self.len().encode_size() + self.next_bit.encode_size() + (self.chunks.len() * N)
    }
}

/// Iterator over bits in a [BitVec].
pub struct Iterator<'a, const N: usize> {
    /// Reference to the BitVec being iterated over
    vec: &'a BitVec<N>,

    /// Current position in the BitVec (0-indexed)
    pos: u64,
}

impl<const N: usize> core::iter::Iterator for Iterator<'_, N> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.vec.len() {
            return None;
        }

        let bit = self.vec.get_bit(self.pos);
        self.pos += 1;
        Some(bit)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = (self.vec.len() - self.pos) as usize;
        (remaining, Some(remaining))
    }
}

impl<const N: usize> ExactSizeIterator for Iterator<'_, N> {}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_constructors() {
        // Test new()
        let bv: BitVec<4> = BitVec::new();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test default()
        let bv: BitVec<4> = Default::default();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test with_capacity()
        let bv: BitVec<4> = BitVec::with_capacity(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        let bv: BitVec<4> = BitVec::with_capacity(10);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
    }

    #[test]
    fn test_zeroes() {
        let bv: BitVec<1> = BitVec::zeroes(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 0);

        let bv: BitVec<1> = BitVec::zeroes(1);
        assert_eq!(bv.len(), 1);
        assert!(!bv.is_empty());
        assert_eq!(bv.len(), 1);
        assert!(!bv.get_bit(0));
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 1);

        let bv: BitVec<1> = BitVec::zeroes(10);
        assert_eq!(bv.len(), 10);
        assert!(!bv.is_empty());
        assert_eq!(bv.len(), 10);
        for i in 0..10 {
            assert!(!bv.get_bit(i));
        }
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 10);
    }

    #[test]
    fn test_ones() {
        let bv: BitVec<1> = BitVec::ones(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 0);

        let bv: BitVec<1> = BitVec::ones(1);
        assert_eq!(bv.len(), 1);
        assert!(!bv.is_empty());
        assert_eq!(bv.len(), 1);
        assert!(bv.get_bit(0));
        assert_eq!(bv.count_ones(), 1);
        assert_eq!(bv.count_zeros(), 0);

        let bv: BitVec<1> = BitVec::ones(10);
        assert_eq!(bv.len(), 10);
        assert!(!bv.is_empty());
        assert_eq!(bv.len(), 10);
        for i in 0..10 {
            assert!(bv.get_bit(i));
        }
        assert_eq!(bv.count_ones(), 10);
        assert_eq!(bv.count_zeros(), 0);
    }

    #[test]
    fn test_get_set() {
        let mut bv: BitVec<4> = BitVec::new();

        // Test initial state
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test append
        bv.append(true);
        bv.append(false);
        bv.append(true);
        assert_eq!(bv.len(), 3);
        assert!(!bv.is_empty());

        // Test get_bit
        assert!(bv.get_bit(0));
        assert!(!bv.get_bit(1));
        assert!(bv.get_bit(2));

        // Test set_bit
        bv.set(1, true);
        assert!(bv.get_bit(1));
        bv.set(2, false);
        assert!(!bv.get_bit(2));

        // Test toggle
        bv.toggle(0); // true -> false
        assert!(!bv.get_bit(0));
        bv.toggle(0); // false -> true
        assert!(bv.get_bit(0));
    }

    #[test]
    fn test_chunk_operations() {
        let mut bv: BitVec<4> = BitVec::new();
        let test_chunk = [0xAB, 0xCD, 0xEF, 0x12];

        // Test append_chunk_unchecked
        bv.append_chunk_unchecked(&test_chunk);
        assert_eq!(bv.len(), 32); // 4 bytes * 8 bits

        // Test get_chunk
        let chunk = bv.get_chunk(0);
        assert_eq!(chunk, &test_chunk);

        // Test get_chunk_by_index
        let chunk_by_index = bv.get_chunk_by_index(0);
        assert_eq!(chunk_by_index, &test_chunk);

        // Test last_chunk
        let (last_chunk, next_bit) = bv.last_chunk();
        assert_eq!(next_bit, 0); // Should be at chunk boundary
        assert_eq!(last_chunk, &[0u8; 4]); // Empty next chunk
    }

    #[test]
    fn test_pop() {
        let mut bv: BitVec<3> = BitVec::new();
        bv.append(true);
        assert!(bv.pop());
        assert_eq!(bv.len(), 0);

        bv.append(false);
        assert!(!bv.pop());
        assert_eq!(bv.len(), 0);

        bv.append(true);
        bv.append(false);
        bv.append(true);
        assert!(bv.pop());
        assert_eq!(bv.len(), 2);
        assert!(!bv.pop());
        assert_eq!(bv.len(), 1);
        assert!(bv.pop());
        assert_eq!(bv.len(), 0);

        for i in 0..100 {
            bv.append(i % 2 == 0);
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
        let mut bv: BitVec<4> = BitVec::new();

        // Test append_byte_unchecked
        bv.append_byte_unchecked(0xFF);
        assert_eq!(bv.len(), 8);

        // All bits in the byte should be set
        for i in 0..8 {
            assert!(bv.get_bit(i));
        }

        bv.append_byte_unchecked(0x00);
        assert_eq!(bv.len(), 16);

        // All bits in the second byte should be clear
        for i in 8..16 {
            assert!(!bv.get_bit(i));
        }
    }

    #[test]
    fn test_count_operations() {
        let mut bv: BitVec<4> = BitVec::new();

        // Empty bitvec
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 0);

        // Add some bits
        bv.append(true);
        bv.append(false);
        bv.append(true);
        bv.append(true);
        bv.append(false);

        assert_eq!(bv.count_ones(), 3);
        assert_eq!(bv.count_zeros(), 2);
        assert_eq!(bv.len(), 5);

        // Test with full bytes
        let mut bv2: BitVec<4> = BitVec::new();
        bv2.append_byte_unchecked(0xFF); // 8 ones
        bv2.append_byte_unchecked(0x00); // 8 zeros
        bv2.append_byte_unchecked(0xAA); // 4 ones, 4 zeros (10101010)

        assert_eq!(bv2.count_ones(), 12);
        assert_eq!(bv2.count_zeros(), 12);
        assert_eq!(bv2.len(), 24);
    }

    #[test]
    fn test_clear_set_all() {
        let mut bv: BitVec<4> = BitVec::new();

        // Add some bits - fill to byte boundary first
        bv.append(true);
        bv.append(false);
        bv.append(true);
        bv.append(false);
        bv.append(true);
        bv.append(false);
        bv.append(true);
        bv.append(false);
        // Now we're byte-aligned, can use append_byte_unchecked
        bv.append_byte_unchecked(0xAB);

        assert_eq!(bv.len(), 16);
        assert!(bv.count_ones() > 0);

        // Test clear_all
        bv.clear_all();
        assert_eq!(bv.len(), 16); // Length shouldn't change
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 16);

        // Test set_all
        bv.set_all();
        assert_eq!(bv.len(), 16); // Length shouldn't change
        assert_eq!(bv.count_ones(), 16);
        assert_eq!(bv.count_zeros(), 0);
    }

    #[test]
    fn test_invert() {
        let mut bv: BitVec<4> = BitVec::new();

        // Test with specific pattern
        bv.append(true);
        bv.append(false);
        bv.append(true);
        bv.append(false);
        bv.append(true);

        let original_ones = bv.count_ones();
        let original_zeros = bv.count_zeros();

        bv.invert();

        // After invert, ones and zeros should be swapped
        assert_eq!(bv.count_ones(), original_zeros);
        assert_eq!(bv.count_zeros(), original_ones);

        // Check bits
        assert!(!bv.get_bit(0));
        assert!(bv.get_bit(1));
        assert!(!bv.get_bit(2));
        assert!(bv.get_bit(3));
        assert!(!bv.get_bit(4));
    }

    #[test]
    fn test_bitwise_and() {
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        // Create test patterns: 10110 & 11010 = 10010
        let pattern1 = [true, false, true, true, false];
        let pattern2 = [true, true, false, true, false];
        let expected = [true, false, false, true, false];

        for &bit in &pattern1 {
            bv1.append(bit);
        }
        for &bit in &pattern2 {
            bv2.append(bit);
        }

        bv1.and(&bv2);

        assert_eq!(bv1.len(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get_bit(i as u64), expected_bit);
        }
    }

    #[test]
    fn test_bitwise_or() {
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        // Create test patterns: 10110 | 11010 = 11110
        let pattern1 = [true, false, true, true, false];
        let pattern2 = [true, true, false, true, false];
        let expected = [true, true, true, true, false];

        for &bit in &pattern1 {
            bv1.append(bit);
        }
        for &bit in &pattern2 {
            bv2.append(bit);
        }

        bv1.or(&bv2);

        assert_eq!(bv1.len(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get_bit(i as u64), expected_bit);
        }
    }

    #[test]
    fn test_bitwise_xor() {
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        // Create test patterns: 10110 ^ 11010 = 01100
        let pattern1 = [true, false, true, true, false];
        let pattern2 = [true, true, false, true, false];
        let expected = [false, true, true, false, false];

        for &bit in &pattern1 {
            bv1.append(bit);
        }
        for &bit in &pattern2 {
            bv2.append(bit);
        }

        bv1.xor(&bv2);

        assert_eq!(bv1.len(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get_bit(i as u64), expected_bit);
        }
    }

    #[test]
    fn test_multi_chunk_operations() {
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        // Fill multiple chunks
        let chunk1 = [0xAA, 0xBB, 0xCC, 0xDD]; // 10101010 10111011 11001100 11011101
        let chunk2 = [0x55, 0x66, 0x77, 0x88]; // 01010101 01100110 01110111 10001000

        bv1.append_chunk_unchecked(&chunk1);
        bv1.append_chunk_unchecked(&chunk1);
        bv2.append_chunk_unchecked(&chunk2);
        bv2.append_chunk_unchecked(&chunk2);

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
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        // Add partial chunks (not aligned to chunk boundaries)
        for i in 0..35 {
            // 35 bits = 4 bytes + 3 bits
            bv1.append(i % 2 == 0);
            bv2.append(i % 3 == 0);
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

        // Test invert with partial chunk
        let mut bv_inv = bv1.clone();
        let original_ones = bv_inv.count_ones();
        let original_zeros = bv_inv.count_zeros();
        bv_inv.invert();
        assert_eq!(bv_inv.count_ones(), original_zeros);
        assert_eq!(bv_inv.count_zeros(), original_ones);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_toggle_out_of_bounds() {
        let mut bv: BitVec<4> = BitVec::new();
        bv.append(true);
        bv.toggle(1); // Only bit 0 exists
    }

    #[test]
    #[should_panic(expected = "BitVec lengths don't match")]
    fn test_and_length_mismatch() {
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        bv1.append(true);
        bv1.append(false);
        bv2.append(true); // Different length

        bv1.and(&bv2);
    }

    #[test]
    #[should_panic(expected = "BitVec lengths don't match")]
    fn test_or_length_mismatch() {
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        bv1.append(true);
        bv2.append(true);
        bv2.append(false); // Different length

        bv1.or(&bv2);
    }

    #[test]
    #[should_panic(expected = "BitVec lengths don't match")]
    fn test_xor_length_mismatch() {
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        bv1.append(true);
        bv1.append(false);
        bv1.append(true);
        bv2.append(true);
        bv2.append(false); // Different length

        bv1.xor(&bv2);
    }

    #[test]
    fn test_equality_ignores_trailing_bits() {
        // Test that equality comparison ignores trailing bits
        let mut bv1: BitVec<4> = BitVec::new();
        let mut bv2: BitVec<4> = BitVec::new();

        // Add same bits to both
        bv1.append(true);
        bv1.append(false);
        bv1.append(true);

        bv2.append(true);
        bv2.append(false);
        bv2.append(true);

        // They should be equal
        assert_eq!(bv1, bv2);

        // Now manually corrupt trailing bits in one of them
        {
            let last_chunk = bv1.chunks.back_mut().unwrap();
            last_chunk[0] |= 0xF8; // Set bits 3-7 (invalid bits)
        }

        // They should still be equal because comparison ignores trailing bits
        assert_eq!(bv1, bv2);

        // But if we change a valid bit, they should be different
        bv1.set(1, true); // Change bit 1 from false to true
        assert_ne!(bv1, bv2);
    }

    #[test]
    fn test_equality_edge_cases() {
        // Test equality with empty bitvecs
        let bv1: BitVec<4> = BitVec::new();
        let bv2: BitVec<4> = BitVec::new();
        assert_eq!(bv1, bv2);

        // Test equality with different lengths
        let mut bv3: BitVec<4> = BitVec::new();
        bv3.append(true);
        assert_ne!(bv1, bv3);

        // Test equality after operations that might leave trailing bits
        let mut bv4: BitVec<4> = [true, false, true].as_ref().into();
        let mut bv5: BitVec<4> = [true, false, true].as_ref().into();

        // Perform operations that would previously require clearing trailing bits
        bv4.set_all();
        bv5.set_all();
        assert_eq!(bv4, bv5);

        bv4.invert();
        bv5.invert();
        assert_eq!(bv4, bv5);

        // Test with bitwise operations
        let bv6: BitVec<4> = [true, true, false].as_ref().into();

        let mut bv8 = bv4.clone();
        let mut bv9 = bv5.clone();

        bv8.and(&bv6);
        bv9.and(&bv6);
        assert_eq!(bv8, bv9);
    }

    #[test]
    fn test_different_chunk_sizes() {
        // Test with different chunk sizes
        let mut bv8: BitVec<8> = BitVec::new();
        let mut bv16: BitVec<16> = BitVec::new();
        let mut bv32: BitVec<32> = BitVec::new();

        // Test chunk operations first (must be chunk-aligned)
        let chunk8 = [0xFF; 8];
        let chunk16 = [0xAA; 16];
        let chunk32 = [0x55; 32];

        bv8.append_chunk_unchecked(&chunk8);
        bv16.append_chunk_unchecked(&chunk16);
        bv32.append_chunk_unchecked(&chunk32);

        // Test basic operations work with different sizes
        bv8.append(true);
        bv8.append(false);
        assert_eq!(bv8.len(), 64 + 2);
        assert_eq!(bv8.count_ones(), 64 + 1); // chunk8 is all 0xFF + 1 true bit
        assert_eq!(bv8.count_zeros(), 1);

        bv16.append(true);
        bv16.append(false);
        assert_eq!(bv16.len(), 128 + 2);
        assert_eq!(bv16.count_ones(), 64 + 1); // chunk16 is 0xAA pattern + 1 true bit
        assert_eq!(bv16.count_zeros(), 64 + 1);

        bv32.append(true);
        bv32.append(false);
        assert_eq!(bv32.len(), 256 + 2);
        assert_eq!(bv32.count_ones(), 128 + 1); // chunk32 is 0x55 pattern + 1 true bit
        assert_eq!(bv32.count_zeros(), 128 + 1);
    }

    #[test]
    fn test_iterator() {
        // Test empty iterator
        let bv: BitVec<4> = BitVec::new();
        let mut iter = bv.iter();
        assert_eq!(iter.next(), None);
        assert_eq!(iter.size_hint(), (0, Some(0)));

        // Test iterator with some bits
        let pattern = [true, false, true, false, true];
        let bv: BitVec<4> = pattern.as_ref().into();

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

        // Test iterator with larger bitvec
        let mut large_bv: BitVec<8> = BitVec::new();
        for i in 0..100 {
            large_bv.append(i % 3 == 0);
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
        let mut bv: BitVec<4> = BitVec::new();
        bv.append(true);

        let collected: Vec<bool> = bv.iter().collect();
        assert_eq!(collected, vec![true]);

        // Test iterator across chunk boundaries
        let mut bv: BitVec<4> = BitVec::new();
        // Fill exactly one chunk (32 bits)
        for i in 0..32 {
            bv.append(i % 2 == 0);
        }
        // Add a few more bits in the next chunk
        bv.append(true);
        bv.append(false);
        bv.append(true);

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
        use commonware_codec::Encode;

        // Test empty bitvec
        let original: BitVec<4> = BitVec::new();
        let encoded = original.encode();
        let decoded = BitVec::decode_cfg(&mut encoded.as_ref(), &(..).into()).unwrap();
        assert_eq!(original, decoded);

        // Test small bitvec
        let pattern = [true, false, true, false, true];
        let original: BitVec<4> = pattern.as_ref().into();
        let encoded = original.encode();
        let decoded = BitVec::decode_cfg(&mut encoded.as_ref(), &(..).into()).unwrap();
        assert_eq!(original, decoded);

        // Verify the decoded bitvec has the same bits
        for (i, &expected) in pattern.iter().enumerate() {
            assert_eq!(decoded.get_bit(i as u64), expected);
        }

        // Test larger bitvec across multiple chunks
        let mut large_original: BitVec<8> = BitVec::new();
        for i in 0..100 {
            large_original.append(i % 7 == 0);
        }

        let encoded = large_original.encode();
        let decoded = BitVec::decode_cfg(&mut encoded.as_ref(), &(..).into()).unwrap();
        assert_eq!(large_original, decoded);

        // Verify all bits match
        assert_eq!(decoded.len(), 100);
        for i in 0..100 {
            assert_eq!(decoded.get_bit(i), i % 7 == 0);
        }
    }

    #[test]
    fn test_codec_different_chunk_sizes() {
        use commonware_codec::Encode;

        let pattern = [true, false, true, true, false, false, true];

        // Test with different chunk sizes
        let bv4: BitVec<4> = pattern.as_ref().into();
        let bv8: BitVec<8> = pattern.as_ref().into();
        let bv16: BitVec<16> = pattern.as_ref().into();

        // Encode and decode each
        let encoded4 = bv4.encode();
        let decoded4 = BitVec::decode_cfg(&mut encoded4.as_ref(), &(..).into()).unwrap();
        assert_eq!(bv4, decoded4);

        let encoded8 = bv8.encode();
        let decoded8 = BitVec::decode_cfg(&mut encoded8.as_ref(), &(..).into()).unwrap();
        assert_eq!(bv8, decoded8);

        let encoded16 = bv16.encode();
        let decoded16 = BitVec::decode_cfg(&mut encoded16.as_ref(), &(..).into()).unwrap();
        assert_eq!(bv16, decoded16);

        // All should have the same logical content
        for (i, &expected) in pattern.iter().enumerate() {
            assert_eq!(decoded4.get_bit(i as u64), expected);
            assert_eq!(decoded8.get_bit(i as u64), expected);
            assert_eq!(decoded16.get_bit(i as u64), expected);
        }
    }

    #[test]
    fn test_codec_edge_cases() {
        use commonware_codec::Encode;

        // Test bitvec with exactly one chunk filled
        let mut bv: BitVec<4> = BitVec::new();
        for i in 0..32 {
            bv.append(i % 2 == 0);
        }

        let encoded = bv.encode();
        let decoded = BitVec::decode_cfg(&mut encoded.as_ref(), &(..).into()).unwrap();
        assert_eq!(bv, decoded);
        assert_eq!(decoded.len(), 32);

        // Test bitvec with partial chunk
        let mut bv2: BitVec<4> = BitVec::new();
        for i in 0..35 {
            // 32 + 3 bits
            bv2.append(i % 3 == 0);
        }

        let encoded2 = bv2.encode();
        let decoded2 = BitVec::decode_cfg(&mut encoded2.as_ref(), &(..).into()).unwrap();
        assert_eq!(bv2, decoded2);
        assert_eq!(decoded2.len(), 35);
    }

    #[test]
    fn test_encode_size() {
        // Test encode size calculation
        let bv: BitVec<4> = BitVec::new();
        let encoded = bv.encode();
        assert_eq!(bv.encode_size(), encoded.len());

        // Test with some data
        let pattern = [true, false, true, false, true];
        let bv: BitVec<4> = pattern.as_ref().into();
        let encoded = bv.encode();
        assert_eq!(bv.encode_size(), encoded.len());

        // Test with larger data
        let mut large_bv: BitVec<8> = BitVec::new();
        for i in 0..100 {
            large_bv.append(i % 2 == 0);
        }
        let encoded = large_bv.encode();
        assert_eq!(large_bv.encode_size(), encoded.len());
    }

    #[test]
    fn test_codec_error_cases() {
        use bytes::BytesMut;

        // Test invalid next_bit (too large)
        let mut buf = BytesMut::new();
        5u64.write(&mut buf); // bits length
        100u64.write(&mut buf); // next_bit (invalid for chunk size 4 = 32 bits max)

        let result = BitVec::<4>::decode_cfg(&mut buf, &(..).into());
        assert!(matches!(
            result,
            Err(CodecError::Invalid("BitVec", "next_bit out of bounds"))
        ));

        // Test inconsistent bits length and next_bit
        let mut buf = BytesMut::new();
        10u64.write(&mut buf); // bits length
        5u64.write(&mut buf); // next_bit
                              // This would imply 5 bits in first chunk, but bit length says 10
        [0u8; 4].write(&mut buf); // One chunk

        let result = BitVec::<4>::decode_cfg(&mut buf, &(..).into());
        assert!(matches!(
            result,
            Err(CodecError::Invalid(
                "BitVec",
                "inconsistent bits length and next_bit"
            ))
        ));
    }

    #[test]
    fn test_from_bool_slice() {
        // Test From trait with different input types

        // Test with Vec<bool>
        let vec_bool = vec![true, false, true, false, true];
        let bv: BitVec<4> = vec_bool.into();
        assert_eq!(bv.len(), 5);
        assert_eq!(bv.count_ones(), 3);
        assert_eq!(bv.count_zeros(), 2);
        for (i, &expected) in [true, false, true, false, true].iter().enumerate() {
            assert_eq!(bv.get_bit(i as u64), expected);
        }

        // Test with array slice
        let array = [false, true, true, false];
        let bv: BitVec<4> = (&array).into();
        assert_eq!(bv.len(), 4);
        assert_eq!(bv.count_ones(), 2);
        assert_eq!(bv.count_zeros(), 2);
        for (i, &expected) in array.iter().enumerate() {
            assert_eq!(bv.get_bit(i as u64), expected);
        }

        // Test with empty slice
        let empty: Vec<bool> = vec![];
        let bv: BitVec<4> = empty.into();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test with large slice
        let large: Vec<bool> = (0..100).map(|i| i % 3 == 0).collect();
        let bv: BitVec<8> = large.clone().into();
        assert_eq!(bv.len(), 100);
        for (i, &expected) in large.iter().enumerate() {
            assert_eq!(bv.get_bit(i as u64), expected);
        }
    }

    #[test]
    fn test_debug_formatting() {
        // Test Debug formatting for different sizes

        // Test empty bitvec
        let bv: BitVec<4> = BitVec::new();
        let debug_str = format!("{bv:?}");
        assert_eq!(debug_str, "BitVec[]");

        // Test small bitvec (should show all bits)
        let bv: BitVec<4> = [true, false, true, false, true].as_ref().into();
        let debug_str = format!("{bv:?}");
        assert_eq!(debug_str, "BitVec[10101]");

        // Test bitvec at the display limit (64 bits)
        let pattern: Vec<bool> = (0..64).map(|i| i % 2 == 0).collect();
        let bv: BitVec<8> = pattern.into();
        let debug_str = format!("{bv:?}");
        let expected_pattern = "1010".repeat(16); // 64 bits alternating
        assert_eq!(debug_str, format!("BitVec[{expected_pattern}]"));

        // Test large bitvec (should show ellipsis)
        let large_pattern: Vec<bool> = (0..100).map(|i| i % 2 == 0).collect();
        let bv: BitVec<16> = large_pattern.into();
        let debug_str = format!("{bv:?}");

        // Should show first 32 bits + "..." + last 32 bits
        let first_32 = "10".repeat(16); // First 32 bits: 1010...
        let last_32 = "10".repeat(16); // Last 32 bits: ...1010
        let expected = format!("BitVec[{first_32}...{last_32}]");
        assert_eq!(debug_str, expected);
    }

    #[test]
    fn test_debug_edge_cases() {
        // Test single bit
        let bv: BitVec<4> = [true].as_ref().into();
        assert_eq!(format!("{bv:?}"), "BitVec[1]");

        let bv: BitVec<4> = [false].as_ref().into();
        assert_eq!(format!("{bv:?}"), "BitVec[0]");

        // Test exactly at boundary (65 bits - should show ellipsis)
        let pattern: Vec<bool> = (0..65).map(|i| i == 0 || i == 64).collect(); // First and last bits are true
        let bv: BitVec<16> = pattern.into();
        let debug_str = format!("{bv:?}");

        // Should show first 32 bits (100000...) + "..." + last 32 bits (...000001)
        let first_32 = "1".to_string() + &"0".repeat(31);
        let last_32 = "0".repeat(31) + "1";
        let expected = format!("BitVec[{first_32}...{last_32}]");
        assert_eq!(debug_str, expected);
    }

    #[test]
    fn test_from_different_chunk_sizes() {
        // Test From trait works with different chunk sizes
        let pattern = [true, false, true, true, false, false, true];

        let bv4: BitVec<4> = pattern.as_ref().into();
        let bv8: BitVec<8> = pattern.as_ref().into();
        let bv16: BitVec<16> = pattern.as_ref().into();

        // All should have the same content regardless of chunk size
        // Test each bitvec separately since they have different types
        for bv in [&bv4] {
            assert_eq!(bv.len(), 7);
            assert_eq!(bv.count_ones(), 4);
            assert_eq!(bv.count_zeros(), 3);
            for (i, &expected) in pattern.iter().enumerate() {
                assert_eq!(bv.get_bit(i as u64), expected);
            }
        }

        assert_eq!(bv8.len(), 7);
        assert_eq!(bv8.count_ones(), 4);
        assert_eq!(bv8.count_zeros(), 3);
        for (i, &expected) in pattern.iter().enumerate() {
            assert_eq!(bv8.get_bit(i as u64), expected);
        }

        assert_eq!(bv16.len(), 7);
        assert_eq!(bv16.count_ones(), 4);
        assert_eq!(bv16.count_zeros(), 3);
        for (i, &expected) in pattern.iter().enumerate() {
            assert_eq!(bv16.get_bit(i as u64), expected);
        }
    }

    #[test]
    fn test_prune_front_chunks() {
        // Test basic pruning
        let mut bv: BitVec<4> = BitVec::new();
        bv.append_chunk_unchecked(&[1, 2, 3, 4]);
        bv.append_chunk_unchecked(&[5, 6, 7, 8]);
        bv.append_chunk_unchecked(&[9, 10, 11, 12]);

        assert_eq!(bv.len(), 96);
        assert_eq!(bv.get_chunk_by_index(0), &[1, 2, 3, 4]);

        // Prune first chunk
        bv.prune_chunks(1);
        assert_eq!(bv.len(), 64);
        assert_eq!(bv.get_chunk_by_index(0), &[5, 6, 7, 8]);
        assert_eq!(bv.get_chunk_by_index(1), &[9, 10, 11, 12]);

        // Prune another chunk
        bv.prune_chunks(1);
        assert_eq!(bv.len(), 32);
        assert_eq!(bv.get_chunk_by_index(0), &[9, 10, 11, 12]);
    }

    #[test]
    #[should_panic(expected = "cannot prune")]
    fn test_prune_too_many_chunks() {
        let mut bv: BitVec<4> = BitVec::new();
        bv.append_chunk_unchecked(&[1, 2, 3, 4]);
        bv.append_chunk_unchecked(&[5, 6, 7, 8]);
        bv.append(true);

        // Try to prune 4 chunks when only 3 are available
        bv.prune_chunks(4);
    }

    #[test]
    fn test_prune_with_partial_last_chunk() {
        let mut bv: BitVec<4> = BitVec::new();
        bv.append_chunk_unchecked(&[1, 2, 3, 4]);
        bv.append_chunk_unchecked(&[5, 6, 7, 8]);
        bv.append(true);
        bv.append(false);

        assert_eq!(bv.len(), 66);

        // Can prune first chunk
        bv.prune_chunks(1);
        assert_eq!(bv.len(), 34);
        assert_eq!(bv.get_chunk_by_index(0), &[5, 6, 7, 8]);

        // Last partial chunk still has the appended bits
        assert!(bv.get_bit(32));
        assert!(!bv.get_bit(33));
    }

    #[test]
    fn test_chunks_needed() {
        // Test with different chunk sizes
        assert_eq!(BitVec::<1>::num_chunks_at_size(0).get(), 1);
        assert_eq!(BitVec::<1>::num_chunks_at_size(1).get(), 1);
        assert_eq!(BitVec::<1>::num_chunks_at_size(8).get(), 2);
        assert_eq!(BitVec::<1>::num_chunks_at_size(9).get(), 2);
        assert_eq!(BitVec::<1>::num_chunks_at_size(16).get(), 3);
        assert_eq!(BitVec::<1>::num_chunks_at_size(17).get(), 3);

        assert_eq!(BitVec::<3>::num_chunks_at_size(0).get(), 1);
        assert_eq!(BitVec::<3>::num_chunks_at_size(1).get(), 1);
        assert_eq!(BitVec::<3>::num_chunks_at_size(23).get(), 1);
        assert_eq!(BitVec::<3>::num_chunks_at_size(24).get(), 2);
        assert_eq!(BitVec::<3>::num_chunks_at_size(25).get(), 2);
        assert_eq!(BitVec::<3>::num_chunks_at_size(48).get(), 3);
        assert_eq!(BitVec::<3>::num_chunks_at_size(49).get(), 3);

        assert_eq!(BitVec::<4>::num_chunks_at_size(0).get(), 1);
        assert_eq!(BitVec::<4>::num_chunks_at_size(1).get(), 1);
        assert_eq!(BitVec::<4>::num_chunks_at_size(31).get(), 1);
        assert_eq!(BitVec::<4>::num_chunks_at_size(32).get(), 2);
        assert_eq!(BitVec::<4>::num_chunks_at_size(33).get(), 2);
        assert_eq!(BitVec::<4>::num_chunks_at_size(63).get(), 2);
        assert_eq!(BitVec::<4>::num_chunks_at_size(64).get(), 3);
        assert_eq!(BitVec::<4>::num_chunks_at_size(65).get(), 3);
    }
}

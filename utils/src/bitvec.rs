//! Bit-vector implementation
//!
//! The bit-vector is a compact representation of a sequence of bits, using [u8] "blocks" for a
//! more-efficient memory layout than doing a [`Vec<bool>`]. Thus, if the length of the bit-vector
//! is not a multiple of 8, the last block will contain some bits that are not part of the vector.
//! An invariant of the implementation is that any bits in the last block that are not part of the
//! vector are set to 0.
//!
//! The implementation is focused on being compact when encoding small bit vectors, so [u8] is
//! used over more performant types like [usize] or [u64]. Such types would result in more
//! complex encoding and decoding logic.

#[cfg(not(feature = "std"))]
use alloc::{collections::VecDeque, vec, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use core::{
    fmt::{self, Formatter, Write as _},
    ops::{BitAnd, BitOr, BitXor, Index},
};
#[cfg(feature = "std")]
use std::collections::VecDeque;

/// Type alias for the underlying block type.
type Block = u8;

/// Number of bits in a [Block].
const BITS_PER_BLOCK: usize = Block::BITS as usize;

/// Empty block of bits (all bits set to 0).
const EMPTY_BLOCK: Block = 0;

/// Full block of bits (all bits set to 1).
const FULL_BLOCK: Block = Block::MAX;

/// Represents a vector of bits.
///
/// Stores bits using [u8] blocks for efficient storage.
#[derive(Clone, PartialEq, Eq)]
pub struct BitVec {
    /// The underlying storage for the bits.
    storage: Vec<Block>,
    /// The total number of bits
    num_bits: usize,
}

impl BitVec {
    /// Creates a new, empty `BitVec`.
    #[inline]
    pub fn new() -> Self {
        BitVec {
            storage: Vec::new(),
            num_bits: 0,
        }
    }

    /// Creates a new `BitVec` with the specified capacity in bits.
    #[inline]
    pub fn with_capacity(size: usize) -> Self {
        BitVec {
            storage: Vec::with_capacity(Self::num_blocks(size)),
            num_bits: 0,
        }
    }

    /// Creates a new `BitVec` with `size` bits, all initialized to zero.
    #[inline]
    pub fn zeroes(size: usize) -> Self {
        BitVec {
            storage: vec![EMPTY_BLOCK; Self::num_blocks(size)],
            num_bits: size,
        }
    }

    /// Creates a new `BitVec` with `size` bits, all initialized to one.
    #[inline]
    pub fn ones(size: usize) -> Self {
        let mut result = Self {
            storage: vec![FULL_BLOCK; Self::num_blocks(size)],
            num_bits: size,
        };
        result.clear_trailing_bits();
        result
    }

    /// Returns the number of bits in the vector.
    #[inline]
    pub fn len(&self) -> usize {
        self.num_bits
    }

    /// Returns true if the vector contains no bits.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.num_bits == 0
    }

    /// Appends a bit to the end of the vector.
    #[inline]
    pub fn push(&mut self, value: bool) {
        // Increment the number of bits and get the index for the new bit
        let index = self.num_bits;
        self.num_bits += 1;

        // Ensure the storage has enough blocks to hold the new bit
        if Self::block_index(index) >= self.storage.len() {
            self.storage.push(EMPTY_BLOCK);
        }

        // Set the bit
        if value {
            self.set_bit_unchecked(index);
        }
    }

    /// Removes the last bit from the vector and returns it.
    ///
    /// Returns `None` if the vector is empty.
    #[inline]
    pub fn pop(&mut self) -> Option<bool> {
        if self.is_empty() {
            return None;
        }

        // Decrement the number of bits and get the value of the last bit
        self.num_bits -= 1;
        let index = self.num_bits;
        let value = self.get_bit_unchecked(index);

        // If that was the last bit in the block, drop the block;
        // otherwise, if the bit was 1, we need to clear it
        if Self::bit_offset(index) == 0 {
            self.storage.pop().expect("Storage should not be empty");
        } else if value {
            self.clear_bit_unchecked(index);
        }

        Some(value)
    }

    /// Gets the value of the bit at `index` (true if 1, false if 0).
    ///
    /// Returns `None` if the index is out of bounds.
    #[inline]
    pub fn get(&self, index: usize) -> Option<bool> {
        if index >= self.num_bits {
            return None;
        }
        Some(self.get_bit_unchecked(index))
    }

    /// Gets the value of the bit at the specified index without bounds checking.
    ///
    /// # Safety
    ///
    /// Caller must ensure `index` is less than the length of the BitVec.
    #[inline]
    pub unsafe fn get_unchecked(&self, index: usize) -> bool {
        self.get_bit_unchecked(index)
    }

    /// Sets the bit at `index` to 1.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn set(&mut self, index: usize) {
        self.assert_index(index);
        self.set_bit_unchecked(index);
    }

    /// Sets the bit at `index` to 0.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn clear(&mut self, index: usize) {
        self.assert_index(index);
        self.clear_bit_unchecked(index);
    }

    /// Flips the bit at `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn toggle(&mut self, index: usize) {
        self.assert_index(index);
        self.toggle_bit_unchecked(index);
    }

    /// Sets the bit at `index` to the specified `value`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn set_to(&mut self, index: usize, value: bool) {
        self.assert_index(index);
        if value {
            self.set_bit_unchecked(index);
        } else {
            self.clear_bit_unchecked(index);
        }
    }

    /// Sets all bits to 0.
    #[inline]
    pub fn clear_all(&mut self) {
        for block in &mut self.storage {
            *block = EMPTY_BLOCK;
        }
    }

    /// Sets all bits to 1.
    #[inline]
    pub fn set_all(&mut self) {
        for block in &mut self.storage {
            *block = FULL_BLOCK;
        }
        self.clear_trailing_bits();
    }

    /// Returns the number of bits set to 1.
    #[inline]
    pub fn count_ones(&self) -> usize {
        self.storage
            .iter()
            .map(|block| block.count_ones() as usize)
            .sum()
    }

    /// Returns the number of bits set to 0.
    #[inline]
    pub fn count_zeros(&self) -> usize {
        self.num_bits
            .checked_sub(self.count_ones())
            .expect("Overflow in count_zeros")
    }

    /// Performs a bitwise AND with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn and(&mut self, other: &BitVec) {
        self.binary_op(other, |a, b| a & b);
        self.clear_trailing_bits();
    }

    /// Performs a bitwise OR with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn or(&mut self, other: &BitVec) {
        self.binary_op(other, |a, b| a | b);
        self.clear_trailing_bits();
    }

    /// Performs a bitwise XOR with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn xor(&mut self, other: &BitVec) {
        self.binary_op(other, |a, b| a ^ b);
        self.clear_trailing_bits();
    }

    /// Flips all bits (1s become 0s and vice versa).
    pub fn invert(&mut self) {
        for block in &mut self.storage {
            *block = !*block;
        }
        self.clear_trailing_bits();
    }

    /// Creates an iterator over the bits.
    pub fn iter(&self) -> BitIterator<'_> {
        BitIterator { vec: self, pos: 0 }
    }

    // ---------- Helper Functions ----------

    /// Calculates the block index for a given bit index.
    #[inline(always)]
    fn block_index(index: usize) -> usize {
        index / BITS_PER_BLOCK
    }

    /// Calculates the bit offset within a block.
    #[inline(always)]
    fn bit_offset(index: usize) -> usize {
        index % BITS_PER_BLOCK
    }

    /// Calculates the number of blocks needed to store `num_bits`.
    #[inline(always)]
    fn num_blocks(num_bits: usize) -> usize {
        num_bits.div_ceil(BITS_PER_BLOCK)
    }

    /// Creates a mask with the first `num_bits` bits set to 1.
    #[inline(always)]
    fn mask_over_first_n_bits(num_bits: usize) -> Block {
        match num_bits {
            BITS_PER_BLOCK => FULL_BLOCK,
            n if n < BITS_PER_BLOCK => FULL_BLOCK.unbounded_shr((BITS_PER_BLOCK - n) as u32),
            _ => panic!("num_bits exceeds block size: {num_bits}"),
        }
    }

    #[inline(always)]
    fn get_bit_unchecked(&self, index: usize) -> bool {
        let block_index = Self::block_index(index);
        let bit_index = Self::bit_offset(index);
        (self.storage[block_index] & (1 << bit_index)) != 0
    }

    #[inline(always)]
    fn set_bit_unchecked(&mut self, index: usize) {
        let block_index = Self::block_index(index);
        let bit_index = Self::bit_offset(index);
        self.storage[block_index] |= 1 << bit_index;
    }

    #[inline(always)]
    fn clear_bit_unchecked(&mut self, index: usize) {
        let block_index = Self::block_index(index);
        let bit_index = Self::bit_offset(index);
        self.storage[block_index] &= !(1 << bit_index);
    }

    #[inline(always)]
    fn toggle_bit_unchecked(&mut self, index: usize) {
        let block_index = Self::block_index(index);
        let bit_index = Self::bit_offset(index);
        self.storage[block_index] ^= 1 << bit_index;
    }

    /// Asserts that the index is within bounds.
    #[inline(always)]
    fn assert_index(&self, index: usize) {
        assert!(index < self.num_bits, "Index out of bounds");
    }

    /// Asserts that the lengths of two BitVecs match.
    #[inline(always)]
    fn assert_eq_len(&self, other: &BitVec) {
        assert_eq!(self.num_bits, other.num_bits, "BitVec lengths don't match");
    }

    /// Helper for binary operations (AND, OR, XOR)
    #[inline]
    fn binary_op<F: Fn(Block, Block) -> Block>(&mut self, other: &BitVec, op: F) {
        self.assert_eq_len(other);
        for (a, b) in self.storage.iter_mut().zip(other.storage.iter()) {
            *a = op(*a, *b);
        }
    }

    /// Clears any bits in storage beyond the last valid bit. Returns true if any bits were cleared.
    #[inline]
    fn clear_trailing_bits(&mut self) -> bool {
        let bit_offset = Self::bit_offset(self.num_bits);
        if bit_offset == 0 {
            // No extra bits to clear
            return false;
        }

        // Clear the bits in the last block
        let block = self
            .storage
            .last_mut()
            .expect("Storage should not be empty");
        let old_block = *block;
        let mask = Self::mask_over_first_n_bits(bit_offset);
        *block &= mask;

        // Check if the last block was modified
        *block != old_block
    }
}

// ---------- Constructors ----------

impl Default for BitVec {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: AsRef<[bool]>> From<T> for BitVec {
    fn from(t: T) -> Self {
        let bools = t.as_ref();
        let mut bv = Self::with_capacity(bools.len());
        for &b in bools {
            bv.push(b);
        }
        bv
    }
}

// ---------- Converters ----------

impl From<BitVec> for Vec<bool> {
    fn from(bv: BitVec) -> Self {
        bv.iter().collect()
    }
}

// ---------- Debug ----------

impl fmt::Debug for BitVec {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // For very large BitVecs, only show a preview
        const MAX_DISPLAY: usize = 64;
        const HALF_DISPLAY: usize = MAX_DISPLAY / 2;

        // Closure for writing a bit
        let write_bit = |formatter: &mut Formatter<'_>, index: usize| -> core::fmt::Result {
            formatter.write_char(if self.get_bit_unchecked(index) {
                '1'
            } else {
                '0'
            })
        };

        f.write_str("BitVec[")?;
        if self.num_bits <= MAX_DISPLAY {
            // Show all bits
            for i in 0..self.num_bits {
                write_bit(f, i)?;
            }
        } else {
            // Show first and last bits with ellipsis
            for i in 0..HALF_DISPLAY {
                write_bit(f, i)?;
            }

            f.write_str("...")?;

            for i in (self.num_bits - HALF_DISPLAY)..self.num_bits {
                write_bit(f, i)?;
            }
        }
        f.write_str("]")
    }
}

// ---------- Operations ----------

impl Index<usize> for BitVec {
    type Output = bool;

    /// Allows accessing bits using the `[]` operator.
    ///
    /// Panics if out of bounds.
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.assert_index(index);
        let value = self.get_bit_unchecked(index);
        if value {
            &true
        } else {
            &false
        }
    }
}

impl BitAnd for &BitVec {
    type Output = BitVec;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.and(rhs);
        result
    }
}

impl BitOr for &BitVec {
    type Output = BitVec;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.or(rhs);
        result
    }
}

impl BitXor for &BitVec {
    type Output = BitVec;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.xor(rhs);
        result
    }
}

// ---------- Codec ----------

impl Write for BitVec {
    fn write(&self, buf: &mut impl BufMut) {
        // Prefix with the number of bits, which is generally larger than the length of the storage
        self.num_bits.write(buf);

        // Write full blocks
        for &block in &self.storage {
            block.write(buf);
        }
    }
}

impl Read for BitVec {
    type Cfg = RangeCfg;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        // Parse length
        let num_bits = usize::read_cfg(buf, range)?;

        // Parse blocks
        let num_blocks = num_bits.div_ceil(BITS_PER_BLOCK);
        let mut storage = Vec::with_capacity(num_blocks);
        for _ in 0..num_blocks {
            let block = Block::read(buf)?;
            storage.push(block);
        }

        // Ensure there were no trailing bits
        let mut result = BitVec { storage, num_bits };
        if result.clear_trailing_bits() {
            return Err(CodecError::Invalid("BitVec", "trailing bits"));
        }

        Ok(result)
    }
}

impl EncodeSize for BitVec {
    fn encode_size(&self) -> usize {
        self.num_bits.encode_size() + (Block::SIZE * self.storage.len())
    }
}

// ---------- Iterator ----------

/// Iterator over bits in a BitVec
pub struct BitIterator<'a> {
    /// Reference to the BitVec being iterated over
    vec: &'a BitVec,

    /// Current position in the BitVec (0-indexed)
    pos: usize,
}

impl Iterator for BitIterator<'_> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.vec.len() {
            return None;
        }

        let bit = self.vec.get_bit_unchecked(self.pos);
        self.pos += 1;
        Some(bit)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.vec.len() - self.pos;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for BitIterator<'_> {}

/// A bitmap that stores data in chunks of N bytes.
#[derive(Clone, Debug)]
pub struct Bitvec2<const N: usize> {
    /// The bitmap itself, in chunks of size N bytes. The number of valid bits in the last chunk is
    /// given by `self.next_bit`. Within each byte, lowest order bits are treated as coming before
    /// higher order bits in the bit ordering.
    ///
    /// Invariant: The last chunk in the bitmap always has room for at least one more bit. This
    /// implies there is always at least one chunk in the bitmap, it's just empty if no bits have
    /// been added yet.
    bitmap: VecDeque<[u8; N]>,

    /// The position within the last chunk of the bitmap where the next bit is to be appended.
    ///
    /// Invariant: This value is always in the range [0, N * 8).
    next_bit: u64,
}

impl<const N: usize> Bitvec2<N> {
    /// The size of a chunk in bytes.
    pub const CHUNK_SIZE: usize = N;

    /// The size of a chunk in bits.
    pub const CHUNK_SIZE_BITS: u64 = N as u64 * 8;

    /// Create a new empty bitmap.
    pub fn new() -> Self {
        let bitmap = VecDeque::from([[0u8; N]]);
        Self {
            bitmap,
            next_bit: 0,
        }
    }

    /// Return the number of bits currently stored in the bitmap.
    #[inline]
    pub fn bit_count(&self) -> u64 {
        self.bitmap.len() as u64 * Self::CHUNK_SIZE_BITS - Self::CHUNK_SIZE_BITS + self.next_bit
    }

    /// Return the last chunk of the bitmap and its size in bits. The size can be 0 (meaning the
    /// last chunk is empty).
    #[inline]
    pub fn last_chunk(&self) -> (&[u8; N], u64) {
        (self.bitmap.back().unwrap(), self.next_bit)
    }

    /// Return the last chunk of the bitmap as a mutable slice.
    #[inline]
    fn last_chunk_mut(&mut self) -> &mut [u8] {
        self.bitmap.back_mut().unwrap()
    }

    /// Returns the bitmap chunk containing the specified bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    #[inline]
    pub fn get_chunk(&self, bit_offset: u64) -> &[u8; N] {
        &self.bitmap[self.chunk_index(bit_offset)]
    }

    /// Get the value of a bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    #[inline]
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        Self::get_bit_from_chunk(self.get_chunk(bit_offset), bit_offset)
    }

    /// Get the value of a bit from its chunk.
    #[inline]
    pub fn get_bit_from_chunk(chunk: &[u8; N], bit_offset: u64) -> bool {
        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let byte = chunk[byte_offset];
        let mask = Self::chunk_byte_bitmask(bit_offset);

        (byte & mask) != 0
    }

    /// Add a single bit to the bitmap.
    pub fn append(&mut self, bit: bool) {
        if bit {
            let chunk_byte = (self.next_bit / 8) as usize;
            self.last_chunk_mut()[chunk_byte] |= Self::chunk_byte_bitmask(self.next_bit);
        }
        self.next_bit += 1;
        assert!(self.next_bit <= Self::CHUNK_SIZE_BITS);

        if self.next_bit == Self::CHUNK_SIZE_BITS {
            self.prepare_next_chunk();
        }
    }

    /// Efficiently add a byte's worth of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// Assumes self.next_bit is currently byte aligned, and panics otherwise.
    pub fn append_byte_unchecked(&mut self, byte: u8) {
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
    /// Assumes we are at a chunk boundary (that is, `self.next_bit` is 0) and panics otherwise.
    pub fn append_chunk_unchecked(&mut self, chunk: &[u8; N]) {
        assert!(
            self.next_bit == 0,
            "cannot add chunk when not chunk aligned"
        );

        self.last_chunk_mut().copy_from_slice(chunk.as_ref());
        self.prepare_next_chunk();
    }

    /// Set the value of the referenced bit.
    pub fn set_bit(&mut self, bit_offset: u64, bit: bool) {
        let chunk_index = self.chunk_index(bit_offset);
        let chunk = &mut self.bitmap[chunk_index];

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
    pub(crate) fn prepare_next_chunk(&mut self) {
        self.next_bit = 0;
        self.bitmap.push_back([0u8; N]);
    }

    /// Convert a bit offset into a bitmask for the byte containing that bit.
    #[inline]
    pub(crate) fn chunk_byte_bitmask(bit_offset: u64) -> u8 {
        1 << (bit_offset % 8)
    }

    /// Convert a bit offset into the offset of the byte within a chunk containing the bit.
    #[inline]
    pub(crate) fn chunk_byte_offset(bit_offset: u64) -> usize {
        (bit_offset / 8) as usize % Self::CHUNK_SIZE
    }

    /// Convert a bit offset into the index of the chunk it belongs to within self.bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist.
    #[inline]
    pub(crate) fn chunk_index(&self, bit_offset: u64) -> usize {
        assert!(bit_offset < self.bit_count(), "out of bounds: {bit_offset}");
        Self::chunk_num(bit_offset)
    }

    /// Convert a bit offset into the number of the chunk it belongs to.
    #[inline]
    pub(crate) fn chunk_num(bit_offset: u64) -> usize {
        (bit_offset / Self::CHUNK_SIZE_BITS) as usize
    }

    /// Get the number of chunks in the bitmap
    pub fn len(&self) -> usize {
        self.bitmap.len()
    }

    /// Returns true if the bitmap is empty.
    pub fn is_empty(&self) -> bool {
        self.bit_count() == 0
    }

    /// Get a reference to a chunk by its index in the current bitmap
    pub fn get_chunk_by_index(&self, index: usize) -> &[u8; N] {
        &self.bitmap[index]
    }

    /// Flips the bit at `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn toggle(&mut self, index: u64) {
        self.assert_index(index);
        self.toggle_bit_unchecked(index);
    }

    /// Sets all bits to 0.
    #[inline]
    pub fn clear_all(&mut self) {
        for chunk in &mut self.bitmap {
            chunk.fill(0u8);
        }
    }

    /// Sets all bits to 1.
    #[inline]
    pub fn set_all(&mut self) {
        for chunk in &mut self.bitmap {
            chunk.fill(u8::MAX);
        }
        self.clear_trailing_bits();
    }

    /// Returns the number of bits set to 1.
    #[inline]
    pub fn count_ones(&self) -> usize {
        let mut count = 0;
        for (i, chunk) in self.bitmap.iter().enumerate() {
            if i == self.bitmap.len() - 1 {
                // For the last chunk, only count bits up to next_bit
                let bytes_to_count = (self.next_bit + 7) / 8; // Round up to nearest byte
                for byte_idx in 0..bytes_to_count as usize {
                    if byte_idx < chunk.len() {
                        if byte_idx == (bytes_to_count - 1) as usize && self.next_bit % 8 != 0 {
                            // For the last byte, only count bits up to next_bit % 8
                            let bits_in_last_byte = self.next_bit % 8;
                            let mask = (1u8 << bits_in_last_byte) - 1;
                            count += (chunk[byte_idx] & mask).count_ones() as usize;
                        } else {
                            count += chunk[byte_idx].count_ones() as usize;
                        }
                    }
                }
            } else {
                // For all other chunks, count all bits
                for byte in chunk {
                    count += byte.count_ones() as usize;
                }
            }
        }
        count
    }

    /// Returns the number of bits set to 0.
    #[inline]
    pub fn count_zeros(&self) -> usize {
        self.bit_count() as usize - self.count_ones()
    }

    /// Performs a bitwise AND with another Bitvec2.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn and(&mut self, other: &Bitvec2<N>) {
        self.binary_op(other, |a, b| a & b);
        self.clear_trailing_bits();
    }

    /// Performs a bitwise OR with another Bitvec2.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn or(&mut self, other: &Bitvec2<N>) {
        self.binary_op(other, |a, b| a | b);
        self.clear_trailing_bits();
    }

    /// Performs a bitwise XOR with another Bitvec2.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn xor(&mut self, other: &Bitvec2<N>) {
        self.binary_op(other, |a, b| a ^ b);
        self.clear_trailing_bits();
    }

    /// Flips all bits (1s become 0s and vice versa).
    pub fn invert(&mut self) {
        for chunk in &mut self.bitmap {
            for byte in chunk {
                *byte = !*byte;
            }
        }
        self.clear_trailing_bits();
    }

    // ---------- Helper Functions ----------

    /// Flips the bit at the specified index without bounds checking.
    #[inline(always)]
    fn toggle_bit_unchecked(&mut self, index: u64) {
        let chunk_index = Self::chunk_num(index);
        let byte_offset = Self::chunk_byte_offset(index);
        let mask = Self::chunk_byte_bitmask(index);
        self.bitmap[chunk_index][byte_offset] ^= mask;
    }

    /// Asserts that the index is within bounds.
    #[inline(always)]
    fn assert_index(&self, index: u64) {
        assert!(index < self.bit_count(), "Index out of bounds");
    }

    /// Asserts that the lengths of two Bitvec2s match.
    #[inline(always)]
    fn assert_eq_len(&self, other: &Bitvec2<N>) {
        assert_eq!(
            self.bit_count(),
            other.bit_count(),
            "Bitvec2 lengths don't match"
        );
    }

    /// Helper for binary operations (AND, OR, XOR)
    #[inline]
    fn binary_op<F: Fn(u8, u8) -> u8>(&mut self, other: &Bitvec2<N>, op: F) {
        self.assert_eq_len(other);
        for (a_chunk, b_chunk) in self.bitmap.iter_mut().zip(other.bitmap.iter()) {
            for (a_byte, b_byte) in a_chunk.iter_mut().zip(b_chunk.iter()) {
                *a_byte = op(*a_byte, *b_byte);
            }
        }
    }

    /// Clears any bits in storage beyond the last valid bit. Returns true if any bits were cleared.
    #[inline]
    fn clear_trailing_bits(&mut self) -> bool {
        if self.next_bit == 0 {
            // No extra bits to clear
            return false;
        }

        let last_chunk = self.bitmap.back_mut().unwrap();
        let mut cleared = false;

        // Clear bits in the last byte that are beyond next_bit
        let last_byte_index = ((self.next_bit - 1) / 8) as usize;
        let bits_in_last_byte = self.next_bit % 8;

        if bits_in_last_byte != 0 {
            let mask = (1u8 << bits_in_last_byte) - 1;
            let old_byte = last_chunk[last_byte_index];
            last_chunk[last_byte_index] &= mask;
            if old_byte != last_chunk[last_byte_index] {
                cleared = true;
            }
        }

        // Clear all bytes after the last byte with valid bits
        for i in (last_byte_index + 1)..N {
            if last_chunk[i] != 0 {
                last_chunk[i] = 0;
                cleared = true;
            }
        }

        cleared
    }
}

impl<const N: usize> Default for Bitvec2<N> {
    fn default() -> Self {
        Self::new()
    }
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use commonware_codec::{Decode, Encode};

    #[test]
    fn test_constructors() {
        // Test new()
        let bv = BitVec::new();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert_eq!(bv.storage.len(), 0);

        // Test with_capacity()
        let bv = BitVec::with_capacity(100);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert!(bv.storage.capacity() >= BitVec::num_blocks(100));

        // Test zeroes()
        let bv = BitVec::zeroes(100);
        assert_eq!(bv.len(), 100);
        assert!(!bv.is_empty());
        assert_eq!(bv.count_zeros(), 100);
        for i in 0..100 {
            assert!(!bv.get(i).unwrap());
        }

        // Test ones()
        let bv = BitVec::ones(100);
        assert_eq!(bv.len(), 100);
        assert!(!bv.is_empty());
        assert_eq!(bv.count_ones(), 100);
        for i in 0..100 {
            assert!(bv.get(i).unwrap());
        }

        // Test From()
        let bools = [true, false, true, false, true];
        let bv = BitVec::from(&bools);
        assert_eq!(bv.len(), 5);
        assert_eq!(bv.count_ones(), 3);

        // Test From trait implementations
        let vec_bool = vec![true, false, true];
        let bv: BitVec = vec_bool.into();
        assert_eq!(bv.len(), 3);
        assert_eq!(bv.count_ones(), 2);

        let bools_slice = [false, true, false];
        let bv: BitVec = bools_slice.into();
        assert_eq!(bv.len(), 3);
        assert_eq!(bv.count_ones(), 1);

        // Test Default trait
        let bv: BitVec = Default::default();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
    }

    #[test]
    fn test_basic_operations() {
        let mut bv = BitVec::zeroes(100);

        // Test initial state
        for i in 0..100 {
            assert_eq!(bv.get(i), Some(false));
        }

        // Test set
        bv.set(0);
        bv.set(50);
        bv.set(63); // Last bit in first block
        bv.set(64); // First bit in second block
        bv.set(99); // Last bit

        assert_eq!(bv.get(0), Some(true));
        assert_eq!(bv.get(50), Some(true));
        assert_eq!(bv.get(63), Some(true));
        assert_eq!(bv.get(64), Some(true));
        assert_eq!(bv.get(99), Some(true));
        assert_eq!(bv.get(30), Some(false));

        // Test clear
        bv.clear(0);
        bv.clear(50);
        bv.clear(64);

        assert_eq!(bv.get(0), Some(false));
        assert_eq!(bv.get(50), Some(false));
        assert_eq!(bv.get(63), Some(true));
        assert_eq!(bv.get(64), Some(false));
        assert_eq!(bv.get(99), Some(true));

        // Test toggle
        bv.toggle(0); // false -> true
        bv.toggle(63); // true -> false

        assert_eq!(bv.get(0), Some(true));
        assert_eq!(bv.get(63), Some(false));

        // Test toggle again
        bv.toggle(0);
        assert!(!bv.get(0).unwrap());
        bv.toggle(0);
        assert!(bv.get(0).unwrap());

        // Test set_to
        bv.set_to(10, true);
        bv.set_to(11, false);

        assert_eq!(bv.get(10), Some(true));
        assert_eq!(bv.get(11), Some(false));

        // Test push and pop
        bv.push(true);
        assert_eq!(bv.len(), 101);
        assert!(bv.get(100).unwrap());

        bv.push(false);
        assert_eq!(bv.len(), 102);
        assert!(!bv.get(101).unwrap());

        assert_eq!(bv.pop(), Some(false));
        assert_eq!(bv.len(), 101);
        assert_eq!(bv.pop(), Some(true));
        assert_eq!(bv.len(), 100);

        // Test out of bounds
        assert_eq!(bv.get(100), None);
        assert_eq!(bv.get(1000), None);
    }

    #[test]
    fn test_conversions() {
        // Test conversion from/to Vec<bool>
        let original = vec![true, false, true];
        let bv: BitVec = original.clone().into();
        assert_eq!(bv.len(), 3);
        assert_eq!(bv.count_ones(), 2);

        let converted: Vec<bool> = bv.into();
        assert_eq!(converted.len(), 3);
        assert_eq!(converted, original);
    }

    #[test]
    fn test_bitwise_operations() {
        // Create test bitvecs
        let a = BitVec::from(&[true, false, true, false, true]);
        let b = BitVec::from(&[true, true, false, false, true]);

        // Test AND
        let mut result = a.clone();
        result.and(&b);
        assert_eq!(result, BitVec::from(&[true, false, false, false, true]));

        // Test OR
        let mut result = a.clone();
        result.or(&b);
        assert_eq!(result, BitVec::from(&[true, true, true, false, true]));

        // Test XOR
        let mut result = a.clone();
        result.xor(&b);
        assert_eq!(result, BitVec::from(&[false, true, true, false, false]));

        // Test INVERT
        let mut result = a.clone();
        result.invert();
        assert_eq!(result, BitVec::from(&[false, true, false, true, false]));

        // Test operator overloads
        let a_ref = &a;
        let b_ref = &b;

        let result = a_ref & b_ref;
        assert_eq!(result, BitVec::from(&[true, false, false, false, true]));

        let result = a_ref | b_ref;
        assert_eq!(result, BitVec::from(&[true, true, true, false, true]));

        let result = a_ref ^ b_ref;
        assert_eq!(result, BitVec::from(&[false, true, true, false, false]));

        // Test multi-block bitwise operations
        let mut bv_long1 = BitVec::zeroes(70);
        bv_long1.set(0);
        bv_long1.set(65);

        let mut bv_long2 = BitVec::zeroes(70);
        bv_long2.set(1);
        bv_long2.set(65);

        let mut bv_long_and = bv_long1.clone();
        bv_long_and.and(&bv_long2);
        let mut expected_and = BitVec::zeroes(70);
        expected_and.set(65);
        assert_eq!(bv_long_and, expected_and);
    }

    #[test]
    fn test_out_of_bounds_get() {
        let bv = BitVec::zeroes(10);
        // Test get returns None for out-of-bounds
        assert_eq!(bv.get(10), None);
        assert_eq!(bv.get(100), None);

        // Test empty BitVec
        let empty_bv = BitVec::new();
        assert_eq!(empty_bv.get(0), None);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_set_out_of_bounds() {
        let mut bv = BitVec::zeroes(10);
        bv.set(10);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_clear_out_of_bounds() {
        let mut bv = BitVec::zeroes(10);
        bv.clear(10);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_toggle_out_of_bounds() {
        let mut bv = BitVec::zeroes(10);
        bv.toggle(10);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_set_to_out_of_bounds() {
        let mut bv = BitVec::zeroes(10);
        bv.set_to(10, true);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_index_out_of_bounds() {
        let bv = BitVec::zeroes(10);
        let _ = bv[10];
    }

    #[test]
    fn test_count_operations() {
        // Small BitVec
        let bv = BitVec::from(&[true, false, true, true, false, true]);
        assert_eq!(bv.count_ones(), 4);
        assert_eq!(bv.count_zeros(), 2);

        // Empty BitVec
        let empty = BitVec::new();
        assert_eq!(empty.count_ones(), 0);
        assert_eq!(empty.count_zeros(), 0);

        // Large BitVecs
        let zeroes = BitVec::zeroes(100);
        assert_eq!(zeroes.count_ones(), 0);
        assert_eq!(zeroes.count_zeros(), 100);

        let ones = BitVec::ones(100);
        assert_eq!(ones.count_ones(), 100);
        assert_eq!(ones.count_zeros(), 0);

        // Test across block boundary
        let mut bv_multi = BitVec::zeroes(70);
        bv_multi.set(0);
        bv_multi.set(63); // Last bit in first block
        bv_multi.set(64); // First bit in second block
        bv_multi.set(69);
        assert_eq!(bv_multi.count_ones(), 4);
        assert_eq!(bv_multi.count_zeros(), 66);
    }

    #[test]
    fn test_clear_set_all_invert() {
        // Test on small BitVec
        let mut bv = BitVec::from(&[true, false, true, false, true]); // 5 bits

        // Set all
        bv.set_all();
        assert_eq!(bv.len(), 5);
        assert_eq!(bv.count_ones(), 5);
        for i in 0..5 {
            assert_eq!(bv.get(i), Some(true));
        }
        // Check trailing bits in the block were cleared
        assert_eq!(bv.storage[0], (1 << 5) - 1);

        // Clear all
        bv.clear_all();
        assert_eq!(bv.len(), 5);
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.storage[0], 0);

        // Set some bits and test invert
        bv.set(1);
        bv.set(3); // 01010
        bv.invert(); // Should become 10101
        assert_eq!(bv.count_ones(), 3);
        assert_eq!(bv.get(0), Some(true));
        assert_eq!(bv.get(1), Some(false));
        assert_eq!(bv.get(2), Some(true));
        assert_eq!(bv.get(3), Some(false));
        assert_eq!(bv.get(4), Some(true));

        // Test invert with blocks
        let mut bv_full = BitVec::ones(64);
        bv_full.invert();
        assert_eq!(bv_full.count_ones(), 0);

        let mut bv_part = BitVec::ones(67);
        bv_part.invert();
        assert_eq!(bv_part.count_ones(), 0);
    }

    #[test]
    fn test_mask_over_first_n_bits() {
        // Test with various sizes
        for i in 0..=BITS_PER_BLOCK {
            let mask = BitVec::mask_over_first_n_bits(i);
            let ones = mask.trailing_ones() as usize;
            let zeroes = mask.leading_zeros() as usize;
            assert_eq!(ones, i);
            assert_eq!(ones.checked_add(zeroes).unwrap(), BITS_PER_BLOCK);
            assert_eq!(
                mask,
                ((1 as Block)
                    .checked_shl(i as u32)
                    .unwrap_or(0)
                    .wrapping_sub(1))
            );
        }
    }

    #[test]
    fn test_codec_roundtrip() {
        let original = BitVec::from(&[true, false, true, false, true]);
        let mut buf = original.encode();
        let decoded = BitVec::decode_cfg(&mut buf, &(..).into()).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_codec_error_invalid_length() {
        let original = BitVec::from(&[true, false, true, false, true]);
        let buf = original.encode();

        let mut buf_clone1 = buf.clone();
        assert!(matches!(
            BitVec::decode_cfg(&mut buf_clone1, &(..=4usize).into()),
            Err(CodecError::InvalidLength(_))
        ));

        let mut buf_clone2 = buf.clone();
        assert!(matches!(
            BitVec::decode_cfg(&mut buf_clone2, &(6usize..).into()),
            Err(CodecError::InvalidLength(_))
        ));
    }

    #[test]
    fn test_codec_error_trailing_bits() {
        let mut buf = BytesMut::new();
        1usize.write(&mut buf); // write the bit length as 1
        (2 as Block).write(&mut buf); // set two bits
        assert!(matches!(
            BitVec::decode_cfg(&mut buf, &(..).into()),
            Err(CodecError::Invalid("BitVec", "trailing bits"))
        ));
    }

    #[test]
    fn test_bitvec2_constructors() {
        // Test new()
        let bv: Bitvec2<4> = Bitvec2::new();
        assert_eq!(bv.bit_count(), 0);
        assert!(bv.is_empty());
        assert_eq!(bv.len(), 1); // Always has at least one chunk

        // Test default()
        let bv: Bitvec2<8> = Default::default();
        assert_eq!(bv.bit_count(), 0);
        assert!(bv.is_empty());
    }

    #[test]
    fn test_bitvec2_basic_operations() {
        let mut bv: Bitvec2<4> = Bitvec2::new();

        // Test initial state
        assert_eq!(bv.bit_count(), 0);
        assert!(bv.is_empty());

        // Test append
        bv.append(true);
        bv.append(false);
        bv.append(true);
        assert_eq!(bv.bit_count(), 3);
        assert!(!bv.is_empty());

        // Test get_bit
        assert_eq!(bv.get_bit(0), true);
        assert_eq!(bv.get_bit(1), false);
        assert_eq!(bv.get_bit(2), true);

        // Test set_bit
        bv.set_bit(1, true);
        assert_eq!(bv.get_bit(1), true);
        bv.set_bit(2, false);
        assert_eq!(bv.get_bit(2), false);

        // Test toggle
        bv.toggle(0); // true -> false
        assert_eq!(bv.get_bit(0), false);
        bv.toggle(0); // false -> true
        assert_eq!(bv.get_bit(0), true);
    }

    #[test]
    fn test_bitvec2_chunk_operations() {
        let mut bv: Bitvec2<4> = Bitvec2::new();
        let test_chunk = [0xAB, 0xCD, 0xEF, 0x12];

        // Test append_chunk_unchecked
        bv.append_chunk_unchecked(&test_chunk);
        assert_eq!(bv.bit_count(), 32); // 4 bytes * 8 bits

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
    fn test_bitvec2_byte_operations() {
        let mut bv: Bitvec2<4> = Bitvec2::new();

        // Test append_byte_unchecked
        bv.append_byte_unchecked(0xFF);
        assert_eq!(bv.bit_count(), 8);

        // All bits in the byte should be set
        for i in 0..8 {
            assert_eq!(bv.get_bit(i), true);
        }

        bv.append_byte_unchecked(0x00);
        assert_eq!(bv.bit_count(), 16);

        // All bits in the second byte should be clear
        for i in 8..16 {
            assert_eq!(bv.get_bit(i), false);
        }
    }

    #[test]
    fn test_bitvec2_count_operations() {
        let mut bv: Bitvec2<4> = Bitvec2::new();

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
        assert_eq!(bv.bit_count(), 5);

        // Test with full bytes
        let mut bv2: Bitvec2<4> = Bitvec2::new();
        bv2.append_byte_unchecked(0xFF); // 8 ones
        bv2.append_byte_unchecked(0x00); // 8 zeros
        bv2.append_byte_unchecked(0xAA); // 4 ones, 4 zeros (10101010)

        assert_eq!(bv2.count_ones(), 12);
        assert_eq!(bv2.count_zeros(), 12);
        assert_eq!(bv2.bit_count(), 24);
    }

    #[test]
    fn test_bitvec2_clear_set_all() {
        let mut bv: Bitvec2<4> = Bitvec2::new();

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

        assert_eq!(bv.bit_count(), 16);
        assert!(bv.count_ones() > 0);

        // Test clear_all
        bv.clear_all();
        assert_eq!(bv.bit_count(), 16); // Length shouldn't change
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 16);

        // Test set_all
        bv.set_all();
        assert_eq!(bv.bit_count(), 16); // Length shouldn't change
        assert_eq!(bv.count_ones(), 16);
        assert_eq!(bv.count_zeros(), 0);
    }

    #[test]
    fn test_bitvec2_invert() {
        let mut bv: Bitvec2<4> = Bitvec2::new();

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

        // Check specific bits
        assert_eq!(bv.get_bit(0), false); // was true
        assert_eq!(bv.get_bit(1), true); // was false
        assert_eq!(bv.get_bit(2), false); // was true
        assert_eq!(bv.get_bit(3), true); // was false
        assert_eq!(bv.get_bit(4), false); // was true
    }

    #[test]
    fn test_bitvec2_bitwise_and() {
        let mut bv1: Bitvec2<4> = Bitvec2::new();
        let mut bv2: Bitvec2<4> = Bitvec2::new();

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

        assert_eq!(bv1.bit_count(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get_bit(i as u64), expected_bit, "Mismatch at bit {}", i);
        }
    }

    #[test]
    fn test_bitvec2_bitwise_or() {
        let mut bv1: Bitvec2<4> = Bitvec2::new();
        let mut bv2: Bitvec2<4> = Bitvec2::new();

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

        assert_eq!(bv1.bit_count(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get_bit(i as u64), expected_bit, "Mismatch at bit {}", i);
        }
    }

    #[test]
    fn test_bitvec2_bitwise_xor() {
        let mut bv1: Bitvec2<4> = Bitvec2::new();
        let mut bv2: Bitvec2<4> = Bitvec2::new();

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

        assert_eq!(bv1.bit_count(), 5);
        for (i, &expected_bit) in expected.iter().enumerate() {
            assert_eq!(bv1.get_bit(i as u64), expected_bit, "Mismatch at bit {}", i);
        }
    }

    #[test]
    fn test_bitvec2_multi_chunk_operations() {
        let mut bv1: Bitvec2<4> = Bitvec2::new();
        let mut bv2: Bitvec2<4> = Bitvec2::new();

        // Fill multiple chunks
        let chunk1 = [0xAA, 0xBB, 0xCC, 0xDD]; // 10101010 10111011 11001100 11011101
        let chunk2 = [0x55, 0x66, 0x77, 0x88]; // 01010101 01100110 01110111 10001000

        bv1.append_chunk_unchecked(&chunk1);
        bv1.append_chunk_unchecked(&chunk1);
        bv2.append_chunk_unchecked(&chunk2);
        bv2.append_chunk_unchecked(&chunk2);

        assert_eq!(bv1.bit_count(), 64);
        assert_eq!(bv2.bit_count(), 64);

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
        assert_eq!(bv_and.bit_count(), 64);
        assert_eq!(bv_or.bit_count(), 64);
        assert_eq!(bv_xor.bit_count(), 64);

        // AND should have fewer or equal ones than either operand
        assert!(bv_and.count_ones() <= bv1.count_ones());
        assert!(bv_and.count_ones() <= bv2.count_ones());

        // OR should have more or equal ones than either operand
        assert!(bv_or.count_ones() >= bv1.count_ones());
        assert!(bv_or.count_ones() >= bv2.count_ones());
    }

    #[test]
    fn test_bitvec2_partial_chunk_operations() {
        let mut bv1: Bitvec2<4> = Bitvec2::new();
        let mut bv2: Bitvec2<4> = Bitvec2::new();

        // Add partial chunks (not aligned to chunk boundaries)
        for i in 0..35 {
            // 35 bits = 4 bytes + 3 bits
            bv1.append(i % 2 == 0);
            bv2.append(i % 3 == 0);
        }

        assert_eq!(bv1.bit_count(), 35);
        assert_eq!(bv2.bit_count(), 35);

        // Test operations with partial chunks
        let mut bv_and = bv1.clone();
        bv_and.and(&bv2);

        let mut bv_or = bv1.clone();
        bv_or.or(&bv2);

        let mut bv_xor = bv1.clone();
        bv_xor.xor(&bv2);

        // All should maintain the same length
        assert_eq!(bv_and.bit_count(), 35);
        assert_eq!(bv_or.bit_count(), 35);
        assert_eq!(bv_xor.bit_count(), 35);

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
    fn test_bitvec2_toggle_out_of_bounds() {
        let mut bv: Bitvec2<4> = Bitvec2::new();
        bv.append(true);
        bv.toggle(1); // Only bit 0 exists
    }

    #[test]
    #[should_panic(expected = "Bitvec2 lengths don't match")]
    fn test_bitvec2_and_length_mismatch() {
        let mut bv1: Bitvec2<4> = Bitvec2::new();
        let mut bv2: Bitvec2<4> = Bitvec2::new();

        bv1.append(true);
        bv1.append(false);
        bv2.append(true); // Different length

        bv1.and(&bv2);
    }

    #[test]
    #[should_panic(expected = "Bitvec2 lengths don't match")]
    fn test_bitvec2_or_length_mismatch() {
        let mut bv1: Bitvec2<4> = Bitvec2::new();
        let mut bv2: Bitvec2<4> = Bitvec2::new();

        bv1.append(true);
        bv2.append(true);
        bv2.append(false); // Different length

        bv1.or(&bv2);
    }

    #[test]
    #[should_panic(expected = "Bitvec2 lengths don't match")]
    fn test_bitvec2_xor_length_mismatch() {
        let mut bv1: Bitvec2<4> = Bitvec2::new();
        let mut bv2: Bitvec2<4> = Bitvec2::new();

        bv1.append(true);
        bv1.append(false);
        bv1.append(true);
        bv2.append(true);
        bv2.append(false); // Different length

        bv1.xor(&bv2);
    }

    #[test]
    fn test_bitvec2_clear_trailing_bits() {
        let mut bv: Bitvec2<4> = Bitvec2::new();

        // Add some bits that don't fill a complete byte
        bv.append(true);
        bv.append(false);
        bv.append(true);

        // Manually set some trailing bits that shouldn't be there
        {
            let last_chunk = bv.bitmap.back_mut().unwrap();
            last_chunk[0] |= 0xF8; // Set bits 3-7
        }

        // clear_trailing_bits should clean this up
        let cleared = bv.clear_trailing_bits();
        assert!(cleared);

        // Only the first 3 bits should remain
        assert_eq!(bv.get_bit(0), true);
        assert_eq!(bv.get_bit(1), false);
        assert_eq!(bv.get_bit(2), true);

        // The byte should only have the first 3 bits set
        let expected_byte = 0b00000101; // bits 0 and 2 set
        let last_chunk = bv.bitmap.back().unwrap();
        assert_eq!(last_chunk[0], expected_byte);
    }

    #[test]
    fn test_bitvec2_different_chunk_sizes() {
        // Test with different chunk sizes
        let mut bv8: Bitvec2<8> = Bitvec2::new();
        let mut bv16: Bitvec2<16> = Bitvec2::new();
        let mut bv32: Bitvec2<32> = Bitvec2::new();

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
        assert_eq!(bv8.bit_count(), 64 + 2);
        assert_eq!(bv8.count_ones(), 64 + 1); // chunk8 is all 0xFF + 1 true bit
        assert_eq!(bv8.count_zeros(), 1);

        bv16.append(true);
        bv16.append(false);
        assert_eq!(bv16.bit_count(), 128 + 2);
        assert_eq!(bv16.count_ones(), 64 + 1); // chunk16 is 0xAA pattern + 1 true bit
        assert_eq!(bv16.count_zeros(), 64 + 1);

        bv32.append(true);
        bv32.append(false);
        assert_eq!(bv32.bit_count(), 256 + 2);
        assert_eq!(bv32.count_ones(), 128 + 1); // chunk32 is 0x55 pattern + 1 true bit
        assert_eq!(bv32.count_zeros(), 128 + 1);
    }
}

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
use alloc::{vec, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use core::fmt::{self, Formatter, Write as _};
use std::collections::VecDeque;

/// Represents a vector of bits.
///
/// Stores bits using [u8] blocks for efficient storage.
#[derive(Clone, PartialEq, Eq)]
pub struct BitVec<const CHUNK_SIZE: usize> {
    /// The underlying storage for the bits.
    storage: VecDeque<[u8; CHUNK_SIZE]>,

    /// The position within the last chunk of the bitmap where the next bit is to be appended.
    ///
    /// Invariant: This value is always in the range [0, N * 8).
    next_bit: u64,
}

impl<const CHUNK_SIZE: usize> BitVec<CHUNK_SIZE> {
    pub const CHUNK_SIZE_BITS: u64 = CHUNK_SIZE as u64 * 8;
    const EMPTY_CHUNK: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
    const FULL_CHUNK: [u8; CHUNK_SIZE] = [u8::MAX; CHUNK_SIZE];

    /// Create a new empty bitmap.
    pub fn new() -> Self {
        let storage = VecDeque::from([[0u8; CHUNK_SIZE]]);
        Self {
            storage,
            next_bit: 0,
        }
    }

    /// Creates a new `BitVec` with the specified capacity in bits.
    #[inline]
    pub fn with_capacity(size: usize) -> Self {
        let mut storage = VecDeque::with_capacity(Self::num_chunks(size));
        storage.push_back(Self::EMPTY_CHUNK);
        Self {
            storage,
            next_bit: 0,
        }
    }

    /// Creates a new `BitVec` with `size` bits, all initialized to zero.
    #[inline]
    pub fn zeroes(size: usize) -> Self {
        let num_chunks = Self::num_chunks(size);
        let mut storage = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            storage.push_back(Self::EMPTY_CHUNK);
        }
        Self {
            storage,
            next_bit: size as u64,
        }
    }

    /// Creates a new `BitVec` with `size` bits, all initialized to one.
    #[inline]
    pub fn ones(size: usize) -> Self {
        let num_chunks = Self::num_chunks(size);
        let mut storage = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            storage.push_back(Self::FULL_CHUNK);
        }
        Self {
            storage,
            next_bit: size as u64,
        }
    }

    /// Returns the number of bits in the vector.
    #[inline]
    pub fn len(&self) -> usize {
        self.next_bit as usize
    }

    /// Returns true if the vector contains no bits.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.next_bit == 0
    }

    /// Return the last chunk of the bitmap as a mutable slice.
    #[inline]
    fn last_chunk_mut(&mut self) -> &mut [u8] {
        self.storage.back_mut().unwrap()
    }

    /// Returns the bitmap chunk containing the specified bit.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub fn get_chunk(&self, bit_offset: u64) -> &[u8; CHUNK_SIZE] {
        &self.storage[self.chunk_index(bit_offset)]
    }

    #[inline]
    pub(crate) fn chunk_byte_bitmask(bit_offset: u64) -> u8 {
        1 << (bit_offset % 8)
    }

    /// Convert a bit offset into the offset of the byte within a chunk containing the bit.
    #[inline]
    pub(crate) fn chunk_byte_offset(bit_offset: u64) -> usize {
        (bit_offset / 8) as usize % CHUNK_SIZE
    }

    /// Convert a bit offset into the index of the chunk it belongs to within self.bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub(crate) fn chunk_index(&self, bit_offset: u64) -> usize {
        assert!(
            bit_offset < self.len() as u64,
            "out of bounds: {bit_offset}"
        );
        Self::chunk_num(bit_offset)
    }

    /// Convert a bit offset into the number of the chunk it belongs to.
    #[inline]
    pub(crate) fn chunk_num(bit_offset: u64) -> usize {
        (bit_offset / Self::CHUNK_SIZE_BITS) as usize
    }

    /// Prepares the next chunk of the bitmap to preserve the invariant that there is always room
    /// for one more bit.
    pub(crate) fn prepare_next_chunk(&mut self) {
        self.next_bit = 0;
        self.storage.push_back(Self::EMPTY_CHUNK);
    }

    /// Appends a bit to the end of the vector.
    #[inline]
    pub fn push(&mut self, bit: bool) {
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

    /// Removes the last bit from the vector and returns it.
    ///
    /// Returns `None` if the vector is empty.
    #[inline]
    pub fn pop(&mut self) -> Option<bool> {
        if self.is_empty() {
            return None;
        }

        // Decrement the number of bits and get the value of the last bit
        self.next_bit -= 1;
        let bit_offset = self.next_bit;
        let value = Self::get_bit_from_chunk(self.get_chunk(bit_offset), bit_offset);

        // Clear the bit we just popped (maintain invariant that unused bits are 0)
        if value {
            self.set_bit(bit_offset, false);
        }

        // If we just emptied the last chunk and there's more than one chunk, remove it
        let remaining_bits_in_chunk = self.next_bit % Self::CHUNK_SIZE_BITS;
        if remaining_bits_in_chunk == 0 && self.storage.len() > 1 {
            self.storage.pop_back();
        }

        Some(value)
    }

    /// Get the value of a bit from its chunk.
    #[inline]
    pub fn get_bit_from_chunk(chunk: &[u8; CHUNK_SIZE], bit_offset: u64) -> bool {
        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let byte = chunk[byte_offset];
        let mask = Self::chunk_byte_bitmask(bit_offset);

        (byte & mask) != 0
    }

    /// Gets the value of the bit at `index` (true if 1, false if 0).
    ///
    /// Returns `None` if the index is out of bounds.
    #[inline]
    pub fn get(&self, index: usize) -> Option<bool> {
        if index >= self.len() {
            return None;
        }
        Some(Self::get_bit_from_chunk(
            self.get_chunk(index as u64),
            index as u64,
        ))
    }

    /*
    /// Gets the value of the bit at the specified index without bounds checking.
    ///
    /// # Safety
    ///
    /// Caller must ensure `index` is less than the length of the BitVec.
    #[inline]
    pub unsafe fn get_unchecked(&self, index: usize) -> bool {
        self.get_bit_unchecked(index)
    }
    */

    /// Sets the bit at `index` to 1.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn set(&mut self, index: usize) {
        self.set_bit(index as u64, true);
    }

    /// Sets the bit at `index` to 0.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn clear(&mut self, index: usize) {
        self.set_bit(index as u64, false);
    }

    /// Set the value of the referenced bit.
    pub fn set_bit(&mut self, bit_offset: u64, bit: bool) {
        let chunk_index = self.chunk_index(bit_offset);
        let chunk = &mut self.storage[chunk_index];

        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let mask = Self::chunk_byte_bitmask(bit_offset);

        if bit {
            chunk[byte_offset] |= mask;
        } else {
            chunk[byte_offset] &= !mask;
        }
    }

    /// Flips the bit at `index`.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn toggle(&mut self, _index: usize) {
        // self.assert_index(index);
        // self.toggle_bit_unchecked(index);
        todo!()
    }

    /*
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
    */

    /// Sets all bits to 0.
    #[inline]
    pub fn clear_all(&mut self) {
        for chunk in &mut self.storage {
            *chunk = Self::EMPTY_CHUNK;
        }
    }

    /// Sets all bits to 1.
    #[inline]
    pub fn set_all(&mut self) {
        for chunk in &mut self.storage {
            *chunk = Self::FULL_CHUNK;
        }
    }

    /// Returns the number of bits set to 1.
    #[inline]
    pub fn count_ones(&self) -> usize {
        let mut count = 0;

        // Count ones in all complete chunks
        let complete_chunks = Self::chunk_num(self.next_bit);
        for chunk_idx in 0..complete_chunks {
            count += self.storage[chunk_idx]
                .iter()
                .map(|b| b.count_ones() as usize)
                .sum::<usize>();
        }

        // Count ones in the partial last chunk (if any)
        let remaining_bits = self.next_bit % Self::CHUNK_SIZE_BITS;
        if remaining_bits > 0 && complete_chunks < self.storage.len() {
            let last_chunk = &self.storage[complete_chunks];
            for bit_offset in 0..remaining_bits {
                if Self::get_bit_from_chunk(last_chunk, bit_offset) {
                    count += 1;
                }
            }
        }

        count
    }

    /// Returns the number of bits set to 0.
    #[inline]
    pub fn count_zeros(&self) -> usize {
        self.len() - self.count_ones()
    }

    /*
    /// Performs a bitwise AND with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn and(&mut self, other: &BitVec<CHUNK_SIZE>) {
        self.binary_op(other, |a, b| a & b);
        self.clear_trailing_bits();
    }
    */

    /*
    /// Performs a bitwise OR with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn or(&mut self, other: &BitVec<CHUNK_SIZE>) {
        self.binary_op(other, |a, b| a | b);
        self.clear_trailing_bits();
    }
    */

    /*
    /// Performs a bitwise XOR with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn xor(&mut self, other: &BitVec<CHUNK_SIZE>) {
        self.binary_op(other, |a, b| a ^ b);
        self.clear_trailing_bits();
    }
    */

    /*
    /// Flips all bits (1s become 0s and vice versa).
    pub fn invert(&mut self) {
        for chunk in &mut self.storage {
            for byte in chunk {
                *byte = !*byte;
            }
        }
        self.clear_trailing_bits();
    }
    */

    /// Creates an iterator over the bits.
    pub fn iter(&self) -> BitIterator<'_, CHUNK_SIZE> {
        BitIterator { vec: self, pos: 0 }
    }

    // ---------- Helper Functions ----------

    /*
    /// Calculates the chunk index for a given bit index.
    #[inline(always)]
    fn chunk_index(index: usize) -> usize {
        index / Self::CHUNK_SIZE_BITS as usize
    }
    */

    /// Calculates the number of chunks needed to store `num_bits`.
    #[inline(always)]
    fn num_chunks(num_bits: usize) -> usize {
        num_bits.div_ceil(Self::CHUNK_SIZE_BITS as usize)
    }

    /*
    /// Creates a mask with the first `num_bits` bits set to 1.
    #[inline(always)]
    fn mask_over_first_n_bits(num_bits: usize) -> Block {
        match num_bits {
            BITS_PER_BLOCK => FULL_BLOCK,
            n if n < BITS_PER_BLOCK => FULL_BLOCK.unbounded_shr((BITS_PER_BLOCK - n) as u32),
            _ => panic!("num_bits exceeds block size: {num_bits}"),
        }
    }
    */

    /*
        #[inline(always)]
        fn get_bit_unchecked(&self, index: usize) -> bool {
            let block_index = Self::chunk_index(index);
            let bit_index = Self::bit_offset(index);
            (self.storage[block_index] & (1 << bit_index)) != 0
        }

        #[inline(always)]
        fn set_bit_unchecked(&mut self, index: usize) {
            let block_index = Self::chunk_index(index);
            let bit_index = Self::bit_offset(index);
            self.storage[block_index] |= 1 << bit_index;
        }

        #[inline(always)]
        fn clear_bit_unchecked(&mut self, index: usize) {
            let block_index = Self::chunk_index(index);
            let bit_index = Self::bit_offset(index);
            self.storage[block_index] &= !(1 << bit_index);
        }

        #[inline(always)]
        fn toggle_bit_unchecked(&mut self, index: usize) {
            let block_index = Self::chunk_index(index);
            let bit_index = Self::bit_offset(index);
            self.storage[block_index] ^= 1 << bit_index;
        }
    */

    /*
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
    */
}

// ---------- Constructors ----------

impl<const CHUNK_SIZE: usize> Default for BitVec<CHUNK_SIZE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CHUNK_SIZE: usize, T: AsRef<[bool]>> From<T> for BitVec<CHUNK_SIZE> {
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

impl<const CHUNK_SIZE: usize> From<BitVec<CHUNK_SIZE>> for Vec<bool> {
    fn from(bv: BitVec<CHUNK_SIZE>) -> Self {
        bv.iter().collect()
    }
}

// ---------- Debug ----------

impl<const CHUNK_SIZE: usize> fmt::Debug for BitVec<CHUNK_SIZE> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        // For very large BitVecs, only show a preview
        const MAX_DISPLAY: usize = 64;
        const HALF_DISPLAY: usize = MAX_DISPLAY / 2;

        // Closure for writing a bit
        let write_bit = |formatter: &mut Formatter<'_>, index: usize| -> core::fmt::Result {
            formatter.write_char(if self.get(index).unwrap_or_default() {
                '1'
            } else {
                '0'
            })
        };

        f.write_str("BitVec[")?;
        if self.next_bit as usize <= MAX_DISPLAY {
            // Show all bits
            for i in 0..self.next_bit {
                write_bit(f, i as usize)?;
            }
        } else {
            // Show first and last bits with ellipsis
            for i in 0..HALF_DISPLAY {
                write_bit(f, i as usize)?;
            }

            f.write_str("...")?;

            for i in (self.next_bit - HALF_DISPLAY as u64)..self.next_bit {
                write_bit(f, i as usize)?;
            }
        }
        f.write_str("]")
    }
}

// ---------- Operations ----------

/*
impl<const CHUNK_SIZE: usize> Index<usize> for BitVec<CHUNK_SIZE> {
    type Output = bool;

    /// Allows accessing bits using the `[]` operator.
    ///
    /// Panics if out of bounds.
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        let value = self.get_bit_unchecked(index);
        if value {
            &true
        } else {
            &false
        }
    }
}
    */

/*
impl<const CHUNK_SIZE: usize> BitAnd for &BitVec<CHUNK_SIZE> {
    type Output = BitVec<CHUNK_SIZE>;

    fn bitand(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.and(rhs);
        result
    }
}

impl<const CHUNK_SIZE: usize> BitOr for &BitVec<CHUNK_SIZE> {
    type Output = BitVec<CHUNK_SIZE>;

    fn bitor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.or(rhs);
        result
    }
}

impl<const CHUNK_SIZE: usize> BitXor for &BitVec<CHUNK_SIZE> {
    type Output = BitVec;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.xor(rhs);
        result
    }
}
    */

// ---------- Codec ----------

impl<const CHUNK_SIZE: usize> Write for BitVec<CHUNK_SIZE> {
    fn write(&self, buf: &mut impl BufMut) {
        self.next_bit.write(buf);
        for &chunk in &self.storage {
            chunk.write(buf);
        }
    }
}

impl<const CHUNK_SIZE: usize> Read for BitVec<CHUNK_SIZE> {
    type Cfg = RangeCfg;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        // Parse length with validation
        let next_bits = u64::read_cfg(buf, &())?;
        let length_as_usize = usize::try_from(next_bits)
            .map_err(|_| CodecError::InvalidLength(next_bits as usize))?;

        // Validate length is within allowed range
        if !range.contains(&length_as_usize) {
            return Err(CodecError::InvalidLength(length_as_usize));
        }

        // Parse blocks
        let num_chunks = Self::num_chunks(next_bits as usize);
        let mut storage = VecDeque::with_capacity(num_chunks as usize);
        for _ in 0..num_chunks {
            let chunk = <[u8; CHUNK_SIZE]>::read(buf)?;
            storage.push_back(chunk);
        }

        Ok(Self {
            storage,
            next_bit: next_bits,
        })
    }
}

impl<const CHUNK_SIZE: usize> EncodeSize for BitVec<CHUNK_SIZE> {
    fn encode_size(&self) -> usize {
        self.next_bit.encode_size() + (<[u8; CHUNK_SIZE]>::SIZE * self.storage.len())
    }
}

// ---------- Iterator ----------

/// Iterator over bits in a BitVec
pub struct BitIterator<'a, const CHUNK_SIZE: usize> {
    /// Reference to the BitVec being iterated over
    vec: &'a BitVec<CHUNK_SIZE>,

    /// Current position in the BitVec (0-indexed)
    pos: usize,
}

impl<const CHUNK_SIZE: usize> Iterator for BitIterator<'_, CHUNK_SIZE> {
    type Item = bool;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.vec.len() {
            return None;
        }

        let bit = self.vec.get(self.pos);
        self.pos += 1;
        bit
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.vec.len() - self.pos;
        (remaining, Some(remaining))
    }
}

impl<const CHUNK_SIZE: usize> ExactSizeIterator for BitIterator<'_, CHUNK_SIZE> {}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use commonware_codec::{Decode, Encode};

    type BitVec = super::BitVec<1>;

    #[test]
    fn test_constructors() {
        // Test new()
        let bv = BitVec::new();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert_eq!(bv.storage.len(), 1);

        // Test with_capacity()
        let bv = BitVec::with_capacity(100);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert!(bv.storage.capacity() >= BitVec::num_chunks(100));

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

        // Test set_bit
        bv.set_bit(10, true);
        bv.set_bit(11, false);

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

    /*
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
    */

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
    fn test_set_bit_out_of_bounds() {
        let mut bv = BitVec::zeroes(10);
        bv.set_bit(10, true);
    }

    /*
    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_index_out_of_bounds() {
        let bv = BitVec::zeroes(10);
        let _ = bv[10];
    }
    */

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

    /*
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
    */

    /*
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
    */

    #[test]
    fn test_codec_roundtrip() {
        let original = BitVec::from(&[true, false, true, false, true]);
        let mut buf = original.encode();
        let decoded = BitVec::decode_cfg(&mut buf, &(..).into()).unwrap();
        assert_eq!(original, decoded);
    }

    /*
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
    */
}

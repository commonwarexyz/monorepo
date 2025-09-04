//! Growable bit vector with configurable chunk size.
//!
//! Uses `VecDeque<[u8; CHUNK_SIZE]>` for storage. Trailing bits in the last chunk
//! may have undefined values but are masked during equality comparisons.
//!
//! ## Invariants
//!
//! - `storage` always contains at least one chunk (never empty)
//! - `next_bit` represents the total number of valid bits (logical length)
//! - Only bits `0..next_bit` are considered valid; trailing bits are ignored
//! - `CHUNK_SIZE` must be > 0 (enforced by const generics)
//!
//! ```
//! use commonware_utils::BitVec;
//!
//! let mut bv = BitVec::<1>::new();
//! bv.push(true);
//! bv.push(false);
//! assert_eq!(bv.len(), 2);
//! assert_eq!(bv.get(0), Some(true));
//! assert_eq!(bv.get(1), Some(false));
//! ```

#[cfg(not(feature = "std"))]
use alloc::{collections::VecDeque, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, FixedSize, RangeCfg, Read, ReadExt, Write,
};
use core::{
    fmt::{self, Formatter, Write as _},
    iter::{Extend, FromIterator},
    ops::{BitAnd, BitOr, BitXor, Index},
};
#[cfg(feature = "std")]
use std::collections::VecDeque;

/// A growable bit vector with configurable chunk size.
///
/// Stores bits in chunks of `CHUNK_SIZE` bytes each. The bit vector can grow by adding
/// more chunks as needed. Bits are indexed from 0 and stored in little-endian bit order
/// within each byte.
#[derive(Clone)]
pub struct BitVec<const CHUNK_SIZE: usize> {
    /// The underlying storage for the bits.
    storage: VecDeque<[u8; CHUNK_SIZE]>,

    /// The total number of bits currently stored in this bit vector.
    /// This determines the logical length of the bit vector.
    next_bit: usize,
}

impl<const CHUNK_SIZE: usize> BitVec<CHUNK_SIZE> {
    pub const CHUNK_SIZE_BITS: usize = CHUNK_SIZE * 8;
    const EMPTY_CHUNK: [u8; CHUNK_SIZE] = [0u8; CHUNK_SIZE];
    const FULL_CHUNK: [u8; CHUNK_SIZE] = [u8::MAX; CHUNK_SIZE];

    /// Creates a new empty bit vector.
    pub fn new() -> Self {
        let storage = VecDeque::from([Self::EMPTY_CHUNK]);
        Self {
            storage,
            next_bit: 0,
        }
    }

    /// Creates a new bit vector with capacity for at least `capacity` bits.
    ///
    /// The bit vector will be empty but will have allocated space for the specified
    /// number of bits without needing to reallocate.
    pub fn with_capacity(capacity: usize) -> Self {
        let num_chunks = if capacity == 0 {
            1
        } else {
            Self::num_chunks(capacity)
        };
        let mut storage = VecDeque::with_capacity(num_chunks);
        storage.push_back(Self::EMPTY_CHUNK);
        Self {
            storage,
            next_bit: 0,
        }
    }

    /// Creates a new bit vector with `size` bits, all set to false (0).
    pub fn zeroes(size: usize) -> Self {
        if size == 0 {
            return Self::new();
        }

        let num_chunks = Self::num_chunks(size);
        let mut storage = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            storage.push_back(Self::EMPTY_CHUNK);
        }
        Self {
            storage,
            next_bit: size,
        }
    }

    /// Creates a new bit vector with `size` bits, all set to true (1).
    pub fn ones(size: usize) -> Self {
        if size == 0 {
            return Self::new();
        }

        let num_chunks = Self::num_chunks(size);
        let mut storage = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            storage.push_back(Self::FULL_CHUNK);
        }
        Self {
            storage,
            next_bit: size,
        }
    }

    /// Returns the number of bits in the vector.
    #[inline]
    pub fn len(&self) -> usize {
        self.next_bit
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
    pub fn get_chunk(&self, bit_offset: usize) -> &[u8; CHUNK_SIZE] {
        &self.storage[self.chunk_index(bit_offset)]
    }

    #[inline]
    pub(crate) fn chunk_byte_bitmask(bit_offset: usize) -> u8 {
        1 << (bit_offset % 8)
    }

    /// Convert a bit offset into the offset of the byte within a chunk containing the bit.
    #[inline]
    pub(crate) fn chunk_byte_offset(bit_offset: usize) -> usize {
        (bit_offset / 8) % CHUNK_SIZE
    }

    /// Convert a bit offset into the index of the chunk it belongs to within self.bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bit doesn't exist or has been pruned.
    #[inline]
    pub(crate) fn chunk_index(&self, bit_offset: usize) -> usize {
        assert!(bit_offset < self.len(), "Index out of bounds");
        Self::chunk_num(bit_offset)
    }

    /// Convert a bit offset into the number of the chunk it belongs to.
    #[inline]
    pub(crate) fn chunk_num(bit_offset: usize) -> usize {
        bit_offset / Self::CHUNK_SIZE_BITS
    }

    /// Prepares the next chunk of the bitmap to preserve the invariant that there is always room
    /// for one more bit.
    pub(crate) fn prepare_next_chunk(&mut self) {
        self.storage.push_back(Self::EMPTY_CHUNK);
    }

    /// Appends a bit to the end of the vector.
    #[inline]
    pub fn push(&mut self, bit: bool) {
        if bit {
            let chunk_byte = Self::chunk_byte_offset(self.next_bit);
            self.last_chunk_mut()[chunk_byte] |= Self::chunk_byte_bitmask(self.next_bit);
        }
        self.next_bit += 1;

        // If we've filled the current chunk, prepare the next one
        if self.next_bit % Self::CHUNK_SIZE_BITS == 0 {
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

        // Get the value of the last bit before decrementing
        let bit_offset = self.next_bit - 1;
        let value = Self::get_bit_from_chunk(self.get_chunk(bit_offset), bit_offset);

        // Clear the bit we're about to pop (maintain invariant that unused bits are 0)
        if value {
            let chunk_index = self.chunk_index(bit_offset);
            let chunk = &mut self.storage[chunk_index];
            let byte_offset = Self::chunk_byte_offset(bit_offset);
            let mask = Self::chunk_byte_bitmask(bit_offset);
            chunk[byte_offset] &= !mask;
        }

        // Decrement the number of bits
        self.next_bit -= 1;

        // If we just emptied the last chunk and there's more than one chunk, remove it
        let remaining_bits_in_chunk = self.next_bit % Self::CHUNK_SIZE_BITS;
        if remaining_bits_in_chunk == 0 && self.storage.len() > 1 {
            self.storage.pop_back();
        }

        Some(value)
    }

    /// Get the value of a bit from its chunk.
    #[inline]
    pub fn get_bit_from_chunk(chunk: &[u8; CHUNK_SIZE], bit_offset: usize) -> bool {
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
        Some(Self::get_bit_from_chunk(self.get_chunk(index), index))
    }

    /// Sets the bit at `index` to 1.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn set(&mut self, index: usize) {
        self.set_bit(index, true);
    }

    /// Sets the bit at `index` to 0.
    ///
    /// # Panics
    ///
    /// Panics if `index` is out of bounds.
    #[inline]
    pub fn clear(&mut self, index: usize) {
        self.set_bit(index, false);
    }

    /// Set the value of the referenced bit.
    pub fn set_bit(&mut self, bit_offset: usize, bit: bool) {
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
    pub fn toggle(&mut self, index: usize) {
        let bit_offset = index;
        let chunk_index = self.chunk_index(bit_offset);
        let chunk = &mut self.storage[chunk_index];

        let byte_offset = Self::chunk_byte_offset(bit_offset);
        let mask = Self::chunk_byte_bitmask(bit_offset);

        chunk[byte_offset] ^= mask;
    }

    /// Sets all bits to 0.
    #[inline]
    pub fn clear_all(&mut self) {
        for chunk in &mut self.storage {
            *chunk = Self::EMPTY_CHUNK;
        }
    }

    /// Sets all bits to 1.
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

    /// Performs a bitwise AND with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn and(&mut self, other: &BitVec<CHUNK_SIZE>) {
        self.binary_op(other, |a, b| a & b);
    }

    /// Performs a bitwise OR with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn or(&mut self, other: &BitVec<CHUNK_SIZE>) {
        self.binary_op(other, |a, b| a | b);
    }

    /// Performs a bitwise XOR with another BitVec.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn xor(&mut self, other: &BitVec<CHUNK_SIZE>) {
        self.binary_op(other, |a, b| a ^ b);
    }

    /// Flips all bits (1s become 0s and vice versa).
    pub fn invert(&mut self) {
        for chunk in &mut self.storage {
            for byte in chunk {
                *byte = !*byte;
            }
        }
    }

    /// Creates an iterator over the bits.
    pub fn iter(&self) -> BitIterator<'_, CHUNK_SIZE> {
        BitIterator { vec: self, pos: 0 }
    }

    /// Calculates the number of chunks needed to store `num_bits`.
    #[inline(always)]
    fn num_chunks(num_bits: usize) -> usize {
        num_bits.div_ceil(Self::CHUNK_SIZE_BITS)
    }

    /// Asserts that the index is within bounds.
    #[inline(always)]
    fn assert_index(&self, index: usize) {
        assert!(index < self.len(), "Index out of bounds");
    }

    /// Asserts that the lengths of two BitVecs match.
    #[inline(always)]
    fn assert_eq_len(&self, other: &BitVec<CHUNK_SIZE>) {
        assert_eq!(self.len(), other.len(), "BitVec lengths don't match");
    }

    /// Helper for binary operations (AND, OR, XOR)
    #[inline]
    fn binary_op<F: Fn(u8, u8) -> u8>(&mut self, other: &BitVec<CHUNK_SIZE>, op: F) {
        self.assert_eq_len(other);
        for (chunk_a, chunk_b) in self.storage.iter_mut().zip(other.storage.iter()) {
            for (byte_a, byte_b) in chunk_a.iter_mut().zip(chunk_b.iter()) {
                *byte_a = op(*byte_a, *byte_b);
            }
        }
    }
}

impl<const CHUNK_SIZE: usize> PartialEq for BitVec<CHUNK_SIZE> {
    fn eq(&self, other: &Self) -> bool {
        // First check if lengths are equal
        if self.next_bit != other.next_bit {
            return false;
        }

        // If both are empty, they're equal
        if self.next_bit == 0 {
            return true;
        }

        // Compare complete chunks
        let complete_chunks = Self::chunk_num(self.next_bit);
        for i in 0..complete_chunks {
            if self.storage[i] != other.storage[i] {
                return false;
            }
        }

        // Compare the partial last chunk (if any) with proper masking
        let remaining_bits = self.next_bit % Self::CHUNK_SIZE_BITS;
        if remaining_bits > 0 {
            let last_chunk_idx = complete_chunks;
            if last_chunk_idx < self.storage.len() && last_chunk_idx < other.storage.len() {
                let self_chunk = &self.storage[last_chunk_idx];
                let other_chunk = &other.storage[last_chunk_idx];

                // Compare each byte in the last chunk, masking the unused bits
                let complete_bytes = remaining_bits / 8;
                let remaining_bits_in_byte = remaining_bits % 8;

                // Compare complete bytes
                for byte_idx in 0..complete_bytes {
                    if self_chunk[byte_idx] != other_chunk[byte_idx] {
                        return false;
                    }
                }

                // Compare the partial last byte (if any)
                if remaining_bits_in_byte > 0 {
                    let byte_idx = complete_bytes;
                    if byte_idx < CHUNK_SIZE {
                        let mask = (1u8 << remaining_bits_in_byte) - 1;
                        let self_masked = self_chunk[byte_idx] & mask;
                        let other_masked = other_chunk[byte_idx] & mask;
                        if self_masked != other_masked {
                            return false;
                        }
                    }
                }
            }
        }

        true
    }
}

impl<const CHUNK_SIZE: usize> Eq for BitVec<CHUNK_SIZE> {}

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

impl<const CHUNK_SIZE: usize> From<BitVec<CHUNK_SIZE>> for Vec<bool> {
    fn from(bv: BitVec<CHUNK_SIZE>) -> Self {
        bv.iter().collect()
    }
}

impl<const CHUNK_SIZE: usize> Extend<bool> for BitVec<CHUNK_SIZE> {
    fn extend<I: IntoIterator<Item = bool>>(&mut self, iter: I) {
        for bit in iter {
            self.push(bit);
        }
    }
}

impl<const CHUNK_SIZE: usize> FromIterator<bool> for BitVec<CHUNK_SIZE> {
    fn from_iter<I: IntoIterator<Item = bool>>(iter: I) -> Self {
        let mut bv = Self::new();
        bv.extend(iter);
        bv
    }
}

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
        if self.next_bit <= MAX_DISPLAY {
            // Show all bits
            for i in 0..self.next_bit {
                write_bit(f, i)?;
            }
        } else {
            // Show first and last bits with ellipsis
            for i in 0..HALF_DISPLAY {
                write_bit(f, i)?;
            }

            f.write_str("...")?;

            for i in (self.next_bit - HALF_DISPLAY)..self.next_bit {
                write_bit(f, i)?;
            }
        }
        f.write_str("]")
    }
}

impl<const CHUNK_SIZE: usize> Index<usize> for BitVec<CHUNK_SIZE> {
    type Output = bool;

    /// Allows accessing bits using the `[]` operator.
    ///
    /// Panics if out of bounds.
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        self.assert_index(index);
        let value = Self::get_bit_from_chunk(self.get_chunk(index), index);
        if value {
            &true
        } else {
            &false
        }
    }
}

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
    type Output = BitVec<CHUNK_SIZE>;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.assert_eq_len(rhs);
        let mut result = self.clone();
        result.xor(rhs);
        result
    }
}

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
        // Parse length with range validation
        let next_bit = usize::read_cfg(buf, range)?;

        // Parse chunks
        let num_chunks = Self::num_chunks(next_bit);
        let mut storage = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            let chunk = <[u8; CHUNK_SIZE]>::read(buf)?;
            storage.push_back(chunk);
        }

        if buf.remaining() > 0 {
            return Err(CodecError::ExtraData(buf.remaining()));
        }

        Ok(Self { storage, next_bit })
    }
}

impl<const CHUNK_SIZE: usize> EncodeSize for BitVec<CHUNK_SIZE> {
    fn encode_size(&self) -> usize {
        self.next_bit.encode_size() + (<[u8; CHUNK_SIZE]>::SIZE * self.storage.len())
    }
}

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

#[cfg(test)]
mod tests {
    use commonware_codec::{Decode, Encode, Error as CodecError, Write};

    type BitVec = super::BitVec<1>;

    #[test]
    fn test_constructors() {
        // Test new()
        let bv = BitVec::new();
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert_eq!(bv.storage.len(), 1); // Always has at least one chunk

        // Test with_capacity()
        let bv = BitVec::with_capacity(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        let bv = BitVec::with_capacity(100);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
        assert!(bv.storage.capacity() >= BitVec::num_chunks(100));

        // Test zeroes()
        let bv = BitVec::zeroes(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        let bv = BitVec::zeroes(5);
        assert_eq!(bv.len(), 5);
        assert!(!bv.is_empty());
        for i in 0..5 {
            assert_eq!(bv.get(i), Some(false));
        }

        let bv = BitVec::zeroes(100);
        assert_eq!(bv.len(), 100);
        assert!(!bv.is_empty());
        assert_eq!(bv.count_zeros(), 100);
        for i in 0..100 {
            assert!(!bv.get(i).unwrap());
        }

        // Test ones()
        let bv = BitVec::ones(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        let bv = BitVec::ones(5);
        assert_eq!(bv.len(), 5);
        assert!(!bv.is_empty());
        for i in 0..5 {
            assert_eq!(bv.get(i), Some(true));
        }

        let bv = BitVec::ones(100);
        assert_eq!(bv.len(), 100);
        assert!(!bv.is_empty());
        assert_eq!(bv.count_ones(), 100);
        for i in 0..100 {
            assert!(bv.get(i).unwrap());
        }

        // Test From trait implementations
        let bools = [true, false, true, false, true];
        let bv = BitVec::from(&bools);
        assert_eq!(bv.len(), 5);
        assert_eq!(bv.count_ones(), 3);

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
        // Test From<Vec<bool>>
        let bools = vec![true, false, true, false];
        let bv: BitVec = bools.clone().into();
        assert_eq!(bv.len(), 4);
        for (i, &expected) in bools.iter().enumerate() {
            assert_eq!(bv.get(i), Some(expected));
        }

        // Test From<&[bool]>
        let bools = [false, true, false, true, true];
        let bv: BitVec = (&bools).into();
        assert_eq!(bv.len(), 5);
        for (i, &expected) in bools.iter().enumerate() {
            assert_eq!(bv.get(i), Some(expected));
        }

        // Test Into<Vec<bool>>
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
        // Test with simple case
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
        let result = &a & &b;
        assert_eq!(result, BitVec::from(&[true, false, false, false, true]));

        let result = &a | &b;
        assert_eq!(result, BitVec::from(&[true, true, true, false, true]));

        let result = &a ^ &b;
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

        // Test with different sizes
        for size in [1, 7, 8, 9, 15, 16, 17] {
            let mut a = BitVec::zeroes(size);
            let mut b = BitVec::zeroes(size);

            // Set some bits in a pattern
            for i in (0..size).step_by(2) {
                a.set(i);
            }
            for i in (1..size).step_by(3) {
                b.set(i);
            }

            // Test AND
            let mut result = a.clone();
            result.and(&b);
            for i in 0..size {
                let expected = a.get(i).unwrap() && b.get(i).unwrap();
                assert_eq!(result.get(i), Some(expected));
            }

            // Test OR
            let mut result = a.clone();
            result.or(&b);
            for i in 0..size {
                let expected = a.get(i).unwrap() || b.get(i).unwrap();
                assert_eq!(result.get(i), Some(expected));
            }

            // Test XOR
            let mut result = a.clone();
            result.xor(&b);
            for i in 0..size {
                let expected = a.get(i).unwrap() ^ b.get(i).unwrap();
                assert_eq!(result.get(i), Some(expected));
            }

            // Test trait operators
            let result = &a & &b;
            for i in 0..size {
                let expected = a.get(i).unwrap() && b.get(i).unwrap();
                assert_eq!(result.get(i), Some(expected));
            }
        }
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
    fn test_set_bit_out_of_bounds() {
        let mut bv = BitVec::zeroes(10);
        bv.set_bit(10, true);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_index_out_of_bounds() {
        let bv = BitVec::zeroes(10);
        let _ = bv[10];
    }

    #[test]
    fn test_count_operations() {
        // Test empty
        let bv = BitVec::new();
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 0);

        // Test single bit
        let bv = BitVec::from(&[true]);
        assert_eq!(bv.count_ones(), 1);
        assert_eq!(bv.count_zeros(), 0);

        let bv = BitVec::from(&[false]);
        assert_eq!(bv.count_ones(), 0);
        assert_eq!(bv.count_zeros(), 1);

        // Small BitVec
        let bv = BitVec::from(&[true, false, true, true, false, true]);
        assert_eq!(bv.count_ones(), 4);
        assert_eq!(bv.count_zeros(), 2);

        // Large BitVecs
        let zeroes = BitVec::zeroes(100);
        assert_eq!(zeroes.count_ones(), 0);
        assert_eq!(zeroes.count_zeros(), 100);

        let ones = BitVec::ones(100);
        assert_eq!(ones.count_ones(), 100);
        assert_eq!(ones.count_zeros(), 0);

        // Test across chunk boundaries
        let mut bv_multi = BitVec::zeroes(70);
        bv_multi.set(0);
        bv_multi.set(63); // Last bit in first block
        bv_multi.set(64); // First bit in second block
        bv_multi.set(69);
        assert_eq!(bv_multi.count_ones(), 4);
        assert_eq!(bv_multi.count_zeros(), 66);

        // Test across multiple chunks with different chunk size
        let mut bv = super::BitVec::<1>::new();
        for i in 0..17 {
            // Spans multiple chunks
            bv.push(i % 2 == 0);
        }
        let expected_ones = (0..17).filter(|&i| i % 2 == 0).count();
        assert_eq!(bv.count_ones(), expected_ones);
        assert_eq!(bv.count_zeros(), 17 - expected_ones);
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

        // Clear all
        bv.clear_all();
        assert_eq!(bv.len(), 5);
        assert_eq!(bv.count_ones(), 0);

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
    fn test_codec_error_extra_data() {
        use bytes::BytesMut;

        // Create a valid BitVec and encode it
        let mut bv = BitVec::new();
        bv.push(true);
        bv.push(false);
        let encoded = bv.encode();

        // Add extra bytes to the encoded data
        let mut buf_with_extra = BytesMut::from(encoded.as_ref());
        buf_with_extra.extend_from_slice(&[0xFF, 0xAA]); // Extra garbage data

        let mut cursor = std::io::Cursor::new(buf_with_extra);
        assert!(matches!(
            BitVec::decode_cfg(&mut cursor, &(..).into()),
            Err(CodecError::ExtraData(2)) // Should detect 2 extra bytes
        ));
    }

    #[test]
    fn test_codec_error_insufficient_data() {
        use bytes::BytesMut;

        // Test case 1: Buffer with length but no chunk data
        let mut buf1 = BytesMut::new();
        5usize.write(&mut buf1); // Write length as 5 bits
                                 // Don't write any chunk data

        let mut cursor1 = std::io::Cursor::new(buf1);
        assert!(matches!(
            BitVec::decode_cfg(&mut cursor1, &(..).into()),
            Err(CodecError::EndOfBuffer)
        ));

        // Test case 2: Buffer with length and partial chunk data
        let mut buf2 = BytesMut::new();
        9usize.write(&mut buf2); // Write length as 9 bits (needs 2 chunks)
        let partial_chunk = [1u8; 1]; // Only 1 byte instead of full chunk
        partial_chunk.write(&mut buf2);

        let mut cursor2 = std::io::Cursor::new(buf2);
        assert!(matches!(
            BitVec::decode_cfg(&mut cursor2, &(..).into()),
            Err(CodecError::EndOfBuffer)
        ));

        // Test case 3: Empty buffer
        let buf3 = BytesMut::new();
        let mut cursor3 = std::io::Cursor::new(buf3);
        assert!(matches!(
            BitVec::decode_cfg(&mut cursor3, &(..).into()),
            Err(CodecError::EndOfBuffer)
        ));
    }

    #[test]
    fn test_push_pop_across_chunks() {
        let mut bv = BitVec::new();

        // Test push
        bv.push(true);
        assert_eq!(bv.len(), 1);
        assert_eq!(bv.get(0), Some(true));

        bv.push(false);
        assert_eq!(bv.len(), 2);
        assert_eq!(bv.get(1), Some(false));

        // Push across chunk boundary
        for i in 2..20 {
            bv.push(i % 2 == 0);
        }
        assert_eq!(bv.len(), 20);

        // Verify all values
        for i in 0..20 {
            let expected = if i == 0 {
                true
            } else if i == 1 {
                false
            } else {
                i % 2 == 0
            };
            assert_eq!(bv.get(i), Some(expected));
        }

        // Test pop
        for expected_len in (0..20).rev() {
            let popped = bv.pop();
            assert!(popped.is_some());
            assert_eq!(bv.len(), expected_len);
        }

        // Pop from empty
        assert_eq!(bv.pop(), None);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
    }

    #[test]
    fn test_bit_manipulation_at_boundaries() {
        let mut bv = BitVec::zeroes(16);

        // Test set/clear/toggle at various positions
        let test_positions = [0, 1, 7, 8, 15]; // Include byte and chunk boundaries

        for &pos in &test_positions {
            // Test set
            bv.set(pos);
            assert_eq!(bv.get(pos), Some(true));

            // Test clear
            bv.clear(pos);
            assert_eq!(bv.get(pos), Some(false));

            // Test toggle
            bv.toggle(pos); // false -> true
            assert_eq!(bv.get(pos), Some(true));
            bv.toggle(pos); // true -> false
            assert_eq!(bv.get(pos), Some(false));
        }

        // Test set_bit method
        bv.set_bit(5, true);
        assert_eq!(bv.get(5), Some(true));
        bv.set_bit(5, false);
        assert_eq!(bv.get(5), Some(false));
    }

    #[test]
    fn test_equality_with_trailing_bits() {
        // Create two BitVecs with same logical content but potentially different trailing bits
        let mut bv1 = BitVec::ones(5);
        let mut bv2 = BitVec::zeroes(5);

        // Make them logically identical
        for i in 0..5 {
            bv2.set(i);
        }

        // They should be equal despite potentially different trailing bits
        assert_eq!(bv1, bv2);

        // Test with different patterns
        bv1.clear_all();
        bv2.clear_all();
        bv1.set(1);
        bv1.set(3);
        bv2.set(1);
        bv2.set(3);
        assert_eq!(bv1, bv2);

        // Test inequality
        bv2.set(2);
        assert_ne!(bv1, bv2);
    }

    #[test]
    fn test_iterator_and_size_hint() {
        // Test empty iterator
        let bv = BitVec::new();
        let mut iter = bv.iter();
        assert_eq!(iter.len(), 0);
        assert_eq!(iter.next(), None);

        // Test iterator with various patterns
        let bv = BitVec::from(&[true, false, true, false, true]);
        let iter = bv.iter();
        assert_eq!(iter.len(), 5);

        let collected: Vec<bool> = iter.collect();
        assert_eq!(collected, vec![true, false, true, false, true]);

        // Test size_hint
        let mut iter = bv.iter();
        assert_eq!(iter.size_hint(), (5, Some(5)));
        iter.next();
        assert_eq!(iter.size_hint(), (4, Some(4)));
    }

    #[test]
    fn test_index_operator() {
        let bv = BitVec::from(&[true, false, true]);
        assert!(bv[0]);
        assert!(!bv[1]);
        assert!(bv[2]);
    }

    #[test]
    #[should_panic(expected = "Index out of bounds")]
    fn test_index_oob_panic() {
        let bv = BitVec::from(&[true, false]);
        let _ = bv[2];
    }

    #[test]
    fn test_different_chunk_sizes() {
        // Test with chunk size 1 (single byte chunks)
        let mut bv = super::BitVec::<1>::new();
        for i in 0..20 {
            bv.push(i % 2 == 0);
        }
        assert_eq!(bv.len(), 20);
        assert_eq!(bv.storage.len(), 3); // 20 bits = 3 chunks of 8 bits each

        // Test with larger chunk size
        let mut bv = super::BitVec::<4>::new();
        for i in 0..40 {
            bv.push(i % 3 == 0);
        }
        assert_eq!(bv.len(), 40);
        assert_eq!(bv.storage.len(), 2); // 40 bits = 2 chunks of 32 bits each

        // Test boundary conditions
        let mut bv = super::BitVec::<1>::new();

        // Fill 7 bits (not quite full)
        for _ in 0..7 {
            bv.push(true);
        }
        assert_eq!(bv.len(), 7);
        assert_eq!(bv.storage.len(), 1); // Still using the initial chunk

        // Add one more to exactly fill the chunk
        bv.push(false);
        assert_eq!(bv.len(), 8);
        assert_eq!(bv.storage.len(), 2); // prepare_next_chunk() was called

        // Add one more to use the new chunk
        bv.push(true);
        assert_eq!(bv.len(), 9);
        assert_eq!(bv.storage.len(), 2); // Still using the second chunk
    }
}

//! Bitmap implementation
//!
//! The bitmap is a compact representation of a sequence of bits, using chunks of bytes for a
//! more-efficient memory layout than doing [`Vec<bool>`].

#[cfg(not(feature = "std"))]
use alloc::{collections::VecDeque, vec::Vec};
use bytes::BufMut;
use commonware_codec::{
    Buf, EncodeSize, Error as CodecError, Read, ReadExt, Write, util::at_least,
};
use core::{
    fmt::{self, Formatter, Write as _},
    iter,
    ops::{BitAnd, BitOr, BitXor, Index, Range},
};
#[cfg(feature = "std")]
use std::collections::VecDeque;
#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg(feature = "std")]
mod atomic;
#[cfg(feature = "std")]
pub use atomic::Atomic;
mod prunable;
pub use prunable::Prunable;

pub mod historical;
commonware_macros::stability_mod!(ALPHA, pub mod roaring);

/// The default [BitMap] chunk size in bytes.
pub const DEFAULT_CHUNK_SIZE: usize = 8;

/// A bitmap that stores data in chunks of N bytes.
///
/// # Panics
///
/// Operations panic if `bit / CHUNK_SIZE_BITS > usize::MAX`. On 32-bit systems
/// with N=32, this occurs at bit >= 1,099,511,627,776.
#[derive(Clone, PartialEq, Eq, Hash)]
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct BitMap<const N: usize = DEFAULT_CHUNK_SIZE> {
    /// The bitmap itself, in chunks of size N bytes. Within each byte, lowest order bits are
    /// treated as coming before higher order bits in the bit ordering.
    ///
    /// Invariant: `chunks.len() == len.div_ceil(CHUNK_SIZE_BITS)`
    /// Invariant: All bits at index `i` where `i >= len` must be 0.
    chunks: VecDeque<[u8; N]>,

    /// The total number of bits stored in the bitmap.
    len: u64,
}

impl<const N: usize> BitMap<N> {
    const _CHUNK_SIZE_NON_ZERO_ASSERT: () = assert!(N > 0, "chunk size must be > 0");

    /// The size of a chunk in bits.
    pub const CHUNK_SIZE_BITS: u64 = Self::chunk_size_bits();

    #[inline(always)]
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, allow(unused, verus_impl_method_marker))]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result =>
        requires N as int * 8 <= usize::MAX,
        ensures result as int == N as int * 8,
    ))]
    const fn chunk_size_bits() -> u64 {
        (N * 8) as u64
    }

    /// A chunk of all 0s.
    pub const EMPTY_CHUNK: [u8; N] = [0u8; N];

    /// A chunk of all 1s.
    pub const FULL_CHUNK: [u8; N] = [u8::MAX; N];

    /* Constructors */

    /// Create a new empty bitmap.
    pub const fn new() -> Self {
        #[allow(path_statements)]
        Self::_CHUNK_SIZE_NON_ZERO_ASSERT; // Prevent compilation for N == 0

        Self {
            chunks: VecDeque::new(),
            len: 0,
        }
    }

    // Create a new empty bitmap with the capacity to hold `size` bits without reallocating.
    pub fn with_capacity(size: u64) -> Self {
        #[allow(path_statements)]
        Self::_CHUNK_SIZE_NON_ZERO_ASSERT; // Prevent compilation for N == 0

        Self {
            chunks: VecDeque::with_capacity(size.div_ceil(Self::CHUNK_SIZE_BITS) as usize),
            len: 0,
        }
    }

    /// Create a new bitmap with `size` bits, with all bits set to 0.
    pub fn zeroes(size: u64) -> Self {
        #[allow(path_statements)]
        Self::_CHUNK_SIZE_NON_ZERO_ASSERT; // Prevent compilation for N == 0

        let num_chunks = size.div_ceil(Self::CHUNK_SIZE_BITS) as usize;
        let mut chunks = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            chunks.push_back(Self::EMPTY_CHUNK);
        }
        Self { chunks, len: size }
    }

    /// Create a new bitmap with `size` bits, with all bits set to 1.
    pub fn ones(size: u64) -> Self {
        #[allow(path_statements)]
        Self::_CHUNK_SIZE_NON_ZERO_ASSERT; // Prevent compilation for N == 0

        let num_chunks = size.div_ceil(Self::CHUNK_SIZE_BITS) as usize;
        let mut chunks = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            chunks.push_back(Self::FULL_CHUNK);
        }
        let mut result = Self { chunks, len: size };
        // Clear trailing bits to maintain invariant
        result.clear_trailing_bits();
        result
    }

    /// Create a bitmap of `len` bits directly from its chunk representation.
    ///
    /// # Panics
    ///
    /// Panics if the chunk count does not match `len` or a bit at index >= `len` is set.
    #[cfg(feature = "std")]
    fn from_chunks(chunks: VecDeque<[u8; N]>, len: u64) -> Self {
        assert_eq!(
            chunks.len() as u64,
            len.div_ceil(Self::CHUNK_SIZE_BITS),
            "chunk count does not match len"
        );
        let mut bitmap = Self { chunks, len };
        assert!(!bitmap.clear_trailing_bits(), "bit past len set");
        bitmap
    }

    /* Length */

    /// Return the number of bits currently stored in the bitmap.
    #[inline]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Returns true if the bitmap is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns true if the bitmap length is aligned to a chunk boundary.
    #[inline]
    pub const fn is_chunk_aligned(&self) -> bool {
        self.len.is_multiple_of(Self::CHUNK_SIZE_BITS)
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
        Self::get_bit_from_chunk(chunk, bit)
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
        &self.chunks[Self::to_chunk_index(bit)]
    }

    /// Get a reference to a chunk by its index in the current bitmap.
    /// Note this is an index into the chunks, not a bit.
    ///
    /// # Warning
    ///
    /// Panics if the `chunk` is out of bounds.
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
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, allow(unused, verus_impl_method_marker))]
    #[cfg_attr(verus_keep_ghost, verus_spec(requires N > 0,))]
    pub const fn get_bit_from_chunk(chunk: &[u8; N], bit: u64) -> bool {
        let byte = Self::chunk_byte_offset(bit);
        let byte = chunk[byte];
        let mask = Self::chunk_byte_bitmask(bit);
        (byte & mask) != 0
    }

    /// Return the last chunk of the bitmap and its size in bits.
    ///
    /// # Panics
    ///
    /// Panics if bitmap is empty.
    #[inline]
    fn last_chunk(&self) -> (&[u8; N], u64) {
        let rem = self.len % Self::CHUNK_SIZE_BITS;
        let bits_in_last_chunk = if rem == 0 { Self::CHUNK_SIZE_BITS } else { rem };
        (self.chunks.back().unwrap(), bits_in_last_chunk)
    }

    /* Setters */

    /// Extend the bitmap to `new_len` bits, filling new positions with zero.
    /// No-op if `new_len <= self.len`.
    pub fn extend_to(&mut self, new_len: u64) {
        if new_len <= self.len {
            return;
        }
        // Allocate any needed new chunks (all zeroed).
        let new_chunks_needed = new_len.div_ceil(Self::CHUNK_SIZE_BITS) as usize;
        let current_chunks = self.chunks.len();
        for _ in current_chunks..new_chunks_needed {
            self.chunks.push_back(Self::EMPTY_CHUNK);
        }
        self.len = new_len;
    }

    /// Add a single bit to the bitmap.
    pub fn push(&mut self, bit: bool) {
        // Check if we need a new chunk
        if self.is_chunk_aligned() {
            self.chunks.push_back(Self::EMPTY_CHUNK);
        }

        // Append to the last chunk
        if bit {
            let last_chunk = self.chunks.back_mut().unwrap();
            let chunk_byte = Self::chunk_byte_offset(self.len);
            last_chunk[chunk_byte] |= Self::chunk_byte_bitmask(self.len);
        }
        // If bit is false, just advance len -- the bit is already 0
        self.len += 1;
    }

    /// Remove and return the last bit from the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bitmap is empty.
    pub fn pop(&mut self) -> bool {
        assert!(!self.is_empty(), "Cannot pop from empty bitmap");

        // Get the bit value at the last position
        let last_bit_pos = self.len - 1;
        let bit = Self::get_bit_from_chunk(self.chunks.back().unwrap(), last_bit_pos);

        // Decrement length
        self.len -= 1;

        // Clear the bit we just popped to maintain invariant (if it was 1)
        if bit {
            let chunk_byte = Self::chunk_byte_offset(last_bit_pos);
            let mask = Self::chunk_byte_bitmask(last_bit_pos);
            self.chunks.back_mut().unwrap()[chunk_byte] &= !mask;
        }

        // Remove the last chunk if it's now empty
        if self.is_chunk_aligned() {
            self.chunks.pop_back();
        }

        bit
    }

    /// Shrink the bitmap to `new_len` bits, discarding trailing bits.
    ///
    /// # Panics
    ///
    /// Panics if `new_len > self.len()`.
    pub fn truncate(&mut self, new_len: u64) {
        assert!(new_len <= self.len(), "cannot truncate to a larger size");

        // Pop single bits until we can remove full chunks.
        while self.len > new_len && !self.is_chunk_aligned() {
            self.pop();
        }

        // Pop full chunks from the back.
        while self.len - new_len >= Self::CHUNK_SIZE_BITS {
            self.pop_chunk();
        }

        // Pop remaining individual bits.
        while self.len > new_len {
            self.pop();
        }
    }

    /// Remove and return the last complete chunk from the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if the bitmap has fewer than `CHUNK_SIZE_BITS` bits or if not chunk-aligned.
    pub(super) fn pop_chunk(&mut self) -> [u8; N] {
        assert!(
            self.len() >= Self::CHUNK_SIZE_BITS,
            "cannot pop chunk: bitmap has fewer than CHUNK_SIZE_BITS bits"
        );
        assert!(
            self.is_chunk_aligned(),
            "cannot pop chunk when not chunk aligned"
        );

        // Remove and return the last data chunk
        let chunk = self.chunks.pop_back().expect("chunk must exist");
        self.len -= Self::CHUNK_SIZE_BITS;
        chunk
    }

    /// Flips the given bit.
    ///
    /// # Panics
    ///
    /// Panics if `bit` is out of bounds.
    #[inline]
    pub fn flip(&mut self, bit: u64) {
        self.assert_bit(bit);
        let chunk = Self::to_chunk_index(bit);
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

        let chunk = &mut self.chunks[Self::to_chunk_index(bit)];
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
        // Clear trailing bits to maintain invariant
        if bit {
            self.clear_trailing_bits();
        }
    }

    // Add a byte's worth of bits to the bitmap.
    //
    // # Warning
    //
    // Panics if self.len is not byte aligned.
    fn push_byte(&mut self, byte: u8) {
        assert!(
            self.len.is_multiple_of(8),
            "cannot add byte when not byte aligned"
        );

        // Check if we need a new chunk
        if self.is_chunk_aligned() {
            self.chunks.push_back(Self::EMPTY_CHUNK);
        }

        let chunk_byte = Self::chunk_byte_offset(self.len);
        self.chunks.back_mut().unwrap()[chunk_byte] = byte;
        self.len += 8;
    }

    /// Add a chunk of bits to the bitmap.
    ///
    /// # Warning
    ///
    /// Panics if self.len is not chunk aligned.
    pub fn push_chunk(&mut self, chunk: &[u8; N]) {
        assert!(
            self.is_chunk_aligned(),
            "cannot add chunk when not chunk aligned"
        );
        self.chunks.push_back(*chunk);
        self.len += Self::CHUNK_SIZE_BITS;
    }

    /* Invariant Maintenance */

    /// Clear all bits in the last chunk that are >= self.len to maintain the invariant.
    /// Returns true if any bits were flipped from 1 to 0.
    fn clear_trailing_bits(&mut self) -> bool {
        if self.chunks.is_empty() {
            return false;
        }

        let pos_in_chunk = self.len % Self::CHUNK_SIZE_BITS;
        if pos_in_chunk == 0 {
            // Chunk is full -- there are no trailing bits to clear.
            return false;
        }

        let mut flipped_any = false;
        let last_chunk = self.chunks.back_mut().unwrap();

        // Clear whole bytes after the last valid bit
        let last_byte_index = ((pos_in_chunk - 1) / 8) as usize;
        for byte in last_chunk.iter_mut().skip(last_byte_index + 1) {
            if *byte != 0 {
                flipped_any = true;
                *byte = 0;
            }
        }

        // Clear the trailing bits in the last partial byte
        let bits_in_last_byte = pos_in_chunk % 8;
        if bits_in_last_byte != 0 {
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

    /// Remove the first `chunks` chunks from the bitmap.
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
        // Update len to reflect the removed chunks
        let bits_removed = (chunks as u64) * Self::CHUNK_SIZE_BITS;
        self.len = self.len.saturating_sub(bits_removed);
    }

    /// Prepend a chunk to the beginning of the bitmap.
    pub(super) fn prepend_chunk(&mut self, chunk: &[u8; N]) {
        self.chunks.push_front(*chunk);
        self.len += Self::CHUNK_SIZE_BITS;
    }

    /// Overwrite a chunk's data at the given index.
    ///
    /// Replaces the entire chunk data, including any bits beyond `len()` in the last chunk.
    /// The caller is responsible for ensuring `chunk_data` has the correct bit pattern
    /// (e.g., zeros beyond the valid length if this is a partial last chunk).
    ///
    /// # Panics
    ///
    /// Panics if chunk_index is out of bounds.
    pub(super) fn set_chunk_by_index(&mut self, chunk_index: usize, chunk_data: &[u8; N]) {
        assert!(
            chunk_index < self.chunks.len(),
            "chunk index {chunk_index} out of bounds (chunks_len: {})",
            self.chunks.len()
        );
        self.chunks[chunk_index].copy_from_slice(chunk_data);
    }

    /* Counting */

    /// Returns the number of bits set to 1.
    #[inline]
    pub fn count_ones(&self) -> u64 {
        // Thanks to the invariant that trailing bits are always 0,
        // we can simply count all set bits in all chunks.
        // Iterate over both contiguous deque segments and count 64-bit words first.
        let (front, back) = self.chunks.as_slices();
        Self::count_ones_in_chunk_slice(front) + Self::count_ones_in_chunk_slice(back)
    }

    #[inline]
    fn count_ones_in_chunk_slice(chunks: &[[u8; N]]) -> u64 {
        let mut total = 0u64;
        let (words, remainder) = chunks.as_flattened().as_chunks::<8>();
        for word in words {
            total += u64::from_le_bytes(*word).count_ones() as u64;
        }
        for byte in remainder {
            total += byte.count_ones() as u64;
        }
        total
    }

    /// Returns the number of bits set to 0.
    #[inline]
    pub fn count_zeros(&self) -> u64 {
        self.len() - self.count_ones()
    }

    /* Indexing Helpers */

    /// Convert a bit offset into a bitmask for the byte containing that bit.
    #[inline]
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, allow(unused, verus_impl_method_marker))]
    #[cfg_attr(verus_keep_ghost, verus_spec())]
    pub(super) const fn chunk_byte_bitmask(bit: u64) -> u8 {
        1 << (bit % 8)
    }

    /// Convert a bit into the index of the byte within a chunk containing the bit.
    #[inline]
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, allow(unused, verus_impl_method_marker))]
    #[cfg_attr(verus_keep_ghost, verus_spec(result => requires N > 0, ensures result < N,))]
    pub(super) const fn chunk_byte_offset(bit: u64) -> usize {
        ((bit / 8) % N as u64) as usize
    }

    /// Convert a bit into the index of the chunk it belongs to.
    ///
    /// # Panics
    ///
    /// Panics if the chunk index overflows `usize`.
    #[inline]
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, allow(unused, verus_impl_method_marker))]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result =>
        requires N > 0, N as int * 8 <= usize::MAX,
            bit as int / (N as int * 8) <= usize::MAX,
        ensures result as int == bit as int / (N as int * 8),
    ))]
    pub(super) fn to_chunk_index(bit: u64) -> usize {
        let chunk = bit / Self::chunk_size_bits();
        #[cfg(not(verus_keep_ghost))]
        assert!(
            chunk <= usize::MAX as u64,
            "chunk overflow: {chunk} exceeds usize::MAX",
        );
        #[cfg(verus_keep_ghost)]
        proof! { assert(chunk <= usize::MAX as u64); }
        chunk as usize
    }

    /* Iterator */

    /// Creates an iterator over the bits.
    pub const fn iter(&self) -> Iterator<'_, N> {
        Iterator {
            bitmap: self,
            pos: 0,
        }
    }

    /// Returns an iterator over the indices of set bits.
    pub fn ones_iter(&self) -> OnesIter<'_, Self, N> {
        Readable::ones_iter_from(self, 0)
    }

    /* Bitwise Operations */

    /// Helper for binary operations
    #[inline]
    fn binary_op<F: Fn(u8, u8) -> u8>(&mut self, other: &Self, op: F) {
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
    pub fn and(&mut self, other: &Self) {
        self.binary_op(other, |a, b| a & b);
    }

    /// Performs a bitwise OR with another BitMap.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn or(&mut self, other: &Self) {
        self.binary_op(other, |a, b| a | b);
    }

    /// Performs a bitwise XOR with another BitMap.
    ///
    /// # Panics
    ///
    /// Panics if the lengths don't match.
    pub fn xor(&mut self, other: &Self) {
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
    fn assert_eq_len(&self, other: &Self) {
        assert_eq!(
            self.len(),
            other.len(),
            "BitMap lengths don't match: {} vs {}",
            self.len(),
            other.len()
        );
    }

    /// Check if all the bits in a given range are 0.
    ///
    /// Returns `true` if every index in the range is unset (i.e.
    /// [`Self::get`] returns `false`). Returns `true` if the range
    /// is empty.
    ///
    /// # Panics
    ///
    /// Panics if `range.end` exceeds the length of the bitmap.
    ///
    /// # Examples
    ///
    /// ```
    /// use commonware_utils::bitmap::BitMap;
    ///
    /// let mut bitmap = BitMap::<8>::zeroes(128);
    /// assert!(bitmap.is_unset(0..128));
    ///
    /// bitmap.set(64, true);
    /// assert!(bitmap.is_unset(0..64));
    /// assert!(!bitmap.is_unset(0..65));
    /// ```
    pub fn is_unset(&self, range: Range<u64>) -> bool {
        assert!(
            range.end <= self.len(),
            "range end {} out of bounds (len: {})",
            range.end,
            self.len()
        );
        if range.start >= range.end {
            return true;
        }
        let start = range.start;
        let end = range.end;

        // We know this can't underflow, because start < end.
        //
        // We now want "end" to represent the last bit we want to consider.
        let end = end - 1;

        // Get the chunks containing the start and end bits.
        let first_chunk = Self::to_chunk_index(start);
        let last_chunk = Self::to_chunk_index(end);

        // All of these chunks require all of their bits to be checked.
        // If first_chunk == last_chunk, we skip the loop.
        for full_chunk in (first_chunk + 1)..last_chunk {
            if self.chunks[full_chunk] != Self::EMPTY_CHUNK {
                return false;
            }
        }

        // Check first chunk tail (or whole range if first_chunk == last_chunk).
        let start_byte = Self::chunk_byte_offset(start);
        let end_byte = Self::chunk_byte_offset(end);
        let start_mask = (0xFFu16 << ((start & 0b111) as u32)) as u8;
        let end_mask = (0xFFu16 >> (7 - ((end & 0b111) as u32))) as u8;
        let first = &self.chunks[first_chunk];
        let first_end_byte = if first_chunk == last_chunk {
            end_byte
        } else {
            N - 1
        };
        for (i, &byte) in first
            .iter()
            .enumerate()
            .take(first_end_byte + 1)
            .skip(start_byte)
        {
            let mut mask = 0xFFu8;
            if i == start_byte {
                mask &= start_mask;
            }
            if first_chunk == last_chunk && i == end_byte {
                mask &= end_mask;
            }
            if (byte & mask) != 0 {
                return false;
            }
        }
        if first_chunk == last_chunk {
            return true;
        }

        // Check last chunk head.
        let last = &self.chunks[last_chunk];
        for (i, &byte) in last.iter().enumerate().take(end_byte + 1) {
            let mask = if i == end_byte { end_mask } else { 0xFF };
            if (byte & mask) != 0 {
                return false;
            }
        }

        true
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
        let mut bv = Self::with_capacity(bools.len() as u64);
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
        if value { &true } else { &false }
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

        // Write all chunks
        let (front, back) = self.chunks.as_slices();
        buf.put_slice(front.as_flattened());
        buf.put_slice(back.as_flattened());
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

        // Calculate how many chunks we need to read
        let num_chunks = len.div_ceil(Self::CHUNK_SIZE_BITS) as usize;

        // Parse chunks
        let mut chunks = VecDeque::with_capacity(num_chunks);
        for _ in 0..num_chunks {
            at_least(buf, N)?;
            let mut chunk = [0u8; N];
            buf.copy_to_slice(&mut chunk);
            chunks.push_back(chunk);
        }

        let mut result = Self { chunks, len };

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
        // Size of length prefix + all chunks
        self.len().encode_size() + (self.chunks.len() * N)
    }
}

/// Iterator over bits in a [BitMap].
pub struct Iterator<'a, const N: usize> {
    /// Reference to the BitMap being iterated over
    bitmap: &'a BitMap<N>,

    /// Current index in the BitMap
    pos: u64,
}

impl<const N: usize> iter::Iterator for Iterator<'_, N> {
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

// Readable implementations supply a coherent chunk snapshot. Callers keep it unchanged
// throughout iteration, including when the source uses interior mutability.
#[cfg(not(verus_keep_ghost))]
#[doc(hidden)]
pub trait ScanModel<const N: usize> {}

#[cfg(not(verus_keep_ghost))]
impl<B: ?Sized, const N: usize> ScanModel<N> for B {}

#[cfg(verus_keep_ghost)]
verus! {
pub trait ScanModel<const N: usize> {
    spec fn scan_snapshot(&self) -> scan_model::Snapshot;
    spec fn scan_coherent(&self) -> bool;
}

impl<const N: usize> ScanModel<N> for BitMap<N> {
    closed spec fn scan_snapshot(&self) -> scan_model::Snapshot {
        scan_model::Snapshot {
            len: self.len,
            pruned: 0,
            chunks: IMap::new(|i: int| 0 <= i < self.chunks@.len(), |i: int| self.chunks@[i]@),
        }
    }

    closed spec fn scan_coherent(&self) -> bool { true }
}

mod scan_model {
    use super::*;
    use vstd::arithmetic::div_mod::{
        lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse,
    };

    pub struct Snapshot {
        pub len: u64,
        pub pruned: usize,
        pub chunks: IMap<int, Seq<u8>>,
    }

    pub open spec fn snapshot<B: ScanModel<N> + ?Sized, const N: usize>(b: &B) -> Snapshot {
        b.scan_snapshot()
    }

    pub open spec fn set(word: u64, i: u64) -> bool { scan_proof::bit(word, i) == 1 }

    // A constructible OnesIter has at least N+32 bytes on the pinned 64-bit
    // compiler, whose object-size limit is 2^61. The 32-bit width bound is smaller.
    pub open spec fn valid<B: ScanModel<N> + ?Sized, const N: usize>(b: &B) -> bool {
        let s = snapshot::<B, N>(b);
        let c = N as int * 8;
        &&& b.scan_coherent()
        &&& N > 0
        &&& c <= usize::MAX
        &&& N as int + 32 < 0x2000_0000_0000_0000int
        &&& s.pruned as int * c <= s.len
        &&& forall|j: int| s.pruned <= j && j * c < s.len ==>
            s.chunks.dom().contains(j) && #[trigger] s.chunks[j].len() == N
    }

    pub open spec fn addressable<B: ScanModel<N> + ?Sized, const N: usize>(b: &B, pos: int) -> bool {
        let s = snapshot::<B, N>(b);
        pos >= s.len || s.pruned as int * (N as int * 8) == s.len
            || (s.len - 1) / (N as int * 8) <= usize::MAX
    }

    pub open spec fn truth<B: ScanModel<N> + ?Sized, const N: usize>(b: &B, i: int) -> bool {
        let s = snapshot::<B, N>(b);
        let c = N as int * 8;
        s.pruned as int * c <= i < s.len
            && set(s.chunks[i / c][(i % c) / 8] as u64, ((i % c) % 8) as u64)
    }

    pub proof fn zero_word()
        ensures forall|i: u64| i < 64 ==> !#[trigger] set(0, i),
    {
        assert forall|i: u64| i < 64 implies !#[trigger] set(0, i) by {
            assert((0u64 >> i) & 1 == 0) by(bit_vector);
        }
    }

    pub proof fn aligned_base(p: int, c: int)
        requires p >= 0, c > 0,
        ensures ({
            let b = p / c * c + (p % c) / 64 * 64;
            &&& 0 <= b <= p < b + 64
            &&& b / c == p / c
            &&& b % c == (p % c) / 64 * 64
            &&& (b % c) % 64 == 0
            &&& (b % c) % 8 == 0
            &&& p < b + c - b % c
        }),
    {
        lemma_fundamental_div_mod(p, c);
        let r = p % c;
        lemma_fundamental_div_mod(r, 64);
        let a = r / 64 * 64;
        assert(p / c * c == c * (p / c)) by(nonlinear_arith);
        assert(0 <= p / c * c <= p) by(nonlinear_arith)
            requires p >= 0, c > 0, 0 <= p % c < c, p == c * (p / c) + p % c;
        lemma_fundamental_div_mod_converse(p / c * c + a, c, p / c, a);
        lemma_fundamental_div_mod_converse(a, 64, r / 64, 0);
        assert(a == (r / 64 * 8) * 8);
        lemma_fundamental_div_mod_converse(a, 8, r / 64 * 8, 0);
    }

    pub proof fn chunk_index(p: int, c: int, pruned: int)
        requires c > 0, pruned >= 0, pruned * c <= p,
        ensures pruned <= p / c, p / c * c <= p,
    {
        lemma_fundamental_div_mod(p, c);
        vstd::arithmetic::div_mod::lemma_div_by_multiple(pruned, c);
        vstd::arithmetic::div_mod::lemma_div_is_ordered(pruned * c, p, c);
        assert(p / c * c == c * (p / c)) by(nonlinear_arith);
    }

    pub proof fn chunk_offset(b: int, c: int, i: int)
        requires b >= 0, c > 0, 0 <= i, b % c + i < c,
        ensures (b + i) / c == b / c, (b + i) % c == b % c + i,
    {
        lemma_fundamental_div_mod(b, c);
        assert(b + i == (b / c) * c + (b % c + i)) by(nonlinear_arith)
            requires b == c * (b / c) + b % c;
        lemma_fundamental_div_mod_converse(b + i, c, b / c, b % c + i);
    }

    pub proof fn advance(b: int, c: int)
        requires b >= 0, c > 0, (b % c) % 64 == 0,
        ensures ({
            let same = b % c + 64 < c;
            let n = b + if same { 64 } else { c - b % c };
            &&& n > b
            &&& (n % c) % 64 == 0
            &&& (n % c) % 8 == 0
            &&& if same { n / c == b / c } else { n / c == b / c + 1 }
        }),
    {
        let r = b % c;
        lemma_fundamental_div_mod(b, c);
        lemma_fundamental_div_mod(r, 64);
        if r + 64 < c {
            chunk_offset(b, c, 64);
            lemma_fundamental_div_mod_converse(r + 64, 64, r / 64 + 1, 0);
            assert(r + 64 == (r / 64 + 1) * 8 * 8);
            lemma_fundamental_div_mod_converse(r + 64, 8, (r / 64 + 1) * 8, 0);
        } else {
            assert(b + c - r == (b / c + 1) * c) by(nonlinear_arith)
                requires b == c * (b / c) + r;
            lemma_fundamental_div_mod_converse(b + c - r, c, b / c + 1, 0);
        }
    }
}

impl<'a, B: ScanModel<N>, const N: usize> OnesIter<'a, B, N> {
    pub closed spec fn source(&self) -> &'a B { self.bitmap }
    pub closed spec fn length(&self) -> u64 { self.len }

    pub closed spec fn end(&self) -> int {
        let c = N as int * 8;
        vstd::math::min(self.len as int,
            vstd::math::min(self.base as int + 64, self.base as int + c - self.base as int % c))
    }

    pub closed spec fn pending(&self, i: int) -> bool {
        (self.base <= i < self.end() && scan_model::set(self.word, (i - self.base) as u64))
            || (self.end() <= i < self.len && scan_model::truth::<B, N>(self.bitmap, i))
    }

    #[verifier::type_invariant]
    pub closed spec fn safe(&self) -> bool {
        let c = N as int * 8;
        let s = scan_model::snapshot::<B, N>(self.bitmap);
        &&& scan_model::valid::<B, N>(self.bitmap)
        &&& self.len == s.len
        &&& self.base <= self.len
        &&& self.base == self.len ==> self.word == 0
        &&& self.base < self.len ==> {
            &&& s.pruned as int * c <= self.base
            &&& (self.base as int % c) % 64 == 0
            &&& (self.len - 1) / c <= usize::MAX
        }
        &&& forall|i: u64| i < 64 && #[trigger] scan_model::set(self.word, i) ==>
            self.base as int + i < self.len && self.base as int % c + i < c
    }

    pub closed spec fn wf(&self) -> bool {
        let c = N as int * 8;
        let s = scan_model::snapshot::<B, N>(self.bitmap);
        &&& self.safe()
        &&& self.base < self.len ==> {
            &&& self.chunk@ == s.chunks[self.base as int / c]
        }
        &&& forall|i: u64| i < 64 && #[trigger] scan_model::set(self.word, i) ==>
            scan_model::truth::<B, N>(self.bitmap, self.base as int + i)
    }

    proof fn zero_pending(&self)
        requires self.word == 0,
        ensures forall|i: int| #[trigger] self.pending(i) <==>
            self.end() <= i < self.len && scan_model::truth::<B, N>(self.bitmap, i),
    {
        scan_model::zero_word();
        assert forall|i: int| #[trigger] self.pending(i) <==>
            (self.end() <= i < self.len && scan_model::truth::<B, N>(self.bitmap, i)) by {
            if self.base <= i < self.end() {
                assert(0 <= i - self.base < 64);
                assert(!scan_model::set(0, (i - self.base) as u64));
            }
        }
    }

    proof fn establish_word(&self, cut: int)
        requires
            scan_model::valid::<B, N>(self.bitmap),
            scan_model::addressable::<B, N>(self.bitmap, self.base as int),
            self.len == scan_model::snapshot::<B, N>(self.bitmap).len,
            scan_model::snapshot::<B, N>(self.bitmap).pruned as int * (N as int * 8) <= self.base,
            self.base < self.len,
            (self.base as int % (N as int * 8)) % 64 == 0,
            self.chunk@ == scan_model::snapshot::<B, N>(self.bitmap).chunks[self.base as int / (N as int * 8)],
            self.base <= cut < self.end(),
            forall|i: u64| i < 64 ==> (#[trigger] scan_model::set(self.word, i) <==>
                cut <= self.base as int + i < self.len && scan_proof::chunk_bit(
                    self.chunk@, self.base as int % (N as int * 8) + i)),
        ensures
            self.wf(),
            forall|i: int| #[trigger] self.pending(i) <==>
                cut <= i && scan_model::truth::<B, N>(self.bitmap, i),
    {
        let c = N as int * 8;
        assert forall|i: u64| i < 64 && #[trigger] scan_model::set(self.word, i) implies
            self.base as int + i < self.len
                && self.base as int % c + i < c
                && scan_model::truth::<B, N>(self.bitmap, self.base as int + i) by {
            scan_model::chunk_offset(self.base as int, c, i as int);
        }
        assert forall|i: int| #[trigger] self.pending(i) <==>
            (cut <= i && scan_model::truth::<B, N>(self.bitmap, i)) by {
            if self.base <= i < self.end() {
                let k = (i - self.base) as u64;
                assert(k < 64);
                scan_model::chunk_offset(self.base as int, c, k as int);
                assert(scan_model::set(self.word, k) <==>
                    cut <= i && scan_model::truth::<B, N>(self.bitmap, i));
            }
        }
    }
}

// Standard adaptor contracts requiring a prophetic sequence are outside this theorem.
// The scanner uses the explicit pending-set transition and enumeration client below.
impl<'a, B: Readable<N>, const N: usize> vstd::std_specs::iter::IteratorSpecImpl
    for OnesIter<'a, B, N>
{
    open spec fn obeys_prophetic_iter_laws(&self) -> bool { false }
    #[verifier::prophetic]
    open spec fn remaining(&self) -> Seq<u64> { Seq::empty() }
    #[verifier::prophetic]
    open spec fn will_return_none(&self) -> bool { false }
    open spec fn decrease(&self) -> Option<nat> { None }
    open spec fn peek(&self, _index: int) -> Option<u64> { None }
}

// The client records only values returned by the production constructor and next.
// Its finite progress measure composes the per-call contract into exact enumeration.
fn verify_enumeration<B: Readable<N>, const N: usize>(bitmap: &B, pos: u64)
    -> (result: Ghost<Seq<u64>>)
    requires scan_model::valid::<B, N>(bitmap), scan_model::addressable::<B, N>(bitmap, pos as int),
    ensures
        forall|bit: u64| #[trigger] result@.contains(bit) <==>
            pos <= bit && scan_model::truth::<B, N>(bitmap, bit as int),
        forall|i: int, j: int| 0 <= i < j < result@.len() ==>
            #[trigger] result@[i] < #[trigger] result@[j],
{
    let mut iter = bitmap.ones_iter_from(pos);
    let mut floor = pos.min(bitmap.len());
    let ghost mut values = Seq::<u64>::empty();
    loop
        invariant
            iter.wf(), iter.source() == bitmap,
            floor <= iter.length(),
            forall|bit: u64| #[trigger] values.contains(bit) <==>
                pos <= bit && scan_model::truth::<B, N>(bitmap, bit as int) && bit < floor,
            forall|i: int| #[trigger] iter.pending(i) <==>
                floor <= i && pos <= i && scan_model::truth::<B, N>(bitmap, i),
            forall|i: int, j: int| 0 <= i < j < values.len() ==>
                #[trigger] values[i] < #[trigger] values[j],
        decreases iter.length() - floor + 1,
    {
        let ghost before = iter;
        let result = iter.next();
        match result {
            None => {
                let again = iter.next();
                assert(again.is_none());
                assert forall|bit: u64| #[trigger] values.contains(bit) <==>
                    (pos <= bit && scan_model::truth::<B, N>(bitmap, bit as int)) by {
                    if pos <= bit && scan_model::truth::<B, N>(bitmap, bit as int) {
                        assert(!before.pending(bit as int));
                        assert(bit < floor);
                    }
                }
                return Ghost(values);
            },
            Some(bit) => {
                assert(bit < iter.length());
                assert(bit >= floor);
                proof {
                    let previous = values;
                    values = values.push(bit);
                    assert forall|i: int, j: int| 0 <= i < j < values.len() implies
                        #[trigger] values[i] < #[trigger] values[j] by {
                        if j == previous.len() {
                            assert(previous.contains(previous[i]));
                        }
                    }
                    assert forall|b: u64| #[trigger] values.contains(b) <==>
                        (pos <= b && scan_model::truth::<B, N>(bitmap, b as int) && b < bit + 1) by {
                        vstd::seq_lib::lemma_seq_contains_after_push(previous, bit, b);
                        assert(values.contains(b) <==> previous.contains(b) || b == bit);
                        if floor <= b < bit {
                            assert(!before.pending(b as int));
                        }
                    }
                }
                floor = bit + 1;
            },
        }
    }
}

// Arbitrary bytes in a concrete non-word-sized bitmap inhabit the input contract.
fn verify_snapshot_domain(bytes: [u8; 3])
{
    let mut chunks = VecDeque::new();
    chunks.push_back(bytes);
    let bitmap = BitMap::<3> { chunks, len: 24 };
    assert(scan_model::valid::<BitMap<3>, 3>(&bitmap));
}
}

/// Read-only access to a bitmap's chunks and metadata.
#[cfg_attr(verus_keep_ghost, verifier::verify)]
pub trait Readable<const N: usize>: ScanModel<N> {
    /// Return the number of complete (fully filled) chunks.
    fn complete_chunks(&self) -> usize;

    /// Return the chunk data at the given absolute chunk index.
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result =>
        requires scan_model::valid::<Self, N>(self),
            scan_model::snapshot::<Self, N>(self).pruned <= chunk,
            chunk as int * (N as int * 8) < scan_model::snapshot::<Self, N>(self).len,
        ensures result@ == scan_model::snapshot::<Self, N>(self).chunks[chunk as int],
    ))]
    fn get_chunk(&self, chunk: usize) -> [u8; N];

    /// Return the last chunk and its size in bits.
    fn last_chunk(&self) -> ([u8; N], u64);

    /// Return the number of pruned chunks.
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result => requires scan_model::valid::<Self, N>(self),
        ensures result == scan_model::snapshot::<Self, N>(self).pruned,
    ))]
    fn pruned_chunks(&self) -> usize;

    /// Return the total number of bits.
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result => requires scan_model::valid::<Self, N>(self),
        ensures result == scan_model::snapshot::<Self, N>(self).len,
    ))]
    fn len(&self) -> u64;

    /// Returns true if the bitmap is empty.
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, verus_spec(requires scan_model::valid::<Self, N>(self),))]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the number of pruned bits (i.e. pruned chunks * bits per chunk).
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result => requires scan_model::valid::<Self, N>(self),
        ensures result as int == scan_model::snapshot::<Self, N>(self).pruned as int * (N as int * 8),
    ))]
    fn pruned_bits(&self) -> u64 {
        (self.pruned_chunks() as u64) * BitMap::<N>::chunk_size_bits()
    }

    /// Return the value of a single bit.
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        requires scan_model::valid::<Self, N>(self),
            scan_model::snapshot::<Self, N>(self).pruned as int * (N as int * 8) <= bit,
            bit < scan_model::snapshot::<Self, N>(self).len,
            bit as int / (N as int * 8) <= usize::MAX,
    ))]
    fn get_bit(&self, bit: u64) -> bool {
        #[cfg(verus_keep_ghost)]
        proof! {
            let c = N as int * 8;
            vstd::arithmetic::div_mod::lemma_div_is_ordered(bit as int, scan_model::snapshot::<Self, N>(self).len as int - 1, c);
            scan_model::chunk_index(bit as int, c, scan_model::snapshot::<Self, N>(self).pruned as int);
        }
        let chunk = self.get_chunk(BitMap::<N>::to_chunk_index(bit));
        BitMap::<N>::get_bit_from_chunk(&chunk, bit % BitMap::<N>::chunk_size_bits())
    }

    /// Returns an iterator over the indices of set bits starting from `pos`.
    ///
    /// If `pos` falls within a pruned region, iteration starts at the first
    /// unpruned bit instead.
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result => requires scan_model::valid::<Self, N>(self),
            scan_model::addressable::<Self, N>(self, pos as int),
        ensures result.wf(), result.source() == self,
            forall|i: int| #[trigger] result.pending(i)
                <==> pos <= i && scan_model::truth::<Self, N>(self, i),
    ))]
    fn ones_iter_from(&self, pos: u64) -> OnesIter<'_, Self, N>
    where
        Self: Sized,
    {
        let len = self.len();
        let pruned_start = self.pruned_bits();
        let pos = pos.max(pruned_start);
        #[cfg(verus_keep_ghost)]
        proof! { scan_model::zero_word(); }
        let mut iter = OnesIter {
            bitmap: self,
            len,
            base: len,
            word: 0,
            chunk: [0; N],
        };
        if pos < len {
            #[cfg(verus_keep_ghost)]
            proof! {
                let c = N as int * 8;
                scan_model::aligned_base(pos as int, c);
                vstd::arithmetic::div_mod::lemma_div_is_ordered(pos as int, len as int - 1, c);
                assert(pruned_start as int == scan_model::snapshot::<Self, N>(self).pruned as int * c);
                scan_model::chunk_index(pos as int, c, scan_model::snapshot::<Self, N>(self).pruned as int);
            }
            let chunk_idx = BitMap::<N>::to_chunk_index(pos);
            let chunk_start = chunk_idx as u64 * BitMap::<N>::chunk_size_bits();
            iter.chunk = self.get_chunk(chunk_idx);
            #[cfg(verus_keep_ghost)]
            proof! {
                let c = N as int * 8;
                let b = chunk_start as int + (pos - chunk_start) / 64 * 64;
                assert(pruned_start <= b) by(nonlinear_arith)
                    requires pruned_start as int == scan_model::snapshot::<Self, N>(self).pruned as int * c,
                        scan_model::snapshot::<Self, N>(self).pruned <= chunk_idx,
                        chunk_start as int == chunk_idx as int * c,
                        b >= chunk_start;
                let future = OnesIter { base: b as u64, ..iter };
                assert(future.safe());
            }
            iter.base = chunk_start + (pos - chunk_start) / 64 * 64;
            #[cfg(verus_keep_ghost)]
            proof! {
                assert(iter.base <= pos < iter.end());
                assert forall|w: u64, i: u64| i < 64 implies
                    (#[trigger] scan_model::set(w & (u64::MAX << sub(pos, iter.base)), i)
                        <==> scan_model::set(w, i) && pos - iter.base <= i) by {
                    scan_proof::lemma_high_mask_bits(w, sub(pos, iter.base));
                    assert(scan_proof::bit(w & (u64::MAX << sub(pos, iter.base)), i) == 1
                        <==> scan_proof::bit(w, i) == 1 && sub(pos, iter.base) <= i);
                }
            }
            iter.word = iter.load_word() & (u64::MAX << (pos - iter.base));
            #[cfg(verus_keep_ghost)]
            proof! { iter.establish_word(pos as int); }
        }
        #[cfg(verus_keep_ghost)]
        proof! { if pos >= len { iter.zero_pending(); } }
        iter
    }
}

impl<const N: usize> Readable<N> for BitMap<N> {
    fn complete_chunks(&self) -> usize {
        self.chunks_len()
            .saturating_sub(if self.is_chunk_aligned() { 0 } else { 1 })
    }

    fn get_chunk(&self, chunk: usize) -> [u8; N] {
        *Self::get_chunk(self, chunk)
    }

    fn last_chunk(&self) -> ([u8; N], u64) {
        let (c, n) = Self::last_chunk(self);
        (*c, n)
    }

    fn pruned_chunks(&self) -> usize {
        0
    }

    fn len(&self) -> u64 {
        self.len
    }
}

/// Iterator over the indices of set (1) bits in a bitmap.
///
/// If the starting position falls within a pruned region, iteration
/// begins at the first unpruned bit.
///
/// `len` and the current chunk are read from the bitmap once and reused (the chunk until
/// iteration crosses into the next one), so the bitmap's contents must not change for the
/// iterator's lifetime. Owned bitmaps (`BitMap`, `Prunable`) guarantee this through the
/// immutable borrow. A `Readable` whose reads go through interior mutability (e.g. a
/// lock-guarded shared bitmap) instead requires the caller to prevent concurrent mutation
/// across the whole iteration, for example by constructing the iterator from a held read
/// guard rather than a bare shared reference.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub struct OnesIter<'a, B: ScanModel<N>, const N: usize> {
    bitmap: &'a B,
    /// Cached `bitmap.len()` at iterator construction. For layered bitmaps, `len()`
    /// walks the layer chain, so caching this avoids that walk on every `next`.
    len: u64,
    /// Bit index of bit 0 of `word`. Always a 64-bit word boundary relative to the start
    /// of its chunk, except when the iterator is constructed exhausted (then `len`).
    base: u64,
    /// Set bits of the bitmap word at `base` that have not been yielded yet.
    word: u64,
    /// The chunk containing `base`. Retaining it serves every word of a multi-word chunk
    /// with one fetch (and, for layered bitmaps, one layer resolution) rather than one
    /// fetch per yielded bit.
    chunk: [u8; N],
}

impl<'a, B: ScanModel<N>, const N: usize> OnesIter<'a, B, N> {
    /// Load the word at `base` from `chunk`, masking off bits at or beyond `len`.
    ///
    /// Requires `base < len` and that `chunk` is the chunk containing `base`. Chunks
    /// shorter than a word (`N < 8`) and trailing sub-word regions (`N % 8 != 0`) are
    /// zero-padded.
    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, allow(unused, verus_impl_method_marker))]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result =>
        requires N > 0, N as int * 8 <= usize::MAX,
            self.base < self.len,
            (self.base as int % (N as int * 8)) % 8 == 0,
        ensures forall|i: u64| i < 64 ==> (
            scan_proof::bit(result, i) == 1 <==>
            self.base as int + i < self.len &&
            scan_proof::chunk_bit(
                self.chunk@,
                self.base as int % (N as int * 8) + i,
            )
        ),
    ))]
    fn load_word(&self) -> u64 {
        let chunk_bits = BitMap::<N>::chunk_size_bits();
        let off = ((self.base % chunk_bits) / 8) as usize;
        let take = (N - off).min(8);
        let mut buf = [0u8; 8];
        buf[..take].copy_from_slice(&self.chunk[off..off + take]);
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(self.chunk@.len() == N);
            assert(buf@.len() == 8);
            assert(0 <= off < N);
            assert(take == if N - off < 8 { N - off } else { 8 });
            assert forall|j: int| 0 <= j < 8 implies #[trigger] buf@[j]
                == if j < take { self.chunk@[off as int + j] } else { 0 } by {
                if j < take {
                    assert(buf@[j] == self.chunk@[off as int + j]);
                } else {
                    assert(buf@[j] == 0);
                }
            }
        }
        // vstd's byte conversion wraps the native conversion for exactly eight bytes.
        #[cfg(not(verus_keep_ghost))]
        let mut word = u64::from_le_bytes(buf);
        #[cfg(verus_keep_ghost)]
        let mut word = vstd::bytes::u64_from_le_bytes(&buf);
        #[cfg(verus_keep_ghost)]
        let raw_word = word;
        #[cfg(verus_keep_ghost)]
        proof! {
            assert forall|i: u64| i < 64 implies (
                scan_proof::bit(raw_word, i) == 1 <==>
                scan_proof::chunk_bit(self.chunk@, off as int * 8 + i)
            ) by {
                scan_proof::lemma_chunk_word(self.chunk@, buf@, off as int, take as int, i);
            }
        }
        let rem = self.len - self.base;
        if rem < 64 {
            #[cfg(verus_keep_ghost)]
            proof! {
                assert(rem < 64 ==> 0 < (1u64 << rem)) by (bit_vector);
            }
            word &= (1u64 << rem) - 1;
            #[cfg(verus_keep_ghost)]
            proof! {
                scan_proof::lemma_low_mask_bits(raw_word, rem);
            }
        }
        #[cfg(verus_keep_ghost)]
        proof! {
            assert forall|i: u64| i < 64 implies (
                scan_proof::bit(word, i) == 1 <==>
                self.base as int + i < self.len &&
                scan_proof::chunk_bit(
                    self.chunk@,
                    self.base as int % (N as int * 8) + i,
                )
            ) by {
                assert(rem as int == self.len as int - self.base as int);
                assert((rem as int == self.len as int - self.base as int) ==>
                    ((self.base as int + i < self.len) <==> (i < rem)))
                    by (nonlinear_arith);
                let rel = self.base % chunk_bits;
                assert(rel as int == self.base as int % (N as int * 8));
                assert(off as int == rel as int / 8);
                assert(rel as int % 8 == 0);
                vstd::arithmetic::div_mod::lemma_fundamental_div_mod(rel as int, 8);
                assert((rel as int == 8 * (rel as int / 8) + rel as int % 8
                    && off as int == rel as int / 8 && rel as int % 8 == 0) ==>
                    rel as int == off as int * 8) by (nonlinear_arith);
                assert(self.base as int % (N as int * 8) == off as int * 8);
                if rem < 64 {
                    assert(scan_proof::bit(word, i) == 1 <==>
                        scan_proof::bit(raw_word, i) == 1 && i < rem);
                } else {
                    assert(word == raw_word);
                    assert(i < rem);
                }
            }
        }
        word
    }
}

#[cfg_attr(verus_keep_ghost, verifier::verify)]
impl<'a, B: Readable<N>, const N: usize> iter::Iterator for OnesIter<'a, B, N> {
    type Item = u64;

    #[cfg_attr(verus_keep_ghost, verus_verify)]
    #[cfg_attr(verus_keep_ghost, verus_spec(
        result =>
        ensures final(self).source() == old(self).source(), final(self).length() == old(self).length(),
            old(self).wf() ==> final(self).wf(),
            old(self).wf() ==> match result {
                Some(r) => old(self).pending(r as int)
                    && (forall|i: int| #[trigger] old(self).pending(i) ==> r <= i)
                    && (forall|i: int| #[trigger] final(self).pending(i)
                        <==> old(self).pending(i) && i != r),
                None => (forall|i: int| !#[trigger] old(self).pending(i))
                    && (forall|i: int| !#[trigger] final(self).pending(i)),
            },
    ))]
    fn next(&mut self) -> Option<u64> {
        #[cfg(verus_keep_ghost)]
        proof! {
            use_type_invariant(&*self);
            scan_model::zero_word();
        }
        let chunk_bits = BitMap::<N>::chunk_size_bits();
        #[cfg_attr(verus_keep_ghost, verus_spec(
            invariant self.safe(), old(self).wf() ==> self.wf(),
                self.bitmap == old(self).bitmap, self.len == old(self).len,
                chunk_bits as int == N as int * 8,
                old(self).wf() ==> forall|i: int| #[trigger] self.pending(i) <==> old(self).pending(i),
            decreases self.len - self.base,
        ))]
        while self.word == 0 {
            #[cfg(verus_keep_ghost)]
            proof_decl! { let ghost before = *self; }
            #[cfg(verus_keep_ghost)]
            proof! {
                scan_model::zero_word();
                self.zero_pending();
            }
            // Advance to the next word: either the next 64-bit stride of the current
            // chunk or the first word of the next chunk. Checked, because a heavily
            // pruned bitmap can end within one stride of u64::MAX.
            let rel = self.base % chunk_bits;
            let same_chunk = rel + 64 < chunk_bits;
            let stride = if same_chunk { 64 } else { chunk_bits - rel };
            #[cfg(verus_keep_ghost)]
            proof! {
                assert(stride > 0);
                assert(self.end() == vstd::math::min(self.len as int, self.base as int + stride));
                if self.base as int + stride >= self.len {
                    assert forall|i: int| !#[trigger] self.pending(i) by {}
                    if old(self).wf() {
                        assert forall|i: int| !#[trigger] old(self).pending(i) by {
                            assert(!self.pending(i));
                        }
                    }
                }
            }
            let next = self.base.checked_add(stride)?;
            if next >= self.len {
                return None;
            }
            #[cfg(verus_keep_ghost)]
            proof! {
                let c = N as int * 8;
                scan_model::advance(self.base as int, c);
                vstd::arithmetic::div_mod::lemma_div_is_ordered(next as int, self.len as int - 1, c);
                scan_model::chunk_index(next as int, c, scan_model::snapshot::<B, N>(self.bitmap).pruned as int);
                let future = OnesIter { base: next, ..*self };
                assert(future.safe());
            }
            self.base = next;
            if !same_chunk {
                self.chunk = self.bitmap.get_chunk(BitMap::<N>::to_chunk_index(next));
            }
            self.word = self.load_word();
            #[cfg(verus_keep_ghost)]
            proof! {
                if old(self).wf() {
                    self.establish_word(next as int);
                    assert forall|i: int| #[trigger] self.pending(i) <==> before.pending(i) by {}
                }
            }
        }
        #[cfg(verus_keep_ghost)]
        proof_decl! { let ghost before = *self; }
        #[cfg(verus_keep_ghost)]
        proof! {
            scan_proof::lemma_trailing_zeros(self.word);
            scan_proof::lemma_clear_lowest_set_bit(self.word);
            assert forall|i: u64| i < 64 && #[trigger] scan_model::set(self.word & sub(self.word, 1), i)
                implies scan_model::set(self.word, i) by {
                assert(scan_proof::bit(self.word & sub(self.word, 1), i) == 1
                    <==> scan_proof::bit(self.word, i) == 1
                        && i != vstd::std_specs::bits::u64_trailing_zeros(self.word));
            }
        }
        let bit = self.word.trailing_zeros() as u64;
        #[cfg(verus_keep_ghost)]
        proof! {
            assert(bit < 64 && scan_model::set(self.word, bit));
            assert(self.base as int + bit < self.end());
            assert(self.pending(self.base as int + bit));
            assert forall|i: int| #[trigger] self.pending(i) implies self.base as int + bit <= i by {
                if i < self.end() {
                    assert(scan_model::set(self.word, (i - self.base) as u64));
                }
            }
        }
        self.word &= self.word - 1;
        #[cfg(verus_keep_ghost)]
        proof! {
            assert forall|i: u64| i < 64 implies (#[trigger] scan_model::set(self.word, i)
                <==> scan_model::set(before.word, i) && i != bit) by {
                assert(scan_proof::bit(before.word & sub(before.word, 1), i) == 1
                    <==> scan_proof::bit(before.word, i) == 1 && i != bit);
            }
            assert forall|i: int| #[trigger] self.pending(i) <==>
                (before.pending(i) && i != self.base as int + bit) by {
                if self.base <= i < self.end() {
                    assert(0 <= i - self.base < 64);
                }
            }
            if old(self).wf() {
                assert(old(self).pending(self.base as int + bit));
                assert forall|i: int| #[trigger] old(self).pending(i) implies self.base as int + bit <= i by {
                    assert(before.pending(i));
                }
                assert forall|i: int| #[trigger] self.pending(i) <==>
                    (old(self).pending(i) && i != self.base as int + bit) by {
                    assert(before.pending(i) <==> old(self).pending(i));
                }
            }
        }
        Some(self.base + bit)
    }
}

#[cfg(feature = "arbitrary")]
impl<const N: usize> arbitrary::Arbitrary<'_> for BitMap<N> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let size = u.int_in_range(0..=1024)?;
        let mut bits = Self::with_capacity(size);
        for _ in 0..size {
            bits.push(u.arbitrary::<bool>()?);
        }
        Ok(bits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_rng;
    use bytes::BytesMut;
    use commonware_codec::{Decode, Encode};
    use commonware_formatting::hex;
    use rand::RngExt as _;

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

        let mut bv_xor = bv1;
        bv_xor.xor(&bv2);
        check_trailing_bits_zero(&bv_xor);

        // Test after deserialization
        let original: BitMap<4> = BitMap::ones(27);
        let encoded = original.encode();
        let decoded: BitMap<4> = BitMap::decode_cfg(encoded, &(usize::MAX as u64)).unwrap();
        check_trailing_bits_zero(&decoded);

        // Test clear_trailing_bits return value
        let mut bv_clean: BitMap<4> = BitMap::ones(20);
        // Should return false since ones() already clears trailing bits
        assert!(!bv_clean.clear_trailing_bits());

        // Create a bitmap with invalid trailing bits by manually setting them
        let mut bv_dirty: BitMap<4> = BitMap::ones(20);
        // Manually corrupt the last chunk to have trailing bits set
        let last_chunk = bv_dirty.chunks.back_mut().unwrap();
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
        let test_chunk = hex!("0xABCDEF12");

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
        assert_eq!(next_bit, BitMap::<4>::CHUNK_SIZE_BITS); // Should be at chunk boundary
        assert_eq!(last_chunk, &test_chunk); // The chunk we just pushed
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
    fn test_truncate() {
        let mut bv: BitMap<4> = BitMap::new();
        let expected: Vec<bool> = (0..70).map(|i| i % 3 == 0).collect();
        for &bit in &expected {
            bv.push(bit);
        }

        bv.truncate(65);
        assert_eq!(bv.len(), 65);
        for i in 0..65 {
            assert_eq!(bv.get(i), expected[i as usize]);
        }

        bv.truncate(32);
        assert_eq!(bv.len(), 32);
        for i in 0..32 {
            assert_eq!(bv.get(i), expected[i as usize]);
        }

        bv.truncate(0);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());
    }

    #[test]
    #[should_panic(expected = "cannot truncate to a larger size")]
    fn test_truncate_larger_size_panics() {
        let mut bv: BitMap<4> = BitMap::new();
        bv.push(true);
        bv.truncate(2);
    }

    #[test]
    fn test_pop_chunk() {
        let mut bv: BitMap<3> = BitMap::new();
        const CHUNK_SIZE: u64 = BitMap::<3>::CHUNK_SIZE_BITS;

        // Test 1: Pop a single chunk and verify it returns the correct data
        let chunk1 = hex!("0xAABBCC");
        bv.push_chunk(&chunk1);
        assert_eq!(bv.len(), CHUNK_SIZE);
        let popped = bv.pop_chunk();
        assert_eq!(popped, chunk1);
        assert_eq!(bv.len(), 0);
        assert!(bv.is_empty());

        // Test 2: Pop multiple chunks in reverse order
        let chunk2 = hex!("0x112233");
        let chunk3 = hex!("0x445566");
        let chunk4 = hex!("0x778899");

        bv.push_chunk(&chunk2);
        bv.push_chunk(&chunk3);
        bv.push_chunk(&chunk4);
        assert_eq!(bv.len(), CHUNK_SIZE * 3);

        assert_eq!(bv.pop_chunk(), chunk4);
        assert_eq!(bv.len(), CHUNK_SIZE * 2);

        assert_eq!(bv.pop_chunk(), chunk3);
        assert_eq!(bv.len(), CHUNK_SIZE);

        assert_eq!(bv.pop_chunk(), chunk2);
        assert_eq!(bv.len(), 0);

        // Test 3: Verify data integrity when popping chunks
        let first_chunk = hex!("0xAABBCC");
        let second_chunk = hex!("0x112233");
        bv.push_chunk(&first_chunk);
        bv.push_chunk(&second_chunk);

        // Pop the second chunk, verify it and that first chunk is intact
        assert_eq!(bv.pop_chunk(), second_chunk);
        assert_eq!(bv.len(), CHUNK_SIZE);

        for i in 0..CHUNK_SIZE {
            let byte_idx = (i / 8) as usize;
            let bit_idx = i % 8;
            let expected = (first_chunk[byte_idx] >> bit_idx) & 1 == 1;
            assert_eq!(bv.get(i), expected);
        }

        assert_eq!(bv.pop_chunk(), first_chunk);
        assert_eq!(bv.len(), 0);
    }

    #[test]
    #[should_panic(expected = "cannot pop chunk when not chunk aligned")]
    fn test_pop_chunk_not_aligned() {
        let mut bv: BitMap<3> = BitMap::new();

        // Push a full chunk plus one bit
        bv.push_chunk(&[0xFF; 3]);
        bv.push(true);

        // Should panic because not chunk-aligned
        bv.pop_chunk();
    }

    #[test]
    #[should_panic(expected = "cannot pop chunk: bitmap has fewer than CHUNK_SIZE_BITS bits")]
    fn test_pop_chunk_insufficient_bits() {
        let mut bv: BitMap<3> = BitMap::new();

        // Push only a few bits (less than a full chunk)
        bv.push(true);
        bv.push(false);

        // Should panic because we don't have a full chunk to pop
        bv.pop_chunk();
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
        let chunk1 = hex!("0xAABBCCDD"); // 10101010 10111011 11001100 11011101
        let chunk2 = hex!("0x55667788"); // 01010101 01100110 01110111 10001000

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
    fn test_ones_iter_empty() {
        let bv: BitMap<4> = BitMap::new();
        let ones: Vec<u64> = bv.ones_iter().collect();
        assert!(ones.is_empty());
    }

    #[test]
    fn test_ones_iter_all_zeros() {
        let bv = BitMap::<4>::zeroes(100);
        let ones: Vec<u64> = bv.ones_iter().collect();
        assert!(ones.is_empty());
    }

    #[test]
    fn test_ones_iter_all_ones() {
        let bv = BitMap::<4>::ones(100);
        let ones: Vec<u64> = bv.ones_iter().collect();
        let expected: Vec<u64> = (0..100).collect();
        assert_eq!(ones, expected);
    }

    #[test]
    fn test_ones_iter_sparse() {
        let mut bv = BitMap::<4>::zeroes(64);
        bv.set(0, true);
        bv.set(31, true);
        bv.set(32, true);
        bv.set(63, true);

        let ones: Vec<u64> = bv.ones_iter().collect();
        assert_eq!(ones, vec![0, 31, 32, 63]);
    }

    #[test]
    fn test_ones_iter_single_bit() {
        let mut bv: BitMap<4> = BitMap::new();
        bv.push(true);
        assert_eq!(bv.ones_iter().collect::<Vec<_>>(), vec![0]);

        let mut bv: BitMap<4> = BitMap::new();
        bv.push(false);
        assert!(bv.ones_iter().collect::<Vec<_>>().is_empty());
    }

    #[test]
    fn test_ones_iter_multi_chunk() {
        // Use small chunks (4 bytes = 32 bits) to ensure multi-chunk coverage.
        let mut bv = BitMap::<4>::zeroes(96);
        // Set one bit per chunk.
        bv.set(7, true); // chunk 0
        bv.set(40, true); // chunk 1
        bv.set(95, true); // chunk 2

        let ones: Vec<u64> = bv.ones_iter().collect();
        assert_eq!(ones, vec![7, 40, 95]);
    }

    #[test]
    fn test_ones_iter_partial_chunk() {
        // 35 bits = 1 full chunk (32 bits) + 3 bits in a partial chunk.
        let mut bv = BitMap::<4>::zeroes(35);
        bv.set(31, true); // last bit of full chunk
        bv.set(32, true); // first bit of partial chunk
        bv.set(34, true); // last bit

        let ones: Vec<u64> = bv.ones_iter().collect();
        assert_eq!(ones, vec![31, 32, 34]);
    }

    #[test]
    fn test_ones_iter_from_midway() {
        let mut bv = BitMap::<4>::zeroes(64);
        bv.set(5, true);
        bv.set(20, true);
        bv.set(40, true);
        bv.set(60, true);

        // Start from position 20 -- should skip bit 5.
        let ones: Vec<u64> = Readable::ones_iter_from(&bv, 20).collect();
        assert_eq!(ones, vec![20, 40, 60]);

        // Start from position 21 -- should skip bits 5 and 20.
        let ones: Vec<u64> = Readable::ones_iter_from(&bv, 21).collect();
        assert_eq!(ones, vec![40, 60]);

        // Start past all set bits.
        let ones: Vec<u64> = Readable::ones_iter_from(&bv, 61).collect();
        assert!(ones.is_empty());
    }

    #[test]
    fn test_ones_iter_matches_count_ones() {
        let mut bv: BitMap<8> = BitMap::new();
        for i in 0..200 {
            bv.push(i % 7 == 0);
        }
        assert_eq!(bv.ones_iter().count() as u64, bv.count_ones());
    }

    #[test]
    fn test_ones_iter_different_chunk_sizes() {
        let pattern: Vec<bool> = (0..100).map(|i| i % 5 == 0).collect();
        let expected: Vec<u64> = (0..100).filter(|i| i % 5 == 0).collect();

        let bv4: BitMap<4> = pattern.as_slice().into();
        let bv8: BitMap<8> = pattern.as_slice().into();
        let bv16: BitMap<16> = pattern.as_slice().into();

        assert_eq!(bv4.ones_iter().collect::<Vec<_>>(), expected);
        assert_eq!(bv8.ones_iter().collect::<Vec<_>>(), expected);
        assert_eq!(bv16.ones_iter().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn test_ones_iter_multi_word_chunk() {
        // 32-byte chunks hold four 64-bit words. Set bits adjacent to every word
        // boundary within a chunk and to the chunk boundary itself.
        let expected = vec![0, 63, 64, 127, 128, 255, 256, 511, 512, 599];
        let mut bv = BitMap::<32>::zeroes(600);
        for &bit in &expected {
            bv.set(bit, true);
        }
        assert_eq!(bv.ones_iter().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn test_ones_iter_from_mid_word() {
        // Starting positions inside every word of a multi-word chunk mask out exactly
        // the bits below the start.
        let bv = BitMap::<32>::ones(300);
        for pos in [0, 1, 63, 64, 65, 191, 192, 255, 256, 299] {
            let ones: Vec<u64> = Readable::ones_iter_from(&bv, pos).collect();
            let expected: Vec<u64> = (pos..300).collect();
            assert_eq!(ones, expected);
        }
    }

    #[test]
    fn test_ones_iter_word_aligned_len() {
        // A length exactly at a word boundary must not mask off the final bit.
        let bv = BitMap::<8>::ones(64);
        assert_eq!(
            bv.ones_iter().collect::<Vec<_>>(),
            (0..64).collect::<Vec<_>>()
        );
        let bv = BitMap::<32>::ones(256);
        assert_eq!(
            bv.ones_iter().collect::<Vec<_>>(),
            (0..256).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_ones_iter_matches_get_bit() {
        // Pseudo-random pattern over every chunk shape: sub-word (1, 3, 4), exactly one
        // word (8), multi-word (16, 32), and multi-word with a partial tail word (12,
        // 23). Check the full iteration and every possible starting position against
        // get_bit.
        fn check<const N: usize>() {
            let mut rng = test_rng();
            let mut bv: BitMap<N> = BitMap::new();
            let len = 5 * BitMap::<N>::CHUNK_SIZE_BITS + 7;
            for _ in 0..len {
                bv.push(rng.random_bool(0.375));
            }
            let expected: Vec<u64> = (0..len).filter(|&i| bv.get_bit(i)).collect();
            assert_eq!(bv.ones_iter().collect::<Vec<_>>(), expected);
            for pos in 0..=len {
                let tail: Vec<u64> = expected.iter().copied().filter(|&b| b >= pos).collect();
                assert_eq!(Readable::ones_iter_from(&bv, pos).collect::<Vec<_>>(), tail);
            }
        }
        check::<1>();
        check::<3>();
        check::<4>();
        check::<8>();
        check::<12>();
        check::<16>();
        check::<23>();
        check::<32>();
    }

    #[test]
    fn test_codec_roundtrip() {
        // Test empty bitmap
        let original: BitMap<4> = BitMap::new();
        let encoded = original.encode();
        let decoded = BitMap::decode_cfg(encoded, &(usize::MAX as u64)).unwrap();
        assert_eq!(original, decoded);

        // Test small bitmap
        let pattern = [true, false, true, false, true];
        let original: BitMap<4> = pattern.as_ref().into();
        let encoded = original.encode();
        let decoded = BitMap::decode_cfg(encoded, &(usize::MAX as u64)).unwrap();
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
        let decoded = BitMap::decode_cfg(encoded, &(usize::MAX as u64)).unwrap();
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
        let decoded4 = BitMap::decode_cfg(encoded4, &(usize::MAX as u64)).unwrap();
        assert_eq!(bv4, decoded4);

        let encoded8 = bv8.encode();
        let decoded8 = BitMap::decode_cfg(encoded8, &(usize::MAX as u64)).unwrap();
        assert_eq!(bv8, decoded8);

        let encoded16 = bv16.encode();
        let decoded16 = BitMap::decode_cfg(encoded16, &(usize::MAX as u64)).unwrap();
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
        let decoded = BitMap::decode_cfg(encoded, &(usize::MAX as u64)).unwrap();
        assert_eq!(bv, decoded);
        assert_eq!(decoded.len(), 32);

        // Test bitmap with partial chunk
        let mut bv2: BitMap<4> = BitMap::new();
        for i in 0..35 {
            // 32 + 3 bits
            bv2.push(i % 3 == 0);
        }

        let encoded2 = bv2.encode();
        let decoded2 = BitMap::decode_cfg(encoded2, &(usize::MAX as u64)).unwrap();
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
            BitMap::decode_cfg(encoded_empty.clone(), &(usize::MAX as u64)).unwrap();
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
            BitMap::decode_cfg(encoded_exact.clone(), &(usize::MAX as u64)).unwrap();
        assert_eq!(bv_exact, decoded_exact);

        // Case 3: Bitmap with partial last chunk (includes last chunk)
        let mut bv_partial: BitMap<4> = BitMap::new();
        for _ in 0..35 {
            bv_partial.push(true);
        }
        let encoded_partial = bv_partial.encode();
        let decoded_partial: BitMap<4> =
            BitMap::decode_cfg(encoded_partial.clone(), &(usize::MAX as u64)).unwrap();
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
        let result = BitMap::<4>::read_cfg(
            &mut bytes::Bytes::from(corrupted_bytes),
            &(usize::MAX as u64),
        );
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
        let result = BitMap::<4>::decode_cfg(buf.clone(), &50);
        assert!(matches!(result, Err(CodecError::InvalidLength(100))));

        // Test with max length == actual size (should succeed)
        let decoded = BitMap::<4>::decode_cfg(buf.clone(), &100).unwrap();
        assert_eq!(decoded.len(), 100);
        assert_eq!(decoded, original);

        // Test with max length > actual size (should succeed)
        let decoded = BitMap::<4>::decode_cfg(buf, &101).unwrap();
        assert_eq!(decoded.len(), 100);
        assert_eq!(decoded, original);

        // Test empty bitmap
        let empty = BitMap::<4>::new();
        let mut buf = BytesMut::new();
        empty.write(&mut buf);

        // Empty bitmap should work with max length 0
        let decoded = BitMap::<4>::decode_cfg(buf.clone(), &0).unwrap();
        assert_eq!(decoded.len(), 0);
        assert!(decoded.is_empty());

        // Empty bitmap should work with max length > 0
        let decoded = BitMap::<4>::decode_cfg(buf, &1).unwrap();
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
    fn test_is_chunk_aligned() {
        // Empty bitmap is chunk aligned
        let bv: BitMap<4> = BitMap::new();
        assert!(bv.is_chunk_aligned());

        // Test with various chunk sizes
        let mut bv4: BitMap<4> = BitMap::new();
        assert!(bv4.is_chunk_aligned());

        // Add bits one at a time and check alignment
        for i in 1..=32 {
            bv4.push(i % 2 == 0);
            if i == 32 {
                assert!(bv4.is_chunk_aligned()); // Exactly one chunk
            } else {
                assert!(!bv4.is_chunk_aligned()); // Partial chunk
            }
        }

        // Add more bits
        for i in 33..=64 {
            bv4.push(i % 2 == 0);
            if i == 64 {
                assert!(bv4.is_chunk_aligned()); // Exactly two chunks
            } else {
                assert!(!bv4.is_chunk_aligned()); // Partial chunk
            }
        }

        // Test with push_chunk
        let mut bv: BitMap<8> = BitMap::new();
        assert!(bv.is_chunk_aligned());
        bv.push_chunk(&[0xFF; 8]);
        assert!(bv.is_chunk_aligned()); // 64 bits = 1 chunk for N=8
        bv.push_chunk(&[0xAA; 8]);
        assert!(bv.is_chunk_aligned()); // 128 bits = 2 chunks
        bv.push(true);
        assert!(!bv.is_chunk_aligned()); // 129 bits = partial chunk

        // Test with push_byte
        let mut bv: BitMap<4> = BitMap::new();
        for _ in 0..4 {
            bv.push_byte(0xFF);
        }
        assert!(bv.is_chunk_aligned()); // 32 bits = 1 chunk for N=4

        // Test after pop
        bv.pop();
        assert!(!bv.is_chunk_aligned()); // 31 bits = partial chunk

        // Test with zeroes and ones constructors
        let bv_zeroes: BitMap<4> = BitMap::zeroes(64);
        assert!(bv_zeroes.is_chunk_aligned());

        let bv_ones: BitMap<4> = BitMap::ones(96);
        assert!(bv_ones.is_chunk_aligned());

        let bv_partial: BitMap<4> = BitMap::zeroes(65);
        assert!(!bv_partial.is_chunk_aligned());
    }

    #[test]
    fn test_unprune_restores_length() {
        let mut prunable: Prunable<4> = Prunable::new_with_pruned_chunks(1).unwrap();
        assert_eq!(prunable.len(), Prunable::<4>::CHUNK_SIZE_BITS);
        assert_eq!(prunable.pruned_chunks(), 1);
        let chunk = [0xDE, 0xAD, 0xBE, 0xEF];

        prunable.unprune_chunks(&[chunk]);

        assert_eq!(prunable.pruned_chunks(), 0);
        assert_eq!(prunable.len(), Prunable::<4>::CHUNK_SIZE_BITS);
        assert_eq!(prunable.get_chunk_containing(0), &chunk);
    }

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn is_unset_matches_naive(
                bits in prop::collection::vec(any::<bool>(), 1..=512usize),
                start in 0u64..=512,
                end in 0u64..=512,
            ) {
                let bitmap: BitMap = BitMap::from(bits.as_slice());
                let len = bitmap.len();
                let start = start.min(len);
                let end = end.max(start).min(len);
                let range = start..end;

                let expected = range.clone().all(|i| !bitmap.get(i));

                prop_assert_eq!(bitmap.is_unset(range), expected);
            }
        }
    }

    #[test]
    fn is_unset_all_zeros() {
        let bitmap = BitMap::<8>::zeroes(256);
        assert!(bitmap.is_unset(0..256));
    }

    #[test]
    fn is_unset_all_ones() {
        let bitmap = BitMap::<8>::ones(256);
        assert!(!bitmap.is_unset(0..256));
    }

    #[test]
    fn is_unset_single_bit() {
        let mut bitmap = BitMap::<8>::zeroes(64);
        bitmap.set(31, true);
        assert!(bitmap.is_unset(0..31));
        assert!(!bitmap.is_unset(0..32));
        assert!(!bitmap.is_unset(31..32));
        assert!(bitmap.is_unset(32..64));
    }

    #[test]
    fn is_unset_empty_range() {
        let bitmap = BitMap::<8>::ones(64);
        assert!(bitmap.is_unset(0..0));
        assert!(bitmap.is_unset(32..32));
        assert!(bitmap.is_unset(64..64));
    }

    #[test]
    fn is_unset_chunk_boundaries() {
        // N=1 means 8 bits per chunk, so boundaries are more frequent
        let mut bitmap = BitMap::<1>::zeroes(32);
        bitmap.set(7, true);
        assert!(bitmap.is_unset(0..7));
        assert!(!bitmap.is_unset(0..8));
        assert!(bitmap.is_unset(8..32));
    }

    #[test]
    fn is_unset_small_chunk_multi_span() {
        // N=4 means 32 bits per chunk, test spanning 3 chunks
        let mut bitmap = BitMap::<4>::zeroes(128);
        bitmap.set(96, true);
        assert!(bitmap.is_unset(0..96));
        assert!(!bitmap.is_unset(0..97));
        assert!(bitmap.is_unset(97..128));
    }

    #[test]
    #[should_panic(expected = "out of bounds")]
    fn is_unset_out_of_bounds() {
        let bitmap = BitMap::<8>::zeroes(64);
        bitmap.is_unset(0..65);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<BitMap>
        }
    }
}

#[cfg(verus_keep_ghost)]
mod scan_proof {
    use super::*;
    use vstd::{
        arithmetic::div_mod::{lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse},
        bytes::{
            lemma_auto_spec_u64_to_from_le_bytes, spec_u64_from_le_bytes, spec_u64_to_le_bytes,
            spec_u64_to_le_bytes_open, spec_u64_to_le_bytes_to_open,
        },
        std_specs::bits::{axiom_u64_trailing_zeros, u64_trailing_zeros},
    };

    verus! {

    pub open spec fn bit(word: u64, index: u64) -> u64 {
        (word >> index) & 1u64
    }

    pub open spec fn chunk_bit(bytes: Seq<u8>, off: int) -> bool {
        0 <= off < bytes.len() * 8
            && bit(bytes[off / 8] as u64, (off % 8) as u64) == 1
    }

    pub proof fn lemma_trailing_zeros(word: u64)
        requires
            word != 0,
        ensures
            u64_trailing_zeros(word) < 64,
            bit(word, u64_trailing_zeros(word) as u64) == 1,
            forall|i: u64| i < u64_trailing_zeros(word) ==>
                #[trigger] bit(word, i) == 0,
    {
        axiom_u64_trailing_zeros(word);
    }

    pub proof fn lemma_clear_lowest_set_bit(word: u64)
        requires
            word != 0,
        ensures
            forall|i: u64| i < 64 ==> (
                #[trigger] bit(word & sub(word, 1), i) == 1
                    <==> bit(word, i) == 1 && i != u64_trailing_zeros(word)
            ),
    {
        lemma_trailing_zeros(word);
        axiom_u64_trailing_zeros(word);
        let tz = u64_trailing_zeros(word) as u64;
        assert forall|i: u64| i < 64 implies (
            #[trigger] bit(word & sub(word, 1), i) == 1
                <==> bit(word, i) == 1 && i != tz
        ) by {
            if i < tz {
                assert(bit(word, i) == 0);
                assert((word >> i) & 1u64 == 0);
                assert(((word >> i) & 1u64 == 0) ==>
                    (((word & sub(word, 1)) >> i) & 1u64 == 0)) by (bit_vector);
            } else {
                assert(tz < 64);
                assert(bit(word, tz) == 1);
                assert((word >> tz) & 1u64 == 1);
                assert(word << sub(64u64, tz) == 0);
                assert((i >= tz && i < 64 && tz < 64 && ((word >> tz) & 1u64) == 1
                    && word << sub(64u64, tz) == 0) ==> (
                    ((((word & sub(word, 1)) >> i) & 1u64 == 1)
                    <==> (((word >> i) & 1u64 == 1) && i != tz)))) by (bit_vector);
            }
        }
    }

    pub proof fn lemma_u64_from_le_bytes_bit(bytes: Seq<u8>, index: u64)
        requires
            bytes.len() == 8,
            index < 64,
        ensures
            bit(spec_u64_from_le_bytes(bytes), index)
                == bit(bytes[(index / 8) as int] as u64, index % 8),
    {
        lemma_auto_spec_u64_to_from_le_bytes();
        let word = spec_u64_from_le_bytes(bytes);
        assert(spec_u64_to_le_bytes(word) == bytes);
        spec_u64_to_le_bytes_to_open(word);
        assert(spec_u64_to_le_bytes_open(word) == bytes);
        assert(index / 8 == index >> 3u64) by (bit_vector);
        assert(index % 8 == index & 7u64) by (bit_vector);
        if index < 8 {
            assert(index < 8 ==> (index >> 3u64) == 0) by (bit_vector);
            assert((index / 8) == 0);
            let byte = bytes[0] as u64;
            assert(word & 0xff < 256) by (bit_vector);
            assert(byte == word & 0xff);
            assert((index < 8 && byte == (word & 0xff)) ==>
                bit(word, index) == bit(byte, index & 7u64)) by (bit_vector);
        } else if index < 16 {
            assert(8 <= index && index < 16 ==> (index >> 3u64) == 1) by (bit_vector);
            assert((index / 8) == 1);
            let byte = bytes[1] as u64;
            assert((word >> 8) & 0xff < 256) by (bit_vector);
            assert(byte == (word >> 8) & 0xff);
            assert((8 <= index && index < 16 && byte == ((word >> 8) & 0xff)) ==>
                bit(word, index) == bit(byte, index & 7u64)) by (bit_vector);
        } else if index < 24 {
            assert(16 <= index && index < 24 ==> (index >> 3u64) == 2) by (bit_vector);
            assert((index / 8) == 2);
            let byte = bytes[2] as u64;
            assert((word >> 16) & 0xff < 256) by (bit_vector);
            assert(byte == (word >> 16) & 0xff);
            assert((16 <= index && index < 24 && byte == ((word >> 16) & 0xff)) ==>
                bit(word, index) == bit(byte, index & 7u64)) by (bit_vector);
        } else if index < 32 {
            assert(24 <= index && index < 32 ==> (index >> 3u64) == 3) by (bit_vector);
            assert((index / 8) == 3);
            let byte = bytes[3] as u64;
            assert((word >> 24) & 0xff < 256) by (bit_vector);
            assert(byte == (word >> 24) & 0xff);
            assert((24 <= index && index < 32 && byte == ((word >> 24) & 0xff)) ==>
                bit(word, index) == bit(byte, index & 7u64)) by (bit_vector);
        } else if index < 40 {
            assert(32 <= index && index < 40 ==> (index >> 3u64) == 4) by (bit_vector);
            assert((index / 8) == 4);
            let byte = bytes[4] as u64;
            assert((word >> 32) & 0xff < 256) by (bit_vector);
            assert(byte == (word >> 32) & 0xff);
            assert((32 <= index && index < 40 && byte == ((word >> 32) & 0xff)) ==>
                bit(word, index) == bit(byte, index & 7u64)) by (bit_vector);
        } else if index < 48 {
            assert(40 <= index && index < 48 ==> (index >> 3u64) == 5) by (bit_vector);
            assert((index / 8) == 5);
            let byte = bytes[5] as u64;
            assert((word >> 40) & 0xff < 256) by (bit_vector);
            assert(byte == (word >> 40) & 0xff);
            assert((40 <= index && index < 48 && byte == ((word >> 40) & 0xff)) ==>
                bit(word, index) == bit(byte, index & 7u64)) by (bit_vector);
        } else if index < 56 {
            assert(48 <= index && index < 56 ==> (index >> 3u64) == 6) by (bit_vector);
            assert((index / 8) == 6);
            let byte = bytes[6] as u64;
            assert((word >> 48) & 0xff < 256) by (bit_vector);
            assert(byte == (word >> 48) & 0xff);
            assert((48 <= index && index < 56 && byte == ((word >> 48) & 0xff)) ==>
                bit(word, index) == bit(byte, index & 7u64)) by (bit_vector);
        } else {
            assert(56 <= index && index < 64 ==> (index >> 3u64) == 7) by (bit_vector);
            assert((index / 8) == 7);
            let byte = bytes[7] as u64;
            assert((word >> 56) & 0xff < 256) by (bit_vector);
            assert(byte == (word >> 56) & 0xff);
            assert((56 <= index && index < 64 && byte == ((word >> 56) & 0xff)) ==>
                bit(word, index) == bit(byte, index & 7u64)) by (bit_vector);
        }
    }

    pub proof fn lemma_low_mask_bits(word: u64, width: u64)
        requires
            0 < width < 64,
        ensures
            forall|i: u64| i < 64 ==> (
                #[trigger] bit(word & sub(1u64 << width, 1), i) == 1
                    <==> bit(word, i) == 1 && i < width
            ),
    {
        assert forall|i: u64| i < 64 implies (
            #[trigger] bit(word & sub(1u64 << width, 1), i) == 1
                <==> bit(word, i) == 1 && i < width
        ) by {
            assert((bit(word & sub(1u64 << width, 1), i) == 1)
                <==> (bit(word, i) == 1 && i < width)) by (bit_vector);
        }
    }

    pub proof fn lemma_high_mask_bits(word: u64, width: u64)
        requires
            width < 64,
        ensures
            forall|i: u64| i < 64 ==> (
                #[trigger] bit(word & (u64::MAX << width), i) == 1
                    <==> bit(word, i) == 1 && width <= i
            ),
    {
        assert forall|i: u64| i < 64 implies (
            #[trigger] bit(word & (u64::MAX << width), i) == 1
                <==> bit(word, i) == 1 && width <= i
        ) by {
            assert((bit(word & (u64::MAX << width), i) == 1)
                <==> (bit(word, i) == 1 && width <= i)) by (bit_vector);
        }
    }

    pub proof fn lemma_chunk_word(
        chunk: Seq<u8>,
        bytes: Seq<u8>,
        off: int,
        take: int,
        index: u64,
    )
        requires
            0 <= off < chunk.len(),
            take == if chunk.len() - off < 8 { chunk.len() - off } else { 8 },
            bytes.len() == 8,
            forall|j: int| 0 <= j < 8 ==> #[trigger] bytes[j]
                == if j < take { chunk[off + j] } else { 0 },
            index < 64,
        ensures
            bit(spec_u64_from_le_bytes(bytes), index) == 1
                <==> chunk_bit(chunk, off * 8 + index as int),
    {
        lemma_u64_from_le_bytes_bit(bytes, index);
        let j = (index / 8) as int;
        let k = (index % 8) as int;
        assert(index / 8 == index >> 3u64) by (bit_vector);
        assert(index < 64 ==> index >> 3u64 < 8) by (bit_vector);
        assert(index % 8 == index & 7u64) by (bit_vector);
        assert(index & 7u64 < 8) by (bit_vector);
        assert(0 <= j < 8);
        assert(0 <= k < 8);
        assert(bytes[j] == if j < take { chunk[off + j] } else { 0 });
        lemma_fundamental_div_mod(index as int, 8);
        assert(index as int == 8 * j + k);
        lemma_fundamental_div_mod_converse(
            off * 8 + index as int,
            8,
            off + j,
            k,
        );
        assert((off * 8 + index as int) / 8 == off + j);
        assert((off * 8 + index as int) % 8 == k);
        assert(k as u64 == index % 8);
        assert(bit(spec_u64_from_le_bytes(bytes), index)
            == bit(bytes[j] as u64, index % 8));
        if j < take {
            if chunk.len() - off < 8 {
                assert((j < take && take == chunk.len() - off) ==>
                    off + j < chunk.len()) by (nonlinear_arith);
            } else {
                assert((j < take && take == 8 && chunk.len() - off >= 8) ==>
                    off + j < chunk.len()) by (nonlinear_arith);
            }
            assert((off + j < chunk.len() && index as int == 8 * j + k && k < 8) ==>
                off * 8 + (index as int) < chunk.len() * 8) by (nonlinear_arith);
            assert(bytes[j] == chunk[off + j]);
            assert(chunk_bit(chunk, off * 8 + index as int)
                <==> bit(chunk[off + j] as u64, index % 8) == 1);
            assert(bit(spec_u64_from_le_bytes(bytes), index) == 1
                <==> chunk_bit(chunk, off * 8 + index as int));
        } else {
            if chunk.len() - off < 8 {
                assert((j >= take && take == chunk.len() - off) ==>
                    chunk.len() <= off + j) by (nonlinear_arith);
            } else {
                assert((j >= take && take == 8 && j < 8) ==> false) by (nonlinear_arith);
            }
            assert((chunk.len() <= off + j && index as int == 8 * j + k && k >= 0) ==>
                chunk.len() * 8 <= off * 8 + (index as int)) by (nonlinear_arith);
            assert(bytes[j] == 0);
            assert(bit(0, index % 8) == 0) by (bit_vector);
            assert(!chunk_bit(chunk, off * 8 + index as int));
            assert(bit(spec_u64_from_le_bytes(bytes), index) == 1
                <==> chunk_bit(chunk, off * 8 + index as int));
        }
    }

    }
}

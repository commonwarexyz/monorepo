use super::Error;
use crate::bitmap::{historical::BitMap, Prunable};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// An active batch that tracks mutations as a diff layer.
///
/// A batch records changes without modifying the underlying bitmap. When committed,
/// these changes are applied atomically. If dropped without committing, all changes
/// are discarded.
///
/// # De-duplication and Cancellation
///
/// **The batch de-duplicates during operations, not at commit time.**
///
/// Operations that cancel out are handled automatically:
///
/// ```text
/// Example 1: push + pop = no-op
///   push(true)  → appended_bits=[true], projected_len=11
///   pop()       → appended_bits=[], projected_len=10
///   Result: batch state unchanged from base!
///
/// Example 2: set_bit + set_bit = last write wins
///   set_bit(5, true)   → modified_bits={5: true}
///   set_bit(5, false)  → modified_bits={5: false}
///   Result: only final value recorded
///
/// Example 3: set_bit + pop = cancels modification
///   set_bit(9, true)  → modified_bits={9: true}
///   pop()             → modified_bits={} (removed), projected_len=9
///   Result: bit 9 no longer exists, modification discarded
/// ```
///
/// The capture functions see only the **final delta**, not intermediate operations.
///
/// # Key Invariants
///
/// 1. **Base immutability**: `base_len` and `base_pruned_chunks` never change after batch creation
/// 2. **Appended region**: Always occupies `[projected_len - appended_bits.len(), projected_len)`
/// 3. **Modified region**: `modified_bits` only contains offsets in `[0, projected_len - appended_bits.len())`
///    - These are modifications to the base bitmap, never to appended bits
///    - Appended bits are modified by directly updating the `appended_bits` vector
/// 4. **No overlap**: A bit is either in `modified_bits` OR `appended_bits`, never both
pub(super) struct Batch<const N: usize> {
    /// Bitmap state when batch started (immutable).
    pub(super) base_len: u64,
    pub(super) base_pruned_chunks: usize,

    /// What the bitmap will look like after commit (mutable).
    pub(super) projected_len: u64,
    pub(super) projected_pruned_chunks: usize,

    /// Modifications to bits that existed in the bitmap (not appended bits).
    /// Contains offsets in [0, projected_len - appended_bits.len()).
    /// Maps: bit -> new_value
    pub(super) modified_bits: BTreeMap<u64, bool>,

    /// New bits pushed in this batch (in order).
    /// Logical position: [projected_len - appended_bits.len(), projected_len)
    pub(super) appended_bits: Vec<bool>,

    /// Old chunk data for chunks being pruned.
    /// Captured eagerly during `prune_to_bit()` for historical reconstruction.
    pub(super) chunks_to_prune: BTreeMap<usize, [u8; N]>,
}

/// Guard for an active batch on a historical bitmap.
///
/// Provides mutable access to an active batch, allowing operations that modify the bitmap
/// through a diff layer. Changes are not applied to the underlying bitmap until
/// [commit](Self::commit) is called.
///
/// # Lifecycle
///
/// The guard **must** be either:
/// - **Committed**: Call [commit(commit_number)](Self::commit) to apply changes
///   and store a historical snapshot.
/// - **Dropped**: Drop without committing to discard all changes.
///
/// # Examples
///
/// ```
/// # use commonware_utils::bitmap::historical::BitMap;
/// let mut bitmap: BitMap<4> = BitMap::new();
///
/// // Create a batch guard and make changes
/// let mut batch = bitmap.start_batch();
/// batch.push(true);
/// batch.push(false);
/// batch.commit(1).unwrap();
///
/// // Bitmap is now modified
/// assert_eq!(bitmap.len(), 2);
/// ```
///
/// ## Discarding Changes
///
/// ```
/// # use commonware_utils::bitmap::historical::BitMap;
/// let mut bitmap: BitMap<4> = BitMap::new();
///
/// {
///     let mut batch = bitmap.start_batch();
///     batch.push(true);
///     // batch dropped here without commit
/// }
///
/// // Bitmap is unchanged
/// assert_eq!(bitmap.len(), 0);
/// ```
#[must_use = "batches must be committed or explicitly dropped"]
pub struct BatchGuard<'a, const N: usize> {
    pub(super) bitmap: &'a mut BitMap<N>,
    pub(super) committed: bool,
}

impl<'a, const N: usize> BatchGuard<'a, N> {
    /// Get the length of the bitmap as it would be after committing this batch.
    #[inline]
    pub fn len(&self) -> u64 {
        self.bitmap
            .active_batch
            .as_ref()
            .expect("active batch must exist since we have this guard")
            .projected_len
    }

    /// Returns true if the bitmap would be empty after committing this batch.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of pruned chunks after this batch.
    #[inline]
    pub fn pruned_chunks(&self) -> usize {
        self.bitmap
            .active_batch
            .as_ref()
            .expect("active batch must exist since we have this guard")
            .projected_pruned_chunks
    }

    /// Get a bit value with read-through semantics.
    ///
    /// Returns the bit's value as it would be after committing this batch.
    /// Priority: appended bits > modified bits > original bitmap.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds or if the bit has been pruned.
    pub fn get_bit(&self, bit: u64) -> bool {
        let batch = self.bitmap.active_batch.as_ref().unwrap();

        assert!(
            bit < batch.projected_len,
            "bit offset {bit} out of bounds (len: {})",
            batch.projected_len
        );

        let chunk_idx = Prunable::<N>::unpruned_chunk(bit);
        assert!(
            chunk_idx >= batch.projected_pruned_chunks,
            "cannot get bit {bit}: chunk {chunk_idx} is pruned (pruned up to chunk {})",
            batch.projected_pruned_chunks
        );

        // Priority 1: Check if bit is in appended region.
        // Must use appended_start, not base_len, to handle net pops + appends.
        let appended_start = batch.projected_len - batch.appended_bits.len() as u64;
        if bit >= appended_start {
            let append_offset = (bit - appended_start) as usize;
            return batch.appended_bits[append_offset];
        }

        // Priority 2: Check if bit was modified in this batch.
        if let Some(&value) = batch.modified_bits.get(&bit) {
            return value;
        }

        // Priority 3: Fall through to original bitmap.
        self.bitmap.current.get_bit(bit)
    }

    /// Get a chunk value with read-through semantics.
    ///
    /// Reconstructs the chunk if it has modifications, otherwise returns from current.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds or if the chunk has been pruned.
    pub fn get_chunk(&self, bit: u64) -> [u8; N] {
        let batch = self.bitmap.active_batch.as_ref().unwrap();

        // Check bounds
        assert!(
            bit < batch.projected_len,
            "bit offset {bit} out of bounds (len: {})",
            batch.projected_len
        );

        let chunk_idx = Prunable::<N>::unpruned_chunk(bit);

        // Check if chunk is in pruned range
        assert!(
            chunk_idx >= batch.projected_pruned_chunks,
            "cannot get chunk at bit offset {bit}: chunk {chunk_idx} is pruned (pruned up to chunk {})",
            batch.projected_pruned_chunks
        );

        let chunk_start_bit = chunk_idx as u64 * Prunable::<N>::CHUNK_SIZE_BITS;
        let chunk_end_bit = chunk_start_bit + Prunable::<N>::CHUNK_SIZE_BITS;

        // Determine if this chunk needs reconstruction.
        let appended_start = batch.projected_len - batch.appended_bits.len() as u64;

        // Skip reconstruction only if chunk is entirely outside modified regions
        let chunk_entirely_past_end = chunk_start_bit >= batch.projected_len;
        let chunk_entirely_before_changes =
            chunk_end_bit <= appended_start && chunk_end_bit <= batch.projected_len;

        let chunk_needs_reconstruction =
            // Chunk overlaps with pops or appends
            !(chunk_entirely_past_end || chunk_entirely_before_changes)
            // OR chunk has explicit bit modifications
            || (chunk_start_bit..chunk_end_bit.min(batch.base_len))
                .any(|bit| batch.modified_bits.contains_key(&bit));

        if chunk_needs_reconstruction {
            // Reconstruct chunk from current + batch modifications
            self.reconstruct_modified_chunk(chunk_start_bit)
        } else {
            // Fall through to current bitmap
            *self.bitmap.current.get_chunk_containing(bit)
        }
    }

    /// Reconstruct a chunk that has modifications, appends, or pops.
    fn reconstruct_modified_chunk(&self, chunk_start: u64) -> [u8; N] {
        let batch = self.bitmap.active_batch.as_ref().unwrap();

        // Start with current chunk if it exists
        let mut chunk = if chunk_start < self.bitmap.current.len() {
            *self.bitmap.current.get_chunk_containing(chunk_start)
        } else {
            [0u8; N]
        };

        // Calculate appended region boundary
        let appended_start = batch.projected_len - batch.appended_bits.len() as u64;

        // Apply batch modifications and zero out popped bits
        for bit_in_chunk in 0..Prunable::<N>::CHUNK_SIZE_BITS {
            let bit = chunk_start + bit_in_chunk;

            let byte_idx = (bit_in_chunk / 8) as usize;
            let bit_idx = bit_in_chunk % 8;
            let mask = 1u8 << bit_idx;

            if bit >= batch.projected_len {
                // Bit is beyond projected length (popped), zero it out
                chunk[byte_idx] &= !mask;
            } else if let Some(&value) = batch.modified_bits.get(&bit) {
                // Bit was explicitly modified in the batch
                if value {
                    chunk[byte_idx] |= mask;
                } else {
                    chunk[byte_idx] &= !mask;
                }
            } else if bit >= appended_start {
                // This is an appended bit
                let append_offset = (bit - appended_start) as usize;
                if append_offset < batch.appended_bits.len() {
                    let value = batch.appended_bits[append_offset];
                    if value {
                        chunk[byte_idx] |= mask;
                    } else {
                        chunk[byte_idx] &= !mask;
                    }
                }
            }
        }

        chunk
    }

    /// Set a bit value in the batch.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds or if the bit has been pruned.
    pub fn set_bit(&mut self, bit: u64, value: bool) -> &mut Self {
        let batch = self.bitmap.active_batch.as_mut().unwrap();

        assert!(
            bit < batch.projected_len,
            "cannot set bit {bit}: out of bounds (len: {})",
            batch.projected_len
        );

        let chunk_idx = Prunable::<N>::unpruned_chunk(bit);
        assert!(
            chunk_idx >= batch.projected_pruned_chunks,
            "cannot set bit {bit}: chunk {chunk_idx} is pruned (pruned up to chunk {})",
            batch.projected_pruned_chunks
        );

        // Determine which region this bit belongs to.
        // Appended region: bits pushed in this batch, starting at projected_len - appended_bits.len()
        let appended_start = batch.projected_len - batch.appended_bits.len() as u64;

        if bit >= appended_start {
            // Bit is in the appended region: update the appended_bits vector directly.
            let append_offset = (bit - appended_start) as usize;
            batch.appended_bits[append_offset] = value;
        } else {
            // Bit is in the base region: record as a modification.
            batch.modified_bits.insert(bit, value);
        }

        self
    }

    /// Push a bit to the end of the bitmap.
    pub fn push(&mut self, bit: bool) -> &mut Self {
        let batch = self.bitmap.active_batch.as_mut().unwrap();

        batch.appended_bits.push(bit);
        batch.projected_len += 1;

        self
    }

    /// Push a byte to the end of the bitmap.
    pub fn push_byte(&mut self, byte: u8) -> &mut Self {
        for i in 0..8 {
            let bit = (byte >> i) & 1 == 1;
            self.push(bit);
        }
        self
    }

    /// Push a full chunk to the end of the bitmap.
    pub fn push_chunk(&mut self, chunk: &[u8; N]) -> &mut Self {
        for byte in chunk {
            self.push_byte(*byte);
        }
        self
    }

    /// Pop the last bit from the bitmap.
    ///
    /// Returns the value of the popped bit, accounting for any modifications in this batch.
    ///
    /// # Panics
    ///
    /// Panics if the bitmap is empty.
    pub fn pop(&mut self) -> bool {
        let batch = self.bitmap.active_batch.as_mut().unwrap();

        assert!(batch.projected_len > 0, "cannot pop from empty bitmap");

        let old_projected_len = batch.projected_len;
        batch.projected_len -= 1;
        let bit = batch.projected_len;

        // Determine which region the popped bit came from.
        // The appended region contains bits pushed in this batch: [appended_start, old_projected_len)
        let appended_start = old_projected_len - batch.appended_bits.len() as u64;

        if bit >= appended_start {
            // Popping from appended region: remove from appended_bits vector.
            batch.appended_bits.pop().unwrap()
        } else {
            // Popping from base region: check if it was modified in this batch.
            if let Some(&modified_value) = batch.modified_bits.get(&bit) {
                batch.modified_bits.remove(&bit);
                modified_value
            } else {
                // Not modified in batch, return original value.
                self.bitmap.current.get_bit(bit)
            }
        }
    }

    /// Prune chunks up to the chunk containing the given bit offset.
    ///
    /// Note: `bit` can equal `projected_len` when pruning at a chunk boundary.
    ///
    /// # Panics
    ///
    /// Panics if `bit` is > the projected length of the batch.
    pub fn prune_to_bit(&mut self, bit: u64) -> &mut Self {
        let batch = self.bitmap.active_batch.as_mut().unwrap();

        assert!(
            bit <= batch.projected_len,
            "cannot prune to bit {bit}: beyond projected length ({})",
            batch.projected_len
        );

        let chunk_num = Prunable::<N>::unpruned_chunk(bit);

        if chunk_num <= batch.projected_pruned_chunks {
            return self; // Already pruned
        }

        // Capture preimages of chunks being pruned
        let current_pruned = self.bitmap.current.pruned_chunks();
        for chunk_idx in batch.projected_pruned_chunks..chunk_num {
            if batch.chunks_to_prune.contains_key(&chunk_idx) {
                continue; // Already captured
            }

            // Invariant: chunk_idx should always be >= current_pruned because
            // projected_pruned_chunks starts at base_pruned_chunks (= current_pruned)
            assert!(
                chunk_idx >= current_pruned,
                "attempting to prune chunk {chunk_idx} which is already pruned (current pruned_chunks={current_pruned})",
            );

            let bitmap_idx = chunk_idx - current_pruned;

            // Get chunk data, which may come from batch if it's appended
            let chunk_data = if bitmap_idx < self.bitmap.current.chunks_len() {
                // Chunk exists in current bitmap
                *self.bitmap.current.get_chunk(bitmap_idx)
            } else {
                // Chunk only exists in this batch's appended bits
                // Manually reconstruct it from appended_bits
                let chunk_start_bit = chunk_idx as u64 * Prunable::<N>::CHUNK_SIZE_BITS;
                let appended_start = batch.projected_len - batch.appended_bits.len() as u64;

                let mut chunk = [0u8; N];
                for bit_in_chunk in 0..Prunable::<N>::CHUNK_SIZE_BITS {
                    let bit = chunk_start_bit + bit_in_chunk;
                    if bit >= batch.projected_len {
                        break;
                    }
                    if bit >= appended_start {
                        let append_idx = (bit - appended_start) as usize;
                        if append_idx < batch.appended_bits.len() && batch.appended_bits[append_idx]
                        {
                            let byte_idx = (bit_in_chunk / 8) as usize;
                            let bit_idx = bit_in_chunk % 8;
                            chunk[byte_idx] |= 1u8 << bit_idx;
                        }
                    }
                }
                chunk
            };

            batch.chunks_to_prune.insert(chunk_idx, chunk_data);
        }

        batch.projected_pruned_chunks = chunk_num;

        self
    }

    /// Commit the batch, applying its changes and storing a historical snapshot.
    ///
    /// # Errors
    ///
    /// Returns [Error::NonMonotonicCommit] if the commit number is not
    /// greater than the previous commit.
    ///
    /// Returns [Error::ReservedCommitNumber] if the commit number is `u64::MAX`.
    pub fn commit(mut self, commit_number: u64) -> Result<(), Error> {
        // Validate commit number is not reserved
        if commit_number == u64::MAX {
            return Err(Error::ReservedCommitNumber);
        }

        // Validate commit number is monotonically increasing
        if let Some(&max_commit) = self.bitmap.commits.keys().next_back() {
            if commit_number <= max_commit {
                return Err(Error::NonMonotonicCommit {
                    previous: max_commit,
                    attempted: commit_number,
                });
            }
        }

        // Take the batch
        let batch = self.bitmap.active_batch.take().unwrap();

        // Build reverse diff (captures OLD state before applying batch)
        let reverse_diff = self.bitmap.build_reverse_diff(&batch);

        // Apply batch changes to current bitmap
        self.bitmap.apply_batch_to_current(&batch);

        // Store the reverse diff
        self.bitmap.commits.insert(commit_number, reverse_diff);

        // Mark as committed
        self.committed = true;

        Ok(())
    }
}

impl<'a, const N: usize> Drop for BatchGuard<'a, N> {
    fn drop(&mut self) {
        if !self.committed {
            // Batch is being dropped without commit - discard the diff layer
            self.bitmap.active_batch = None;
        }
    }
}

use super::Error;
use crate::bitmap::Prunable;
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Sealed trait for bitmap state types.
mod private {
    pub trait Sealed {}
}

/// Trait for valid bitmap type states [Clean], [Dirty].
pub trait State: private::Sealed + Sized + Send + Sync {}

/// Clean bitmap type state - bitmap has no pending mutations.
#[derive(Clone, Debug)]
pub struct Clean;

impl private::Sealed for Clean {}
impl State for Clean {}

/// Dirty bitmap type state - bitmap has pending mutations not yet committed.
///
/// # De-duplication and Cancellation
///
/// **The dirty state de-duplicates during operations, not at commit time.**
///
/// Operations that cancel out are handled automatically:
///
/// ```text
/// Example 1: push + pop = no-op
///   push(true)  → appended_bits=[true], projected_len=11
///   pop()       → appended_bits=[], projected_len=10
///   Result: dirty state unchanged from base
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
/// # Key Invariants
///
/// 1. **Base immutability**: `base_len` and `base_pruned_chunks` never change
/// 2. **Appended region**: Always occupies `[projected_len - appended_bits.len(), projected_len)`
/// 3. **Modified region**: `modified_bits` only contains offsets in `[0, projected_len - appended_bits.len())`
///    - These are modifications to the base bitmap, never to appended bits
///    - Appended bits are modified by directly updating the `appended_bits` vector
/// 4. **No overlap**: A bit is either in `modified_bits` OR `appended_bits`, never both
#[derive(Clone, Debug)]
pub struct Dirty<const N: usize> {
    /// Bitmap state when dirty started (immutable).
    base_len: u64,
    base_pruned_chunks: usize,

    /// What the bitmap will look like after commit (mutable).
    projected_len: u64,
    projected_pruned_chunks: usize,

    /// Modifications to bits that existed in the bitmap (not appended bits).
    /// Contains offsets in [0, projected_len - appended_bits.len()).
    /// Maps: bit -> new_value
    modified_bits: BTreeMap<u64, bool>,

    /// New bits pushed in this dirty state (in order).
    /// Logical position: [projected_len - appended_bits.len(), projected_len)
    appended_bits: Vec<bool>,

    /// Old chunk data for chunks being pruned.
    /// Captured eagerly during `prune_to_bit()` for historical reconstruction.
    chunks_to_prune: BTreeMap<usize, [u8; N]>,
}

impl<const N: usize> private::Sealed for Dirty<N> {}
impl<const N: usize> State for Dirty<N> {}

/// A change to a chunk.
#[derive(Clone, Debug)]
pub(super) enum ChunkDiff<const N: usize> {
    /// Chunk was modified (contains old value before the change).
    Modified([u8; N]),
    /// Chunk was removed from the right side (contains old value before removal).
    Removed([u8; N]),
    /// Chunk was added (did not exist before).
    Added,
    /// Chunk was pruned from the left side (contains old value before pruning).
    Pruned([u8; N]),
}

/// A reverse diff that describes the state before a commit.
#[derive(Clone, Debug)]
pub(super) struct CommitDiff<const N: usize> {
    /// Total length in bits before this commit.
    pub(super) len: u64,
    /// Number of pruned chunks before this commit.
    pub(super) pruned_chunks: usize,
    /// Chunk-level changes.
    pub(super) chunk_diffs: BTreeMap<usize, ChunkDiff<N>>,
}

/// A historical bitmap that maintains one actual bitmap plus diffs for history.
///
/// Uses a type-state pattern to track whether the bitmap is clean (no pending
/// mutations) or dirty (has pending mutations).
///
/// Commit numbers must be strictly monotonically increasing and < u64::MAX.
#[derive(Clone, Debug)]
pub struct BitMap<const N: usize, S: State = Clean> {
    /// The current/HEAD state - the one and only full bitmap.
    current: Prunable<N>,

    /// Historical commits: commit_number -> reverse diff from that commit.
    commits: BTreeMap<u64, CommitDiff<N>>,

    /// State marker (Clean or Dirty).
    state: S,
}

/// Type alias for a clean bitmap with no pending mutations.
pub type CleanBitMap<const N: usize> = BitMap<N, Clean>;

/// Type alias for a dirty bitmap with pending mutations.
pub type DirtyBitMap<const N: usize> = BitMap<N, Dirty<N>>;

impl<const N: usize> CleanBitMap<N> {
    /// Create a new empty historical bitmap.
    pub const fn new() -> Self {
        Self {
            current: Prunable::new(),
            commits: BTreeMap::new(),
            state: Clean,
        }
    }

    /// Create a new historical bitmap with the given number of pruned chunks.
    pub fn new_with_pruned_chunks(pruned_chunks: usize) -> Result<Self, Error> {
        Ok(Self {
            current: Prunable::new_with_pruned_chunks(pruned_chunks)?,
            commits: BTreeMap::new(),
            state: Clean,
        })
    }

    /// Transition to dirty state to begin making mutations.
    ///
    /// All mutations are applied to a diff layer and do not affect the current
    /// bitmap until commit.
    ///
    /// # Examples
    ///
    /// ```
    /// # use commonware_utils::bitmap::historical::BitMap;
    /// let bitmap: BitMap<4> = BitMap::new();
    ///
    /// let mut dirty = bitmap.into_dirty();
    /// dirty.push(true);
    /// dirty.push(false);
    /// let bitmap = dirty.commit(1).unwrap();
    ///
    /// assert_eq!(bitmap.len(), 2);
    /// ```
    pub fn into_dirty(self) -> DirtyBitMap<N> {
        DirtyBitMap {
            state: Dirty {
                base_len: self.current.len(),
                base_pruned_chunks: self.current.pruned_chunks(),
                projected_len: self.current.len(),
                projected_pruned_chunks: self.current.pruned_chunks(),
                modified_bits: BTreeMap::new(),
                appended_bits: Vec::new(),
                chunks_to_prune: BTreeMap::new(),
            },
            current: self.current,
            commits: self.commits,
        }
    }

    /// Execute a closure with a dirty bitmap and commit it at the given commit number.
    ///
    /// # Errors
    ///
    /// Returns [Error::NonMonotonicCommit] if the commit number is not
    /// greater than the previous commit.
    ///
    /// Returns [Error::ReservedCommitNumber] if the commit number is `u64::MAX`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use commonware_utils::bitmap::historical::BitMap;
    /// let mut bitmap: BitMap<4> = BitMap::new();
    ///
    /// bitmap = bitmap.apply_batch(1, |dirty| {
    ///     dirty.push(true).push(false);
    /// }).unwrap();
    ///
    /// assert_eq!(bitmap.len(), 2);
    /// ```
    pub fn apply_batch<F>(self, commit_number: u64, f: F) -> Result<Self, Error>
    where
        F: FnOnce(&mut DirtyBitMap<N>),
    {
        let mut dirty = self.into_dirty();
        f(&mut dirty);
        dirty.commit(commit_number)
    }

    /// Get the bitmap state as it existed at a specific commit.
    ///
    /// Returns `None` if the commit does not exist or if `commit_number` is `u64::MAX`
    /// (which is reserved and cannot be used as a commit number).
    ///
    /// This reconstructs the historical state by applying reverse diffs backward from
    /// the current state. Each commit's reverse diff describes the state before that
    /// commit, so we "undo" commits one by one until we reach the target.
    ///
    /// # Examples
    ///
    /// ```
    /// # use commonware_utils::bitmap::historical::BitMap;
    /// let mut bitmap: BitMap<4> = BitMap::new();
    ///
    /// bitmap = bitmap.apply_batch(1, |dirty| {
    ///     dirty.push(true);
    ///     dirty.push(false);
    /// }).unwrap();
    ///
    /// bitmap = bitmap.apply_batch(2, |dirty| {
    ///     dirty.set_bit(0, false);
    ///     dirty.push(true);
    /// }).unwrap();
    ///
    /// // Get state as it was at commit 1
    /// let state_at_1 = bitmap.get_at_commit(1).unwrap();
    /// assert_eq!(state_at_1.len(), 2);
    /// assert!(state_at_1.get_bit(0));
    /// assert!(!state_at_1.get_bit(1));
    ///
    /// // Current state is different
    /// assert_eq!(bitmap.len(), 3);
    /// assert!(!bitmap.get_bit(0));
    /// ```
    pub fn get_at_commit(&self, commit_number: u64) -> Option<Prunable<N>> {
        // Check if the commit exists and is valid
        if commit_number == u64::MAX || !self.commits.contains_key(&commit_number) {
            return None;
        }

        // Start with current state
        let mut state = self.current.clone();

        // Apply reverse diffs from newest down to target (exclusive)
        // Each reverse diff at commit N describes the state before commit N
        // Addition can't overflow because commit_number < u64::MAX
        for (_commit, diff) in self.commits.range(commit_number + 1..).rev() {
            self.apply_reverse_diff(&mut state, diff);
        }

        Some(state)
    }

    /// Check if a commit exists.
    pub fn commit_exists(&self, commit_number: u64) -> bool {
        self.commits.contains_key(&commit_number)
    }

    /// Get an iterator over all commit numbers in ascending order.
    pub fn commits(&self) -> impl Iterator<Item = u64> + '_ {
        self.commits.keys().copied()
    }

    /// Get the latest commit number, if any commits exist.
    pub fn latest_commit(&self) -> Option<u64> {
        self.commits.keys().next_back().copied()
    }

    /// Get the earliest commit number, if any commits exist.
    pub fn earliest_commit(&self) -> Option<u64> {
        self.commits.keys().next().copied()
    }

    /// Get a reference to the current bitmap state.
    pub const fn current(&self) -> &Prunable<N> {
        &self.current
    }

    /// Number of bits in the current bitmap.
    #[inline]
    pub const fn len(&self) -> u64 {
        self.current.len()
    }

    /// Returns true if the current bitmap is empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.current.is_empty()
    }

    /// Get the value of a bit in the current bitmap.
    #[inline]
    pub fn get_bit(&self, bit: u64) -> bool {
        self.current.get_bit(bit)
    }

    /// Get the chunk containing a bit in the current bitmap.
    #[inline]
    pub fn get_chunk_containing(&self, bit: u64) -> &[u8; N] {
        self.current.get_chunk_containing(bit)
    }

    /// Number of pruned chunks in the current bitmap.
    #[inline]
    pub const fn pruned_chunks(&self) -> usize {
        self.current.pruned_chunks()
    }

    /// Remove all commits with numbers below the commit number.
    ///
    /// Returns the number of commits removed.
    pub fn prune_commits_before(&mut self, commit_number: u64) -> usize {
        let count = self.commits.len();
        self.commits = self.commits.split_off(&commit_number);
        count - self.commits.len()
    }

    /// Clear all historical commits.
    pub fn clear_history(&mut self) {
        self.commits.clear();
    }

    /// Push bits to extend the bitmap to target length.
    fn push_to_length(&self, state: &mut Prunable<N>, target_len: u64) {
        while state.len() < target_len {
            let remaining = target_len - state.len();
            let next_bit = state.len() % Prunable::<N>::CHUNK_SIZE_BITS;

            // If we're at a chunk boundary and need at least a full chunk, push an entire chunk
            if next_bit == 0 && remaining >= Prunable::<N>::CHUNK_SIZE_BITS {
                state.push_chunk(&[0u8; N]);
            } else {
                // Otherwise push individual bits
                state.push(false);
            }
        }
    }

    /// Pop bits to shrink the bitmap to target length.
    /// Optimized to pop entire chunks when possible.
    fn pop_to_length(&self, state: &mut Prunable<N>, target_len: u64) {
        while state.len() > target_len {
            let excess = state.len() - target_len;
            let next_bit = state.len() % Prunable::<N>::CHUNK_SIZE_BITS;

            // If at chunk boundary and we need to remove at least a full chunk, pop entire chunk
            if next_bit == 0 && excess >= Prunable::<N>::CHUNK_SIZE_BITS {
                state.pop_chunk();
            } else {
                // Otherwise pop individual bits
                state.pop();
            }
        }
    }

    /// Apply a reverse diff to transform newer_state into the previous state (in-place).
    ///
    /// Algorithm:
    /// 1. Restore pruned chunks by prepending them back (unprune)
    /// 2. Adjust bitmap structure to target length (extend/shrink as needed)
    /// 3. Update chunk data for Modified and Removed chunks
    /// 4. Set next_bit to match target length exactly
    fn apply_reverse_diff(&self, newer_state: &mut Prunable<N>, diff: &CommitDiff<N>) {
        let target_len = diff.len;
        let target_pruned = diff.pruned_chunks;
        let newer_pruned = newer_state.pruned_chunks();

        // Phase 1: Restore pruned chunks
        assert!(
            target_pruned <= newer_pruned,
            "invariant violation: target_pruned ({target_pruned}) > newer_pruned ({newer_pruned})"
        );
        let mut chunks_to_unprune = Vec::with_capacity(newer_pruned - target_pruned);
        for chunk_index in (target_pruned..newer_pruned).rev() {
            let Some(ChunkDiff::Pruned(chunk)) = diff.chunk_diffs.get(&chunk_index) else {
                panic!("chunk {chunk_index} should be Pruned in diff");
            };
            chunks_to_unprune.push(*chunk);
        }
        newer_state.unprune_chunks(&chunks_to_unprune);

        // Phase 2: Adjust bitmap structure to target length
        if newer_state.len() < target_len {
            self.push_to_length(newer_state, target_len);
        } else if newer_state.len() > target_len {
            self.pop_to_length(newer_state, target_len);
        }

        // Phase 3: Update chunk data
        for (&chunk_index, change) in diff
            .chunk_diffs
            .iter()
            .filter(|(chunk_index, _)| **chunk_index >= newer_pruned)
        {
            match change {
                ChunkDiff::Modified(old_data) | ChunkDiff::Removed(old_data) => {
                    // Both cases: chunk exists in target, just update its data
                    newer_state.set_chunk_by_index(chunk_index, old_data);
                }
                ChunkDiff::Added => {
                    // Chunk didn't exist in target - already handled by pop_to_length.
                    // We can break here because there are no more modifications to apply.
                    // Added can only occur after all Modified. If we encounter Added, we know
                    // there are no Removed. (diff.chunk_diffs can't have both Added and Removed.)
                    break;
                }
                ChunkDiff::Pruned(_) => {
                    panic!("pruned chunk found at unexpected index {chunk_index}")
                }
            }
        }

        assert_eq!(newer_state.pruned_chunks(), target_pruned);
        assert_eq!(newer_state.len(), target_len);
    }
}

impl<const N: usize> Default for CleanBitMap<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> DirtyBitMap<N> {
    /// Get the length of the bitmap as it would be after committing.
    #[inline]
    pub const fn len(&self) -> u64 {
        self.state.projected_len
    }

    /// Returns true if the bitmap would be empty after committing.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of pruned chunks after committing.
    #[inline]
    pub const fn pruned_chunks(&self) -> usize {
        self.state.projected_pruned_chunks
    }

    /// Get a bit value with read-through semantics.
    ///
    /// Returns the bit's value as it would be after committing.
    /// Priority: appended bits > modified bits > original bitmap.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds or if the bit has been pruned.
    pub fn get_bit(&self, bit: u64) -> bool {
        assert!(
            bit < self.state.projected_len,
            "bit offset {bit} out of bounds (len: {})",
            self.state.projected_len
        );

        let chunk_idx = Prunable::<N>::unpruned_chunk(bit);
        assert!(
            chunk_idx >= self.state.projected_pruned_chunks,
            "cannot get bit {bit}: chunk {chunk_idx} is pruned (pruned up to chunk {})",
            self.state.projected_pruned_chunks
        );

        // Priority 1: Check if bit is in appended region.
        // Must use appended_start, not base_len, to handle net pops + appends.
        let appended_start = self.state.projected_len - self.state.appended_bits.len() as u64;
        if bit >= appended_start {
            let append_offset = (bit - appended_start) as usize;
            return self.state.appended_bits[append_offset];
        }

        // Priority 2: Check if bit was modified.
        if let Some(&value) = self.state.modified_bits.get(&bit) {
            return value;
        }

        // Priority 3: Fall through to original bitmap.
        self.current.get_bit(bit)
    }

    /// Get a chunk value with read-through semantics.
    ///
    /// Reconstructs the chunk if it has modifications, otherwise returns from current.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds or if the chunk has been pruned.
    pub fn get_chunk(&self, bit: u64) -> [u8; N] {
        // Check bounds
        assert!(
            bit < self.state.projected_len,
            "bit offset {bit} out of bounds (len: {})",
            self.state.projected_len
        );

        let chunk_idx = Prunable::<N>::unpruned_chunk(bit);

        // Check if chunk is in pruned range
        assert!(
            chunk_idx >= self.state.projected_pruned_chunks,
            "cannot get chunk at bit offset {bit}: chunk {chunk_idx} is pruned (pruned up to chunk {})",
            self.state.projected_pruned_chunks
        );

        let chunk_start_bit = chunk_idx as u64 * Prunable::<N>::CHUNK_SIZE_BITS;
        let chunk_end_bit = chunk_start_bit + Prunable::<N>::CHUNK_SIZE_BITS;

        // Determine if this chunk needs reconstruction.
        let appended_start = self.state.projected_len - self.state.appended_bits.len() as u64;

        // Skip reconstruction only if chunk is entirely outside modified regions
        let chunk_entirely_past_end = chunk_start_bit >= self.state.projected_len;
        let chunk_entirely_before_changes =
            chunk_end_bit <= appended_start && chunk_end_bit <= self.state.projected_len;

        let chunk_needs_reconstruction =
            // Chunk overlaps with pops or appends
            !(chunk_entirely_past_end || chunk_entirely_before_changes)
            // OR chunk has explicit bit modifications
            || (chunk_start_bit..chunk_end_bit.min(self.state.base_len))
                .any(|bit| self.state.modified_bits.contains_key(&bit));

        if chunk_needs_reconstruction {
            // Reconstruct chunk from current + modifications
            self.reconstruct_modified_chunk(chunk_start_bit)
        } else {
            // Fall through to current bitmap
            *self.current.get_chunk_containing(bit)
        }
    }

    /// Reconstruct a chunk that has modifications, appends, or pops.
    fn reconstruct_modified_chunk(&self, chunk_start: u64) -> [u8; N] {
        // Start with current chunk if it exists
        let mut chunk = if chunk_start < self.current.len() {
            *self.current.get_chunk_containing(chunk_start)
        } else {
            [0u8; N]
        };

        // Calculate appended region boundary
        let appended_start = self.state.projected_len - self.state.appended_bits.len() as u64;

        // Apply modifications and zero out popped bits
        for bit_in_chunk in 0..Prunable::<N>::CHUNK_SIZE_BITS {
            let bit = chunk_start + bit_in_chunk;

            let byte_idx = (bit_in_chunk / 8) as usize;
            let bit_idx = bit_in_chunk % 8;
            let mask = 1u8 << bit_idx;

            if bit >= self.state.projected_len {
                // Bit is beyond projected length (popped), zero it out
                chunk[byte_idx] &= !mask;
            } else if let Some(&value) = self.state.modified_bits.get(&bit) {
                // Bit was explicitly modified
                if value {
                    chunk[byte_idx] |= mask;
                } else {
                    chunk[byte_idx] &= !mask;
                }
            } else if bit >= appended_start {
                // This is an appended bit
                let append_offset = (bit - appended_start) as usize;
                if append_offset < self.state.appended_bits.len() {
                    let value = self.state.appended_bits[append_offset];
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

    /// Set a bit value.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds or if the bit has been pruned.
    pub fn set_bit(&mut self, bit: u64, value: bool) -> &mut Self {
        assert!(
            bit < self.state.projected_len,
            "cannot set bit {bit}: out of bounds (len: {})",
            self.state.projected_len
        );

        let chunk_idx = Prunable::<N>::unpruned_chunk(bit);
        assert!(
            chunk_idx >= self.state.projected_pruned_chunks,
            "cannot set bit {bit}: chunk {chunk_idx} is pruned (pruned up to chunk {})",
            self.state.projected_pruned_chunks
        );

        // Determine which region this bit belongs to.
        // Appended region: bits pushed, starting at projected_len - appended_bits.len()
        let appended_start = self.state.projected_len - self.state.appended_bits.len() as u64;

        if bit >= appended_start {
            // Bit is in the appended region: update the appended_bits vector directly.
            let append_offset = (bit - appended_start) as usize;
            self.state.appended_bits[append_offset] = value;
        } else {
            // Bit is in the base region: record as a modification.
            self.state.modified_bits.insert(bit, value);
        }

        self
    }

    /// Push a bit to the end of the bitmap.
    pub fn push(&mut self, bit: bool) -> &mut Self {
        self.state.appended_bits.push(bit);
        self.state.projected_len += 1;
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
    /// Returns the value of the popped bit, accounting for any modifications.
    ///
    /// # Panics
    ///
    /// Panics if the bitmap is empty.
    pub fn pop(&mut self) -> bool {
        assert!(self.state.projected_len > 0, "cannot pop from empty bitmap");

        let old_projected_len = self.state.projected_len;
        self.state.projected_len -= 1;
        let bit = self.state.projected_len;

        // Determine which region the popped bit came from.
        // The appended region contains bits pushed: [appended_start, old_projected_len)
        let appended_start = old_projected_len - self.state.appended_bits.len() as u64;

        if bit >= appended_start {
            // Popping from appended region: remove from appended_bits vector.
            self.state.appended_bits.pop().unwrap()
        } else {
            // Popping from base region: check if it was modified.
            if let Some(&modified_value) = self.state.modified_bits.get(&bit) {
                self.state.modified_bits.remove(&bit);
                modified_value
            } else {
                // Not modified, return original value.
                self.current.get_bit(bit)
            }
        }
    }

    /// Prune chunks up to the chunk containing the given bit offset.
    ///
    /// Note: `bit` can equal `projected_len` when pruning at a chunk boundary.
    ///
    /// # Panics
    ///
    /// Panics if `bit` is > the projected length.
    pub fn prune_to_bit(&mut self, bit: u64) -> &mut Self {
        assert!(
            bit <= self.state.projected_len,
            "cannot prune to bit {bit}: beyond projected length ({})",
            self.state.projected_len
        );

        let chunk_num = Prunable::<N>::unpruned_chunk(bit);

        if chunk_num <= self.state.projected_pruned_chunks {
            return self; // Already pruned
        }

        // Capture preimages of chunks being pruned
        let current_pruned = self.current.pruned_chunks();
        for chunk_idx in self.state.projected_pruned_chunks..chunk_num {
            if self.state.chunks_to_prune.contains_key(&chunk_idx) {
                continue; // Already captured
            }

            // Invariant: chunk_idx should always be >= current_pruned because
            // projected_pruned_chunks starts at base_pruned_chunks (= current_pruned)
            assert!(
                chunk_idx >= current_pruned,
                "attempting to prune chunk {chunk_idx} which is already pruned (current pruned_chunks={current_pruned})",
            );

            // Get chunk data, which may come from dirty state if it's appended
            let chunk_data = if chunk_idx < self.current.chunks_len() {
                *self.current.get_chunk(chunk_idx)
            } else {
                // Chunk only exists in appended bits
                // Manually reconstruct it from appended_bits
                let chunk_start_bit = chunk_idx as u64 * Prunable::<N>::CHUNK_SIZE_BITS;
                let appended_start =
                    self.state.projected_len - self.state.appended_bits.len() as u64;

                let mut chunk = [0u8; N];
                for bit_in_chunk in 0..Prunable::<N>::CHUNK_SIZE_BITS {
                    let bit = chunk_start_bit + bit_in_chunk;
                    if bit >= self.state.projected_len {
                        break;
                    }
                    if bit >= appended_start {
                        let append_idx = (bit - appended_start) as usize;
                        if append_idx < self.state.appended_bits.len()
                            && self.state.appended_bits[append_idx]
                        {
                            let byte_idx = (bit_in_chunk / 8) as usize;
                            let bit_idx = bit_in_chunk % 8;
                            chunk[byte_idx] |= 1u8 << bit_idx;
                        }
                    }
                }
                chunk
            };

            self.state.chunks_to_prune.insert(chunk_idx, chunk_data);
        }

        self.state.projected_pruned_chunks = chunk_num;

        self
    }

    /// Commit the changes and return a clean bitmap with a historical snapshot.
    ///
    /// # Errors
    ///
    /// Returns [Error::NonMonotonicCommit] if the commit number is not
    /// greater than the previous commit.
    ///
    /// Returns [Error::ReservedCommitNumber] if the commit number is `u64::MAX`.
    pub fn commit(mut self, commit_number: u64) -> Result<CleanBitMap<N>, Error> {
        // Validate commit number is not reserved
        if commit_number == u64::MAX {
            return Err(Error::ReservedCommitNumber);
        }

        // Validate commit number is monotonically increasing
        if let Some(&max_commit) = self.commits.keys().next_back() {
            if commit_number <= max_commit {
                return Err(Error::NonMonotonicCommit {
                    previous: max_commit,
                    attempted: commit_number,
                });
            }
        }

        // Build reverse diff (captures OLD state before applying changes)
        let reverse_diff = self.build_reverse_diff();

        // Shrink to length before appends (handles net pops)
        let target_len_before_appends =
            self.state.projected_len - self.state.appended_bits.len() as u64;
        while self.current.len() > target_len_before_appends {
            self.current.pop();
        }
        // Grow by appending new bits
        for &bit in &self.state.appended_bits {
            self.current.push(bit);
        }
        assert_eq!(self.current.len(), self.state.projected_len);
        // Modify existing base bits (not appended bits)
        for (&bit, &value) in &self.state.modified_bits {
            self.current.set_bit(bit, value);
        }
        // Prune chunks from the beginning
        if self.state.projected_pruned_chunks > self.state.base_pruned_chunks {
            let prune_to_bit =
                self.state.projected_pruned_chunks as u64 * Prunable::<N>::CHUNK_SIZE_BITS;
            self.current.prune_to_bit(prune_to_bit);
        }

        // Store the reverse diff
        self.commits.insert(commit_number, reverse_diff);

        Ok(CleanBitMap {
            current: self.current,
            commits: self.commits,
            state: Clean,
        })
    }

    /// Abort the changes and return to clean state.
    ///
    /// All pending mutations are discarded.
    pub fn abort(self) -> CleanBitMap<N> {
        CleanBitMap {
            current: self.current,
            commits: self.commits,
            state: Clean,
        }
    }

    /// Build a reverse diff from current dirty state.
    fn build_reverse_diff(&self) -> CommitDiff<N> {
        let mut changes = BTreeMap::new();
        self.capture_modified_chunks(&mut changes);
        self.capture_appended_chunks(&mut changes);
        self.capture_popped_chunks(&mut changes);
        self.capture_pruned_chunks(&mut changes);
        CommitDiff {
            len: self.state.base_len,
            pruned_chunks: self.state.base_pruned_chunks,
            chunk_diffs: changes,
        }
    }

    /// Capture chunks affected by bit modifications.
    ///
    /// For each chunk containing modified bits, we store its original value so we can
    /// restore it when reconstructing historical states.
    fn capture_modified_chunks(&self, changes: &mut BTreeMap<usize, ChunkDiff<N>>) {
        for &bit in self.state.modified_bits.keys() {
            let chunk_idx = Prunable::<N>::unpruned_chunk(bit);
            changes.entry(chunk_idx).or_insert_with(|| {
                // `modified_bits` only contains bits from the base region, so the chunk must exist.
                let old_chunk = self
                    .get_chunk_from_current(chunk_idx)
                    .expect("chunk must exist for modified bit");
                ChunkDiff::Modified(old_chunk)
            });
        }
    }

    /// Capture chunks affected by appended bits.
    ///
    /// When bits are appended, they may:
    /// - Extend an existing partial chunk (mark as Modified with old data)
    /// - Create entirely new chunks (mark as Added)
    fn capture_appended_chunks(&self, changes: &mut BTreeMap<usize, ChunkDiff<N>>) {
        if self.state.appended_bits.is_empty() {
            return;
        }

        // Calculate which chunks will be affected by appends.
        // Note: append_start_bit accounts for any net pops before the pushes.
        let append_start_bit = self.state.projected_len - self.state.appended_bits.len() as u64;
        let start_chunk = Prunable::<N>::unpruned_chunk(append_start_bit);
        let end_chunk = Prunable::<N>::unpruned_chunk(self.state.projected_len.saturating_sub(1));

        for chunk_idx in start_chunk..=end_chunk {
            // Use or_insert_with so we don't overwrite chunks already captured
            // by capture_modified_chunks (which runs first and takes precedence).
            changes.entry(chunk_idx).or_insert_with(|| {
                self.get_chunk_from_current(chunk_idx).map_or(
                    // Chunk is brand new: mark as Added
                    ChunkDiff::Added,
                    // Chunk existed before: store its old data
                    ChunkDiff::Modified,
                )
            });
        }
    }

    /// Capture chunks affected by pop operations.
    ///
    /// When bits are popped (projected_len < base_len), we need to capture the original
    /// data of chunks that will be truncated or fully removed. This allows reconstruction
    /// to restore the bits that were popped.
    fn capture_popped_chunks(&self, changes: &mut BTreeMap<usize, ChunkDiff<N>>) {
        if self.state.projected_len >= self.state.base_len || self.state.base_len == 0 {
            return; // No net pops
        }

        // Identify the range of chunks affected by length reduction.
        let old_last_chunk = Prunable::<N>::unpruned_chunk(self.state.base_len - 1);
        let new_last_chunk = if self.state.projected_len > 0 {
            Prunable::<N>::unpruned_chunk(self.state.projected_len - 1)
        } else {
            0
        };

        // Capture all chunks between the new and old endpoints.

        // Handle the case where we popped all unpruned bits, leaving new_last_chunk
        // < self.state.base_pruned_chunks. For example, suppose bitmap has 10 bits per chunk,
        // and 50 entries, where 40 are pruned. Then we pop 10 bits to make the bitmap have 40 entries,
        // where all 40 are pruned. Then new_last_chunk is 3 and self.state.base_pruned_chunks is 4.
        let start_chunk = self.state.base_pruned_chunks.max(new_last_chunk);

        for chunk_idx in start_chunk..=old_last_chunk {
            changes.entry(chunk_idx).or_insert_with(|| {
                let old_chunk = self
                    .get_chunk_from_current(chunk_idx)
                    .expect("chunk must exist in base bitmap for popped bits");

                // Determine if this chunk is partially kept or completely removed
                let chunk_start_bit = chunk_idx as u64 * Prunable::<N>::CHUNK_SIZE_BITS;

                if self.state.projected_len > chunk_start_bit {
                    // Chunk spans the new length boundary → partially kept (Modified)
                    ChunkDiff::Modified(old_chunk)
                } else {
                    // Chunk is completely beyond the new length → fully removed (Removed)
                    ChunkDiff::Removed(old_chunk)
                }
            });
        }
    }

    /// Capture chunks that will be pruned.
    ///
    /// The `prune_to_bit` method already captured the old chunk data,
    /// so we simply copy it into the reverse diff.
    fn capture_pruned_chunks(&self, changes: &mut BTreeMap<usize, ChunkDiff<N>>) {
        for (&chunk_idx, &chunk_data) in &self.state.chunks_to_prune {
            changes.insert(chunk_idx, ChunkDiff::Pruned(chunk_data));
        }
    }

    /// Get chunk data from current state if it exists.
    ///
    /// Returns `Some(chunk_data)` if the chunk exists in the current bitmap,
    /// or `None` if it's out of bounds or pruned.
    fn get_chunk_from_current(&self, chunk_idx: usize) -> Option<[u8; N]> {
        let current_pruned = self.current.pruned_chunks();
        if chunk_idx >= current_pruned && chunk_idx < self.current.chunks_len() {
            return Some(*self.current.get_chunk(chunk_idx));
        }
        None
    }
}

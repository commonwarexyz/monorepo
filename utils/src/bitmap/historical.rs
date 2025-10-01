//! A historical wrapper around [Prunable] that maintains snapshots via diff-based batching.
//!
//! The Historical bitmap maintains one full [Prunable] bitmap (the current/head state).
//! All historical states and batch mutations are represented as diffs, not full bitmap clones.
//!
//! # Examples
//!
//! ## Basic Batching
//!
//! ```
//! # use commonware_utils::bitmap::Historical;
//! let mut historical: Historical<4> = Historical::new();
//!
//! // Create and commit a batch
//! historical.with_batch(1, |batch| {
//!     batch.push(true);
//!     batch.push(false);
//! }).unwrap();
//!
//! assert_eq!(historical.len(), 2);
//! assert!(historical.get_bit(0));
//! assert!(!historical.get_bit(1));
//! ```
//!
//! ## Read-Through Semantics
//!
//! ```
//! # use commonware_utils::bitmap::Historical;
//! let mut historical: Historical<4> = Historical::new();
//! historical.with_batch(1, |batch| { batch.push(false); }).unwrap();
//!
//! // Before modification
//! assert!(!historical.get_bit(0));
//!
//! {
//!     let mut batch = historical.start_batch();
//!     batch.set_bit(0, true);
//!
//!     // Read through batch sees the modification
//!     assert!(batch.get_bit(0));
//!
//!     batch.commit(2).unwrap();
//! }
//!
//! // After commit, modification is in current
//! assert!(historical.get_bit(0));
//! ```
//!
//! ## Abort on Drop
//!
//! ```
//! # use commonware_utils::bitmap::Historical;
//! # let mut historical: Historical<4> = Historical::new();
//! # historical.with_batch(1, |batch| { batch.push(true); }).unwrap();
//! let len_before = historical.len();
//!
//! {
//!     let mut batch = historical.start_batch();
//!     batch.push(true);
//!     batch.push(false);
//!     // Drop without commit = automatic abort
//! }
//!
//! assert_eq!(historical.len(), len_before); // Unchanged
//! ```
//!
//! ## Commit History Management
//!
//! ```
//! # use commonware_utils::bitmap::Historical;
//! # let mut historical: Historical<4> = Historical::new();
//! for i in 1..=5 {
//!     historical.with_batch(i, |batch| {
//!         batch.push(true);
//!     }).unwrap();
//! }
//!
//! assert_eq!(historical.commits().count(), 5);
//!
//! // Prune old commits
//! historical.prune_commits_before(3);
//! assert_eq!(historical.commits().count(), 3);
//! ```

use super::Prunable;
#[cfg(not(feature = "std"))]
use alloc::{
    collections::{BTreeMap, HashMap},
    vec::Vec,
};
#[cfg(feature = "std")]
use std::collections::{BTreeMap, HashMap};

/// Errors that can occur in Historical bitmap operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Commit numbers must be strictly monotonically increasing.
    #[error("commit number ({attempted}) <= previous commit ({previous})")]
    NonMonotonicCommit { previous: u64, attempted: u64 },
}

/// Metadata about a historical state.
#[derive(Clone, Debug)]
struct CommitMetadata {
    /// Total length in bits at this commit.
    len: u64,
    /// Number of pruned chunks at this commit.
    pruned_chunks: usize,
}

/// Type of change to a chunk.
#[derive(Clone, Debug)]
enum ChunkChange<const N: usize> {
    /// Chunk was modified (contains old value before the change).
    Modified([u8; N]),
    /// Chunk was added (did not exist before).
    Added,
    /// Chunk was pruned/removed (contains old value before pruning).
    Pruned([u8; N]),
}

/// A reverse diff that describes the state before a commit.
#[derive(Clone, Debug)]
struct CommitDiff<const N: usize> {
    /// Metadata about the state before this commit.
    metadata: CommitMetadata,
    /// Chunk-level changes.
    changes: BTreeMap<usize, ChunkChange<N>>,
}

/// An active batch that tracks mutations as a diff layer.
struct Batch<const N: usize> {
    /// State when batch started.
    base_len: u64,
    base_pruned_chunks: usize,

    /// Projected state if batch is committed.
    projected_len: u64,
    projected_pruned_chunks: usize,

    /// Bits that were modified (exist in base and were changed).
    modified_bits: HashMap<u64, bool>,

    /// Bits appended beyond base_len.
    appended_bits: Vec<bool>,

    /// Chunks that will be pruned if batch commits (captures old data for reverse diff).
    chunks_to_prune: BTreeMap<usize, [u8; N]>,
}

/// A historical bitmap that maintains one actual bitmap plus diffs for history and batching.
pub struct Historical<const N: usize> {
    /// The current/HEAD state - the one and only full bitmap.
    current: Prunable<N>,

    /// Historical commits: commit_number -> reverse diff from that commit.
    commits: BTreeMap<u64, CommitDiff<N>>,

    /// Active batch (if any).
    active_batch: Option<Batch<N>>,
}

impl<const N: usize> Historical<N> {
    /// Create a new empty historical bitmap.
    pub fn new() -> Self {
        Self {
            current: Prunable::new(),
            commits: BTreeMap::new(),
            active_batch: None,
        }
    }

    /// Create a new historical bitmap with the given number of pruned chunks.
    pub fn new_with_pruned_chunks(pruned_chunks: usize) -> Self {
        Self {
            current: Prunable::new_with_pruned_chunks(pruned_chunks),
            commits: BTreeMap::new(),
            active_batch: None,
        }
    }

    /// Start a new batch for making mutations.
    ///
    /// The returned [BatchGuard] must be either committed or dropped. All mutations
    /// are applied to the guard's diff layer and do not affect the current bitmap
    /// until commit.
    ///
    /// # Examples
    ///
    /// ```
    /// # use commonware_utils::bitmap::Historical;
    /// let mut historical: Historical<4> = Historical::new();
    ///
    /// let mut batch = historical.start_batch();
    /// batch.push(true);
    /// batch.push(false);
    /// batch.commit(1).unwrap();
    ///
    /// assert_eq!(historical.len(), 2);
    /// ```
    ///
    /// # Panics
    ///
    /// Panics if a batch is already active.
    pub fn start_batch(&mut self) -> BatchGuard<'_, N> {
        assert!(
            self.active_batch.is_none(),
            "cannot start batch: batch already active"
        );

        let batch = Batch {
            base_len: self.current.len(),
            base_pruned_chunks: self.current.pruned_chunks(),
            projected_len: self.current.len(),
            projected_pruned_chunks: self.current.pruned_chunks(),
            modified_bits: HashMap::new(),
            appended_bits: Vec::new(),
            chunks_to_prune: BTreeMap::new(),
        };

        self.active_batch = Some(batch);

        BatchGuard {
            historical: self,
            committed: false,
        }
    }

    /// Execute a closure with a batch and commit it at the given commit number.
    ///
    /// # Errors
    ///
    /// Returns [Error::NonMonotonicCommit] if the commit number is not
    /// greater than the previous commit.
    ///
    /// # Panics
    ///
    /// Panics if a batch is already active.
    pub fn with_batch<F>(&mut self, commit_number: u64, f: F) -> Result<(), Error>
    where
        F: FnOnce(&mut BatchGuard<'_, N>),
    {
        let mut guard = self.start_batch();
        f(&mut guard);
        guard.commit(commit_number)
    }

    /// Get the bitmap state as it existed at a specific commit.
    ///
    /// Returns `None` if the commit does not exist.
    ///
    /// This reconstructs the historical state by applying reverse diffs backward from
    /// the current state. Each commit's reverse diff describes the state before that
    /// commit, so we "undo" commits one by one until we reach the target.
    ///
    /// # Examples
    ///
    /// ```
    /// # use commonware_utils::bitmap::Historical;
    /// let mut historical: Historical<4> = Historical::new();
    ///
    /// historical.with_batch(1, |batch| {
    ///     batch.push(true);
    ///     batch.push(false);
    /// }).unwrap();
    ///
    /// historical.with_batch(2, |batch| {
    ///     batch.set_bit(0, false);
    ///     batch.push(true);
    /// }).unwrap();
    ///
    /// // Get state as it was at commit 1
    /// let state_at_1 = historical.get_at_commit(1).unwrap();
    /// assert_eq!(state_at_1.len(), 2);
    /// assert!(state_at_1.get_bit(0));
    /// assert!(!state_at_1.get_bit(1));
    ///
    /// // Current state is different
    /// assert_eq!(historical.len(), 3);
    /// assert!(!historical.get_bit(0));
    /// ```
    pub fn get_at_commit(&self, commit_number: u64) -> Option<Prunable<N>> {
        // Check if the commit exists
        if !self.commits.contains_key(&commit_number) {
            return None;
        }

        // Start with current state
        let mut state = self.current.clone();

        // Apply reverse diffs from newest down to target (exclusive)
        // Each reverse diff at commit N describes the state before commit N
        for (_commit, diff) in self.commits.range(commit_number + 1..).rev() {
            state = self.apply_reverse_diff(state, diff);
        }

        Some(state)
    }

    /// Apply a reverse diff to a bitmap, producing the previous state.
    fn apply_reverse_diff(&self, newer_state: Prunable<N>, diff: &CommitDiff<N>) -> Prunable<N> {
        // The diff describes the state before the commit
        // We need to transform newer_state into that older state

        // Start with the target metadata
        let target_len = diff.metadata.len;
        let target_pruned = diff.metadata.pruned_chunks;

        // Create result bitmap with correct pruning
        let mut result = Prunable::new_with_pruned_chunks(target_pruned);

        if target_len == 0 {
            return result;
        }

        // Calculate the raw chunk indices we need to reconstruct
        // (accounting for pruning)
        let raw_first_chunk = target_pruned;
        let raw_last_chunk = Prunable::<N>::raw_chunk_index(target_len - 1);
        let last_chunk_bits = ((target_len - 1) % Prunable::<N>::CHUNK_SIZE_BITS) + 1;

        // Reconstruct complete chunks (all but the last)
        for raw_chunk_idx in raw_first_chunk..raw_last_chunk {
            let chunk_data = self.get_chunk_from_diff_or_newer(&newer_state, diff, raw_chunk_idx);
            result.push_chunk(&chunk_data);
        }

        // Handle the last chunk (may be partial)
        let last_chunk_data = self.get_chunk_from_diff_or_newer(&newer_state, diff, raw_last_chunk);

        if last_chunk_bits < Prunable::<N>::CHUNK_SIZE_BITS as u64 {
            // Partial chunk, push bits one by one
            for bit_idx in 0..last_chunk_bits as usize {
                let byte_idx = bit_idx / 8;
                let bit_in_byte = bit_idx % 8;
                let bit_value = (last_chunk_data[byte_idx] >> bit_in_byte) & 1 == 1;
                result.push(bit_value);
            }
        } else {
            // Complete chunk
            result.push_chunk(&last_chunk_data);
        }

        result
    }

    /// Get chunk data for reconstruction, either from the diff or from the newer state.
    ///
    /// `raw_chunk_idx` is the global chunk index (not adjusted for target pruning).
    fn get_chunk_from_diff_or_newer(
        &self,
        newer_state: &Prunable<N>,
        diff: &CommitDiff<N>,
        raw_chunk_idx: usize,
    ) -> [u8; N] {
        // Check if this chunk has a recorded change
        if let Some(change) = diff.changes.get(&raw_chunk_idx) {
            match change {
                ChunkChange::Modified(old_data) => {
                    // Use the old data from before the modification
                    return *old_data;
                }
                ChunkChange::Added => {
                    // This is a logic bug: we're reconstructing chunks up to target_len
                    // (the length before the commit), so we shouldn't be asking for
                    // chunks that were added in this commit.
                    panic!(
                        "attempted to reconstruct chunk {raw_chunk_idx} marked as Added at target_len {}",
                        diff.metadata.len
                    );
                }
                ChunkChange::Pruned(old_data) => {
                    // This chunk was pruned, use the captured old data
                    return *old_data;
                }
            }
        }

        // No change recorded, so the chunk was the same in both states
        // Get it from the newer state, adjusting for pruning differences
        let newer_pruned = newer_state.pruned_chunks();

        // If a chunk was pruned between target state and newer state,
        // we should have captured it in the diff.
        assert!(
            raw_chunk_idx >= newer_pruned,
            "chunk {raw_chunk_idx} (raw) is pruned in newer state (pruned={})",
            newer_pruned
        );

        // The chunk should either be in the diff (if it changed)
        // or accessible in the newer state (if unchanged).
        let newer_chunk_idx = raw_chunk_idx - newer_pruned;
        assert!(
            newer_chunk_idx < newer_state.chunks_len(),
            "chunk {raw_chunk_idx} (raw) is out of bounds in newer state"
        );

        *newer_state.get_chunk_by_index(newer_chunk_idx)
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
    pub fn current(&self) -> &Prunable<N> {
        &self.current
    }

    /// Number of bits in the current bitmap.
    pub fn len(&self) -> u64 {
        self.current.len()
    }

    /// Returns true if the current bitmap is empty.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }

    /// Get the value of a bit in the current bitmap.
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        self.current.get_bit(bit_offset)
    }

    /// Get the chunk containing a bit in the current bitmap.
    pub fn get_chunk(&self, bit_offset: u64) -> &[u8; N] {
        self.current.get_chunk(bit_offset)
    }

    /// Number of pruned chunks in the current bitmap.
    pub fn pruned_chunks(&self) -> usize {
        self.current.pruned_chunks()
    }

    /// Remove all commits with numbers below the commit number.
    ///
    /// Returns the number of commits removed.
    pub fn prune_commits_before(&mut self, commit_number: u64) -> usize {
        let keys_to_remove: Vec<u64> = self
            .commits
            .range(..commit_number)
            .map(|(k, _)| *k)
            .collect();
        let count = keys_to_remove.len();
        for key in keys_to_remove {
            self.commits.remove(&key);
        }
        count
    }

    /// Remove all commits with numbers at or below the commit number.
    ///
    /// Returns the number of commits removed.
    pub fn prune_commits_at_or_below(&mut self, commit_number: u64) -> usize {
        let keys_to_remove: Vec<u64> = self
            .commits
            .range(..=commit_number)
            .map(|(k, _)| *k)
            .collect();
        let count = keys_to_remove.len();
        for key in keys_to_remove {
            self.commits.remove(&key);
        }
        count
    }

    /// Clear all historical commits.
    pub fn clear_history(&mut self) {
        self.commits.clear();
    }

    /// Apply a batch's changes to the current bitmap.
    fn apply_batch_to_current(&mut self, batch: &Batch<N>) {
        // Calculate the target length before appending (accounting for any net pops)
        let target_len_before_appends = batch.projected_len - batch.appended_bits.len() as u64;

        // Pop down to the target length before appends
        while self.current.len() > target_len_before_appends {
            self.current.pop();
        }

        // Apply appended bits (these fill in positions from target_len_before_appends to projected_len)
        for &bit in &batch.appended_bits {
            self.current.push(bit);
        }

        // Apply modifications to existing bits
        for (&bit_offset, &value) in &batch.modified_bits {
            self.current.set_bit(bit_offset, value);
        }

        // Apply pruning
        if batch.projected_pruned_chunks > batch.base_pruned_chunks {
            let prune_to_bit =
                batch.projected_pruned_chunks as u64 * Prunable::<N>::CHUNK_SIZE_BITS;
            self.current.prune_to_bit(prune_to_bit);
        }
    }

    /// Build a reverse diff from a batch before applying it.
    fn build_reverse_diff(&self, batch: &Batch<N>) -> CommitDiff<N> {
        let mut changes = BTreeMap::new();

        // Capture old values of modified chunks
        #[cfg(not(feature = "std"))]
        let mut affected_chunks = alloc::collections::BTreeSet::new();
        #[cfg(feature = "std")]
        let mut affected_chunks = std::collections::BTreeSet::new();

        for &bit_offset in batch.modified_bits.keys() {
            affected_chunks.insert(Prunable::<N>::raw_chunk_index(bit_offset));
        }

        for &chunk_idx in &affected_chunks {
            // Get the chunk value before batch modifications
            let current_pruned = self.current.pruned_chunks();
            if chunk_idx >= current_pruned {
                let bitmap_idx = chunk_idx - current_pruned;
                if bitmap_idx < self.current.chunks_len() {
                    let old_chunk = *self.current.get_chunk_by_index(bitmap_idx);
                    changes.insert(chunk_idx, ChunkChange::Modified(old_chunk));
                }
            }
        }

        // Record appended chunks as Added (if they didn't exist before)
        // or Modified (if they partially existed and we're extending them)
        if !batch.appended_bits.is_empty() {
            // Appended bits start at: projected_len - appended_bits.len()
            // (accounts for net pops that happened before the pushes)
            let append_start_bit = batch.projected_len - batch.appended_bits.len() as u64;
            let start_chunk = Prunable::<N>::raw_chunk_index(append_start_bit);
            let end_chunk = Prunable::<N>::raw_chunk_index(batch.projected_len.saturating_sub(1));
            for chunk_idx in start_chunk..=end_chunk {
                // Only mark as Added/Modified if not already recorded (don't overwrite existing entries)
                changes.entry(chunk_idx).or_insert_with(|| {
                    // Check if chunk existed before at all
                    let current_pruned = self.current.pruned_chunks();
                    if chunk_idx >= current_pruned {
                        let bitmap_idx = chunk_idx - current_pruned;
                        if bitmap_idx < self.current.chunks_len() {
                            // Chunk existed, capture its old value as Modified
                            let old_chunk = *self.current.get_chunk_by_index(bitmap_idx);
                            ChunkChange::Modified(old_chunk)
                        } else {
                            // Chunk is entirely new
                            ChunkChange::Added
                        }
                    } else {
                        // Chunk was pruned, which shouldn't happen for appends
                        ChunkChange::Added
                    }
                });
            }
        }

        // Handle length reduction (pop operations)
        // If projected_len < base_len, we need to capture chunks that will be affected
        if batch.projected_len < batch.base_len && batch.base_len > 0 {
            let old_last_chunk = Prunable::<N>::raw_chunk_index(batch.base_len - 1);
            let start_chunk = if batch.projected_len > 0 {
                Prunable::<N>::raw_chunk_index(batch.projected_len - 1)
            } else {
                0
            };

            // Capture chunks that are being removed or truncated
            for chunk_idx in start_chunk..=old_last_chunk {
                changes.entry(chunk_idx).or_insert_with(|| {
                    let current_pruned = self.current.pruned_chunks();
                    if chunk_idx >= current_pruned {
                        let bitmap_idx = chunk_idx - current_pruned;
                        if bitmap_idx < self.current.chunks_len() {
                            let old_chunk = *self.current.get_chunk_by_index(bitmap_idx);
                            ChunkChange::Modified(old_chunk)
                        } else {
                            ChunkChange::Added
                        }
                    } else {
                        ChunkChange::Added
                    }
                });
            }
        }

        // Record pruned chunks with their old values
        for (&chunk_idx, &chunk_data) in &batch.chunks_to_prune {
            changes.insert(chunk_idx, ChunkChange::Pruned(chunk_data));
        }

        CommitDiff {
            metadata: CommitMetadata {
                len: batch.base_len,
                pruned_chunks: batch.base_pruned_chunks,
            },
            changes,
        }
    }
}

impl<const N: usize> Default for Historical<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Guard for a batch of mutations with read-through semantics.
#[must_use = "batches must be committed or explicitly dropped"]
pub struct BatchGuard<'a, const N: usize> {
    historical: &'a mut Historical<N>,
    committed: bool,
}

impl<'a, const N: usize> BatchGuard<'a, N> {
    /// Get the length of the bitmap as it would be after committing this batch.
    pub fn len(&self) -> u64 {
        self.historical
            .active_batch
            .as_ref()
            .map(|b| b.projected_len)
            .unwrap_or(0)
    }

    /// Returns true if the bitmap would be empty after committing this batch.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of pruned chunks after this batch.
    pub fn pruned_chunks(&self) -> usize {
        self.historical
            .active_batch
            .as_ref()
            .map(|b| b.projected_pruned_chunks)
            .unwrap_or(0)
    }

    /// Get a bit value with read-through semantics.
    ///
    /// Checks the batch's modifications first, then falls through to current bitmap.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds (>= projected length after pops)
    /// or if the bit has been pruned in this batch.
    pub fn get_bit(&self, bit_offset: u64) -> bool {
        let batch = self.historical.active_batch.as_ref().unwrap();

        // Check bounds (including pops)
        assert!(
            bit_offset < batch.projected_len,
            "bit offset {bit_offset} out of bounds (len: {})",
            batch.projected_len
        );

        // Check if bit was pruned in batch
        let chunk_idx = Prunable::<N>::raw_chunk_index(bit_offset);
        assert!(
            chunk_idx >= batch.projected_pruned_chunks,
            "bit {bit_offset} is pruned"
        );

        // Check if bit is in appended range
        if bit_offset >= batch.base_len {
            let append_offset = (bit_offset - batch.base_len) as usize;
            return batch.appended_bits[append_offset];
        }

        // Check if bit was modified in batch
        if let Some(&value) = batch.modified_bits.get(&bit_offset) {
            return value;
        }

        // Fall through to current bitmap
        self.historical.current.get_bit(bit_offset)
    }

    /// Get a chunk value with read-through semantics.
    ///
    /// Reconstructs the chunk if it has modifications, otherwise returns from current.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds or if the chunk has been pruned.
    pub fn get_chunk(&self, bit_offset: u64) -> [u8; N] {
        let batch = self.historical.active_batch.as_ref().unwrap();

        // Check bounds
        assert!(
            bit_offset < batch.projected_len,
            "bit offset {bit_offset} out of bounds (len: {})",
            batch.projected_len
        );

        let chunk_idx = Prunable::<N>::raw_chunk_index(bit_offset);

        // Check if chunk is in pruned range
        assert!(
            chunk_idx >= batch.projected_pruned_chunks,
            "chunk pruned at bit offset: {bit_offset}"
        );

        let chunk_start_bit = chunk_idx as u64 * Prunable::<N>::CHUNK_SIZE_BITS;

        // Check if chunk has any modifications
        let chunk_has_mods = (chunk_start_bit..chunk_start_bit + Prunable::<N>::CHUNK_SIZE_BITS)
            .any(|bit| {
                batch.modified_bits.contains_key(&bit)
                    || (bit >= batch.base_len && bit < batch.projected_len)
            });

        if chunk_has_mods {
            // Reconstruct chunk from current + batch modifications
            self.reconstruct_modified_chunk(chunk_start_bit)
        } else {
            // Fall through to current bitmap
            *self.historical.current.get_chunk(bit_offset)
        }
    }

    /// Reconstruct a chunk that has modifications or appends.
    fn reconstruct_modified_chunk(&self, chunk_start: u64) -> [u8; N] {
        let batch = self.historical.active_batch.as_ref().unwrap();

        // Start with current chunk if it exists
        let mut chunk = if chunk_start < self.historical.current.len() {
            *self.historical.current.get_chunk(chunk_start)
        } else {
            [0u8; N]
        };

        // Apply batch modifications
        for bit_in_chunk in 0..Prunable::<N>::CHUNK_SIZE_BITS {
            let bit_offset = chunk_start + bit_in_chunk;

            if bit_offset >= batch.projected_len {
                break;
            }

            let byte_idx = (bit_in_chunk / 8) as usize;
            let bit_idx = bit_in_chunk % 8;
            let mask = 1u8 << bit_idx;

            // Check if this bit is modified
            if let Some(&value) = batch.modified_bits.get(&bit_offset) {
                if value {
                    chunk[byte_idx] |= mask;
                } else {
                    chunk[byte_idx] &= !mask;
                }
            } else if bit_offset >= batch.base_len {
                // This is an appended bit
                let append_offset = (bit_offset - batch.base_len) as usize;
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
    pub fn set_bit(&mut self, bit_offset: u64, value: bool) -> &mut Self {
        let batch = self.historical.active_batch.as_mut().unwrap();

        // Check bounds
        assert!(
            bit_offset < batch.projected_len,
            "bit offset {bit_offset} out of range"
        );

        // Check not pruned
        let chunk_idx = Prunable::<N>::raw_chunk_index(bit_offset);
        assert!(
            chunk_idx >= batch.projected_pruned_chunks,
            "cannot set pruned bit"
        );

        // Determine the start of the appended region
        // Appended bits start at: projected_len - appended_bits.len()
        let appended_start = batch.projected_len - batch.appended_bits.len() as u64;

        // If the bit is in the appended region, update appended_bits directly
        if bit_offset >= appended_start {
            let append_offset = (bit_offset - appended_start) as usize;
            batch.appended_bits[append_offset] = value;
        } else {
            // Bit is in the base region, record as modification
            batch.modified_bits.insert(bit_offset, value);
        }

        self
    }

    /// Push a bit to the end of the bitmap.
    pub fn push(&mut self, bit: bool) -> &mut Self {
        let batch = self.historical.active_batch.as_mut().unwrap();

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
    /// Returns the value of the popped bit, respecting any modifications made in this batch.
    ///
    /// # Panics
    ///
    /// Panics if the bitmap is empty.
    pub fn pop(&mut self) -> bool {
        let batch = self.historical.active_batch.as_mut().unwrap();

        assert!(batch.projected_len > 0, "cannot pop from empty bitmap");

        let old_projected_len = batch.projected_len;
        batch.projected_len -= 1;
        let bit_offset = batch.projected_len;

        // Determine if the bit being popped is in the appended region
        // Appended region starts at: (projected_len before pop) - appended_bits.len()
        let appended_start_before_pop = old_projected_len - batch.appended_bits.len() as u64;

        // Check if popping from appended region
        if bit_offset >= appended_start_before_pop {
            batch.appended_bits.pop().unwrap()
        } else {
            // Popping from base region - check if it was modified in batch
            if let Some(&modified_value) = batch.modified_bits.get(&bit_offset) {
                // Remove the modification since we're popping this bit
                batch.modified_bits.remove(&bit_offset);
                modified_value
            } else {
                // Not modified, read original value
                self.historical.current.get_bit(bit_offset)
            }
        }
    }

    /// Prune chunks up to the chunk containing the given bit offset.
    pub fn prune_to_bit(&mut self, bit_offset: u64) -> &mut Self {
        let batch = self.historical.active_batch.as_mut().unwrap();
        let chunk_num = Prunable::<N>::raw_chunk_index(bit_offset);

        if chunk_num <= batch.projected_pruned_chunks {
            return self; // Already pruned
        }

        // Capture preimages of chunks being pruned
        let current_pruned = self.historical.current.pruned_chunks();
        for chunk_idx in batch.projected_pruned_chunks..chunk_num {
            #[cfg(not(feature = "std"))]
            use alloc::collections::btree_map::Entry;
            #[cfg(feature = "std")]
            use std::collections::btree_map::Entry;

            if let Entry::Vacant(e) = batch.chunks_to_prune.entry(chunk_idx) {
                if chunk_idx >= current_pruned {
                    let bitmap_idx = chunk_idx - current_pruned;
                    if bitmap_idx < self.historical.current.chunks_len() {
                        let chunk_data = *self.historical.current.get_chunk_by_index(bitmap_idx);
                        e.insert(chunk_data);
                    }
                }
            }
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
    pub fn commit(mut self, commit_number: u64) -> Result<(), Error> {
        // Validate commit number is monotonically increasing
        if let Some(&max_commit) = self.historical.commits.keys().next_back() {
            if commit_number <= max_commit {
                return Err(Error::NonMonotonicCommit {
                    previous: max_commit,
                    attempted: commit_number,
                });
            }
        }

        // Take the batch
        let batch = self.historical.active_batch.take().unwrap();

        // Build reverse diff (captures OLD state before applying batch)
        let reverse_diff = self.historical.build_reverse_diff(&batch);

        // Apply batch changes to current bitmap
        self.historical.apply_batch_to_current(&batch);

        // Store the reverse diff
        self.historical.commits.insert(commit_number, reverse_diff);

        // Mark as committed
        self.committed = true;

        Ok(())
    }
}

impl<'a, const N: usize> Drop for BatchGuard<'a, N> {
    fn drop(&mut self) {
        if !self.committed {
            // Batch is being dropped without commit - discard the diff layer
            self.historical.active_batch = None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let historical: Historical<4> = Historical::new();
        assert_eq!(historical.len(), 0);
        assert!(historical.is_empty());
        assert_eq!(historical.commits().count(), 0);
    }

    #[test]
    fn test_basic_batch_commit() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(1, |batch| {
                batch.push(true);
                batch.push(false);
                batch.push(true);
            })
            .unwrap();

        assert_eq!(historical.len(), 3);
        assert!(historical.get_bit(0));
        assert!(!historical.get_bit(1));
        assert!(historical.get_bit(2));
        assert_eq!(historical.commits().count(), 1);
    }

    #[test]
    fn test_batch_abort() {
        let mut historical: Historical<4> = Historical::new();

        // Initial commit
        historical
            .with_batch(1, |batch| {
                batch.push(true);
                batch.push(false);
            })
            .unwrap();

        assert_eq!(historical.len(), 2);

        // Start batch and drop without commit (abort)
        {
            let mut batch = historical.start_batch();
            batch.push(true);
            batch.push(true);
            // Drop here - should abort
        }

        // State should be unchanged
        assert_eq!(historical.len(), 2);
        assert!(historical.get_bit(0));
        assert!(!historical.get_bit(1));
        assert_eq!(historical.commits().count(), 1);
    }

    #[test]
    fn test_read_through_semantics() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(1, |batch| {
                batch.push(true);
                batch.push(false);
                batch.push(true);
            })
            .unwrap();

        let mut batch = historical.start_batch();

        // Read unmodified bits (should fall through)
        assert!(batch.get_bit(0));
        assert!(!batch.get_bit(1));
        assert!(batch.get_bit(2));

        // Modify a bit
        batch.set_bit(1, true);

        // Read modified bit (should see new value)
        assert!(batch.get_bit(1));

        // Append a bit
        batch.push(false);

        // Read appended bit
        assert!(!batch.get_bit(3));

        batch.commit(2).unwrap();

        // After commit, changes should be in current
        assert_eq!(historical.len(), 4);
        assert!(historical.get_bit(1));
        assert!(!historical.get_bit(3));
    }

    #[test]
    fn test_monotonic_commit_numbers() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(5, |batch| {
                batch.push(true);
            })
            .unwrap();

        let err = historical
            .with_batch(5, |batch| {
                batch.push(false);
            })
            .unwrap_err();

        match err {
            Error::NonMonotonicCommit {
                previous,
                attempted,
            } => {
                assert_eq!(previous, 5);
                assert_eq!(attempted, 5);
            }
        }

        let err = historical
            .with_batch(3, |batch| {
                batch.push(false);
            })
            .unwrap_err();

        match err {
            Error::NonMonotonicCommit {
                previous,
                attempted,
            } => {
                assert_eq!(previous, 5);
                assert_eq!(attempted, 3);
            }
        }

        // Should succeed with larger number
        historical
            .with_batch(10, |batch| {
                batch.push(false);
            })
            .unwrap();
    }

    #[test]
    fn test_prune_commits() {
        let mut historical: Historical<4> = Historical::new();

        for i in 1..=5 {
            historical
                .with_batch(i, |batch| {
                    batch.push(true);
                })
                .unwrap();
        }

        assert_eq!(historical.commits().count(), 5);

        let removed = historical.prune_commits_before(3);
        assert_eq!(removed, 2);
        assert_eq!(historical.commits().count(), 3);

        let removed = historical.prune_commits_at_or_below(4);
        assert_eq!(removed, 2);
        assert_eq!(historical.commits().count(), 1);
    }

    #[test]
    #[should_panic(expected = "batch already active")]
    fn test_cannot_start_batch_when_active() {
        let mut historical: Historical<4> = Historical::new();
        let _batch1 = historical.start_batch();
        // This should panic because a batch is already active
        // We need to use core::mem::forget to prevent drop from clearing the batch
        core::mem::forget(_batch1);
        let _batch2 = historical.start_batch();
    }

    #[test]
    fn test_batch_with_modifications_and_appends() {
        let mut historical: Historical<4> = Historical::new();

        // Initial state
        historical
            .with_batch(1, |batch| {
                batch.push(false); // bit 0
                batch.push(false); // bit 1
                batch.push(false); // bit 2
            })
            .unwrap();

        // Modify existing bits and append new ones
        historical
            .with_batch(2, |batch| {
                batch.set_bit(0, true); // Modify
                batch.set_bit(1, true); // Modify
                batch.push(true); // Append bit 3
                batch.push(true); // Append bit 4
            })
            .unwrap();

        assert_eq!(historical.len(), 5);
        assert!(historical.get_bit(0));
        assert!(historical.get_bit(1));
        assert!(!historical.get_bit(2));
        assert!(historical.get_bit(3));
        assert!(historical.get_bit(4));
    }

    #[test]
    fn test_batch_pop_operations() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(1, |batch| {
                batch.push(true);
                batch.push(false);
                batch.push(true);
            })
            .unwrap();

        // Pop within batch
        historical
            .with_batch(2, |batch| {
                batch.push(false); // Add bit 3
                let popped = batch.pop(); // Remove bit 3
                assert!(!popped);
                assert_eq!(batch.len(), 3); // Back to original length
            })
            .unwrap();

        assert_eq!(historical.len(), 3);
    }

    #[test]
    fn test_batch_prune_operations() {
        let mut historical: Historical<4> = Historical::new();

        // Create multiple chunks
        historical
            .with_batch(1, |batch| {
                for _ in 0..64 {
                    batch.push(true);
                }
            })
            .unwrap();

        assert_eq!(historical.len(), 64);
        assert_eq!(historical.pruned_chunks(), 0);

        // Prune first chunk
        historical
            .with_batch(2, |batch| {
                batch.prune_to_bit(32);
            })
            .unwrap();

        assert_eq!(historical.len(), 64);
        assert_eq!(historical.pruned_chunks(), 1);
    }

    #[test]
    fn test_commit_history_queries() {
        let mut historical: Historical<4> = Historical::new();

        assert!(historical.earliest_commit().is_none());
        assert!(historical.latest_commit().is_none());

        for i in 1..=5 {
            historical
                .with_batch(i * 10, |batch| {
                    batch.push(true);
                })
                .unwrap();
        }

        assert_eq!(historical.earliest_commit(), Some(10));
        assert_eq!(historical.latest_commit(), Some(50));
        assert!(historical.commit_exists(30));
        assert!(!historical.commit_exists(25));

        let commits: Vec<u64> = historical.commits().collect();
        assert_eq!(commits, vec![10, 20, 30, 40, 50]);
    }

    #[test]
    fn test_clear_history() {
        let mut historical: Historical<4> = Historical::new();

        for i in 1..=5 {
            historical
                .with_batch(i, |batch| {
                    batch.push(true);
                })
                .unwrap();
        }

        assert_eq!(historical.commits().count(), 5);

        historical.clear_history();

        assert_eq!(historical.commits().count(), 0);
        assert!(historical.earliest_commit().is_none());
        assert!(historical.latest_commit().is_none());
        // Current state should be preserved
        assert_eq!(historical.len(), 5);
    }

    #[test]
    fn test_batch_push_byte_and_chunk() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(1, |batch| {
                batch.push_chunk(&[0xAA, 0xBB, 0xCC, 0xDD]); // 32 bits (full chunk)
                batch.push_byte(0xFF); // 8 more bits
            })
            .unwrap();

        assert_eq!(historical.len(), 40);

        // Verify first chunk
        let chunk = historical.get_chunk(0);
        assert_eq!(chunk, &[0xAA, 0xBB, 0xCC, 0xDD]);

        // Check byte pushed after chunk (bits 32-39)
        for i in 32..40 {
            assert!(historical.get_bit(i));
        }
    }

    #[test]
    fn test_batch_get_chunk_with_modifications() {
        let mut historical: Historical<4> = Historical::new();

        // Create initial chunk
        historical
            .with_batch(1, |batch| {
                batch.push_chunk(&[0x00, 0x00, 0x00, 0x00]);
            })
            .unwrap();

        let mut batch = historical.start_batch();

        // Modify some bits in the chunk
        batch.set_bit(0, true);
        batch.set_bit(7, true);

        // Get chunk through batch - should show modifications
        let chunk = batch.get_chunk(0);

        // Check modifications are reflected
        assert_eq!(chunk[0] & 0x01, 0x01); // bit 0 set
        assert_eq!(chunk[0] & 0x80, 0x80); // bit 7 set

        batch.commit(2).unwrap();

        // Verify modifications persisted
        let final_chunk = historical.get_chunk(0);
        assert_eq!(final_chunk[0] & 0x01, 0x01);
        assert_eq!(final_chunk[0] & 0x80, 0x80);
    }

    #[test]
    fn test_empty_batch_commit() {
        let mut historical: Historical<4> = Historical::new();

        // Commit an empty batch
        historical.with_batch(1, |_batch| {}).unwrap();

        assert_eq!(historical.len(), 0);
        assert!(historical.commit_exists(1));
    }

    #[test]
    fn test_method_chaining() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(1, |batch| {
                batch.push(true).push(false).push(true).push_byte(0xAA);
            })
            .unwrap();

        assert_eq!(historical.len(), 11); // 3 + 8 bits

        // Now modify and chain in another batch
        historical
            .with_batch(2, |batch| {
                batch.set_bit(1, true).push(true);
            })
            .unwrap();

        assert_eq!(historical.len(), 12);
        assert!(historical.get_bit(0));
        assert!(historical.get_bit(1)); // Modified from false to true
        assert!(historical.get_bit(2));
        assert!(historical.get_bit(11)); // Newly pushed
    }

    #[test]
    fn test_get_at_commit_basic() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: Add 3 bits
        historical
            .with_batch(1, |batch| {
                batch.push(true);
                batch.push(false);
                batch.push(true);
            })
            .unwrap();

        // Current state after commit 1
        assert_eq!(historical.len(), 3);
        assert!(historical.get_bit(0));
        assert!(!historical.get_bit(1));
        assert!(historical.get_bit(2));

        // Commit 2: Modify bit and append
        historical
            .with_batch(2, |batch| {
                batch.set_bit(0, false);
                batch.push(false);
            })
            .unwrap();

        // Current state should be at commit 2
        assert_eq!(historical.len(), 4);
        assert!(!historical.get_bit(0));
        assert!(!historical.get_bit(1));
        assert!(historical.get_bit(2));
        assert!(!historical.get_bit(3));

        // Get state at commit 1
        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 3);
        assert!(state_at_1.get_bit(0)); // Was true
        assert!(!state_at_1.get_bit(1));
        assert!(state_at_1.get_bit(2));

        // Get state at commit 2 (should match current)
        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_at_2.len(), 4);
        assert!(!state_at_2.get_bit(0));
        assert!(!state_at_2.get_bit(1));
        assert!(state_at_2.get_bit(2));
        assert!(!state_at_2.get_bit(3));
    }

    #[test]
    fn test_get_at_commit_multiple_modifications() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: Initial state
        historical
            .with_batch(1, |batch| {
                batch.push_chunk(&[0xFF, 0x00, 0xFF, 0x00]);
            })
            .unwrap();

        // Commit 2: Modify some bits
        historical
            .with_batch(2, |batch| {
                batch.set_bit(0, false);
                batch.set_bit(8, true);
            })
            .unwrap();

        // Commit 3: Modify more bits
        historical
            .with_batch(3, |batch| {
                batch.set_bit(16, false);
                batch.set_bit(24, true);
            })
            .unwrap();

        // Verify we can get each state
        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 32);
        assert!(state_at_1.get_bit(0)); // Original
        assert!(!state_at_1.get_bit(8)); // Original
        assert!(state_at_1.get_bit(16)); // Original
        assert!(!state_at_1.get_bit(24)); // Original

        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_at_2.len(), 32);
        assert!(!state_at_2.get_bit(0)); // Modified in commit 2
        assert!(state_at_2.get_bit(8)); // Modified in commit 2
        assert!(state_at_2.get_bit(16)); // Not yet modified
        assert!(!state_at_2.get_bit(24)); // Not yet modified

        let state_at_3 = historical.get_at_commit(3).unwrap();
        assert_eq!(state_at_3.len(), 32);
        assert!(!state_at_3.get_bit(0));
        assert!(state_at_3.get_bit(8));
        assert!(!state_at_3.get_bit(16)); // Modified in commit 3
        assert!(state_at_3.get_bit(24)); // Modified in commit 3
    }

    #[test]
    fn test_get_at_commit_with_appends() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: 2 bits
        historical
            .with_batch(1, |batch| {
                batch.push(true);
                batch.push(false);
            })
            .unwrap();

        // Commit 2: Append 2 more bits
        historical
            .with_batch(2, |batch| {
                batch.push(true);
                batch.push(true);
            })
            .unwrap();

        // Commit 3: Append 2 more bits
        historical
            .with_batch(3, |batch| {
                batch.push(false);
                batch.push(false);
            })
            .unwrap();

        // Verify lengths
        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 2);

        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_at_2.len(), 4);

        let state_at_3 = historical.get_at_commit(3).unwrap();
        assert_eq!(state_at_3.len(), 6);
        assert_eq!(historical.len(), 6);
    }

    #[test]
    fn test_get_at_commit_with_pruning() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: Create 64 bits (2 chunks)
        historical
            .with_batch(1, |batch| {
                batch.push_chunk(&[0xAA, 0xBB, 0xCC, 0xDD]);
                batch.push_chunk(&[0x11, 0x22, 0x33, 0x44]);
            })
            .unwrap();

        assert_eq!(historical.pruned_chunks(), 0);

        // Commit 2: Prune first chunk
        historical
            .with_batch(2, |batch| {
                batch.prune_to_bit(32);
            })
            .unwrap();

        assert_eq!(historical.pruned_chunks(), 1);

        // Get state at commit 1 - should have both chunks, no pruning
        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 64);
        assert_eq!(state_at_1.pruned_chunks(), 0);

        // Verify first chunk data is restored
        let chunk = state_at_1.get_chunk(0);
        assert_eq!(chunk, &[0xAA, 0xBB, 0xCC, 0xDD]);

        let chunk2 = state_at_1.get_chunk(32);
        assert_eq!(chunk2, &[0x11, 0x22, 0x33, 0x44]);

        // Get state at commit 2 - should have pruning
        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_at_2.len(), 64);
        assert_eq!(state_at_2.pruned_chunks(), 1);

        let chunk2_at_2 = state_at_2.get_chunk(32);
        assert_eq!(chunk2_at_2, &[0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_get_at_commit_nonexistent() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(10, |batch| {
                batch.push(true);
            })
            .unwrap();

        // Query non-existent commit
        assert!(historical.get_at_commit(5).is_none());
        assert!(historical.get_at_commit(15).is_none());

        // Query existing commit
        assert!(historical.get_at_commit(10).is_some());
    }

    #[test]
    fn test_get_at_commit_after_pruning_history() {
        let mut historical: Historical<4> = Historical::new();

        for i in 1..=5 {
            historical
                .with_batch(i, |batch| {
                    for _ in 0..i {
                        batch.push(true);
                    }
                })
                .unwrap();
        }

        // Prune old history
        historical.prune_commits_before(3);

        // Should not be able to get commits 1 and 2
        assert!(historical.get_at_commit(1).is_none());
        assert!(historical.get_at_commit(2).is_none());

        // Should be able to get commits 3, 4, 5
        assert!(historical.get_at_commit(3).is_some());
        assert!(historical.get_at_commit(4).is_some());
        assert!(historical.get_at_commit(5).is_some());

        let state_at_3 = historical.get_at_commit(3).unwrap();
        assert_eq!(state_at_3.len(), 6); // 1+2+3 bits
    }

    #[test]
    fn test_get_at_commit_complex_scenario() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: Initial bits
        historical
            .with_batch(1, |batch| {
                batch.push(true);
                batch.push(true);
                batch.push(true);
                batch.push(true);
            })
            .unwrap();

        // Commit 2: Modify and append
        historical
            .with_batch(2, |batch| {
                batch.set_bit(0, false);
                batch.set_bit(2, false);
                batch.push(false);
                batch.push(false);
            })
            .unwrap();

        // Commit 3: More modifications
        historical
            .with_batch(3, |batch| {
                batch.set_bit(1, false);
                batch.set_bit(3, false);
                batch.push(true);
                batch.push(true);
            })
            .unwrap();

        // Verify state at each commit
        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 4);
        for i in 0..4 {
            assert!(state_at_1.get_bit(i));
        }

        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_at_2.len(), 6);
        assert!(!state_at_2.get_bit(0)); // Modified
        assert!(state_at_2.get_bit(1)); // Unchanged
        assert!(!state_at_2.get_bit(2)); // Modified
        assert!(state_at_2.get_bit(3)); // Unchanged
        assert!(!state_at_2.get_bit(4)); // Appended
        assert!(!state_at_2.get_bit(5)); // Appended

        let state_at_3 = historical.get_at_commit(3).unwrap();
        assert_eq!(state_at_3.len(), 8);
        assert!(!state_at_3.get_bit(0));
        assert!(!state_at_3.get_bit(1)); // Modified in commit 3
        assert!(!state_at_3.get_bit(2));
        assert!(!state_at_3.get_bit(3)); // Modified in commit 3
        assert!(state_at_3.get_bit(6)); // Appended in commit 3
        assert!(state_at_3.get_bit(7)); // Appended in commit 3
    }

    #[test]
    fn test_get_at_commit_with_pop_and_append() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: Add 5 bits
        historical
            .with_batch(1, |batch| {
                for i in 0..5 {
                    batch.push(i % 2 == 0);
                }
            })
            .unwrap();
        assert_eq!(historical.len(), 5);

        // Commit 2: Pop 2 bits
        historical
            .with_batch(2, |batch| {
                batch.pop();
                batch.pop();
            })
            .unwrap();
        assert_eq!(historical.len(), 3);

        // Commit 3: Append 3 bits
        historical
            .with_batch(3, |batch| {
                batch.push(true);
                batch.push(true);
                batch.push(true);
            })
            .unwrap();
        assert_eq!(historical.len(), 6);

        // Verify reconstruction at each commit
        let state_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_1.len(), 5);
        assert!(state_1.get_bit(0)); // true
        assert!(!state_1.get_bit(1)); // false
        assert!(state_1.get_bit(2)); // true
        assert!(!state_1.get_bit(3)); // false
        assert!(state_1.get_bit(4)); // true

        let state_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_2.len(), 3);
        assert!(state_2.get_bit(0));
        assert!(!state_2.get_bit(1));
        assert!(state_2.get_bit(2));

        let state_3 = historical.get_at_commit(3).unwrap();
        assert_eq!(state_3.len(), 6);
        assert!(state_3.get_bit(3));
        assert!(state_3.get_bit(4));
        assert!(state_3.get_bit(5));
    }

    // Regression test for issue: modifying an appended bit in the same batch causes panic
    #[test]
    fn test_modify_appended_bit_same_batch() {
        let mut historical: Historical<4> = Historical::new();

        // Append a bit and then modify it in the same batch
        historical
            .with_batch(1, |batch| {
                batch.push(true); // Append bit 0
                batch.set_bit(0, false); // Modify that appended bit
            })
            .unwrap();

        assert_eq!(historical.len(), 1);
        assert!(!historical.get_bit(0)); // Should be false after modification
    }

    // Regression test for issue: push, modify, then pop leaves dangling modification
    #[test]
    fn test_push_modify_pop_same_batch() {
        let mut historical: Historical<4> = Historical::new();

        // This should work: push a bit, modify it, then pop it
        historical
            .with_batch(1, |batch| {
                batch.push(true); // Append bit 0
                batch.set_bit(0, false); // Modify that appended bit
                batch.pop(); // Remove bit 0
            })
            .unwrap();

        // Should result in empty bitmap (the push/pop cancel out)
        assert_eq!(historical.len(), 0);
    }

    // Regression test for issue: reconstructing a less-pruned state from a more-pruned state
    #[test]
    fn test_reconstruct_less_pruned_state() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: 64 bits, no pruning (chunks 0 and 1)
        historical
            .with_batch(1, |batch| {
                batch.push_chunk(&[0xAA, 0xBB, 0xCC, 0xDD]); // chunk 0: bits 0-31
                batch.push_chunk(&[0x11, 0x22, 0x33, 0x44]); // chunk 1: bits 32-63
            })
            .unwrap();

        assert_eq!(historical.len(), 64);
        assert_eq!(historical.pruned_chunks(), 0);

        // Commit 2: Prune first chunk
        historical
            .with_batch(2, |batch| {
                batch.prune_to_bit(32);
            })
            .unwrap();

        // Current state: 64 bits, 1 pruned chunk
        assert_eq!(historical.len(), 64);
        assert_eq!(historical.pruned_chunks(), 1);

        // Reconstruct commit 1: should have 64 bits, 0 pruned chunks, and both chunks intact
        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 64);
        assert_eq!(state_at_1.pruned_chunks(), 0);

        // Verify chunk 0 data is restored
        let chunk0 = state_at_1.get_chunk(0);
        assert_eq!(chunk0, &[0xAA, 0xBB, 0xCC, 0xDD]);

        // Verify chunk 1 data is still correct
        let chunk1 = state_at_1.get_chunk(32);
        assert_eq!(chunk1, &[0x11, 0x22, 0x33, 0x44]);
    }

    // Test for issue: reading popped bits should fail
    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_read_popped_bit_should_fail() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(1, |batch| {
                for _ in 0..10 {
                    batch.push(true);
                }
            })
            .unwrap();

        // Pop 2 bits, so valid range is now 0-7
        let mut batch = historical.start_batch();
        batch.pop();
        batch.pop();

        // This should panic - bit 8 is out of bounds
        batch.get_bit(8);
    }

    // Test for issue: pop() should return modified value, not original
    #[test]
    fn test_pop_returns_modified_value() {
        let mut historical: Historical<4> = Historical::new();

        // Create initial bits, all true
        historical
            .with_batch(1, |batch| {
                for _ in 0..10 {
                    batch.push(true);
                }
            })
            .unwrap();

        // Modify bit 9 to false, then pop it
        let mut popped_value = true;
        historical
            .with_batch(2, |batch| {
                batch.set_bit(9, false); // Modify bit 9 in batch
                popped_value = batch.pop(); // Should return false (modified value)
            })
            .unwrap();

        // The popped value should be false (the modified value), not true (original)
        assert!(
            !popped_value,
            "pop() should return modified value, not original"
        );
    }

    // Generalized ground truth test with random operations.
    //
    // This test compares historical reconstruction against actual saved bitmap states.
    // It performs random operations across multiple commits and verifies that reconstructing
    // historical states produces bit-for-bit identical results to the saved states.
    fn test_randomized_helper<R: rand::Rng>(rng: &mut R) {
        // Test configuration
        const NUM_COMMITS: u64 = 20;
        const OPERATIONS_PER_COMMIT: usize = 32;
        const CHUNK_SIZE_BITS: u64 = 32; // 4 bytes * 8 bits

        // Operation probability thresholds (out of 100)
        // These define a probability distribution over different operations
        const PROB_PUSH: u64 = 55; // 0-54: 55% chance to push a new bit
        const PROB_MODIFY: u64 = 75; // 55-74: 20% chance to modify existing bit
        const PROB_POP: u64 = 90; // 75-89: 15% chance to pop last bit
        const PROB_PRUNE: u64 = 100; // 90-99: 10% chance to prune (if possible)

        let mut historical: Historical<4> = Historical::new();
        let mut ground_truth = Prunable::<4>::new();
        let mut checkpoints: Vec<(u64, Prunable<4>)> = Vec::new();

        // Perform random operations across multiple commits
        for commit_num in 0..NUM_COMMITS {
            let initial_len = ground_truth.len();
            let initial_pruned = ground_truth.pruned_chunks();

            historical
                .with_batch(commit_num, |batch| {
                    // Track current state within this batch (changes as we apply operations)
                    let mut current_len = initial_len;
                    let mut current_pruned = initial_pruned;

                    for _ in 0..OPERATIONS_PER_COMMIT {
                        // Pick a random operation based on probability distribution
                        let op_choice = rng.gen_range(0..100);

                        // Special case: if bitmap is empty, we can only push
                        if current_len == 0 {
                            let bit_value = rng.gen_bool(0.5);
                            batch.push(bit_value);
                            ground_truth.push(bit_value);
                            current_len += 1;
                            continue;
                        }

                        // Operation: PUSH (55% probability)
                        if op_choice < PROB_PUSH {
                            let bit_value = rng.gen_bool(0.5);
                            batch.push(bit_value);
                            ground_truth.push(bit_value);
                            current_len += 1;
                        }
                        // Operation: MODIFY existing bit (20% probability)
                        else if op_choice < PROB_MODIFY {
                            let bit_offset = rng.gen_range(0..current_len);
                            let new_value = rng.gen_bool(0.5);

                            // Safety: Only modify bits that aren't pruned
                            let chunk_idx = Prunable::<4>::raw_chunk_index(bit_offset);
                            if chunk_idx >= current_pruned {
                                batch.set_bit(bit_offset, new_value);
                                ground_truth.set_bit(bit_offset, new_value);
                            }
                        }
                        // Operation: POP last bit (15% probability)
                        else if op_choice < PROB_POP {
                            batch.pop();
                            ground_truth.pop();
                            current_len -= 1;
                        }
                        // Operation: PRUNE to random chunk boundary (10% probability)
                        else if op_choice < PROB_PRUNE {
                            // Calculate the maximum chunk we can prune to (keep at least 1 chunk of data)
                            let total_chunks = (current_len / CHUNK_SIZE_BITS) as usize;
                            let max_prune_chunk = total_chunks.saturating_sub(1);

                            // Only prune if there's at least one unpruned complete chunk we can prune
                            if max_prune_chunk > current_pruned {
                                // Randomly pick a chunk boundary to prune to (between current_pruned+1 and max)
                                let prune_chunk =
                                    rng.gen_range((current_pruned + 1)..=max_prune_chunk);
                                let prune_to = (prune_chunk as u64) * CHUNK_SIZE_BITS;

                                batch.prune_to_bit(prune_to);
                                ground_truth.prune_to_bit(prune_to);
                                current_pruned = prune_chunk;
                            }
                        }
                    }
                })
                .unwrap();

            // Save checkpoint for verification
            checkpoints.push((commit_num, ground_truth.clone()));
        }

        // Verify all checkpoints match reconstructed states
        for (commit_num, checkpoint) in &checkpoints {
            let reconstructed = historical.get_at_commit(*commit_num).unwrap();

            assert_eq!(
                reconstructed.len(),
                checkpoint.len(),
                "Length mismatch at commit {commit_num}"
            );
            assert_eq!(
                reconstructed.pruned_chunks(),
                checkpoint.pruned_chunks(),
                "Pruned chunks mismatch at commit {commit_num}"
            );

            // Verify all accessible bits
            let start_bit = reconstructed.pruned_chunks() as u64 * Prunable::<4>::CHUNK_SIZE_BITS;
            for i in start_bit..checkpoint.len() {
                let expected = checkpoint.get_bit(i);
                let actual = reconstructed.get_bit(i);
                assert_eq!(
                    actual, expected,
                    "Bit {i} mismatch at commit {commit_num} (expected {expected}, got {actual})"
                );
            }
        }
    }

    #[test]
    fn test_randomized() {
        use rand::{rngs::StdRng, SeedableRng};
        for seed in 0..=100 {
            let mut rng = StdRng::seed_from_u64(seed);
            test_randomized_helper(&mut rng);
        }
    }
}

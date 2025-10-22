use super::{batch::Batch, Error};
use crate::bitmap::{historical::BatchGuard, Prunable};
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Type of change to a chunk.
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

/// A historical bitmap that maintains one actual bitmap plus diffs for history and batching.
///
/// Commit numbers must be strictly monotonically increasing and < u64::MAX.
pub struct BitMap<const N: usize> {
    /// The current/HEAD state - the one and only full bitmap.
    pub(super) current: Prunable<N>,

    /// Historical commits: commit_number -> reverse diff from that commit.
    pub(super) commits: BTreeMap<u64, CommitDiff<N>>,

    /// Active batch (if any).
    pub(super) active_batch: Option<Batch<N>>,
}

impl<const N: usize> BitMap<N> {
    /// Create a new empty historical bitmap.
    pub fn new() -> Self {
        Self {
            current: Prunable::new(),
            commits: BTreeMap::new(),
            active_batch: None,
        }
    }

    /// Create a new historical bitmap with the given number of pruned chunks.
    pub fn new_with_pruned_chunks(pruned_chunks: usize) -> Result<Self, Error> {
        Ok(Self {
            current: Prunable::new_with_pruned_chunks(pruned_chunks)?,
            commits: BTreeMap::new(),
            active_batch: None,
        })
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
    /// # use commonware_utils::bitmap::historical::BitMap;
    /// let mut bitmap: BitMap<4> = BitMap::new();
    ///
    /// let mut batch = bitmap.start_batch();
    /// batch.push(true);
    /// batch.push(false);
    /// batch.commit(1).unwrap();
    ///
    /// assert_eq!(bitmap.len(), 2);
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
            modified_bits: BTreeMap::new(),
            appended_bits: Vec::new(),
            chunks_to_prune: BTreeMap::new(),
        };

        self.active_batch = Some(batch);

        BatchGuard {
            bitmap: self,
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
    /// Returns [Error::ReservedCommitNumber] if the commit number is `u64::MAX`.
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
    /// bitmap.with_batch(1, |batch| {
    ///     batch.push(true);
    ///     batch.push(false);
    /// }).unwrap();
    ///
    /// bitmap.with_batch(2, |batch| {
    ///     batch.set_bit(0, false);
    ///     batch.push(true);
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
    #[inline]
    pub fn len(&self) -> u64 {
        self.current.len()
    }

    /// Returns true if the current bitmap is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
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
    pub fn pruned_chunks(&self) -> usize {
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

    /// Apply a batch's changes to the current bitmap.
    pub(super) fn apply_batch_to_current(&mut self, batch: &Batch<N>) {
        // Step 1: Shrink to length before appends (handles net pops)
        let target_len_before_appends = batch.projected_len - batch.appended_bits.len() as u64;

        while self.current.len() > target_len_before_appends {
            self.current.pop();
        }

        // Step 2: Grow by appending new bits
        for &bit in &batch.appended_bits {
            self.current.push(bit);
        }
        assert_eq!(self.current.len(), batch.projected_len);

        // Step 3: Modify existing base bits (not appended bits)
        for (&bit, &value) in &batch.modified_bits {
            self.current.set_bit(bit, value);
        }

        // Step 4: Prune chunks from the beginning
        if batch.projected_pruned_chunks > batch.base_pruned_chunks {
            let prune_to_bit =
                batch.projected_pruned_chunks as u64 * Prunable::<N>::CHUNK_SIZE_BITS;
            self.current.prune_to_bit(prune_to_bit);
        }
    }

    /// Build a reverse diff from a batch.
    pub(super) fn build_reverse_diff(&self, batch: &Batch<N>) -> CommitDiff<N> {
        let mut changes = BTreeMap::new();
        self.capture_modified_chunks(batch, &mut changes);
        self.capture_appended_chunks(batch, &mut changes);
        self.capture_popped_chunks(batch, &mut changes);
        self.capture_pruned_chunks(batch, &mut changes);
        CommitDiff {
            len: batch.base_len,
            pruned_chunks: batch.base_pruned_chunks,
            chunk_diffs: changes,
        }
    }

    /// Capture chunks affected by bit modifications.
    ///
    /// For each chunk containing modified bits, we store its original value so we can
    /// restore it when reconstructing historical states.
    fn capture_modified_chunks(
        &self,
        batch: &Batch<N>,
        changes: &mut BTreeMap<usize, ChunkDiff<N>>,
    ) {
        for &bit in batch.modified_bits.keys() {
            let chunk_idx = Prunable::<N>::unpruned_chunk(bit);
            changes.entry(chunk_idx).or_insert_with(|| {
                // `modified_bits` only contains bits from the base region that existed
                // at batch creation. Since current hasn't changed yet (we're still
                // building the diff), the chunk MUST exist.
                let old_chunk = self
                    .get_chunk(chunk_idx)
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
    fn capture_appended_chunks(
        &self,
        batch: &Batch<N>,
        changes: &mut BTreeMap<usize, ChunkDiff<N>>,
    ) {
        if batch.appended_bits.is_empty() {
            return;
        }

        // Calculate which chunks will be affected by appends.
        // Note: append_start_bit accounts for any net pops before the pushes.
        let append_start_bit = batch.projected_len - batch.appended_bits.len() as u64;
        let start_chunk = Prunable::<N>::unpruned_chunk(append_start_bit);
        let end_chunk = Prunable::<N>::unpruned_chunk(batch.projected_len.saturating_sub(1));

        for chunk_idx in start_chunk..=end_chunk {
            // Use or_insert_with so we don't overwrite chunks already captured
            // by capture_modified_chunks (which runs first and takes precedence).
            changes.entry(chunk_idx).or_insert_with(|| {
                if let Some(old_chunk) = self.get_chunk(chunk_idx) {
                    // Chunk existed before: store its old data
                    ChunkDiff::Modified(old_chunk)
                } else {
                    // Chunk is brand new: mark as Added
                    ChunkDiff::Added
                }
            });
        }
    }

    /// Capture chunks affected by pop operations.
    ///
    /// When bits are popped (projected_len < base_len), we need to capture the original
    /// data of chunks that will be truncated or fully removed. This allows reconstruction
    /// to restore the bits that were popped.
    fn capture_popped_chunks(&self, batch: &Batch<N>, changes: &mut BTreeMap<usize, ChunkDiff<N>>) {
        if batch.projected_len >= batch.base_len || batch.base_len == 0 {
            return; // No net pops
        }

        // Identify the range of chunks affected by length reduction.
        let old_last_chunk = Prunable::<N>::unpruned_chunk(batch.base_len - 1);
        let new_last_chunk = if batch.projected_len > 0 {
            Prunable::<N>::unpruned_chunk(batch.projected_len - 1)
        } else {
            0
        };

        // Capture all chunks between the new and old endpoints.
        // Skip chunks that were already pruned before this batch started.
        for chunk_idx in new_last_chunk..=old_last_chunk {
            if chunk_idx < batch.base_pruned_chunks {
                // This chunk was already pruned before the batch, skip it
                continue;
            }

            changes.entry(chunk_idx).or_insert_with(|| {
                let old_chunk = self
                    .get_chunk(chunk_idx)
                    .expect("chunk must exist in base bitmap for popped bits");

                // Determine if this chunk is partially kept or completely removed
                let chunk_start_bit = chunk_idx as u64 * Prunable::<N>::CHUNK_SIZE_BITS;

                if batch.projected_len > chunk_start_bit {
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
    /// The batch's `prune_to_bit` method already captured the old chunk data,
    /// so we simply copy it into the reverse diff.
    fn capture_pruned_chunks(&self, batch: &Batch<N>, changes: &mut BTreeMap<usize, ChunkDiff<N>>) {
        for (&chunk_idx, &chunk_data) in &batch.chunks_to_prune {
            changes.insert(chunk_idx, ChunkDiff::Pruned(chunk_data));
        }
    }

    /// Get chunk data from current state if it exists.
    ///
    /// Returns `Some(chunk_data)` if the chunk exists in the current bitmap,
    /// or `None` if it's out of bounds or pruned.
    fn get_chunk(&self, chunk_idx: usize) -> Option<[u8; N]> {
        let current_pruned = self.current.pruned_chunks();
        if chunk_idx >= current_pruned {
            let bitmap_idx = chunk_idx - current_pruned;
            if bitmap_idx < self.current.chunks_len() {
                return Some(*self.current.get_chunk(bitmap_idx));
            }
        }
        None
    }
}

impl<const N: usize> Default for BitMap<N> {
    fn default() -> Self {
        Self::new()
    }
}

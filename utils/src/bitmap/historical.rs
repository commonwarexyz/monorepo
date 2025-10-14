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
use alloc::{collections::BTreeMap, vec::Vec};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Errors that can occur in Historical bitmap operations.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Commit numbers must be strictly monotonically increasing.
    #[error("commit number ({attempted}) <= previous commit ({previous})")]
    NonMonotonicCommit { previous: u64, attempted: u64 },

    /// Error from the underlying Prunable bitmap.
    #[error("prunable error: {0}")]
    Prunable(#[from] super::prunable::Error),
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
enum ChunkDiff<const N: usize> {
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
struct CommitDiff<const N: usize> {
    /// Metadata about the state before this commit.
    metadata: CommitMetadata,
    /// Chunk-level changes.
    changes: BTreeMap<usize, ChunkDiff<N>>,
}

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
struct Batch<const N: usize> {
    /// Bitmap state when batch started (immutable).
    base_len: u64,
    base_pruned_chunks: usize,

    /// What the bitmap will look like after commit (mutable).
    projected_len: u64,
    projected_pruned_chunks: usize,

    /// Modifications to bits that existed in the bitmap (not appended bits).
    /// Contains offsets in [0, projected_len - appended_bits.len()).
    /// Maps: bit -> new_value
    modified_bits: BTreeMap<u64, bool>,

    /// New bits pushed in this batch (in order).
    /// Logical position: [projected_len - appended_bits.len(), projected_len)
    appended_bits: Vec<bool>,

    /// Old chunk data for chunks being pruned.
    /// Captured eagerly during `prune_to_bit()` for historical reconstruction.
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
            modified_bits: BTreeMap::new(),
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

            // If current chunk is empty and we need to remove at least a full chunk, pop entire chunk
            if next_bit == 0 && excess >= Prunable::<N>::CHUNK_SIZE_BITS {
                state.pop(); // This removes the empty chunk
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
    ///
    /// Key insight: We adjust the bitmap's STRUCTURE first (ensuring all chunks exist),
    /// then update chunk DATA. This avoids the alignment issues that occur when trying
    /// to push chunks onto a non-aligned bitmap.
    fn apply_reverse_diff(&self, newer_state: &mut Prunable<N>, diff: &CommitDiff<N>) {
        let target_len = diff.metadata.len;
        let target_pruned = diff.metadata.pruned_chunks;
        let newer_pruned = newer_state.pruned_chunks();

        // Phase 1: Restore pruned chunks
        assert!(
            target_pruned <= newer_pruned,
            "invariant violation: target_pruned ({target_pruned}) > newer_pruned ({newer_pruned})"
        );
        let mut chunks_to_unprune = Vec::with_capacity(newer_pruned - target_pruned);
        for chunk_index in (target_pruned..newer_pruned).rev() {
            let Some(ChunkDiff::Pruned(chunk)) = diff.changes.get(&chunk_index) else {
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
            .changes
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
                    // there are no Removed. (diff.changes can't have both Added and Removed.)
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

    /// Clear all historical commits.
    pub fn clear_history(&mut self) {
        self.commits.clear();
    }

    /// Apply a batch's changes to the current bitmap.
    ///
    /// # Order of Operations
    ///
    /// The order is chosen for correctness and clarity:
    ///
    /// 1. **Pop to target length**: Remove bits that were popped in the batch
    ///    - Must happen BEFORE appends to establish the correct base length
    ///    - Example: bitmap has 10 bits, batch pops 3 then pushes 2
    ///      → First shrink to 7, then grow to 9 (not directly from 10 to 9)
    ///    - After this step: `current.len() == projected_len - appended_bits.len()`
    ///
    /// 2. **Apply appends**: Push all bits from `appended_bits`
    ///    - Grows the bitmap from base length to final length
    ///    - After this step: `current.len() == projected_len`
    ///
    /// 3. **Apply modifications**: Set bits recorded in `modified_bits`
    ///    - Must happen AFTER step 1 so all offsets in `modified_bits` are valid
    ///      (after step 1: all offsets < current.len())
    ///    - Could happen before step 2 (modifications only affect base region, which
    ///      is already at correct length after step 1), but doing it after is clearer
    ///    - `modified_bits` never contains appended bit offsets (those are modified
    ///      directly in `appended_bits` vector via `set_bit()` during the batch)
    ///
    /// 4. **Apply pruning**: Remove chunks from the beginning
    ///    - Must happen LAST to avoid invalidating bit offsets in steps 2-3
    ///    - Pruning changes which bits are accessible but doesn't change values
    fn apply_batch_to_current(&mut self, batch: &Batch<N>) {
        // Step 1: Shrink to length before appends (handles net pops)
        let target_len_before_appends = batch.projected_len - batch.appended_bits.len() as u64;

        while self.current.len() > target_len_before_appends {
            self.current.pop();
        }

        // Step 2: Grow by appending new bits
        for &bit in &batch.appended_bits {
            self.current.push(bit);
        }

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

    /// Build a reverse diff from a batch before applying it.
    ///
    /// # Purpose
    ///
    /// A reverse diff describes the state BEFORE this commit. When we later want to
    /// reconstruct the historical state at this commit, we start with the current state
    /// and apply reverse diffs backward, "undoing" each subsequent commit.
    ///
    /// # What We Capture
    ///
    /// We capture old chunk data for any chunks that will change. **Important**: We only
    /// see the batch's final state, not intermediate operations.
    ///
    /// - **Modified chunks**: Chunks with bits in `modified_bits` (final modifications only)
    /// - **Appended chunks**: Chunks created/extended by final `appended_bits` vector
    /// - **Popped chunks**: Chunks that will be truncated (comparing `projected_len` vs `base_len`)
    /// - **Pruned chunks**: Chunks in `chunks_to_prune` map
    ///
    /// # How De-duplication Works
    ///
    /// Because the batch de-duplicates during operations, we automatically capture the
    /// minimal diff:
    ///
    /// ```text
    /// Example: What capture sees after: push(A), push(B), pop(), set_bit(5, true)
    ///
    /// Batch final state:
    ///   - appended_bits = [A]  (B was popped)
    ///   - modified_bits = {5: true}
    ///   - projected_len = base_len + 1
    ///
    /// Captured chunks:
    ///   - Chunk containing bit 5: Modified (from modified_bits)
    ///   - Chunk containing bit base_len: Modified or Added (from appended_bits)
    ///
    /// NOT captured:
    ///   - Bit B: never in final state, so no chunk captured for it
    /// ```
    ///
    /// # Capture Order and Precedence
    ///
    /// The capture order ensures correct handling when a chunk is affected by multiple operations:
    ///
    /// 1. **`capture_modified_chunks` first** (strictest invariants)
    ///    - Captures chunks modified via explicit `set_bit()` calls
    ///    - Uses `expect()` because modified bits MUST exist in base bitmap
    ///    - Has "precedence" because it runs first with `or_insert_with()`
    ///
    /// 2. **`capture_appended_chunks` second**
    ///    - Captures chunks created or extended by `push()` operations
    ///    - Uses `or_insert_with()` → won't overwrite chunks from step 1
    ///    - Gracefully handles both existing chunks (→ `Modified`) and new chunks (→ `Added`)
    ///
    /// 3. **`capture_popped_chunks` third**
    ///    - Captures chunks truncated by `pop()` operations
    ///    - Uses `or_insert_with()` → won't overwrite chunks from steps 1-2
    ///    - Also uses `expect()` because popped bits MUST have existed
    ///
    /// 4. **`capture_pruned_chunks` last** (overwrites)
    ///    - Captures chunks removed from the beginning via `prune_to_bit()`
    ///    - Uses `insert()` to OVERWRITE previous entries
    ///    - Pruned chunks MUST be marked `Pruned`, not `Modified`
    ///
    /// # Example: Overlapping Operations
    ///
    /// ```text
    /// Start: len = 35 (chunk 1 has 3 bits: [32, 33, 34])
    /// Batch:
    ///   - set_bit(33, true)  → bit 33 goes in modified_bits
    ///   - push(29)           → bits [35..63] fill chunk 1 and create chunk 2
    ///
    /// Chunk 1 is affected by BOTH modified_bits AND appended_bits.
    ///
    /// Capture sequence:
    ///   1. capture_modified_chunks: Captures chunk 1 → Modified(old_chunk_1_data)
    ///   2. capture_appended_chunks: Tries chunk 1, but already captured → skipped
    ///   3. capture_appended_chunks: Captures chunk 2 → Added
    ///
    /// Result: Chunk 1 is Modified (correct), chunk 2 is Added (correct)
    /// ```
    ///
    /// # Why This Order?
    ///
    /// - **Fail-fast on violations**: `capture_modified_chunks` runs first with strict checks
    /// - **Avoid redundant work**: Once a chunk is captured, later steps skip it
    /// - **Correct change types**: Each chunk gets the most specific classification
    /// - **Pruning overrides all**: Pruned chunks must be marked `Pruned` regardless of other changes
    fn build_reverse_diff(&self, batch: &Batch<N>) -> CommitDiff<N> {
        let mut changes = BTreeMap::new();

        self.capture_modified_chunks(batch, &mut changes);
        self.capture_appended_chunks(batch, &mut changes);
        self.capture_popped_chunks(batch, &mut changes);
        self.capture_pruned_chunks(batch, &mut changes);

        CommitDiff {
            metadata: CommitMetadata {
                len: batch.base_len,
                pruned_chunks: batch.base_pruned_chunks,
            },
            changes,
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
                // modified_bits only contains bits from the base region that existed
                // at batch creation. Since current hasn't changed yet (we're still
                // building the diff), the chunk MUST exist.
                let old_chunk = self
                    .get_chunk_if_exists(chunk_idx)
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
                if let Some(old_chunk) = self.get_chunk_if_exists(chunk_idx) {
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
        for chunk_idx in new_last_chunk..=old_last_chunk {
            changes.entry(chunk_idx).or_insert_with(|| {
                let old_chunk = self
                    .get_chunk_if_exists(chunk_idx)
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
    fn get_chunk_if_exists(&self, chunk_idx: usize) -> Option<[u8; N]> {
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
    #[inline]
    pub fn len(&self) -> u64 {
        self.historical
            .active_batch
            .as_ref()
            .map(|b| b.projected_len)
            .unwrap_or(0)
    }

    /// Returns true if the bitmap would be empty after committing this batch.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Get the number of pruned chunks after this batch.
    #[inline]
    pub fn pruned_chunks(&self) -> usize {
        self.historical
            .active_batch
            .as_ref()
            .map(|b| b.projected_pruned_chunks)
            .unwrap_or(0)
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
        let batch = self.historical.active_batch.as_ref().unwrap();

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
        self.historical.current.get_bit(bit)
    }

    /// Get a chunk value with read-through semantics.
    ///
    /// Reconstructs the chunk if it has modifications, otherwise returns from current.
    ///
    /// # Panics
    ///
    /// Panics if the bit offset is out of bounds or if the chunk has been pruned.
    pub fn get_chunk(&self, bit: u64) -> [u8; N] {
        let batch = self.historical.active_batch.as_ref().unwrap();

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
            *self.historical.current.get_chunk_containing(bit)
        }
    }

    /// Reconstruct a chunk that has modifications, appends, or pops.
    fn reconstruct_modified_chunk(&self, chunk_start: u64) -> [u8; N] {
        let batch = self.historical.active_batch.as_ref().unwrap();

        // Start with current chunk if it exists
        let mut chunk = if chunk_start < self.historical.current.len() {
            *self.historical.current.get_chunk_containing(chunk_start)
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
        let batch = self.historical.active_batch.as_mut().unwrap();

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
    /// Returns the value of the popped bit, accounting for any modifications in this batch.
    ///
    /// # Panics
    ///
    /// Panics if the bitmap is empty.
    pub fn pop(&mut self) -> bool {
        let batch = self.historical.active_batch.as_mut().unwrap();

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
                self.historical.current.get_bit(bit)
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
        let batch = self.historical.active_batch.as_mut().unwrap();

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
        let current_pruned = self.historical.current.pruned_chunks();
        for chunk_idx in batch.projected_pruned_chunks..chunk_num {
            if batch.chunks_to_prune.contains_key(&chunk_idx) {
                continue; // Already captured
            }

            // Invariant: chunk_idx should always be >= current_pruned because
            // projected_pruned_chunks starts at base_pruned_chunks (= current_pruned)
            assert!(
                chunk_idx >= current_pruned,
                "attempting to prune chunk {chunk_idx} which is already pruned (current pruned_chunks={})",
                current_pruned
            );

            let bitmap_idx = chunk_idx - current_pruned;

            // Get chunk data, which may come from batch if it's appended
            let chunk_data = if bitmap_idx < self.historical.current.chunks_len() {
                // Chunk exists in current bitmap
                *self.historical.current.get_chunk(bitmap_idx)
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

    /// Test basic batch lifecycle: creation, operations, commit, and abort.
    ///
    /// Covers:
    /// - Empty initialization
    /// - Basic push operations and commits
    /// - Batch abort (drop without commit)
    /// - Read-through semantics (modifications visible in batch, committed to current)
    /// - Method chaining API
    /// - Empty batch commits
    #[test]
    fn test_batch_lifecycle_and_operations() {
        // Empty initialization
        let mut historical: Historical<4> = Historical::new();
        assert_eq!(historical.len(), 0);
        assert!(historical.is_empty());
        assert_eq!(historical.commits().count(), 0);

        // Basic push and commit
        historical
            .with_batch(1, |batch| {
                batch.push(true).push(false).push(true);
            })
            .unwrap();
        assert_eq!(historical.len(), 3);
        assert!(historical.get_bit(0));
        assert!(!historical.get_bit(1));
        assert!(historical.get_bit(2));
        assert_eq!(historical.commits().count(), 1);

        // Batch abort (drop without commit)
        {
            let mut batch = historical.start_batch();
            batch.push(true).push(true);
            // Drop here - should abort
        }
        assert_eq!(historical.len(), 3); // Unchanged

        // Read-through semantics
        let mut batch = historical.start_batch();
        assert!(batch.get_bit(0)); // Read unmodified
        batch.set_bit(1, true); // Modify
        assert!(batch.get_bit(1)); // See modification in batch
        batch.push(false); // Append
        assert!(!batch.get_bit(3)); // See appended bit
        batch.commit(2).unwrap();

        // After commit, changes persisted
        assert_eq!(historical.len(), 4);
        assert!(historical.get_bit(1));
        assert!(!historical.get_bit(3));

        // Empty batch commit
        historical.with_batch(3, |_batch| {}).unwrap();
        assert_eq!(historical.len(), 4);
        assert!(historical.commit_exists(3));

        // Method chaining with batch.set_bit()
        historical
            .with_batch(4, |batch| {
                batch.set_bit(0, false).push_byte(0xAA);
            })
            .unwrap();
        assert_eq!(historical.len(), 12); // 4 + 8 bits
        assert!(!historical.get_bit(0)); // Modified
    }

    /// Test that only one batch can be active at a time.
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

    /// Test batch operations: push, pop, prune, push_byte, push_chunk, and get_chunk.
    ///
    /// Covers:
    /// - Pop operations (return value, length changes)
    /// - Bitmap chunk pruning (prune_to_bit)
    /// - Bulk operations (push_byte, push_chunk)
    /// - Chunk retrieval with modifications (get_chunk with read-through)
    /// - Modifications combined with appends in same batch
    #[test]
    fn test_batch_operations_push_pop_prune() {
        let mut historical: Historical<4> = Historical::new();

        // Push, modify, and append operations
        historical
            .with_batch(1, |batch| {
                batch.push(false).push(false).push(false);
            })
            .unwrap();

        historical
            .with_batch(2, |batch| {
                batch.set_bit(0, true); // Modify
                batch.set_bit(1, true); // Modify
                batch.push(true); // Append
                batch.push(true); // Append
            })
            .unwrap();

        assert_eq!(historical.len(), 5);
        assert!(historical.get_bit(0));
        assert!(historical.get_bit(1));
        assert!(!historical.get_bit(2));

        // Pop operations
        historical
            .with_batch(3, |batch| {
                batch.push(false); // Add bit 5
                let popped = batch.pop(); // Remove it
                assert!(!popped);
                assert_eq!(batch.len(), 5); // Back to original
            })
            .unwrap();

        // Bulk push operations (push_chunk, push_byte)
        // Start fresh with 32 bits so chunks align cleanly
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |b| {
                b.push_chunk(&[0x00, 0x00, 0x00, 0x00]);
            })
            .unwrap();

        historical
            .with_batch(2, |batch| {
                batch.push_chunk(&[0xAA, 0xBB, 0xCC, 0xDD]); // 32 bits at offset 32
                batch.push_byte(0xFF); // 8 bits at offset 64
            })
            .unwrap();

        assert_eq!(historical.len(), 72); // 32 + 32 + 8
        let chunk = historical.get_chunk_containing(32); // Read second chunk
        assert_eq!(chunk, &[0xAA, 0xBB, 0xCC, 0xDD]);
        for i in 64..72 {
            assert!(historical.get_bit(i)); // Verify pushed byte
        }

        // get_chunk with modifications in batch
        let mut batch = historical.start_batch();
        batch.set_bit(32, true); // First bit of second chunk
        batch.set_bit(39, true); // 8th bit of second chunk
        let chunk = batch.get_chunk(32);
        assert_eq!(chunk[0] & 0x01, 0x01); // bit 32 (0 in chunk) set
        assert_eq!(chunk[0] & 0x80, 0x80); // bit 39 (7 in chunk) set
        batch.commit(3).unwrap();

        // Prune operations
        historical
            .with_batch(4, |batch| {
                batch.prune_to_bit(32);
            })
            .unwrap();

        assert_eq!(historical.len(), 72); // Length unchanged
        assert_eq!(historical.pruned_chunks(), 1); // First chunk pruned
    }

    /// Test commit history management: validation, pruning, queries, and clearing.
    ///
    /// Covers:
    /// - Monotonic commit number validation
    /// - Pruning commits (prune_commits_before)
    /// - Commit queries (earliest_commit, latest_commit, commit_exists)
    /// - Clearing all history (clear_history)
    #[test]
    fn test_commit_history_management() {
        let mut historical: Historical<4> = Historical::new();

        // Validate monotonic commit numbers
        historical
            .with_batch(5, |b| {
                b.push(true);
            })
            .unwrap();

        let err = historical
            .with_batch(5, |b| {
                b.push(false);
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
            _ => panic!("Expected NonMonotonicCommit error"),
        }

        let err = historical
            .with_batch(3, |b| {
                b.push(false);
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
            _ => panic!("Expected NonMonotonicCommit error"),
        }

        historical
            .with_batch(10, |b| {
                b.push(false);
            })
            .unwrap(); // Should succeed

        // Commit queries (need fresh instance)
        let mut historical: Historical<4> = Historical::new();
        assert!(historical.earliest_commit().is_none());
        assert!(historical.latest_commit().is_none());
        for i in 1..=5 {
            historical
                .with_batch(i * 10, |b| {
                    b.push(true);
                })
                .unwrap();
        }

        assert_eq!(historical.earliest_commit(), Some(10));
        assert_eq!(historical.latest_commit(), Some(50));
        assert!(historical.commit_exists(30));
        assert!(!historical.commit_exists(25));

        let commits: Vec<u64> = historical.commits().collect();
        assert_eq!(commits, vec![10, 20, 30, 40, 50]);

        // Prune commits
        let removed = historical.prune_commits_before(30);
        assert_eq!(removed, 2);
        assert_eq!(historical.commits().count(), 3);

        // Clear history
        historical.clear_history();
        assert_eq!(historical.commits().count(), 0);
        assert!(historical.earliest_commit().is_none());
        assert!(historical.latest_commit().is_none());
        assert_eq!(historical.len(), 5); // Current state preserved
    }

    /// Test historical reconstruction with bit modifications across multiple commits.
    ///
    /// Covers:
    /// - Reconstructing states with simple bit modifications
    /// - Multiple successive modifications across commits
    /// - Combining modifications with appends
    /// - Verifying each historical state independently
    #[test]
    fn test_historical_reconstruction_with_modifications() {
        let mut historical: Historical<4> = Historical::new();

        // Simple modification scenario
        historical
            .with_batch(1, |b| {
                b.push(true).push(false).push(true);
            })
            .unwrap();
        historical
            .with_batch(2, |b| {
                b.set_bit(0, false);
                b.push(false);
            })
            .unwrap();

        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 3);
        assert!(state_at_1.get_bit(0)); // Original true
        assert!(!state_at_1.get_bit(1));

        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_at_2.len(), 4);
        assert!(!state_at_2.get_bit(0)); // Modified to false
        assert!(!state_at_2.get_bit(3)); // Appended

        // Multiple successive modifications
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |b| {
                b.push_chunk(&[0xFF, 0x00, 0xFF, 0x00]);
            })
            .unwrap();
        historical
            .with_batch(2, |b| {
                b.set_bit(0, false);
                b.set_bit(8, true);
            })
            .unwrap();
        historical
            .with_batch(3, |b| {
                b.set_bit(16, false);
                b.set_bit(24, true);
            })
            .unwrap();

        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert!(state_at_1.get_bit(0));
        assert!(!state_at_1.get_bit(8));

        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert!(!state_at_2.get_bit(0)); // Modified
        assert!(state_at_2.get_bit(8)); // Modified
        assert!(state_at_2.get_bit(16)); // Not yet modified

        let state_at_3 = historical.get_at_commit(3).unwrap();
        assert!(!state_at_3.get_bit(16)); // Modified
        assert!(state_at_3.get_bit(24)); // Modified

        // Modifications combined with appends
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |b| {
                for _ in 0..4 {
                    b.push(true);
                }
            })
            .unwrap();
        historical
            .with_batch(2, |b| {
                b.set_bit(0, false).set_bit(2, false);
                b.push(false).push(false);
            })
            .unwrap();
        historical
            .with_batch(3, |b| {
                b.set_bit(1, false).set_bit(3, false);
                b.push(true).push(true);
            })
            .unwrap();

        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 4);
        for i in 0..4 {
            assert!(state_at_1.get_bit(i)); // All true
        }

        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_at_2.len(), 6);
        assert!(!state_at_2.get_bit(0)); // Modified
        assert!(state_at_2.get_bit(1)); // Unchanged
        assert!(!state_at_2.get_bit(4)); // Appended false

        let state_at_3 = historical.get_at_commit(3).unwrap();
        assert_eq!(state_at_3.len(), 8);
        assert!(!state_at_3.get_bit(1)); // Modified in commit 3
        assert!(state_at_3.get_bit(6)); // Appended in commit 3
    }

    /// Test historical reconstruction with length-changing operations (appends and pops).
    ///
    /// Covers:
    /// - Pure append operations
    /// - Pop operations followed by appends
    /// - Verifying length changes across commits
    #[test]
    fn test_historical_reconstruction_with_length_changes() {
        let mut historical: Historical<4> = Historical::new();

        // Pure append operations
        historical
            .with_batch(1, |b| {
                b.push(true).push(false);
            })
            .unwrap();
        historical
            .with_batch(2, |b| {
                b.push(true).push(true);
            })
            .unwrap();
        historical
            .with_batch(3, |b| {
                b.push(false).push(false);
            })
            .unwrap();

        assert_eq!(historical.get_at_commit(1).unwrap().len(), 2);
        assert_eq!(historical.get_at_commit(2).unwrap().len(), 4);
        assert_eq!(historical.get_at_commit(3).unwrap().len(), 6);

        // Pops followed by appends
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |b| {
                for i in 0..5 {
                    b.push(i % 2 == 0);
                }
            })
            .unwrap();
        historical
            .with_batch(2, |b| {
                b.pop();
                b.pop();
            })
            .unwrap();
        historical
            .with_batch(3, |b| {
                b.push(true).push(true).push(true);
            })
            .unwrap();

        let state_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_1.len(), 5);
        assert!(state_1.get_bit(0)); // true
        assert!(!state_1.get_bit(1)); // false
        assert!(state_1.get_bit(4)); // true

        let state_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_2.len(), 3);

        let state_3 = historical.get_at_commit(3).unwrap();
        assert_eq!(state_3.len(), 6);
        assert!(state_3.get_bit(3));
        assert!(state_3.get_bit(5));
    }

    /// Test historical reconstruction with bitmap chunk pruning.
    ///
    /// Covers:
    /// - Reconstructing state before pruning (restores pruned chunks)
    /// - Reconstructing state after pruning (maintains pruning)
    /// - Verifying chunk data integrity across pruning boundaries
    #[test]
    fn test_historical_reconstruction_with_pruning() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: Create 64 bits (2 chunks), no pruning
        historical
            .with_batch(1, |b| {
                b.push_chunk(&[0xAA, 0xBB, 0xCC, 0xDD]);
                b.push_chunk(&[0x11, 0x22, 0x33, 0x44]);
            })
            .unwrap();

        // Commit 2: Prune first chunk
        historical
            .with_batch(2, |b| {
                b.prune_to_bit(32);
            })
            .unwrap();
        assert_eq!(historical.pruned_chunks(), 1);

        // Reconstruct state before pruning
        let state_at_1 = historical.get_at_commit(1).unwrap();
        assert_eq!(state_at_1.len(), 64);
        assert_eq!(state_at_1.pruned_chunks(), 0); // No pruning
        assert_eq!(
            state_at_1.get_chunk_containing(0),
            &[0xAA, 0xBB, 0xCC, 0xDD]
        ); // Restored
        assert_eq!(
            state_at_1.get_chunk_containing(32),
            &[0x11, 0x22, 0x33, 0x44]
        );

        // Reconstruct state after pruning
        let state_at_2 = historical.get_at_commit(2).unwrap();
        assert_eq!(state_at_2.len(), 64);
        assert_eq!(state_at_2.pruned_chunks(), 1); // Pruning preserved
        assert_eq!(
            state_at_2.get_chunk_containing(32),
            &[0x11, 0x22, 0x33, 0x44]
        );
    }

    /// Test edge cases in historical reconstruction.
    ///
    /// Covers:
    /// - Querying nonexistent commits (returns None)
    /// - Reconstructing after commit history pruning
    #[test]
    fn test_historical_reconstruction_edge_cases() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(10, |b| {
                b.push(true);
            })
            .unwrap();

        // Nonexistent commits
        assert!(historical.get_at_commit(5).is_none());
        assert!(historical.get_at_commit(15).is_none());
        assert!(historical.get_at_commit(10).is_some());

        // After pruning commit history
        let mut historical: Historical<4> = Historical::new();
        for i in 1..=5 {
            historical
                .with_batch(i, |b| {
                    for _ in 0..i {
                        b.push(true);
                    }
                })
                .unwrap();
        }

        historical.prune_commits_before(3);

        // Cannot reconstruct pruned commits
        assert!(historical.get_at_commit(1).is_none());
        assert!(historical.get_at_commit(2).is_none());

        // Can reconstruct remaining commits
        assert!(historical.get_at_commit(3).is_some());
        assert!(historical.get_at_commit(4).is_some());
        assert_eq!(historical.get_at_commit(3).unwrap().len(), 6); // 1+2+3 bits
    }

    /// Test batch modifications on appended bits (regression tests).
    ///
    /// Covers:
    /// - Modifying a bit immediately after appending it in the same batch
    /// - Push, modify, then pop sequence (ensures no dangling modifications)
    #[test]
    fn test_batch_modifications_on_appended_bits() {
        let mut historical: Historical<4> = Historical::new();

        // Modify appended bit in same batch
        historical
            .with_batch(1, |batch| {
                batch.push(true); // Append bit 0
                batch.set_bit(0, false); // Modify that appended bit
            })
            .unwrap();
        assert_eq!(historical.len(), 1);
        assert!(!historical.get_bit(0)); // Should be false after modification

        // Push, modify, then pop (should cancel out cleanly)
        historical
            .with_batch(2, |batch| {
                batch.push(true); // Append bit 1
                batch.set_bit(1, false); // Modify that appended bit
                batch.pop(); // Remove bit 1
            })
            .unwrap();
        assert_eq!(historical.len(), 1); // Only bit 0 remains
    }

    /// Test pop() behavior with batch modifications (regression tests).
    ///
    /// Covers:
    /// - pop() returns the modified value, not the original
    /// - Reading popped bits fails with proper error
    #[test]
    fn test_pop_behavior_with_modifications() {
        let mut historical: Historical<4> = Historical::new();

        // Create initial bits
        historical
            .with_batch(1, |b| {
                for _ in 0..10 {
                    b.push(true);
                }
            })
            .unwrap();

        // pop() should return modified value
        let mut popped_value = true;
        historical
            .with_batch(2, |batch| {
                batch.set_bit(9, false); // Modify bit 9 in batch
                popped_value = batch.pop(); // Should return false (modified)
            })
            .unwrap();
        assert!(
            !popped_value,
            "pop() should return modified value, not original"
        );
    }

    /// Test reading popped bits should fail.
    #[test]
    #[should_panic(expected = "out of bounds")]
    fn test_read_popped_bit_panics() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |b| {
                for _ in 0..10 {
                    b.push(true);
                }
            })
            .unwrap();

        let mut batch = historical.start_batch();
        batch.pop();
        batch.pop();
        batch.get_bit(8); // Should panic - bit 8 is now out of bounds
    }

    /// Test pruning beyond bitmap length should fail.
    #[test]
    #[should_panic(expected = "beyond projected length")]
    fn test_prune_beyond_length_panics() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |b| {
                for _ in 0..10 {
                    b.push(true);
                }
            })
            .unwrap();

        let mut batch = historical.start_batch();
        batch.pop(); // projected_len = 9
        batch.prune_to_bit(100); // Should panic - bit 100 is beyond projected length
    }

    /// Test that get_chunk can read entirely appended chunks.
    ///
    /// This tests the scenario where:
    /// 1. We start with an empty (or short) bitmap
    /// 2. We append bits that create a chunk entirely in the appended region
    /// 3. We call get_chunk on that chunk
    ///
    /// The bug is that when a chunk is entirely appended (chunk_start >= base_len),
    /// the range_end calculation (chunk_end.min(base_len)) creates an empty range,
    /// so all checks return false and we fall back to current.get_chunk(), which
    /// panics because that chunk doesn't exist in current.
    #[test]
    fn test_get_chunk_on_appended_only_chunk() {
        let mut historical: Historical<4> = Historical::new();

        // Start with empty bitmap
        let mut batch = historical.start_batch();

        // Push 32 bits (fills chunk 0 entirely)
        for i in 0..32 {
            batch.push(i % 2 == 0); // Alternating pattern: true, false, true, false...
        }

        // Now try to read chunk 0 - this chunk is entirely appended
        let chunk = batch.get_chunk(0);

        // Verify the alternating pattern: true, false, true, false...
        assert_ne!(chunk[0] & 0x01, 0, "bit 0 should be true");
        assert_eq!(chunk[0] & 0x02, 0, "bit 1 should be false");
        assert_ne!(chunk[0] & 0x04, 0, "bit 2 should be true");
        assert_eq!(chunk[0] & 0x08, 0, "bit 3 should be false");

        // Overall pattern should be 0x55 (binary 01010101)
        assert_eq!(chunk[0], 0x55, "byte 0 should be 0x55");
    }

    /// Test that get_chunk zeros out bits beyond projected_len after pops.
    ///
    /// This tests the scenario where:
    /// 1. We have a chunk with all bits set
    /// 2. We pop some bits from the end of that chunk
    /// 3. We call get_chunk on that chunk
    ///
    /// The bug is that get_chunk would return the full chunk from current without
    /// zeroing out the popped bits, so readers see stale data that will be zeroed
    /// after commit.
    #[test]
    fn test_pop_zeros_chunk_tail() {
        let mut historical: Historical<4> = Historical::new();

        // Setup: Create 33 bits (chunk 0 has bits 0-31 all true, chunk 1 has bit 32 true)
        historical
            .with_batch(1, |b| {
                for _ in 0..33 {
                    b.push(true);
                }
            })
            .unwrap();

        // Start a new batch and pop 2 bits
        let mut batch = historical.start_batch();
        batch.pop(); // projected_len = 32
        batch.pop(); // projected_len = 31

        // Now bit 31 is out of bounds (projected_len = 31)
        // get_chunk(0) returns chunk 0, which contains bits 0-31
        let chunk = batch.get_chunk(0);

        // Bit 31 should be zeroed since it's >= projected_len
        let byte_31 = chunk[31 / 8]; // byte 3
        let bit_31_in_byte = 31 % 8; // bit 7
        let bit_31_set = (byte_31 >> bit_31_in_byte) & 1 == 1;

        assert!(!bit_31_set);
    }

    /// Test pruning a chunk that was just appended in the same batch.
    ///
    /// This tests the scenario where:
    /// 1. We have a bitmap with some bits (not chunk-aligned)
    /// 2. We append enough bits to create a NEW chunk beyond what exists in current
    /// 3. We immediately prune that new chunk
    ///
    /// The bug is that prune_to_bit tries to capture chunk data from current,
    /// but the new chunk only exists in appended_bits, causing a panic.
    #[test]
    fn test_prune_freshly_appended_chunk() {
        let mut historical: Historical<4> = Historical::new();

        // Start with 10 bits (chunk 0 is partial, no chunk 1)
        historical
            .with_batch(1, |b| {
                for _ in 0..10 {
                    b.push(true);
                }
            })
            .unwrap();

        assert_eq!(historical.current().chunks_len(), 1); // Only chunk 0 exists

        // Now in a new batch, append 54 more bits
        // This creates chunk 1 (bits 32-63) entirely within the batch
        let mut batch = historical.start_batch();
        for _ in 0..54 {
            batch.push(true);
        }

        // projected_len = 64, we now have chunks 0 and 1
        // But chunk 1 is ONLY in appended_bits, not in current
        assert_eq!(batch.len(), 64);

        // Try to prune to bit 64 (prune chunks 0 and 1)
        // This should capture chunk 0 from current (OK)
        // But chunk 1 doesn't exist in current yet!
        batch.prune_to_bit(64);

        // Should commit successfully
        batch.commit(2).unwrap();
    }

    /// Test that batch reads correctly see appended bits after pops.
    ///
    /// This tests the scenario where:
    /// 1. We start with a bitmap of length N
    /// 2. Pop some bits (reducing length to M < N)
    /// 3. Push new bits (growing length back toward N)
    /// 4. Read those newly pushed bits within the same batch
    ///
    /// The bug was that `get_bit` and `get_chunk_containing` checked `bit >= base_len`
    /// to identify appended bits, but after net pops, the appended region actually
    /// starts at `projected_len - appended_bits.len()`, which is less than `base_len`.
    /// This caused reads to fall through to the stale underlying bitmap instead of
    /// reading from the batch's `appended_bits` vector.
    #[test]
    fn test_read_appended_bits_after_pops() {
        let mut historical: Historical<4> = Historical::new();

        // Setup: Create bitmap with 10 bits, all set to true
        historical
            .with_batch(1, |b| {
                for _ in 0..10 {
                    b.push(true);
                }
            })
            .unwrap();

        // Start batch: pop 3 bits, then push 2 bits with value false
        let mut batch = historical.start_batch();
        batch.pop(); // projected_len = 9
        batch.pop(); // projected_len = 8
        batch.pop(); // projected_len = 7
        batch.push(false); // projected_len = 8, appended_bits = [false]
        batch.push(false); // projected_len = 9, appended_bits = [false, false]

        // The appended region is now [7, 9), not [10, 12)
        // Verify get_bit sees the new false values, not the old true values
        assert!(!batch.get_bit(7));
        assert!(!batch.get_bit(8));

        // Verify get_chunk also reconstructs correctly
        let chunk = batch.get_chunk(0); // Chunk containing bits 0..31
        assert_eq!(chunk[0] & 0x80, 0, "bit 7 should be false in chunk");
        assert_eq!(chunk[1] & 0x01, 0, "bit 8 should be false in chunk");

        // Also verify we can modify appended bits
        batch.set_bit(7, true);
        assert!(batch.get_bit(7));

        // Commit and verify the final state
        batch.commit(2).unwrap();
        assert_eq!(historical.len(), 9);
        assert!(historical.get_bit(7));
        assert!(!historical.get_bit(8));
    }

    /// Test historical reconstruction when current state has MORE pruning than target.
    ///
    /// This tests the scenario where:
    /// 1. We commit a state with some unpruned data
    /// 2. We prune that data in a later commit
    /// 3. We try to reconstruct the earlier state (which needs the now-pruned data)
    ///
    /// The diff system should have captured the pruned chunk data as `ChunkDiff::Pruned`,
    /// allowing reconstruction even though that chunk no longer exists in current state.
    #[test]
    fn test_reconstruct_less_pruned_from_more_pruned() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: Create 64 bits (2 chunks) with pattern
        historical
            .with_batch(1, |b| {
                for i in 0..64 {
                    b.push(i < 32); // First chunk all true, second chunk all false
                }
            })
            .unwrap();
        assert_eq!(historical.len(), 64);
        assert_eq!(historical.pruned_chunks(), 0);

        // Commit 2: Prune first chunk
        historical
            .with_batch(2, |b| {
                b.prune_to_bit(32); // Prune chunk 0
            })
            .unwrap();
        assert_eq!(historical.len(), 64);
        assert_eq!(historical.pruned_chunks(), 1);

        // Now reconstruct commit 1 (which has chunk 0 unpruned)
        // This requires getting chunk 0 from the diff, not from current state
        let reconstructed = historical
            .get_at_commit(1)
            .expect("should be able to reconstruct less-pruned state");

        assert_eq!(reconstructed.len(), 64);
        assert_eq!(reconstructed.pruned_chunks(), 0, "commit 1 had no pruning");

        // Verify the data is correct
        for i in 0..32 {
            assert!(reconstructed.get_bit(i));
        }
        for i in 32..64 {
            assert!(!reconstructed.get_bit(i));
        }
    }

    /// Test historical reconstruction when all non-pruned bits are in pruned chunks.
    ///
    /// This tests the scenario where:
    /// 1. We have a bitmap with some bits (e.g., 32 bits = 1 chunk)
    /// 2. We prune all chunks (e.g., prune chunk 0, so only pruned metadata remains)
    /// 3. We commit this state
    /// 4. We try to reconstruct this historical state via `get_at_commit`
    ///
    /// The bug was that `apply_reverse_diff` always computed `raw_last_chunk` from
    /// `target_len - 1`, but when `target_len <= target_pruned * CHUNK_SIZE_BITS`,
    /// this gives a chunk index that's less than `raw_first_chunk` (the first
    /// unpruned chunk). The code then tried to access this pruned chunk from
    /// `newer_state`, causing a panic. The fix is to detect this case early and
    /// return an empty bitmap with the correct pruning metadata.
    #[test]
    fn test_reconstruct_fully_pruned_commit() {
        let mut historical: Historical<4> = Historical::new();

        // Commit 1: Create 32 bits (1 complete chunk)
        historical
            .with_batch(1, |b| {
                for i in 0..32 {
                    b.push(i % 2 == 0); // Alternating pattern
                }
            })
            .unwrap();
        assert_eq!(historical.len(), 32);
        assert_eq!(historical.pruned_chunks(), 0);

        // Commit 2: Prune the entire chunk
        historical
            .with_batch(2, |b| {
                b.prune_to_bit(32); // Prune chunk 0 (bits 0..32)
            })
            .unwrap();
        assert_eq!(historical.len(), 32);
        assert_eq!(historical.pruned_chunks(), 1);

        // The bitmap now has 32 bits but they're all in pruned chunks
        // Try to reconstruct commit 2 - this should not panic
        let reconstructed = historical
            .get_at_commit(2)
            .expect("should be able to reconstruct fully pruned commit");

        assert_eq!(reconstructed.len(), 32, "length should match");
        assert_eq!(
            reconstructed.pruned_chunks(),
            1,
            "should have 1 pruned chunk"
        );

        // Also test reconstruction of commit 1 (before pruning)
        let before_prune = historical
            .get_at_commit(1)
            .expect("should be able to reconstruct pre-prune state");

        assert_eq!(before_prune.len(), 32);
        assert_eq!(before_prune.pruned_chunks(), 0);
        // Verify the alternating pattern
        for i in 0..32 {
            assert_eq!(before_prune.get_bit(i), i % 2 == 0);
        }
    }

    /// Verify historical bitmap reconstruction correctness by comparing to another bitmap.
    ///
    /// This test creates a "ground truth" (`Prunable`) bitmap alongside the `Historical` bitmap.
    /// Both bitmaps receive the same random operations. After each commit, we save the ground
    /// truth state. At the end, we reconstruct each commit from the `Historical` bitmap and
    /// verify it matches the saved ground truth state bit-for-bit.
    fn test_randomized_helper<R: rand::Rng>(rng: &mut R) {
        // Test configuration
        const NUM_COMMITS: u64 = 20;
        const OPERATIONS_PER_COMMIT: usize = 32;
        const CHUNK_SIZE_BITS: u64 = Prunable::<4>::CHUNK_SIZE_BITS;

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
                            let bit = rng.gen_range(0..current_len);
                            let new_value = rng.gen_bool(0.5);

                            // Safety: Only modify bits that aren't pruned
                            let chunk_idx = Prunable::<4>::unpruned_chunk(bit);
                            if chunk_idx >= current_pruned {
                                batch.set_bit(bit, new_value);
                                ground_truth.set_bit(bit, new_value);
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

    /// Run property-based tests with multiple seeds to explore the state space.
    ///
    /// Tests 101 different random operation sequences (seeds 0-100) to ensure
    /// historical reconstruction works correctly across a wide variety of scenarios.
    #[test]
    fn test_randomized_with_multiple_seeds() {
        use rand::{rngs::StdRng, SeedableRng};
        for seed in 0..=100 {
            let mut rng = StdRng::seed_from_u64(seed);
            test_randomized_helper(&mut rng);
        }
    }

    #[test]
    #[should_panic(expected = "bit pruned: 31")]
    fn test_pop_into_pruned_region_panics() {
        let mut historical: Historical<4> = Historical::new();

        // Create a bitmap with 64 bits (2 chunks), then prune first chunk
        historical
            .with_batch(1, |b| {
                b.push_chunk(&[0xFF; 4]);
                b.push_chunk(&[0xFF; 4]);
            })
            .unwrap();

        historical
            .with_batch(2, |b| {
                b.prune_to_bit(32);
            })
            .unwrap();

        // Now we have: len=64, pruned_chunks=1 (32 pruned bits, 32 live bits)
        assert_eq!(historical.len(), 64);
        assert_eq!(historical.pruned_chunks(), 1);

        // Try to pop past the prune boundary
        // This should panic with "cannot pop into pruned region"
        let mut batch = historical.start_batch();
        for _ in 0..33 {
            // Pop 33 times (32 live bits + 1 pruned bit)
            batch.pop();
        }
    }
}

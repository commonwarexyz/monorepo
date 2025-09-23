//! A historical wrapper around [`Prunable`] that stores snapshots via batched mutation tracking.
//!
//! Each snapshot is identified by a monotonically increasing `u64` key. The latest snapshot is
//! stored in full while older snapshots are reverse diffs that describe how to recover their state
//! from the newer snapshot. Diffs are built from chunk-level preimages that are captured as the
//! bitmap is mutated inside a [`BatchGuard`], so creating a new snapshot never requires scanning
//! the entire bitmap.
//!
//! # Examples
//!
//! ```
//! # use commonware_utils::bitmap::Historical;
//! let mut historical: Historical<4> = Historical::new();
//!
//! // 1. Mutate inside a batch and commit snapshot 1.
//! historical.with_batch(1, |batch| {
//!     batch.push(true);
//! }).unwrap();
//!
//! // 2. Start another batch, record changes, and commit snapshot 2.
//! let mut batch = historical.start_batch();
//! batch.set_bit(0, false);
//! batch.commit(2).unwrap();
//!
//! // 3. Read historical states and prune old entries when desired.
//! assert!(historical.get_snapshot(1).unwrap().get_bit(0));
//! assert!(!historical.get_snapshot(2).unwrap().get_bit(0));
//! let removed = historical.remove_snapshots_below(2);
//! assert_eq!(removed, 1);
//! ```

use super::Prunable;
#[cfg(not(feature = "std"))]
use alloc::{collections::BTreeMap, vec::Vec};
use core::{fmt, ops::Deref};
#[cfg(feature = "std")]
use std::collections::BTreeMap;

/// Represents a change to a single chunk in the bitmap.
#[derive(Clone, Debug)]
struct ChunkDiff<const N: usize> {
    /// Index of the chunk in the bitmap.
    chunk_index: usize,
    /// The chunk data at this snapshot.
    chunk_data: [u8; N],
}

/// Represents a reverse diff between two snapshots.
#[derive(Clone, Debug)]
struct BitmapDiff<const N: usize> {
    /// Length of the target (older) bitmap.
    len: usize,
    /// Number of pruned chunks in the target (older) bitmap.
    pruned_chunks: usize,
    /// Changed chunks needed to transform from newer snapshot to older snapshot.
    changed_chunks: Vec<ChunkDiff<N>>,
}

/// Storage type for snapshots - either a full bitmap or a reverse diff.
#[derive(Clone, Debug)]
enum SnapshotStorage<const N: usize> {
    /// Full bitmap snapshot (used for the newest/base snapshot).
    Full(Prunable<N>),
    /// Reverse diff showing how to get from a newer snapshot to this older snapshot.
    Diff(BitmapDiff<N>),
}

#[cfg(feature = "std")]
type MapIter<'a, const N: usize> = std::collections::btree_map::Iter<'a, u64, SnapshotStorage<N>>;
#[cfg(not(feature = "std"))]
type MapIter<'a, const N: usize> = alloc::collections::btree_map::Iter<'a, u64, SnapshotStorage<N>>;

/// Errors that can arise while recording historical snapshots.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotError {
    /// Snapshot keys must be strictly increasing; attempting to reuse or go backwards is rejected.
    NonMonotonicKey { previous: u64, attempted: u64 },
}

impl fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnapshotError::NonMonotonicKey {
                previous,
                attempted,
            } => write!(
                f,
                "snapshot key {attempted} must be greater than previously committed key {previous}"
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SnapshotError {}

/// Errors that can arise when executing a batched mutation with user-provided fallible logic.
#[derive(Debug, PartialEq, Eq)]
pub enum BatchError<E> {
    /// The user-provided closure returned an error; no snapshot was committed.
    User(E),
    /// Committing the batch failed due to snapshot bookkeeping (for example, a non-monotonic key).
    Snapshot(SnapshotError),
}

impl<E: fmt::Display> fmt::Display for BatchError<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BatchError::User(err) => write!(f, "batch aborted: {err}"),
            BatchError::Snapshot(err) => write!(f, "batch commit failed: {err}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: fmt::Display + fmt::Debug> std::error::Error for BatchError<E> {}

#[derive(Clone, Debug)]
struct ActiveBatch<const N: usize> {
    /// Number of bits in the bitmap when the batch began.
    base_len: usize,
    /// Number of pruned chunks when the batch began.
    base_pruned_chunks: usize,
    /// Snapshot of every chunk that was modified or pruned during the batch, keyed by the
    /// chunk index in the base snapshot (after accounting for pruned chunks).
    preimages: BTreeMap<usize, [u8; N]>,
}

/// Guard that records chunk-level preimages while a batch of mutations is applied.
///
/// All bitmap writes must go through the guard so that we know exactly which chunks changed. When
/// [`commit`](BatchGuard::commit) is called the preimages are turned into a reverse diff and stored
/// as the historical snapshot for the provided key.
#[must_use = "historical batches must be explicitly committed"]
pub struct BatchGuard<'a, const N: usize> {
    historical: &'a mut Historical<N>,
    committed: bool,
}

/// Read-only view of a stored snapshot.
#[derive(Clone, Copy, Debug)]
pub enum SnapshotView<'a, const N: usize> {
    /// Snapshot stored as a full bitmap.
    Full(&'a Prunable<N>),
    /// Snapshot stored as a reverse diff from a newer snapshot.
    Diff(SnapshotDiffRef<'a, N>),
}

/// Reference to a stored reverse diff.
#[derive(Clone, Copy, Debug)]
pub struct SnapshotDiffRef<'a, const N: usize> {
    len: usize,
    pruned_chunks: usize,
    changed_chunks: &'a [ChunkDiff<N>],
}

impl<'a, const N: usize> SnapshotDiffRef<'a, N> {
    /// Length of the older bitmap that this diff reconstructs.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Number of pruned chunks in the older bitmap.
    pub fn pruned_chunks(&self) -> usize {
        self.pruned_chunks
    }

    /// Iterator over the chunk updates recorded in the diff.
    pub fn changed_chunks(&self) -> impl Iterator<Item = (usize, &'a [u8; N])> {
        self.changed_chunks
            .iter()
            .map(|diff| (diff.chunk_index, &diff.chunk_data))
    }
}

/// Iterator over stored snapshots.
pub struct SnapshotIter<'a, const N: usize> {
    inner: MapIter<'a, N>,
}

impl<'a, const N: usize> Iterator for SnapshotIter<'a, N> {
    type Item = (u64, SnapshotView<'a, N>);

    fn next(&mut self) -> Option<Self::Item> {
        let (key, storage) = self.inner.next()?;
        let view = match storage {
            SnapshotStorage::Full(bitmap) => SnapshotView::Full(bitmap),
            SnapshotStorage::Diff(diff) => SnapshotView::Diff(SnapshotDiffRef {
                len: diff.len,
                pruned_chunks: diff.pruned_chunks,
                changed_chunks: &diff.changed_chunks,
            }),
        };
        Some((*key, view))
    }
}

/// A historical bitmap that records snapshots using batched mutation tracking.
///
/// The newest snapshot is stored in full; older snapshots are reverse diffs that describe how to
/// recover their state from the newer snapshot. A snapshot can only be created through a
/// [`BatchGuard`], ensuring we never need to scan the entire bitmap to learn what changed.
/// Mutating the bitmap outside a batch is unsupported and will produce incorrect history.
#[derive(Clone, Debug)]
pub struct Historical<const N: usize> {
    /// The current/active prunable bitmap.
    current: Prunable<N>,

    /// Historical snapshots: key -> snapshot storage (full or diff).
    /// The BTreeMap maintains key order, with the NEWEST snapshot being the full base.
    /// Older snapshots are stored as reverse diffs from newer snapshots.
    /// Keys must be monotonically increasing for the diff-chain approach to work correctly.
    snapshots: BTreeMap<u64, SnapshotStorage<N>>,

    /// Active batch collecting chunk preimages for diff construction.
    active_batch: Option<ActiveBatch<N>>,
}

impl<const N: usize> Historical<N> {
    /// Create a new empty historical bitmap.
    pub fn new() -> Self {
        Self {
            current: Prunable::new(),
            snapshots: BTreeMap::new(),
            active_batch: None,
        }
    }

    /// Create a new historical bitmap with the given number of pruned chunks.
    pub fn new_with_pruned_chunks(pruned_chunks: usize) -> Self {
        Self {
            current: Prunable::new_with_pruned_chunks(pruned_chunks),
            snapshots: BTreeMap::new(),
            active_batch: None,
        }
    }

    /// Retrieve a historical snapshot by key.
    ///
    /// Note: This method may need to reconstruct the snapshot from diffs,
    /// so it returns an owned `Prunable<N>` rather than a reference.
    pub fn get_snapshot(&self, key: u64) -> Option<Prunable<N>> {
        // Find the target snapshot
        self.snapshots.get(&key)?;

        // Reconstruct by following the reverse diff chain from the newest base
        self.reconstruct_snapshot_chain(key)
    }

    /// Remove all snapshots with keys below the given threshold.
    ///
    /// Returns the number of snapshots removed.
    pub fn remove_snapshots_below(&mut self, threshold: u64) -> usize {
        let keys_to_remove: Vec<u64> = self.snapshots.range(..threshold).map(|(k, _)| *k).collect();

        if keys_to_remove.is_empty() {
            return 0;
        }

        // Handle newest snapshot removal if needed
        self.handle_newest_removal_if_needed(&keys_to_remove);

        // Remove the old snapshots
        let count = keys_to_remove.len();
        for key in keys_to_remove {
            self.snapshots.remove(&key);
        }
        count
    }

    /// Remove all snapshots with keys at or below the given threshold.
    ///
    /// Returns the number of snapshots removed.
    pub fn remove_snapshots_at_or_below(&mut self, threshold: u64) -> usize {
        let keys_to_remove: Vec<u64> = self
            .snapshots
            .range(..=threshold)
            .map(|(k, _)| *k)
            .collect();

        if keys_to_remove.is_empty() {
            return 0;
        }

        // Handle newest snapshot removal if needed
        self.handle_newest_removal_if_needed(&keys_to_remove);

        // Remove the old snapshots
        let count = keys_to_remove.len();
        for key in keys_to_remove {
            self.snapshots.remove(&key);
        }
        count
    }

    /// Remove a specific snapshot by key.
    ///
    /// Returns true if the snapshot existed and was removed, false otherwise.
    pub fn remove_snapshot(&mut self, key: u64) -> bool {
        if !self.snapshots.contains_key(&key) {
            return false;
        }

        // Handle newest snapshot removal if needed
        self.handle_newest_removal_if_needed(&[key]);

        // Remove the snapshot
        self.snapshots.remove(&key).is_some()
    }

    /// Get the number of stored snapshots.
    pub fn snapshot_count(&self) -> usize {
        self.snapshots.len()
    }

    /// Get an iterator over all snapshot keys in ascending order.
    pub fn snapshot_keys(&self) -> impl Iterator<Item = u64> + '_ {
        self.snapshots.keys().copied()
    }

    /// Get the smallest snapshot key, if any snapshots exist.
    pub fn min_snapshot_key(&self) -> Option<u64> {
        self.snapshots.keys().next().copied()
    }

    /// Get the largest snapshot key, if any snapshots exist.
    pub fn max_snapshot_key(&self) -> Option<u64> {
        self.snapshots.keys().next_back().copied()
    }

    /// Clear all snapshots.
    pub fn clear_snapshots(&mut self) {
        self.snapshots.clear();
    }

    /// Iterate over stored snapshots in ascending key order.
    pub fn snapshots(&self) -> SnapshotIter<'_, N> {
        SnapshotIter {
            inner: self.snapshots.iter(),
        }
    }

    /// Number of bits currently in the live bitmap state.
    pub fn len(&self) -> usize {
        self.current.len()
    }

    /// Returns true if the live bitmap is empty.
    pub fn is_empty(&self) -> bool {
        self.current.is_empty()
    }

    /// Returns the number of pruned chunks in the live bitmap.
    pub fn pruned_chunks(&self) -> usize {
        self.current.pruned_chunks()
    }

    /// Returns the number of pruned bits in the live bitmap.
    pub fn pruned_bits(&self) -> usize {
        self.current.pruned_bits()
    }

    /// Returns the number of chunks in the live bitmap (including the trailing spare chunk).
    pub fn chunks_len(&self) -> usize {
        self.current.chunks_len()
    }

    /// Returns the bit value at `bit_offset` in the live bitmap.
    pub fn get_bit(&self, bit_offset: usize) -> bool {
        self.current.get_bit(bit_offset)
    }

    /// Returns the chunk containing `bit_offset` in the live bitmap.
    pub fn get_chunk(&self, bit_offset: usize) -> &[u8; N] {
        self.current.get_chunk(bit_offset)
    }

    /// Returns the last chunk of the live bitmap along with the number of bits it contains.
    pub fn last_chunk(&self) -> (&[u8; N], usize) {
        self.current.last_chunk()
    }

    /// Returns the live bitmap state after the most recent batch commit.
    pub fn bitmap(&self) -> &Prunable<N> {
        &self.current
    }

    /// Begin a batch that records chunk preimages while mutating the bitmap.
    ///
    /// Each mutation performed through the returned guard stores the original chunk contents so
    /// that we can build a diff in `O(changed_chunks)` time when the batch is committed. The caller
    /// is responsible for committing the batch with a strictly increasing snapshot key.
    pub fn start_batch(&mut self) -> BatchGuard<'_, N> {
        assert!(
            self.active_batch.is_none(),
            "a historical bitmap batch is already active"
        );

        let batch = ActiveBatch {
            base_len: self.current.len(),
            base_pruned_chunks: self.current.pruned_chunks(),
            preimages: BTreeMap::new(),
        };
        self.active_batch = Some(batch);
        BatchGuard {
            historical: self,
            committed: false,
        }
    }

    /// Convenience helper that starts a batch, executes `f`, then commits at `key`.
    ///
    /// This is the preferred way to mutate the bitmap:
    ///
    /// ```
    /// # use commonware_utils::bitmap::Historical;
    /// let mut historical: Historical<4> = Historical::new();
    /// historical
    ///     .with_batch(42, |batch| {
    ///         batch.push(true);
    ///         batch.set_bit(0, false);
    ///     })
    ///     .unwrap();
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::NonMonotonicKey`] if `key` is not greater than the largest
    /// previously committed key.
    pub fn with_batch<F>(&mut self, key: u64, f: F) -> Result<(), SnapshotError>
    where
        F: FnOnce(&mut BatchGuard<'_, N>),
    {
        let mut guard = self.start_batch();
        f(&mut guard);
        guard.commit(key)
    }

    /// Execute a fallible batch and commit it at the provided key.
    ///
    /// If the user-provided closure returns an error, the batch is aborted and the error is
    /// returned as [`BatchError::User`]. If the closure succeeds but committing the batch fails,
    /// the batch is aborted automatically and [`BatchError::Snapshot`] is returned.
    pub fn with_batch_try<F, R, E>(&mut self, key: u64, f: F) -> Result<R, BatchError<E>>
    where
        F: FnOnce(&mut BatchGuard<'_, N>) -> Result<R, E>,
    {
        let mut guard = self.start_batch();
        let result = f(&mut guard);
        match result {
            Ok(value) => guard
                .commit(key)
                .map(|()| value)
                .map_err(BatchError::Snapshot),
            Err(err) => {
                guard.abort();
                Err(BatchError::User(err))
            }
        }
    }

    /// Finalise the active batch and record a snapshot entry for `key`.
    fn finish_active_batch(&mut self, key: u64) -> Result<(), SnapshotError> {
        let Some(batch) = self.active_batch.take() else {
            panic!("no active batch to finish");
        };

        if let Some(existing_max) = self.max_snapshot_key() {
            if key <= existing_max {
                self.active_batch = Some(batch);
                return Err(SnapshotError::NonMonotonicKey {
                    previous: existing_max,
                    attempted: key,
                });
            }
        }

        let changed_chunks = batch
            .preimages
            .into_iter()
            .map(|(chunk_index, chunk_data)| ChunkDiff {
                chunk_index,
                chunk_data,
            })
            .collect();

        let diff = BitmapDiff {
            len: batch.base_len,
            pruned_chunks: batch.base_pruned_chunks,
            changed_chunks,
        };

        if self.snapshots.is_empty() {
            self.snapshots
                .insert(key, SnapshotStorage::Full(self.current.clone()));
        } else {
            let newest_key = *self.snapshots.keys().next_back().unwrap();
            self.snapshots
                .insert(newest_key, SnapshotStorage::Diff(diff));
            self.snapshots
                .insert(key, SnapshotStorage::Full(self.current.clone()));
        }

        Ok(())
    }

    /// Check if we're removing the newest snapshot and handle it appropriately.
    /// With reverse diff approach, we need to promote the next newest to full if we remove the current newest.
    fn handle_newest_removal_if_needed(&mut self, keys_to_remove: &[u64]) {
        if keys_to_remove.is_empty() || self.snapshots.is_empty() {
            return;
        }

        let newest_key = *self.snapshots.keys().next_back().unwrap();
        let removing_newest = keys_to_remove.contains(&newest_key);

        if removing_newest && keys_to_remove.len() < self.snapshots.len() {
            // Find the next newest snapshot that will remain
            let next_newest_key = self
                .snapshots
                .keys()
                .rev()
                .find(|&&k| !keys_to_remove.contains(&k))
                .copied();

            if let Some(next_newest_key) = next_newest_key {
                // Reconstruct it as a full snapshot to become the new base
                if let Some(reconstructed) = self.reconstruct_snapshot_chain(next_newest_key) {
                    self.snapshots
                        .insert(next_newest_key, SnapshotStorage::Full(reconstructed));
                }
            }
        }
    }

    /// Reconstruct a snapshot by following the reverse diff chain from the newest base.
    fn reconstruct_snapshot_chain(&self, target_key: u64) -> Option<Prunable<N>> {
        // Find the newest (highest key) snapshot - this is our base
        let newest_key = *self.snapshots.keys().next_back()?;

        // If we're asking for the newest snapshot, it should be full
        if target_key == newest_key {
            let newest_storage = self.snapshots.get(&newest_key)?;
            return match newest_storage {
                SnapshotStorage::Full(bitmap) => Some(bitmap.clone()),
                SnapshotStorage::Diff(_) => None, // Newest should always be full
            };
        }

        // Start from the newest full snapshot and work backward
        let newest_storage = self.snapshots.get(&newest_key)?;
        let mut result = match newest_storage {
            SnapshotStorage::Full(bitmap) => bitmap.clone(),
            SnapshotStorage::Diff(_) => return None, // Newest should always be full
        };

        // Apply reverse diffs going backward from newest to target
        for (&key, storage) in self.snapshots.range(target_key..newest_key).rev() {
            // Apply this reverse diff to continue going backward
            match storage {
                SnapshotStorage::Full(bitmap) => {
                    // If we encounter another full snapshot, use it as new base
                    result = bitmap.clone();
                }
                SnapshotStorage::Diff(diff) => {
                    // Apply the reverse diff to go further back in time
                    result = self.apply_reverse_diff_to_bitmap(&result, diff)?;
                }
            }

            // Check if we've reached our target after applying the diff
            if key == target_key {
                return Some(result);
            }
        }

        None
    }

    /// Apply a reverse diff to a bitmap to get the previous (older) state.
    fn apply_reverse_diff_to_bitmap(
        &self,
        newer_bitmap: &Prunable<N>,
        reverse_diff: &BitmapDiff<N>,
    ) -> Option<Prunable<N>> {
        // Create a new bitmap with the target properties
        let mut result = Prunable::new_with_pruned_chunks(reverse_diff.pruned_chunks);

        let newer_pruned = newer_bitmap.pruned_chunks();
        let base_pruned = reverse_diff.pruned_chunks;

        // Calculate how many complete chunks we need
        let complete_chunks = reverse_diff.len / Prunable::<N>::CHUNK_SIZE_BITS;
        let remaining_bits = reverse_diff.len % Prunable::<N>::CHUNK_SIZE_BITS;

        // Add complete chunks
        for chunk_idx in 0..complete_chunks {
            let chunk_data = Self::chunk_from_diff_or_newer(
                newer_bitmap,
                reverse_diff,
                chunk_idx,
                base_pruned,
                newer_pruned,
            );

            result.push_chunk(&chunk_data);
        }

        // Handle the partial last chunk if there are remaining bits
        if remaining_bits > 0 {
            let chunk_idx = complete_chunks;
            let chunk_data = Self::chunk_from_diff_or_newer(
                newer_bitmap,
                reverse_diff,
                chunk_idx,
                base_pruned,
                newer_pruned,
            );

            // Add bits from this chunk one by one until we reach the target length
            for bit_idx in 0..remaining_bits {
                let byte_idx = bit_idx / 8;
                let bit_in_byte = bit_idx % 8;
                let bit_value = (chunk_data[byte_idx] >> bit_in_byte) & 1 == 1;
                result.push(bit_value);
            }
        }

        Some(result)
    }

    /// Fetches the chunk data for `chunk_index` of the older snapshot described by
    /// `reverse_diff`, either from the recorded diff or by reusing chunk data from the newer
    /// snapshot (adjusting for differences in pruned prefixes).
    fn chunk_from_diff_or_newer(
        newer_bitmap: &Prunable<N>,
        reverse_diff: &BitmapDiff<N>,
        chunk_index: usize,
        base_pruned: usize,
        newer_pruned: usize,
    ) -> [u8; N] {
        if let Some(diff) = reverse_diff
            .changed_chunks
            .iter()
            .find(|chunk_diff| chunk_diff.chunk_index == chunk_index)
        {
            return diff.chunk_data;
        }

        let raw_chunk_index = chunk_index + base_pruned;
        if raw_chunk_index < newer_pruned {
            debug_assert!(
                reverse_diff
                    .changed_chunks
                    .iter()
                    .any(|chunk_diff| chunk_diff.chunk_index == chunk_index),
                "missing diff entry for pruned chunk"
            );
            return [0u8; N];
        }

        let current_chunk_index = raw_chunk_index - newer_pruned;
        if current_chunk_index < newer_bitmap.chunks_len() {
            *newer_bitmap.get_chunk_by_index(current_chunk_index)
        } else {
            [0u8; N]
        }
    }
}

impl<const N: usize> Default for Historical<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, const N: usize> BatchGuard<'a, N> {
    /// Returns the current length (after applied batch mutations).
    pub fn len(&self) -> usize {
        self.historical.current.len()
    }

    /// Returns the number of pruned chunks after applied batch mutations.
    pub fn pruned_chunks(&self) -> usize {
        self.historical.current.pruned_chunks()
    }

    /// Read-only access to the current bitmap state during the batch.
    pub fn current(&self) -> &Prunable<N> {
        &self.historical.current
    }

    /// Set the value of a bit, recording preimage data for the touched chunk.
    pub fn set_bit(&mut self, bit_offset: usize, bit: bool) -> &mut Self {
        self.capture_preimage_for_bit(bit_offset);
        self.historical.current.set_bit(bit_offset, bit);
        self
    }

    /// Push a single bit to the bitmap, tracking the chunk when necessary.
    pub fn push(&mut self, bit: bool) -> &mut Self {
        let (_, next_bit) = self.historical.current.last_chunk();
        if next_bit > 0 {
            let current_chunk_index = self.historical.current.chunks_len() - 1;
            self.capture_preimage_for_current_chunk(current_chunk_index);
        }
        self.historical.current.push(bit);
        self
    }

    /// Push a byte to the bitmap, tracking the affected chunk.
    pub fn push_byte(&mut self, byte: u8) -> &mut Self {
        let (_, next_bit) = self.historical.current.last_chunk();
        if next_bit > 0 {
            let current_chunk_index = self.historical.current.chunks_len() - 1;
            self.capture_preimage_for_current_chunk(current_chunk_index);
        }
        self.historical.current.push_byte(byte);
        self
    }

    /// Push a full chunk to the bitmap. No preimage tracking is required because the chunk
    /// did not exist in the base snapshot.
    pub fn push_chunk(&mut self, chunk: &[u8; N]) -> &mut Self {
        self.historical.current.push_chunk(chunk);
        self
    }

    /// Extend the bitmap by appending a series of bits.
    pub fn extend_bits<I>(&mut self, bits: I) -> &mut Self
    where
        I: IntoIterator<Item = bool>,
    {
        for bit in bits {
            self.push(bit);
        }
        self
    }

    /// Apply a set of direct bit updates.
    pub fn set_bits<I>(&mut self, updates: I) -> &mut Self
    where
        I: IntoIterator<Item = (usize, bool)>,
    {
        for (index, value) in updates {
            self.set_bit(index, value);
        }
        self
    }

    /// Pop the last bit, recording the chunk that will be modified.
    pub fn pop(&mut self) -> bool {
        self.capture_preimage_for_pop();
        self.historical.current.pop()
    }

    /// Prune chunks preceding `bit_offset`, capturing preimages for every chunk that will be
    /// removed so we can reconstruct the older snapshot without scanning.
    pub fn prune_to_bit(&mut self, bit_offset: usize) -> &mut Self {
        let chunk_num = Prunable::<N>::raw_chunk_index(bit_offset);
        let current_pruned = self.historical.current.pruned_chunks();
        if chunk_num <= current_pruned {
            return self;
        }

        let chunks_to_prune = chunk_num - current_pruned;
        self.capture_preimages_for_pruned_chunks(chunks_to_prune);
        self.historical.current.prune_to_bit(bit_offset);
        self
    }

    /// Commit the batch, writing a snapshot at `key` and clearing the batch state.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::NonMonotonicKey`] if `key` is not greater than the previously
    /// committed snapshot key.
    pub fn commit(&mut self, key: u64) -> Result<(), SnapshotError> {
        assert!(!self.committed, "batch guard already committed");
        match self.historical.finish_active_batch(key) {
            Ok(()) => {
                self.committed = true;
                Ok(())
            }
            Err(err) => {
                self.abort();
                Err(err)
            }
        }
    }

    /// Mark the batch as finished without creating a snapshot.
    ///
    /// This simply clears the tracked preimages; any mutations that were performed remain applied
    /// to the live bitmap state.
    pub fn abort(&mut self) {
        if !self.committed {
            self.historical.active_batch = None;
            self.committed = true;
        }
    }

    fn capture_preimage_for_bit(&mut self, bit_offset: usize) {
        let base_pruned = self
            .historical
            .active_batch
            .as_ref()
            .expect("batch not active")
            .base_pruned_chunks;
        let raw_chunk_index = Prunable::<N>::raw_chunk_index(bit_offset);
        debug_assert!(
            raw_chunk_index >= base_pruned,
            "bit is below base pruning boundary"
        );
        let base_chunk_index = raw_chunk_index - base_pruned;
        let current_chunk_index = self.historical.current.pruned_chunk_index(bit_offset);
        self.capture_preimage_for_chunk_indices(base_chunk_index, current_chunk_index);
    }

    fn capture_preimage_for_current_chunk(&mut self, current_chunk_index: usize) {
        let (base_pruned, current_pruned) = {
            let batch = self
                .historical
                .active_batch
                .as_ref()
                .expect("batch not active");
            (
                batch.base_pruned_chunks,
                self.historical.current.pruned_chunks(),
            )
        };
        debug_assert!(
            current_pruned >= base_pruned,
            "pruned chunk count cannot decrease within a batch"
        );
        let base_chunk_index = current_chunk_index + (current_pruned - base_pruned);
        self.capture_preimage_for_chunk_indices(base_chunk_index, current_chunk_index);
    }

    fn capture_preimages_for_pruned_chunks(&mut self, chunks_to_prune: usize) {
        for current_chunk_index in 0..chunks_to_prune {
            self.capture_preimage_for_current_chunk(current_chunk_index);
        }
    }

    fn capture_preimage_for_pop(&mut self) {
        let (.., next_bit) = self.historical.current.last_chunk();
        let chunk_len = self.historical.current.chunks_len();
        let current_chunk_index = if next_bit == 0 {
            debug_assert!(
                chunk_len >= 2,
                "pop from empty bitmap should panic elsewhere"
            );
            chunk_len - 2
        } else {
            chunk_len - 1
        };
        self.capture_preimage_for_current_chunk(current_chunk_index);
    }

    fn capture_preimage_for_chunk_indices(
        &mut self,
        base_chunk_index: usize,
        current_chunk_index: usize,
    ) {
        let needs_insert = {
            let batch = self
                .historical
                .active_batch
                .as_ref()
                .expect("batch not active");
            !batch.preimages.contains_key(&base_chunk_index)
        };

        if !needs_insert {
            return;
        }

        let chunk = *self
            .historical
            .current
            .get_chunk_by_index(current_chunk_index);

        self.historical
            .active_batch
            .as_mut()
            .expect("batch not active")
            .preimages
            .insert(base_chunk_index, chunk);
    }
}

impl<'a, const N: usize> Drop for BatchGuard<'a, N> {
    fn drop(&mut self) {
        if !self.committed {
            panic!("historical batch dropped without commit; call commit() before releasing it");
        }
    }
}

impl<'a, const N: usize> Deref for BatchGuard<'a, N> {
    type Target = Prunable<N>;

    fn deref(&self) -> &Self::Target {
        &self.historical.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let historical: Historical<4> = Historical::new();
        assert_eq!(historical.len(), 0);
        assert_eq!(historical.snapshot_count(), 0);
        assert!(historical.is_empty());
    }

    #[test]
    fn test_new_with_pruned_chunks() {
        let historical: Historical<4> = Historical::new_with_pruned_chunks(2);
        assert_eq!(historical.len(), 64); // 2 chunks * 32 bits
        assert_eq!(historical.pruned_chunks(), 2);
        assert_eq!(historical.snapshot_count(), 0);
    }

    #[test]
    fn test_create_and_get_snapshot() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(100, |batch| {
                batch.push(true);
                batch.push(false);
                batch.push(true);
            })
            .unwrap();
        assert_eq!(historical.len(), 3);

        historical
            .with_batch(200, |batch| {
                batch.push(false);
                batch.push(true);
            })
            .unwrap();
        assert_eq!(historical.len(), 5);

        let snapshot100 = historical.get_snapshot(100).unwrap();
        assert_eq!(snapshot100.len(), 3);
        assert!(snapshot100.get_bit(0));
        assert!(!snapshot100.get_bit(1));
        assert!(snapshot100.get_bit(2));

        let snapshot200 = historical.get_snapshot(200).unwrap();
        assert_eq!(snapshot200.len(), 5);
        assert!(snapshot200.get_bit(0));
        assert!(!snapshot200.get_bit(1));
        assert!(snapshot200.get_bit(2));
        assert!(!snapshot200.get_bit(3));
        assert!(snapshot200.get_bit(4));
    }

    #[test]
    fn test_batch_extend_and_set_bits() {
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(10, |batch| {
                batch
                    .extend_bits([true, false, true, true])
                    .set_bits([(1, true), (3, false)]);
            })
            .unwrap();

        let snapshot = historical.get_snapshot(10).unwrap();
        assert_eq!(snapshot.len(), 4);
        assert!(snapshot.get_bit(0));
        assert!(snapshot.get_bit(1));
        assert!(snapshot.get_bit(2));
        assert!(!snapshot.get_bit(3));
    }

    #[test]
    fn test_with_batch_try_user_error() {
        let mut historical: Historical<4> = Historical::new();
        let err: BatchError<&'static str> = historical
            .with_batch_try(1, |_batch| -> Result<(), &'static str> { Err("oops") })
            .unwrap_err();
        assert_eq!(historical.snapshot_count(), 0);
        match err {
            BatchError::User(msg) => assert_eq!(msg, "oops"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_with_batch_try_snapshot_error() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |batch| {
                batch.push(true);
            })
            .unwrap();

        let err: BatchError<()> = historical
            .with_batch_try(1, |batch| -> Result<(), ()> {
                batch.push(false);
                Ok(())
            })
            .unwrap_err();

        assert_eq!(historical.snapshot_count(), 1);
        match err {
            BatchError::Snapshot(SnapshotError::NonMonotonicKey {
                previous,
                attempted,
            }) => {
                assert_eq!(previous, 1);
                assert_eq!(attempted, 1);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn test_batch_method_chaining() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(7, |batch| {
                batch
                    .push(true)
                    .push(false)
                    .set_bit(0, false)
                    .extend_bits([true, true]);
            })
            .unwrap();

        let snapshot = historical.get_snapshot(7).unwrap();
        assert_eq!(snapshot.len(), 4);
        assert!(!snapshot.get_bit(0));
        assert!(!snapshot.get_bit(1));
        assert!(snapshot.get_bit(2));
        assert!(snapshot.get_bit(3));
    }

    #[test]
    fn test_batch_abort_allows_new_batch() {
        let mut historical: Historical<4> = Historical::new();
        let starting_len = historical.len();

        {
            let mut guard = historical.start_batch();
            guard.push(true);
            guard.abort();
        }

        assert_eq!(historical.len(), starting_len + 1);

        historical
            .with_batch(1, |batch| {
                batch.push(false);
            })
            .unwrap();

        let snapshot = historical.get_snapshot(1).unwrap();
        assert_eq!(snapshot.len(), starting_len + 2);
    }

    #[test]
    fn test_get_snapshot_not_found() {
        let historical: Historical<4> = Historical::new();
        assert!(historical.get_snapshot(100).is_none());
    }

    #[test]
    fn test_snapshot_key_monotonicity_error() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(5, |batch| {
                batch.push(true);
            })
            .unwrap();

        let err = historical.with_batch(5, |_| {}).unwrap_err();
        assert!(matches!(
            err,
            SnapshotError::NonMonotonicKey {
                previous: 5,
                attempted: 5
            }
        ));
    }

    #[test]
    fn test_remove_snapshots_below() {
        let mut historical: Historical<4> = Historical::new();

        for key in [10_u64, 20, 30, 40, 50] {
            historical
                .with_batch(key, |batch| {
                    batch.push(true);
                })
                .unwrap();
        }

        assert_eq!(historical.snapshot_count(), 5);

        // Remove snapshots below 30
        let removed = historical.remove_snapshots_below(30);
        assert_eq!(removed, 2); // 10 and 20
        assert_eq!(historical.snapshot_count(), 3);

        // Verify remaining snapshots
        assert!(historical.get_snapshot(10).is_none());
        assert!(historical.get_snapshot(20).is_none());
        assert!(historical.get_snapshot(30).is_some());
        assert!(historical.get_snapshot(40).is_some());
        assert!(historical.get_snapshot(50).is_some());
    }

    #[test]
    fn test_remove_snapshots_at_or_below() {
        let mut historical: Historical<4> = Historical::new();

        for key in [10_u64, 20, 30, 40, 50] {
            historical
                .with_batch(key, |batch| {
                    batch.push(true);
                })
                .unwrap();
        }

        // Remove snapshots at or below 30
        let removed = historical.remove_snapshots_at_or_below(30);
        assert_eq!(removed, 3); // 10, 20, and 30
        assert_eq!(historical.snapshot_count(), 2);

        // Verify remaining snapshots
        assert!(historical.get_snapshot(30).is_none());
        assert!(historical.get_snapshot(40).is_some());
        assert!(historical.get_snapshot(50).is_some());
    }

    #[test]
    fn test_remove_snapshot() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(100, |batch| {
                batch.push(true);
            })
            .unwrap();

        assert!(historical.remove_snapshot(100));
        assert_eq!(historical.snapshot_count(), 0);
        assert!(!historical.remove_snapshot(100)); // Already removed
    }

    #[test]
    fn test_snapshot_keys_and_bounds() {
        let mut historical: Historical<4> = Historical::new();

        assert_eq!(historical.snapshot_count(), 0);
        assert!(historical.min_snapshot_key().is_none());
        assert!(historical.max_snapshot_key().is_none());

        for key in [5_u64, 10, 20, 30] {
            historical
                .with_batch(key, |batch| {
                    batch.push(true);
                })
                .unwrap();
        }

        let keys: Vec<u64> = historical.snapshot_keys().collect();
        assert_eq!(keys, vec![5, 10, 20, 30]);

        assert_eq!(historical.min_snapshot_key(), Some(5));
        assert_eq!(historical.max_snapshot_key(), Some(30));
    }

    #[test]
    fn test_snapshot_iterator_views() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |batch| {
                batch.push(true);
            })
            .unwrap();
        historical
            .with_batch(2, |batch| {
                batch.set_bit(0, false);
            })
            .unwrap();

        let mut iter = historical.snapshots();

        let (key1, view1) = iter.next().expect("missing first snapshot");
        assert_eq!(key1, 1);
        match view1 {
            SnapshotView::Diff(diff) => {
                assert_eq!(diff.len(), 1);
                assert_eq!(diff.pruned_chunks(), 0);
                let changes: Vec<_> = diff.changed_chunks().collect();
                assert_eq!(changes.len(), 1);
                let (chunk_idx, chunk_bytes) = changes[0];
                assert_eq!(chunk_idx, 0);
                assert_ne!(chunk_bytes[0], 0);
            }
            SnapshotView::Full(_) => panic!("older snapshot should be diff"),
        }

        let (key2, view2) = iter.next().expect("missing newest snapshot");
        assert_eq!(key2, 2);
        match view2 {
            SnapshotView::Full(bitmap) => {
                assert_eq!(bitmap.len(), 1);
                assert!(!bitmap.get_bit(0));
            }
            SnapshotView::Diff(_) => panic!("newest snapshot must be full"),
        }

        assert!(iter.next().is_none());
    }

    #[test]
    fn test_clear_snapshots() {
        let mut historical: Historical<4> = Historical::new();

        for key in 1_u64..=3 {
            historical
                .with_batch(key, |batch| {
                    batch.push(true);
                })
                .unwrap();
        }

        assert_eq!(historical.snapshot_count(), 3);
        historical.clear_snapshots();
        assert_eq!(historical.snapshot_count(), 0);
    }

    #[test]
    fn test_read_access() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(1, |batch| {
                batch.push(true);
                batch.push(false);
                batch.push(true);
            })
            .unwrap();

        let view: &Prunable<4> = historical.bitmap();
        assert_eq!(view.len(), 3);
        assert!(view.get_bit(0));
        assert!(!view.get_bit(1));
        assert!(view.get_bit(2));
    }

    #[test]
    fn test_pruning_with_snapshots() {
        let mut historical: Historical<4> = Historical::new();

        // Add multiple chunks
        let chunk1 = [0x01, 0x02, 0x03, 0x04];
        let chunk2 = [0x05, 0x06, 0x07, 0x08];
        let chunk3 = [0x09, 0x0A, 0x0B, 0x0C];

        historical
            .with_batch(100, |batch| {
                batch.push_chunk(&chunk1);
                batch.push_chunk(&chunk2);
            })
            .unwrap();

        historical
            .with_batch(200, |batch| {
                batch.push_chunk(&chunk3);
            })
            .unwrap();

        historical
            .with_batch(300, |batch| {
                batch.prune_to_bit(64);
            })
            .unwrap();
        assert_eq!(historical.pruned_chunks(), 2);

        // Snapshots should be unaffected by pruning of current state
        let snapshot100 = historical.get_snapshot(100).unwrap();
        assert_eq!(snapshot100.len(), 64);
        assert_eq!(snapshot100.pruned_chunks(), 0);
        assert_eq!(snapshot100.get_chunk(0), &chunk1);
        assert_eq!(snapshot100.get_chunk(32), &chunk2);

        let snapshot200 = historical.get_snapshot(200).unwrap();
        assert_eq!(snapshot200.len(), 96);
        assert_eq!(snapshot200.pruned_chunks(), 0);
        assert_eq!(snapshot200.get_chunk(0), &chunk1);
        assert_eq!(snapshot200.get_chunk(32), &chunk2);
        assert_eq!(snapshot200.get_chunk(64), &chunk3);

        let snapshot300 = historical.get_snapshot(300).unwrap();
        assert_eq!(snapshot300.pruned_chunks(), 2);
        assert_eq!(snapshot300.get_chunk(64), &chunk3);
    }

    #[test]
    fn test_multiple_snapshots_different_states() {
        let mut historical: Historical<4> = Historical::new();

        historical.with_batch(0, |_| {}).unwrap();

        historical
            .with_batch(1, |batch| {
                batch.push(true);
            })
            .unwrap();

        historical
            .with_batch(2, |batch| {
                batch.push(false);
                batch.push(true);
            })
            .unwrap();

        // Verify each snapshot has the correct state
        let snapshot0 = historical.get_snapshot(0).unwrap();
        assert_eq!(snapshot0.len(), 0);

        let snapshot1 = historical.get_snapshot(1).unwrap();
        assert_eq!(snapshot1.len(), 1);
        assert!(snapshot1.get_bit(0));

        let snapshot2 = historical.get_snapshot(2).unwrap();
        assert_eq!(snapshot2.len(), 3);
        assert!(snapshot2.get_bit(0));
        assert!(!snapshot2.get_bit(1));
        assert!(snapshot2.get_bit(2));

        // Current state should have 3 bits
        assert_eq!(historical.len(), 3);
    }

    #[test]
    fn test_diff_based_snapshots() {
        // Test diff-based storage with reverse diff approach
        let mut historical: Historical<4> = Historical::new();

        historical
            .with_batch(100, |batch| {
                batch.push(true);
                batch.push(false);
            })
            .unwrap();

        historical
            .with_batch(200, |batch| {
                batch.set_bit(1, true);
                batch.push(true);
            })
            .unwrap();

        // Verify both snapshots work
        let snapshot100 = historical.get_snapshot(100).unwrap();
        assert_eq!(snapshot100.len(), 2);
        assert!(snapshot100.get_bit(0));
        assert!(!snapshot100.get_bit(1));

        let snapshot200 = historical.get_snapshot(200).unwrap();
        assert_eq!(snapshot200.len(), 3);
        assert!(snapshot200.get_bit(0));
        assert!(snapshot200.get_bit(1));
        assert!(snapshot200.get_bit(2));
    }

    #[test]
    fn test_batch_set_bit_commit() {
        let mut historical: Historical<4> = Historical::new();
        historical
            .with_batch(0, |batch| {
                batch.push(false);
            })
            .unwrap();

        let mut batch = historical.start_batch();
        batch.set_bit(0, true);
        batch.commit(1).unwrap();
        drop(batch);

        let snapshot0 = historical.get_snapshot(0).unwrap();
        assert_eq!(snapshot0.len(), 1);
        assert!(!snapshot0.get_bit(0));

        let snapshot1 = historical.get_snapshot(1).unwrap();
        assert_eq!(snapshot1.len(), 1);
        assert!(snapshot1.get_bit(0));
    }

    #[test]
    fn test_batch_push_and_flip() {
        let mut historical: Historical<4> = Historical::new();

        {
            let mut batch = historical.start_batch();
            batch.push(true);
            batch.push(false);
            batch.commit(10).unwrap();
        }

        assert_eq!(historical.len(), 2);

        historical
            .with_batch(11, |batch| {
                batch.set_bit(0, false);
                batch.set_bit(1, true);
            })
            .unwrap();

        let snapshot10 = historical.get_snapshot(10).unwrap();
        assert!(snapshot10.get_bit(0));
        assert!(!snapshot10.get_bit(1));

        let snapshot11 = historical.get_snapshot(11).unwrap();
        assert!(!snapshot11.get_bit(0));
        assert!(snapshot11.get_bit(1));
    }

    #[test]
    fn test_batch_prune_preserves_history() {
        let mut historical: Historical<4> = Historical::new();
        let chunk1 = [0xFF, 0x00, 0xFF, 0x00];
        let chunk2 = [0xAA, 0x55, 0xAA, 0x55];

        historical
            .with_batch(1, |batch| {
                batch.push_chunk(&chunk1);
                batch.push_chunk(&chunk2);
            })
            .unwrap();

        assert_eq!(historical.pruned_chunks(), 0);

        let mut batch = historical.start_batch();
        batch.prune_to_bit(32); // Remove the first chunk
        batch.commit(2).unwrap();
        drop(batch);

        assert_eq!(historical.pruned_chunks(), 1);

        let snapshot1 = historical.get_snapshot(1).unwrap();
        assert_eq!(snapshot1.pruned_chunks(), 0);
        assert_eq!(snapshot1.get_chunk(0), &chunk1);
        assert_eq!(snapshot1.get_chunk(32), &chunk2);

        let snapshot2 = historical.get_snapshot(2).unwrap();
        assert_eq!(snapshot2.pruned_chunks(), 1);
        assert_eq!(snapshot2.get_chunk(32), &chunk2);
        // The pruned chunk should still decode correctly when going back to the old snapshot
        assert!(historical.get_snapshot(1).is_some());
    }

    #[test]
    #[should_panic(expected = "historical batch dropped without commit")]
    fn test_batch_drop_without_commit_panics() {
        let mut historical: Historical<4> = Historical::new();
        let _batch = historical.start_batch();
        // Dropping `_batch` without committing should panic.
    }
}

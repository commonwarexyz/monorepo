//! In-memory state of an open volume: the catalog, per-blob state, and the chunk allocator.
//!
//! # Chunk lifecycle
//!
//! ```text
//!             allocate (blobs and journal extents)
//!   zeroed ------------------------------------------> owned
//!     ^                                                  |
//!     | zero-write rides a commit batch;                 | freed by resize, delete,
//!     | durable at its barrier                           | or extent retirement
//!     |                                                  v
//!    raw <------------------------------------------- grave
//!             promoted once the freeing record is durable, no live handle
//!             can reach the chunk, and no in-flight I/O pinned it
//! ```
//!
//! Only durably-zero chunks are allocatable to blobs: if a crash keeps a mapping record
//! but loses the payload write, the mapped chunk must read zeros, never a previous
//! owner's bytes. Chunks past the end of the file count as zeroed (untouched file space
//! reads as zeros through the high-water clamp, and holes read as zeros once payload
//! lands nearby), so growth is pure bookkeeping: the file is extended by payload writes,
//! never by `resize`.

use super::format::Extent;
use commonware_utils::sync::Mutex;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::{
        Arc, Weak,
        atomic::{AtomicU64, Ordering},
    },
};

/// Chunk geometry of a volume, frozen at creation.
#[derive(Debug, Clone, Copy)]
pub(super) struct Geometry {
    /// Chunk size in bytes.
    pub chunk_size: u32,
}

impl Geometry {
    /// Logical byte offset of `chunk`.
    pub fn chunk_offset(&self, chunk: u32) -> u64 {
        u64::from(chunk) * u64::from(self.chunk_size)
    }

    /// The slot containing byte `offset` of a blob.
    pub fn slot_of(&self, offset: u64) -> u64 {
        offset / u64::from(self.chunk_size)
    }

    /// Number of slots a blob of length `len` spans.
    pub fn slots_of_len(&self, len: u64) -> u64 {
        len.div_ceil(u64::from(self.chunk_size))
    }
}

/// One blob's mutable state. Guarded by [Core::state]; never locked across I/O.
#[derive(Debug, Default)]
pub(super) struct BlobState {
    /// Logical length, visible to all handles immediately.
    pub len: u64,
    /// Mapped slots. Slots inside `[0, len)` absent here read zeros.
    pub map: BTreeMap<u32, u32>,
    /// Length as of the blob's last journaled record: what replay reconstructs before
    /// any staged change.
    pub journaled_len: u64,
    /// The minimum staged length since the last journaled record. Journaling this floor
    /// (not just the final length) keeps replay from resurrecting chunks that a staged
    /// shrink unmapped before later writes re-extended the blob.
    pub staged_floor: u64,
    /// Mappings added since the last journaled record.
    pub staged_mappings: Vec<(u32, u32)>,
    /// Chunks unmapped by staged shrinks. They enter the grave when the shrink is
    /// drained into a batch (reuse before the freeing record is durable could hand a
    /// crash a chunk that replay still maps to this blob; chunks that were never
    /// journaled at all just ride the same conservative path).
    pub staged_free: Vec<u32>,
    /// Set when the row leaves the catalog. Checked and set under the state lock so a
    /// racing write can never stage a chunk after the removal collected the chunk set.
    pub removed: bool,
}

/// The staged changes drained from a blob into one journal record.
#[derive(Debug)]
pub(super) struct Drained {
    pub trunc_floor: u64,
    pub len: u64,
    pub mappings: Vec<(u32, u32)>,
}

impl BlobState {
    /// Take all staged state for journaling. Returns the record to journal (`None` when
    /// the journal already reflects this blob, so a bare barrier suffices) and any
    /// chunks freed since the last drain, which must be buried under the batch either
    /// way.
    pub fn drain(&mut self) -> (Option<Drained>, Vec<u32>) {
        let freed = std::mem::take(&mut self.staged_free);
        if self.staged_floor == self.journaled_len
            && self.len == self.journaled_len
            && self.staged_mappings.is_empty()
        {
            // Freed chunks can still exist here: a staged grow can shrink back to
            // exactly the journaled length, freeing chunks no record ever named.
            return (None, freed);
        }
        let drained = Drained {
            trunc_floor: self.staged_floor,
            len: self.len,
            mappings: std::mem::take(&mut self.staged_mappings),
        };
        self.journaled_len = self.len;
        self.staged_floor = self.len;
        (Some(drained), freed)
    }

    /// Mark the current state as journaled (a checkpoint snapshot row covers it),
    /// returning chunks freed since the last drain.
    pub fn snapshotted(&mut self) -> Vec<u32> {
        self.journaled_len = self.len;
        self.staged_floor = self.len;
        self.staged_mappings.clear();
        std::mem::take(&mut self.staged_free)
    }
}

/// One blob of the volume. All handles to a name share one `Core`.
#[derive(Debug)]
pub(super) struct Core {
    /// Journal identity. Strictly increasing across creations within an epoch.
    pub id: u64,
    pub version: u16,
    pub name: Vec<u8>,
    /// The batch whose barrier makes this blob's creation durable. Recovered blobs are 0
    /// (already durable); fresh blobs are `u64::MAX` until the committer drains their
    /// create record. An open of an existing name only rides a barrier when this exceeds
    /// the volume's durable batch.
    pub created_batch: AtomicU64,
    pub state: Mutex<BlobState>,
}

impl Core {
    /// A freshly created blob, pending its create record.
    pub fn new(id: u64, version: u16, name: Vec<u8>) -> Self {
        Self {
            id,
            version,
            name,
            created_batch: AtomicU64::new(u64::MAX),
            state: Mutex::new(BlobState::default()),
        }
    }

    /// A blob rebuilt from the journal.
    pub fn recovered(
        id: u64,
        version: u16,
        name: Vec<u8>,
        len: u64,
        map: BTreeMap<u32, u32>,
    ) -> Self {
        Self {
            id,
            version,
            name,
            created_batch: AtomicU64::new(0),
            state: Mutex::new(BlobState {
                len,
                map,
                journaled_len: len,
                staged_floor: len,
                ..BlobState::default()
            }),
        }
    }
}

/// The blob namespace of a volume.
#[derive(Debug, Default)]
pub(super) struct Catalog {
    pub blobs: BTreeMap<Vec<u8>, Arc<Core>>,
    /// Next journal identity to mint. Exceeds every id created this epoch, including
    /// deleted ones, so replay's monotonic-id invariant holds.
    pub next_id: u64,
}

/// A group of freed chunks awaiting reuse eligibility.
#[derive(Debug)]
struct GraveEntry {
    /// The batch whose barrier makes the freeing record durable.
    batch: u64,
    /// The blob whose handles may still read these chunks (deletes only). `None` when
    /// the chunks were already unreachable when freed (shrinks clamp every handle at
    /// once; retired journal extents were never blob-addressable).
    holder: Option<Weak<Core>>,
    chunks: Vec<u32>,
}

/// Chunk accounting for one volume.
#[derive(Debug, Default)]
pub(super) struct Allocator {
    /// Durably-zero chunks, ready for allocation.
    zeroed: BTreeSet<u32>,
    /// Freed chunks awaiting a zero-write.
    raw: BTreeSet<u32>,
    /// Freed chunks not yet eligible for `raw`.
    grave: Vec<GraveEntry>,
    /// Chunk ids minted so far; ids `size_chunks..` are beyond every write issued so
    /// far, so fresh mints read as zeros exactly like zeroed chunks.
    size_chunks: u32,
}

impl Allocator {
    pub fn new(size_chunks: u32) -> Self {
        Self {
            size_chunks,
            ..Self::default()
        }
    }

    /// Seed the free set derived by replay. Recovered chunks are raw: zeroed-ness is
    /// never persisted, so it must be re-established by zero-writes.
    pub fn recovered(&mut self, free: impl IntoIterator<Item = u32>) {
        self.raw.extend(free);
    }

    /// Allocate `n` zeroed chunks, minting fresh file space when the pool runs dry.
    pub fn allocate(&mut self, n: usize) -> Vec<u32> {
        let mut chunks = Vec::with_capacity(n);
        while chunks.len() < n {
            match self.zeroed.pop_first() {
                Some(chunk) => chunks.push(chunk),
                None => {
                    chunks.push(self.size_chunks);
                    self.size_chunks += 1;
                }
            }
        }
        chunks
    }

    /// Allocate a contiguous run for a journal extent, preferring free space over fresh
    /// file growth. Returns the extent and whether it must be zero-written before use
    /// (false only when every chunk came from the zeroed pool).
    pub fn allocate_extent(&mut self, chunks: u32) -> (Extent, bool) {
        // First fit over the sorted union of both pools.
        let mut run_start = 0u32;
        let mut prev = None;
        let mut found = None;
        for &chunk in self.zeroed.union(&self.raw) {
            if prev != Some(chunk.wrapping_sub(1)) {
                run_start = chunk;
            }
            prev = Some(chunk);
            if chunk - run_start + 1 == chunks {
                found = Some(run_start);
                break;
            }
        }
        let Some(first_chunk) = found else {
            // Mint fresh space. It must still be zero-written: replay requires the
            // extent's bytes to physically exist (end-of-file inside an extent is
            // damage), and only a real write makes that durable.
            let extent = Extent {
                first_chunk: self.size_chunks,
                chunks,
            };
            self.size_chunks += chunks;
            return (extent, true);
        };
        let mut needs_zero = false;
        for chunk in first_chunk..first_chunk + chunks {
            needs_zero |= self.raw.remove(&chunk);
            self.zeroed.remove(&chunk);
        }
        (
            Extent {
                first_chunk,
                chunks,
            },
            needs_zero,
        )
    }

    /// Bury freed chunks until `batch`'s barrier completes (and, for deletes, until the
    /// removed blob's last handle drops).
    pub fn bury(&mut self, chunks: Vec<u32>, holder: Option<Weak<Core>>, batch: u64) {
        if chunks.is_empty() {
            return;
        }
        self.grave.push(GraveEntry {
            batch,
            holder,
            chunks,
        });
    }

    /// Move grave chunks whose gates have all cleared into the raw pool: the freeing
    /// batch is durable (`batch <= durable_batch`), the holding blob (if any) is
    /// dropped, and no in-flight I/O pinned the chunk.
    pub fn exhume(&mut self, durable_batch: u64, pins: &Pins) {
        let mut kept = Vec::new();
        for mut entry in self.grave.drain(..) {
            let durable = entry.batch <= durable_batch;
            let unreachable = entry
                .holder
                .as_ref()
                .is_none_or(|holder| holder.strong_count() == 0);
            if durable && unreachable {
                let pinned = pins.split_pinned(&mut entry.chunks);
                self.raw.extend(entry.chunks);
                if pinned.is_empty() {
                    continue;
                }
                entry.chunks = pinned;
            }
            kept.push(entry);
        }
        self.grave = kept;
    }

    /// Take up to `n` raw chunks for a zero-write. The caller owns them until it returns
    /// them via [Self::zeroed] after the zero-write's barrier completes.
    pub fn take_raw(&mut self, n: usize) -> Vec<u32> {
        let mut chunks = Vec::new();
        while chunks.len() < n {
            match self.raw.pop_first() {
                Some(chunk) => chunks.push(chunk),
                None => break,
            }
        }
        chunks
    }

    /// Return chunks whose zero-writes are durable to the allocatable pool.
    pub fn zeroed(&mut self, chunks: Vec<u32>) {
        self.zeroed.extend(chunks);
    }

    /// Return an allocated chunk that was written to but never mapped or journaled.
    /// No replay can reference it, so it needs no grave — only a zero-write before it
    /// becomes allocatable again.
    pub fn release(&mut self, chunk: u32) {
        self.raw.insert(chunk);
    }
}

/// Pins on chunks with in-flight I/O.
///
/// Every data read or write pins the chunks it resolved through a blob's map (under that
/// blob's state lock) before issuing I/O and unpins when the I/O completes. The grave
/// never promotes a pinned chunk, so a chunk freed mid-I/O cannot be reallocated (and its
/// bytes replaced) under a raced syscall.
#[derive(Debug, Default)]
pub(super) struct Pins {
    counts: Mutex<HashMap<u32, u32>>,
}

impl Pins {
    /// Pin `chunks` for the duration of one I/O. Returns a guard that unpins on drop.
    pub fn pin(self: &Arc<Self>, chunks: Vec<u32>) -> PinGuard {
        let mut counts = self.counts.lock();
        for &chunk in &chunks {
            *counts.entry(chunk).or_insert(0) += 1;
        }
        drop(counts);
        PinGuard {
            pins: self.clone(),
            chunks,
        }
    }

    /// Remove and return the pinned chunks from `chunks`, leaving the unpinned ones.
    fn split_pinned(&self, chunks: &mut Vec<u32>) -> Vec<u32> {
        let counts = self.counts.lock();
        if counts.is_empty() {
            return Vec::new();
        }
        let mut pinned = Vec::new();
        chunks.retain(|chunk| {
            if counts.contains_key(chunk) {
                pinned.push(*chunk);
                false
            } else {
                true
            }
        });
        pinned
    }
}

/// Unpins its chunks when dropped.
#[derive(Debug)]
pub(super) struct PinGuard {
    pins: Arc<Pins>,
    chunks: Vec<u32>,
}

impl Drop for PinGuard {
    fn drop(&mut self) {
        let mut counts = self.pins.counts.lock();
        for chunk in &self.chunks {
            match counts.get_mut(chunk) {
                Some(1) => {
                    counts.remove(chunk);
                }
                Some(count) => *count -= 1,
                None => unreachable!("unpin of unpinned chunk"),
            }
        }
    }
}

/// Tracks how far into the file bytes may have been written.
///
/// Reads clamp at this high-water mark and zero-fill beyond it: bytes past every issued
/// write are holes or untouched space, which read as zeros. The mark only grows.
#[derive(Debug)]
pub(super) struct HighWater(AtomicU64);

impl HighWater {
    pub const fn new(size: u64) -> Self {
        Self(AtomicU64::new(size))
    }

    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }

    /// Record that bytes up to `end` may now exist on disk. Called before the write is
    /// issued so the mark never understates what a concurrent read could see.
    pub fn extend(&self, end: u64) {
        self.0.fetch_max(end, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drain_empty_is_none() {
        let mut state = BlobState::default();
        let (drained, freed) = state.drain();
        assert!(drained.is_none());
        assert!(freed.is_empty());

        // A pure write extends the length and stages a mapping.
        state.len = 100;
        state.map.insert(0, 7);
        state.staged_mappings.push((0, 7));
        let (drained, freed) = state.drain();
        let drained = drained.unwrap();
        assert_eq!(drained.trunc_floor, 0);
        assert_eq!(drained.len, 100);
        assert_eq!(drained.mappings, vec![(0, 7)]);
        assert!(freed.is_empty());

        // Draining again with nothing staged is a bare barrier.
        assert!(state.drain().0.is_none());
    }

    #[test]
    fn drain_pure_shrink_is_journaled() {
        // A shrink with no other staged state must still journal: the floor equals the
        // final length, but both differ from what the journal knows.
        let mut state = BlobState {
            len: 100,
            journaled_len: 100,
            staged_floor: 100,
            ..Default::default()
        };
        state.len = 40;
        state.staged_floor = 40;
        let (drained, _) = state.drain();
        let drained = drained.unwrap();
        assert_eq!(drained.trunc_floor, 40);
        assert_eq!(drained.len, 40);
        assert_eq!(state.journaled_len, 40);
        assert!(state.drain().0.is_none());
    }

    #[test]
    fn drain_records_trajectory_floor() {
        let mut state = BlobState {
            len: 100,
            journaled_len: 100,
            staged_floor: 100,
            ..Default::default()
        };

        // Shrink to 10 (unmapping some chunk), then grow back to 200.
        state.staged_floor = 10;
        state.staged_free.push(9);
        state.len = 200;
        state.map.insert(1, 4);
        state.staged_mappings.push((1, 4));

        let (drained, freed) = state.drain();
        let drained = drained.unwrap();
        assert_eq!(drained.trunc_floor, 10);
        assert_eq!(drained.len, 200);
        assert_eq!(freed, vec![9]);
        assert_eq!(state.staged_floor, 200);
    }

    #[test]
    fn drain_staged_only_shrink_frees_without_record() {
        // A staged grow that shrinks back to the journaled length frees chunks that no
        // record ever named; they must still surface for burial.
        let mut state = BlobState {
            len: 100,
            journaled_len: 100,
            staged_floor: 100,
            ..Default::default()
        };
        state.len = 100;
        state.staged_free.push(5);
        let (drained, freed) = state.drain();
        assert!(drained.is_none());
        assert_eq!(freed, vec![5]);
    }

    #[test]
    fn allocator_prefers_zeroed_then_mints() {
        let mut alloc = Allocator::new(5);
        alloc.zeroed(vec![2, 3]);
        let chunks = alloc.allocate(4);
        assert_eq!(chunks, vec![2, 3, 5, 6]);
        assert_eq!(alloc.size_chunks, 7);
    }

    #[test]
    fn allocate_extent_first_fit() {
        let mut alloc = Allocator::new(10);
        alloc.zeroed(vec![2, 3, 7, 8, 9]);
        alloc.recovered([4]);

        // 2..=4 is the first run of three, and chunk 4 is raw, so zeroing is needed.
        let (extent, needs_zero) = alloc.allocate_extent(3);
        assert_eq!(extent.first_chunk, 2);
        assert!(needs_zero);

        // 7..=9 is entirely zeroed.
        let (extent, needs_zero) = alloc.allocate_extent(3);
        assert_eq!(extent.first_chunk, 7);
        assert!(!needs_zero);

        // Nothing contiguous left: mint fresh space, which must be materialized.
        let (extent, needs_zero) = alloc.allocate_extent(2);
        assert_eq!(extent.first_chunk, 10);
        assert!(needs_zero);
        assert_eq!(alloc.size_chunks, 12);
    }

    #[test]
    fn grave_gates() {
        let pins = Arc::new(Pins::default());
        let mut alloc = Allocator::new(10);

        // Durability gate: batch 5's chunks stay buried until batch 5 is durable.
        alloc.bury(vec![1, 2], None, 5);
        alloc.exhume(4, &pins);
        assert!(alloc.take_raw(10).is_empty());
        alloc.exhume(5, &pins);
        assert_eq!(alloc.take_raw(10), vec![1, 2]);

        // Reachability gate: a delete's chunks stay buried while the blob has handles.
        let core = Arc::new(Core::new(0, 0, vec![]));
        alloc.bury(vec![3], Some(Arc::downgrade(&core)), 6);
        alloc.exhume(6, &pins);
        assert!(alloc.take_raw(10).is_empty());
        drop(core);
        alloc.exhume(6, &pins);
        assert_eq!(alloc.take_raw(10), vec![3]);

        // Pin gate: pinned chunks stay buried; unpinned siblings promote.
        alloc.bury(vec![4, 5], None, 6);
        let guard = pins.pin(vec![4]);
        alloc.exhume(6, &pins);
        assert_eq!(alloc.take_raw(10), vec![5]);
        drop(guard);
        alloc.exhume(6, &pins);
        assert_eq!(alloc.take_raw(10), vec![4]);
    }

    #[test]
    fn pins_count() {
        let pins = Arc::new(Pins::default());
        let a = pins.pin(vec![7, 8]);
        let b = pins.pin(vec![7]);
        let mut chunks = vec![6, 7, 8];
        assert_eq!(pins.split_pinned(&mut chunks), vec![7, 8]);
        assert_eq!(chunks, vec![6]);
        drop(a);
        let mut chunks = vec![6, 7, 8];
        assert_eq!(pins.split_pinned(&mut chunks), vec![7]);
        drop(b);
        let mut chunks = vec![6, 7, 8];
        assert!(pins.split_pinned(&mut chunks).is_empty());
        assert_eq!(chunks, vec![6, 7, 8]);
    }

    #[test]
    fn high_water_grows_only() {
        let hw = HighWater::new(100);
        hw.extend(50);
        assert_eq!(hw.get(), 100);
        hw.extend(150);
        assert_eq!(hw.get(), 150);
    }

    #[test]
    fn geometry() {
        let geometry = Geometry {
            chunk_size: 1 << 16,
        };
        assert_eq!(geometry.chunk_offset(2), 2 << 16);
        assert_eq!(geometry.slot_of(0), 0);
        assert_eq!(geometry.slot_of((1 << 16) - 1), 0);
        assert_eq!(geometry.slot_of(1 << 16), 1);
        assert_eq!(geometry.slots_of_len(0), 0);
        assert_eq!(geometry.slots_of_len(1), 1);
        assert_eq!(geometry.slots_of_len(1 << 16), 1);
        assert_eq!(geometry.slots_of_len((1 << 16) + 1), 2);
    }
}

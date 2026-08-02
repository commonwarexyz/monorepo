//! Log-structured storage for epoch-atomic blobs.
//!
//! Payloads are written once into shadow storage in the live inode. Repeated overwrites within an
//! epoch reuse shadow slots that no committed root references. A sync checkpoints the current map,
//! durably prepares payload and metadata, then publishes the older of two fixed root slots with a
//! small durable write. Recovery validates only the selected self-contained checkpoint; it never
//! rereads payload bytes or historical records. Small checkpoints live in the root page itself so
//! contiguous payloads remain contiguous across synchronization epochs.

use crate::IoBufs;
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_formatting::hex;
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Seek as _, SeekFrom, Write as _},
    os::unix::fs::FileExt,
    path::Path,
};

#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;

#[cfg(test)]
std::thread_local! {
    static TRACKED_READ_BYTES: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
    static TRACKED_DURABLE_WRITES: std::cell::RefCell<Option<Vec<(u64, usize)>>> = const {
        std::cell::RefCell::new(None)
    };
}

const ROOT_MAGIC: &[u8; 8] = b"CWUNOR05";
const PREPARED_ROOT_MAGIC: &[u8; 8] = b"CWUNOP05";
const MANIFEST_MAGIC: &[u8; 8] = b"CWUNOM05";
const CREATION_PREFIX: &str = ".commonware-uno-create-";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_LOG_ROOT";
const CHECKPOINT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_LOG_CHECKPOINT";
const ROOT_BODY_LEN: usize = 36;
pub(super) const ROOT_LEN: usize = 40;
const ROOT_SLOT_LEN: u64 = 4096;
const MANIFEST_HEADER_LEN: usize = 40;
const MANIFEST_ENTRY_LEN: usize = 24;
const ROOT_OFFSETS: [u64; 2] = [4096, 8192];
const DENSE_PAGE_LEN: u64 = 4096;
const MAX_DENSE_PAGES: usize = 1 << 20;
const MAX_MANIFEST_ENTRIES: usize = MAX_DENSE_PAGES;
const MAX_MANIFEST_LEN: usize = MANIFEST_HEADER_LEN + MAX_MANIFEST_ENTRIES * MANIFEST_ENTRY_LEN;
const SPARSE_MUTATION_ENTRY_RESERVE: usize = 2;
const DENSE_MIN_EXTENTS: usize = 256;
const DENSE_MAX_PAGES_PER_EXTENT: usize = 256;
const DENSE_ZERO: u64 = u64::MAX;
const DENSE_UNCHANGED: u64 = u64::MAX;
const DENSE_PENDING_ZERO: u64 = u64::MAX - 1;
pub(super) type PayloadRange = (u64, u64);
pub(super) type PendingPayload = (u64, u64, Vec<PayloadRange>);
#[cfg(target_os = "linux")]
const RECLAIM_ALIGNMENT: u64 = 4096;
// Retaining short garbage runs is cheaper than issuing thousands of extent-tree mutations. Large
// runs dominate both allocation and the bytes an ext4 sync must flush.
#[cfg(target_os = "linux")]
const MIN_RECLAIM_LEN: u64 = 64 * 1024;

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn resource_exhausted(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::OutOfMemory, message.into())
}

fn invalid_candidate(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
    )
}

fn checked_end(offset: u64, len: u64) -> io::Result<u64> {
    offset
        .checked_add(len)
        .ok_or_else(|| invalid_input("atomic log offset overflow"))
}

fn checksum(parts: &[&[u8]]) -> u32 {
    let mut hasher = Crc32::default();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().1.as_u32()
}

fn read_exact_at(file: &File, mut offset: u64, mut out: &mut [u8]) -> io::Result<()> {
    while !out.is_empty() {
        let read = match file.read_at(out, offset) {
            Ok(read) => read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "atomic log record is truncated",
            ));
        }
        #[cfg(test)]
        TRACKED_READ_BYTES.with(|tracked| {
            if let Some(bytes) = tracked.get() {
                tracked.set(Some(bytes + read as u64));
            }
        });
        offset = checked_end(offset, read as u64)?;
        out = &mut out[read..];
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn track_read_bytes<T>(operation: impl FnOnce() -> T) -> (T, u64) {
    TRACKED_READ_BYTES.with(|tracked| {
        assert!(tracked.replace(Some(0)).is_none());
    });
    let result = operation();
    let bytes = TRACKED_READ_BYTES.with(|tracked| tracked.replace(None).unwrap());
    (result, bytes)
}

#[cfg(test)]
pub(super) fn track_durable_writes<T>(operation: impl FnOnce() -> T) -> (T, Vec<(u64, usize)>) {
    TRACKED_DURABLE_WRITES.with(|tracked| {
        assert!(tracked.borrow_mut().replace(Vec::new()).is_none());
    });
    let result = operation();
    let writes = TRACKED_DURABLE_WRITES.with(|tracked| tracked.borrow_mut().take().unwrap());
    (result, writes)
}

fn normalize_ranges(
    offset: u64,
    len: u64,
    ranges: impl IntoIterator<Item = (u64, u64)>,
) -> io::Result<Vec<(u64, u64)>> {
    let end = checked_end(offset, len)?;
    let mut ranges = ranges.into_iter().collect::<Vec<_>>();
    ranges.sort_unstable_by_key(|&(start, _)| start);
    let mut normalized: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
    for (start, range_len) in ranges {
        let range_end = checked_end(start, range_len)?;
        if range_len == 0 || start < offset || range_end > end {
            return Err(invalid_data("atomic payload range is outside its epoch"));
        }
        if let Some((previous_start, previous_len)) = normalized.last_mut() {
            let previous_end = checked_end(*previous_start, *previous_len)?;
            if start < previous_end {
                return Err(invalid_data("atomic payload ranges overlap"));
            }
            if start == previous_end {
                *previous_len = checked_end(*previous_len, range_len)?;
                continue;
            }
        }
        normalized.push((start, range_len));
    }
    Ok(normalized)
}

/// Start Linux writeback for the current payload while its checkpoint is built.
#[cfg(target_os = "linux")]
pub(super) fn begin_payload_writeback(file: &File, offset: u64, len: u64) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }
    let offset = libc::off64_t::try_from(offset)
        .map_err(|_| invalid_input("atomic payload offset exceeds off64_t"))?;
    let len = libc::off64_t::try_from(len)
        .map_err(|_| invalid_input("atomic payload length exceeds off64_t"))?;
    // SAFETY: the descriptor remains valid for the call and both offsets fit off64_t. This only
    // initiates writeback; the existing inode sync remains the durability and ordering barrier.
    let result = unsafe {
        libc::sync_file_range(file.as_raw_fd(), offset, len, libc::SYNC_FILE_RANGE_WRITE)
    };
    if result == 0 {
        return Ok(());
    }
    let error = io::Error::last_os_error();
    if matches!(
        error.raw_os_error(),
        Some(libc::EINVAL | libc::ENOSYS | libc::EOPNOTSUPP)
    ) {
        return Ok(());
    }
    Err(error)
}

#[cfg(not(target_os = "linux"))]
pub(super) const fn begin_payload_writeback(
    _file: &File,
    _offset: u64,
    _len: u64,
) -> io::Result<()> {
    Ok(())
}

/// Deallocate complete Linux pages in an epoch that no canonical manifest entry references.
///
/// These bytes are newer than the last committed root and cannot be observed through the new root,
/// so reclaiming them before publication is safe. Unsupported filesystems retain the bytes.
#[cfg(not(target_os = "linux"))]
pub(super) const fn reclaim_shadowed_payload(
    file: &File,
    offset: u64,
    len: u64,
    live_ranges: &[PayloadRange],
) -> io::Result<()> {
    let _ = (file, offset, len, live_ranges);
    Ok(())
}

/// Deallocate complete Linux pages in an epoch that no canonical manifest entry references.
///
/// These bytes are newer than the last committed root and cannot be observed through the new root,
/// so reclaiming them before publication is safe. Unsupported filesystems retain the bytes.
#[cfg(target_os = "linux")]
pub(super) fn reclaim_shadowed_payload(
    file: &File,
    offset: u64,
    len: u64,
    live_ranges: &[PayloadRange],
) -> io::Result<()> {
    let end = checked_end(offset, len)?;
    let live_ranges = normalize_ranges(offset, len, live_ranges.iter().copied())?;
    let mut cursor = offset;
    for (start, range_len) in live_ranges.into_iter().chain(std::iter::once((end, 0))) {
        let reclaim_start = cursor
            .checked_add(RECLAIM_ALIGNMENT - 1)
            .ok_or_else(|| invalid_input("atomic reclaim offset overflow"))?
            / RECLAIM_ALIGNMENT
            * RECLAIM_ALIGNMENT;
        let reclaim_end = start / RECLAIM_ALIGNMENT * RECLAIM_ALIGNMENT;
        if reclaim_end.saturating_sub(reclaim_start) >= MIN_RECLAIM_LEN {
            let file_offset = libc::off_t::try_from(reclaim_start)
                .map_err(|_| invalid_input("atomic reclaim offset overflow"))?;
            let reclaim_len = libc::off_t::try_from(reclaim_end - reclaim_start)
                .map_err(|_| invalid_input("atomic reclaim length overflow"))?;
            loop {
                // SAFETY: the descriptor remains open, the range is validated within the current
                // epoch, and the state lock excludes reads and mutations while the filesystem
                // changes its allocation.
                let result = unsafe {
                    libc::fallocate(
                        file.as_raw_fd(),
                        libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE,
                        file_offset,
                        reclaim_len,
                    )
                };
                if result == 0 {
                    break;
                }
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EOPNOTSUPP | libc::ENOSYS | libc::EINVAL)
                ) {
                    return Ok(());
                }
                return Err(error);
            }
        }
        cursor = checked_end(start, range_len)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Extent {
    end: u64,
    physical: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Delta {
    end: u64,
    physical: Option<u64>,
}

#[derive(Debug)]
struct DenseIndex {
    pages: Vec<u64>,
    pending: Vec<u64>,
}

impl DenseIndex {
    fn page_count(len: u64) -> Option<usize> {
        if !len.is_multiple_of(DENSE_PAGE_LEN) {
            return None;
        }
        let pages = usize::try_from(len / DENSE_PAGE_LEN).ok()?;
        (pages <= MAX_DENSE_PAGES).then_some(pages)
    }

    fn from_maps(
        extents: &BTreeMap<u64, Extent>,
        pending: &BTreeMap<u64, Delta>,
        logical_len: u64,
    ) -> Option<Self> {
        let page_count = Self::page_count(logical_len)?;
        let mut pages = vec![DENSE_ZERO; page_count];
        for (&start, extent) in extents {
            if !start.is_multiple_of(DENSE_PAGE_LEN) || !extent.end.is_multiple_of(DENSE_PAGE_LEN) {
                return None;
            }
            let start_page = usize::try_from(start / DENSE_PAGE_LEN).ok()?;
            let end_page = usize::try_from(extent.end / DENSE_PAGE_LEN).ok()?;
            if end_page > pages.len() {
                return None;
            }
            for (index, page) in pages[start_page..end_page].iter_mut().enumerate() {
                *page = extent.physical + index as u64 * DENSE_PAGE_LEN;
            }
        }
        let mut dense_pending = vec![DENSE_UNCHANGED; page_count];
        for (&start, delta) in pending {
            if !start.is_multiple_of(DENSE_PAGE_LEN) || !delta.end.is_multiple_of(DENSE_PAGE_LEN) {
                return None;
            }
            let start_page = usize::try_from(start / DENSE_PAGE_LEN).ok()?;
            let end_page = usize::try_from(delta.end / DENSE_PAGE_LEN).ok()?;
            if end_page > dense_pending.len() {
                return None;
            }
            for (index, page) in dense_pending[start_page..end_page].iter_mut().enumerate() {
                *page = delta.physical.map_or(DENSE_PENDING_ZERO, |physical| {
                    physical + index as u64 * DENSE_PAGE_LEN
                });
            }
        }
        Some(Self {
            pages,
            pending: dense_pending,
        })
    }

    fn supports_write(offset: u64, end: u64, final_len: u64) -> bool {
        offset.is_multiple_of(DENSE_PAGE_LEN)
            && end.is_multiple_of(DENSE_PAGE_LEN)
            && Self::page_count(final_len).is_some()
    }

    fn write(&mut self, start: u64, end: u64, physical: u64) {
        let start_page = (start / DENSE_PAGE_LEN) as usize;
        let end_page = (end / DENSE_PAGE_LEN) as usize;
        for (index, page) in self.pages[start_page..end_page].iter_mut().enumerate() {
            let physical = physical + index as u64 * DENSE_PAGE_LEN;
            *page = physical;
            self.pending[start_page + index] = physical;
        }
    }

    fn resize(&mut self, old_len: u64, new_len: u64) {
        let old_pages = (old_len / DENSE_PAGE_LEN) as usize;
        let new_pages = (new_len / DENSE_PAGE_LEN) as usize;
        if new_pages < old_pages {
            if self.pending.len() < old_pages {
                self.pending.resize(old_pages, DENSE_UNCHANGED);
            }
            self.pending[new_pages..old_pages].fill(DENSE_PENDING_ZERO);
            self.pages.truncate(new_pages);
        } else if new_pages > old_pages {
            self.pages.resize(new_pages, DENSE_ZERO);
            self.pending.resize(new_pages, DENSE_UNCHANGED);
        }
    }

    fn entries(&self) -> BTreeMap<u64, Extent> {
        let mut extents = BTreeMap::new();
        for (index, &physical) in self.pages.iter().enumerate() {
            if physical == DENSE_ZERO {
                continue;
            }
            let start = index as u64 * DENSE_PAGE_LEN;
            replace_extent(&mut extents, start, start + DENSE_PAGE_LEN, Some(physical));
        }
        extents
    }

    fn pending_entries(&self, page_count: usize) -> Vec<(u64, u64, Option<u64>)> {
        let mut entries: Vec<(u64, u64, Option<u64>)> = Vec::new();
        for (index, &value) in self.pending.iter().take(page_count).enumerate() {
            if value == DENSE_UNCHANGED {
                continue;
            }
            let start = index as u64 * DENSE_PAGE_LEN;
            let physical = (value != DENSE_PENDING_ZERO).then_some(value);
            if let Some((previous_start, previous_end, previous_physical)) = entries.last_mut() {
                let contiguous = match (*previous_physical, physical) {
                    (None, None) => true,
                    (Some(previous), Some(current)) => {
                        previous + (*previous_end - *previous_start) == current
                    }
                    _ => false,
                };
                if *previous_end == start && contiguous {
                    *previous_end += DENSE_PAGE_LEN;
                    continue;
                }
            }
            entries.push((start, start + DENSE_PAGE_LEN, physical));
        }
        entries
    }

    fn read_plan(&self, offset: u64, end: u64) -> io::Result<Vec<ReadSpan>> {
        let mut plan: Vec<ReadSpan> = Vec::new();
        let mut cursor = offset;
        while cursor < end {
            let page_index = usize::try_from(cursor / DENSE_PAGE_LEN)
                .map_err(|_| invalid_input("dense page index overflow"))?;
            let within_page = cursor % DENSE_PAGE_LEN;
            let span_end = end.min(checked_end(cursor - within_page, DENSE_PAGE_LEN)?);
            let source = match self.pages[page_index] {
                DENSE_ZERO => ReadSource::Zero,
                physical => ReadSource::File(physical + within_page),
            };
            let destination = usize::try_from(cursor - offset)
                .map_err(|_| invalid_input("read destination overflow"))?;
            let len = usize::try_from(span_end - cursor)
                .map_err(|_| invalid_input("read span overflow"))?;
            if let Some(previous) = plan.last_mut() {
                let merge = match (previous.source, source) {
                    (ReadSource::Zero, ReadSource::Zero) => true,
                    (ReadSource::File(previous_offset), ReadSource::File(current_offset)) => {
                        previous_offset + previous.len as u64 == current_offset
                    }
                    _ => false,
                };
                if previous.destination + previous.len == destination && merge {
                    previous.len += len;
                    cursor = span_end;
                    continue;
                }
            }
            plan.push(ReadSpan {
                destination,
                len,
                source,
            });
            cursor = span_end;
        }
        Ok(plan)
    }

    fn finish_commit(&mut self) {
        self.pending.truncate(self.pages.len());
        self.pending.fill(DENSE_UNCHANGED);
    }
}

fn split_extent(extents: &mut BTreeMap<u64, Extent>, at: u64) {
    let Some((&start, extent)) = extents.range(..=at).next_back() else {
        return;
    };
    let extent = *extent;
    if at <= start || at >= extent.end {
        return;
    }
    extents.get_mut(&start).unwrap().end = at;
    extents.insert(
        at,
        Extent {
            end: extent.end,
            physical: extent.physical + (at - start),
        },
    );
}

fn merge_extent(extents: &mut BTreeMap<u64, Extent>, mut start: u64) {
    if let Some((&previous_start, previous)) = extents.range(..start).next_back() {
        let previous = *previous;
        let current = extents[&start];
        if previous.end == start
            && previous.physical + (previous.end - previous_start) == current.physical
        {
            extents.get_mut(&previous_start).unwrap().end = current.end;
            extents.remove(&start);
            start = previous_start;
        }
    }
    let current = extents[&start];
    if let Some((&next_start, next)) = extents
        .range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
        .next()
    {
        let next = *next;
        if current.end == next_start && current.physical + (current.end - start) == next.physical {
            extents.get_mut(&start).unwrap().end = next.end;
            extents.remove(&next_start);
        }
    }
}

fn replace_extent(
    extents: &mut BTreeMap<u64, Extent>,
    start: u64,
    end: u64,
    physical: Option<u64>,
) {
    if start == end {
        return;
    }
    if extents.get(&start).is_some_and(|extent| extent.end == end) {
        if let Some(physical) = physical {
            extents.get_mut(&start).unwrap().physical = physical;
            merge_extent(extents, start);
        } else {
            extents.remove(&start);
        }
        return;
    }
    if let Some(physical) = physical
        && extents.range(start..end).next().is_none()
        && let Some((&previous_start, previous)) = extents.range(..start).next_back()
        && previous.end == start
        && previous.physical + (previous.end - previous_start) == physical
    {
        extents.get_mut(&previous_start).unwrap().end = end;
        merge_extent(extents, previous_start);
        return;
    }
    split_extent(extents, start);
    split_extent(extents, end);
    let covered = extents
        .range(start..end)
        .map(|(&key, _)| key)
        .collect::<Vec<_>>();
    for key in covered {
        extents.remove(&key);
    }
    if let Some(physical) = physical {
        extents.insert(start, Extent { end, physical });
        merge_extent(extents, start);
    }
}

fn split_delta(deltas: &mut BTreeMap<u64, Delta>, at: u64) {
    let Some((&start, delta)) = deltas.range(..=at).next_back() else {
        return;
    };
    let delta = *delta;
    if at <= start || at >= delta.end {
        return;
    }
    deltas.get_mut(&start).unwrap().end = at;
    deltas.insert(
        at,
        Delta {
            end: delta.end,
            physical: delta.physical.map(|physical| physical + (at - start)),
        },
    );
}

fn merge_delta(deltas: &mut BTreeMap<u64, Delta>, mut start: u64) {
    if let Some((&previous_start, previous)) = deltas.range(..start).next_back() {
        let previous = *previous;
        let current = deltas[&start];
        let contiguous = match (previous.physical, current.physical) {
            (None, None) => true,
            (Some(previous_physical), Some(current_physical)) => {
                previous_physical + (previous.end - previous_start) == current_physical
            }
            _ => false,
        };
        if previous.end == start && contiguous {
            deltas.get_mut(&previous_start).unwrap().end = current.end;
            deltas.remove(&start);
            start = previous_start;
        }
    }
    let current = deltas[&start];
    if let Some((&next_start, next)) = deltas
        .range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
        .next()
    {
        let next = *next;
        let contiguous = match (current.physical, next.physical) {
            (None, None) => true,
            (Some(current_physical), Some(next_physical)) => {
                current_physical + (current.end - start) == next_physical
            }
            _ => false,
        };
        if current.end == next_start && contiguous {
            deltas.get_mut(&start).unwrap().end = next.end;
            deltas.remove(&next_start);
        }
    }
}

fn replace_delta(deltas: &mut BTreeMap<u64, Delta>, start: u64, end: u64, physical: Option<u64>) {
    if start == end {
        return;
    }
    if deltas.get(&start).is_some_and(|delta| delta.end == end) {
        deltas.get_mut(&start).unwrap().physical = physical;
        merge_delta(deltas, start);
        return;
    }
    if deltas.range(start..end).next().is_none()
        && let Some((&previous_start, previous)) = deltas.range(..start).next_back()
        && previous.end == start
    {
        let contiguous = match (previous.physical, physical) {
            (None, None) => true,
            (Some(previous_physical), Some(physical)) => {
                previous_physical + (previous.end - previous_start) == physical
            }
            _ => false,
        };
        if contiguous {
            deltas.get_mut(&previous_start).unwrap().end = end;
            merge_delta(deltas, previous_start);
            return;
        }
    }
    split_delta(deltas, start);
    split_delta(deltas, end);
    let covered = deltas
        .range(start..end)
        .map(|(&key, _)| key)
        .collect::<Vec<_>>();
    for key in covered {
        deltas.remove(&key);
    }
    deltas.insert(start, Delta { end, physical });
    merge_delta(deltas, start);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadSource {
    Zero,
    File(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReadSpan {
    pub(super) destination: usize,
    pub(super) len: usize,
    pub(super) source: ReadSource,
}

#[derive(Debug)]
pub(super) struct Mutation {
    logical_start: u64,
    logical_end: u64,
    physical: u64,
    final_len: Option<u64>,
}

pub(super) struct PreparedMutation {
    pub(super) file_offset: u64,
    pub(super) data: IoBufs,
    pub(super) mutation: Mutation,
}

#[derive(Debug)]
struct Commit {
    generation: u64,
    append_offset: u64,
}

/// Durable per-blob candidate named by a multi-blob coordinator decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Candidate {
    pub(crate) base_generation: u64,
    pub(crate) root_offset: u64,
    pub(crate) prepared_root: [u8; ROOT_LEN],
    pub(crate) committed_root: [u8; ROOT_LEN],
}

pub(super) struct PreparedCommit {
    pub(super) manifest_offset: u64,
    /// Empty when the manifest follows the root header in the same root-slot write.
    pub(super) manifest: Vec<u8>,
    pub(super) root_offset: u64,
    /// Transaction-ineligible root and inline checkpoint written before the prepare barrier.
    pub(super) prepared_root: Vec<u8>,
    /// Root header published only after the prepare barrier succeeds.
    pub(super) committed_root: [u8; ROOT_LEN],
    materialized_previous: Option<Candidate>,
    commit: Commit,
}

impl PreparedCommit {
    /// Return the fixed-size identity needed to validate and install this candidate after a group
    /// decision. The checkpoint itself remains in the blob and is reached through the root.
    pub(super) fn candidate(&self) -> Candidate {
        Candidate {
            base_generation: self
                .commit
                .generation
                .checked_sub(1)
                .expect("prepared generations are nonzero"),
            root_offset: self.root_offset,
            prepared_root: self.prepared_root[..ROOT_LEN]
                .try_into()
                .expect("prepared roots contain a complete header"),
            committed_root: self.committed_root,
        }
    }

    /// Candidate from the preceding batch whose committed root crossed this preparation barrier.
    pub(super) const fn materialized_previous(&self) -> Option<&Candidate> {
        self.materialized_previous.as_ref()
    }

    pub(super) const fn set_materialized_previous(&mut self, candidate: Option<Candidate>) {
        self.materialized_previous = candidate;
    }
}

#[derive(Debug)]
pub(super) struct State {
    logical_len: u64,
    epoch_start: u64,
    append_offset: u64,
    generation: u64,
    extents: BTreeMap<u64, Extent>,
    pending: BTreeMap<u64, Delta>,
    dense: Option<DenseIndex>,
    deferred_batch_root: Option<Candidate>,
    dirty: bool,
    poisoned: bool,
    #[cfg(test)]
    tail_extensions: usize,
}

impl State {
    const fn empty(data_offset: u64) -> Self {
        Self {
            logical_len: 0,
            epoch_start: data_offset,
            append_offset: data_offset,
            generation: 0,
            extents: BTreeMap::new(),
            pending: BTreeMap::new(),
            dense: None,
            deferred_batch_root: None,
            dirty: false,
            poisoned: false,
            #[cfg(test)]
            tail_extensions: 0,
        }
    }

    pub(super) fn recover(file: &File, data_offset: u64) -> io::Result<Self> {
        if data_offset < ROOT_OFFSETS[1] + ROOT_SLOT_LEN {
            return Err(invalid_input(
                "V2 data offset does not reserve both root slots",
            ));
        }
        let raw_len = file.metadata()?.len();
        if raw_len < data_offset {
            return Err(invalid_data("atomic blob is shorter than its V2 header"));
        }

        let mut roots = Vec::new();
        let mut recovery_error = None;
        let mut invalid_root_slot = false;
        let mut slot_zero = [false; ROOT_OFFSETS.len()];
        let mut observed_later_generation = false;
        for (index, offset) in ROOT_OFFSETS.into_iter().enumerate() {
            let mut encoded = [0u8; ROOT_LEN];
            read_exact_at(file, offset, &mut encoded)?;
            if encoded.iter().all(|byte| *byte == 0) {
                slot_zero[index] = true;
                continue;
            }
            if let Some(root) = decode_root(&encoded) {
                if ROOT_OFFSETS[(root.generation as usize) & 1] != offset {
                    invalid_root_slot = true;
                    recovery_error.get_or_insert_with(|| {
                        invalid_data("atomic root generation is in the wrong slot")
                    });
                    continue;
                }
                observed_later_generation |= root.generation > 1;
                roots.push((root, offset, encoded));
            }
        }
        roots.sort_by_key(|(root, _, _)| std::cmp::Reverse(root.generation));

        let mut recovered = None;
        for (root, root_offset, encoded) in roots {
            match recover_root(file, data_offset, raw_len, root_offset, root) {
                Ok(candidate) => {
                    write_durable_at(file, root_offset, &encoded)?;
                    recovered = Some(candidate);
                    break;
                }
                Err(error) if invalid_candidate(&error) => {
                    recovery_error.get_or_insert(error);
                }
                Err(error) => return Err(error),
            }
        }
        let mut state = match recovered {
            Some(state) => state,
            None if slot_zero[0] && !observed_later_generation && !invalid_root_slot => {
                Self::empty(data_offset)
            }
            None => {
                return Err(recovery_error
                    .unwrap_or_else(|| invalid_data("atomic blob has no recoverable root")));
            }
        };
        if raw_len != state.append_offset {
            file.set_len(state.append_offset)?;
            file.sync_all()?;
        }
        state.dirty = false;
        Ok(state)
    }

    pub(super) const fn logical_len(&self) -> u64 {
        self.logical_len
    }

    pub(super) const fn deferred_batch_root(&self) -> Option<&Candidate> {
        self.deferred_batch_root.as_ref()
    }

    pub(super) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(super) const fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub(super) fn pending_payload(&self) -> io::Result<PendingPayload> {
        let len = self.append_offset - self.epoch_start;
        let entries = self.pending_entries();
        let ranges = entries
            .into_iter()
            .filter_map(|(start, end, physical)| physical.map(|physical| (physical, end - start)));
        let ranges = normalize_ranges(self.epoch_start, len, ranges)?;
        Ok((self.epoch_start, len, ranges))
    }

    pub(super) const fn poison(&mut self) {
        self.poisoned = true;
    }

    #[cfg(test)]
    fn extent_count(&self) -> usize {
        self.dense
            .as_ref()
            .map_or(self.extents.len(), |dense| dense.entries().len())
    }

    #[cfg(test)]
    fn pending_extent_count(&self) -> usize {
        self.dense.as_ref().map_or(self.pending.len(), |dense| {
            dense
                .pending_entries(DenseIndex::page_count(self.logical_len).unwrap_or(0))
                .len()
        })
    }

    #[cfg(test)]
    const fn tail_extension_count(&self) -> usize {
        self.tail_extensions
    }

    fn enable_dense(&mut self) {
        if self.dense.is_some() {
            return;
        }
        let Some(page_count) = DenseIndex::page_count(self.logical_len) else {
            return;
        };
        if self.extents.len() < DENSE_MIN_EXTENTS
            || page_count
                > self
                    .extents
                    .len()
                    .saturating_mul(DENSE_MAX_PAGES_PER_EXTENT)
        {
            return;
        }
        let Some(dense) = DenseIndex::from_maps(&self.extents, &self.pending, self.logical_len)
        else {
            return;
        };
        self.extents.clear();
        self.pending.clear();
        self.dense = Some(dense);
    }

    #[cfg(test)]
    fn enable_dense_for_test(&mut self) {
        let dense = DenseIndex::from_maps(&self.extents, &self.pending, self.logical_len).unwrap();
        self.extents.clear();
        self.pending.clear();
        self.dense = Some(dense);
    }

    fn disable_dense(&mut self) {
        let Some(dense) = self.dense.take() else {
            return;
        };
        self.extents = dense.entries();
        self.pending.clear();
        for (start, end, physical) in dense.pending_entries(dense.pending.len()) {
            replace_delta(&mut self.pending, start, end, physical);
        }
    }

    fn pending_entries(&self) -> Vec<(u64, u64, Option<u64>)> {
        if let Some(dense) = &self.dense {
            return dense.pending_entries(DenseIndex::page_count(self.logical_len).unwrap_or(0));
        }
        self.pending
            .iter()
            .filter_map(|(&start, delta)| {
                let end = delta.end.min(self.logical_len);
                (start < end).then_some((start, end, delta.physical))
            })
            .collect()
    }

    fn checkpoint_entries(&self) -> Vec<(u64, u64, Option<u64>)> {
        if let Some(dense) = &self.dense {
            return dense
                .entries()
                .into_iter()
                .map(|(start, extent)| (start, extent.end, Some(extent.physical)))
                .collect();
        }
        self.extents
            .iter()
            .map(|(&start, extent)| (start, extent.end, Some(extent.physical)))
            .collect()
    }

    fn reusable_physical(&self, start: u64, end: u64) -> Option<u64> {
        if let Some(dense) = &self.dense {
            let start_page = usize::try_from(start / DENSE_PAGE_LEN).ok()?;
            let end_page = usize::try_from(end / DENSE_PAGE_LEN).ok()?;
            let physical = *dense.pages.get(start_page)?;
            if physical == DENSE_ZERO || physical < self.epoch_start {
                return None;
            }
            for (index, &page) in dense.pages.get(start_page..end_page)?.iter().enumerate() {
                if page != physical + index as u64 * DENSE_PAGE_LEN {
                    return None;
                }
            }
            return (checked_end(physical, end - start).ok()? <= self.append_offset)
                .then_some(physical);
        }

        let (&extent_start, extent) = self.extents.range(..=start).next_back()?;
        if extent.end < end {
            return None;
        }
        let physical = extent.physical.checked_add(start - extent_start)?;
        (physical >= self.epoch_start
            && checked_end(physical, end - start).ok()? <= self.append_offset)
            .then_some(physical)
    }

    fn extend_sparse_tail(&mut self, start: u64, end: u64, physical: u64) -> bool {
        let Some(mut extent) = self.extents.last_entry() else {
            return false;
        };
        let extent_start = *extent.key();
        if extent.get().end != start
            || extent.get().physical.checked_add(start - extent_start) != Some(physical)
        {
            return false;
        }
        let Some(mut delta) = self.pending.last_entry() else {
            return false;
        };
        let delta_start = *delta.key();
        if delta.get().end != start
            || !delta.get().physical.is_some_and(|delta_physical| {
                delta_physical.checked_add(start - delta_start) == Some(physical)
            })
        {
            return false;
        }

        extent.get_mut().end = end;
        delta.get_mut().end = end;
        #[cfg(test)]
        {
            self.tail_extensions += 1;
        }
        true
    }

    pub(super) fn prepare_write(
        &mut self,
        offset: u64,
        data: IoBufs,
        final_len: Option<u64>,
    ) -> io::Result<Option<PreparedMutation>> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        let data_len = u64::try_from(data.len())
            .map_err(|_| invalid_input("atomic update length does not fit in u64"))?;
        if data_len == 0 {
            if let Some(final_len) = final_len {
                self.resize(final_len);
            }
            return Ok(None);
        }
        let logical_end = checked_end(offset, data_len)?;
        if let Some(final_len) = final_len
            && logical_end > final_len
        {
            return Err(invalid_input(
                "atomic update exceeds its final logical length",
            ));
        }
        let resulting_len = final_len.unwrap_or_else(|| self.logical_len.max(logical_end));
        let sparse_logical_tail = self.dense.is_none()
            && offset == self.logical_len
            && resulting_len == logical_end
            && self.extents.len() < DENSE_MIN_EXTENTS;
        if !sparse_logical_tail {
            if DenseIndex::supports_write(offset, logical_end, resulting_len) {
                self.enable_dense();
            } else {
                self.disable_dense();
            }
        }
        if self.dense.is_none()
            && (self.extents.len()
                > MAX_MANIFEST_ENTRIES.saturating_sub(SPARSE_MUTATION_ENTRY_RESERVE)
                || self.pending.len()
                    > MAX_MANIFEST_ENTRIES.saturating_sub(SPARSE_MUTATION_ENTRY_RESERVE))
        {
            return Err(resource_exhausted(
                "atomic sparse index requires synchronization or compaction",
            ));
        }
        let follows_sparse_tail = sparse_logical_tail
            || (self.dense.is_none()
                && self
                    .extents
                    .last_key_value()
                    .is_none_or(|(_, extent)| extent.end <= offset));
        let physical = if follows_sparse_tail {
            let physical = self.append_offset;
            self.append_offset = checked_end(self.append_offset, data_len)?;
            physical
        } else if let Some(physical) = self.reusable_physical(offset, logical_end) {
            physical
        } else {
            let physical = self.append_offset;
            self.append_offset = checked_end(self.append_offset, data_len)?;
            physical
        };
        Ok(Some(PreparedMutation {
            file_offset: physical,
            data,
            mutation: Mutation {
                logical_start: offset,
                logical_end,
                physical,
                final_len,
            },
        }))
    }

    pub(super) fn finish_mutation(&mut self, mutation: Mutation) {
        let final_len = mutation
            .final_len
            .unwrap_or_else(|| self.logical_len.max(mutation.logical_end));
        let extends_sparse_tail = self.dense.is_none()
            && mutation.logical_start == self.logical_len
            && final_len == mutation.logical_end;
        if extends_sparse_tail {
            self.logical_len = final_len;
        } else {
            self.resize(final_len);
        }
        if let Some(dense) = &mut self.dense {
            dense.write(
                mutation.logical_start,
                mutation.logical_end,
                mutation.physical,
            );
        } else if !self.extend_sparse_tail(
            mutation.logical_start,
            mutation.logical_end,
            mutation.physical,
        ) {
            replace_extent(
                &mut self.extents,
                mutation.logical_start,
                mutation.logical_end,
                Some(mutation.physical),
            );
            replace_delta(
                &mut self.pending,
                mutation.logical_start,
                mutation.logical_end,
                Some(mutation.physical),
            );
        }
        self.dirty = true;
    }

    pub(super) fn resize(&mut self, len: u64) {
        if len == self.logical_len {
            return;
        }
        if DenseIndex::page_count(len).is_none() {
            self.disable_dense();
        }
        if let Some(dense) = &mut self.dense {
            dense.resize(self.logical_len, len);
            self.logical_len = len;
            self.dirty = true;
            return;
        }
        if len < self.logical_len {
            replace_extent(&mut self.extents, len, self.logical_len, None);
            replace_delta(&mut self.pending, len, self.logical_len, None);
        }
        self.logical_len = len;
        self.dirty = true;
    }

    pub(super) fn read_plan(&self, offset: u64, len: usize) -> io::Result<Vec<ReadSpan>> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        let len_u64 = u64::try_from(len).map_err(|_| invalid_input("read length overflow"))?;
        let end = checked_end(offset, len_u64)?;
        if end > self.logical_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read exceeds atomic blob length",
            ));
        }

        if let Some(dense) = &self.dense {
            return dense.read_plan(offset, end);
        }

        let mut plan = Vec::new();
        let mut cursor = offset;
        while cursor < end {
            if let Some((&start, extent)) = self.extents.range(..=cursor).next_back()
                && extent.end > cursor
            {
                let span_end = extent.end.min(end);
                plan.push(ReadSpan {
                    destination: usize::try_from(cursor - offset)
                        .map_err(|_| invalid_input("read destination overflow"))?,
                    len: usize::try_from(span_end - cursor)
                        .map_err(|_| invalid_input("read span overflow"))?,
                    source: ReadSource::File(extent.physical + (cursor - start)),
                });
                cursor = span_end;
                continue;
            }
            let next = self
                .extents
                .range((
                    std::ops::Bound::Excluded(cursor),
                    std::ops::Bound::Unbounded,
                ))
                .next()
                .map_or(end, |(&start, _)| start.min(end));
            plan.push(ReadSpan {
                destination: usize::try_from(cursor - offset)
                    .map_err(|_| invalid_input("read destination overflow"))?,
                len: usize::try_from(next - cursor)
                    .map_err(|_| invalid_input("read span overflow"))?,
                source: ReadSource::Zero,
            });
            cursor = next;
        }
        Ok(plan)
    }

    pub(super) fn prepare_commit(&mut self) -> io::Result<Option<PreparedCommit>> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        if !self.dirty {
            return Ok(None);
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("atomic generation overflow"))?;
        let payload_end = self.append_offset;

        let entries = self.checkpoint_entries();
        let manifest = encode_manifest(
            ManifestFields {
                generation,
                logical_len: self.logical_len,
                payload_end,
            },
            &entries,
        )?;
        let manifest_len = u64::try_from(manifest.len())
            .map_err(|_| invalid_input("atomic manifest length overflow"))?;
        let root_offset = ROOT_OFFSETS[(generation as usize) & 1];
        let inline = manifest_len <= ROOT_SLOT_LEN - ROOT_LEN as u64;
        let manifest_offset = if inline {
            root_offset + ROOT_LEN as u64
        } else {
            payload_end
        };
        let commit_checksum = checksum(&[CHECKPOINT_DOMAIN, &manifest]);
        let committed_root = encode_root(
            ROOT_MAGIC,
            generation,
            manifest_offset,
            manifest_len,
            commit_checksum,
        );
        let mut prepared_root = encode_root(
            PREPARED_ROOT_MAGIC,
            generation,
            manifest_offset,
            manifest_len,
            commit_checksum,
        )
        .to_vec();
        let manifest = if inline {
            prepared_root.extend_from_slice(&manifest);
            Vec::new()
        } else {
            manifest
        };
        let append_offset = if inline {
            payload_end
        } else {
            checked_end(manifest_offset, manifest_len)?
        };
        self.append_offset = append_offset;

        Ok(Some(PreparedCommit {
            manifest_offset,
            manifest,
            root_offset,
            prepared_root,
            committed_root,
            materialized_previous: None,
            commit: Commit {
                generation,
                append_offset,
            },
        }))
    }

    fn apply_commit(&mut self, prepared: PreparedCommit) {
        self.generation = prepared.commit.generation;
        self.append_offset = prepared.commit.append_offset;
        self.epoch_start = prepared.commit.append_offset;
        if let Some(dense) = &mut self.dense {
            dense.finish_commit();
        } else {
            self.pending.clear();
        }
        self.dirty = false;
    }

    pub(super) fn finish_commit(&mut self, prepared: PreparedCommit) {
        self.apply_commit(prepared);
        self.deferred_batch_root = None;
    }

    pub(super) fn finish_batch_commit(&mut self, prepared: PreparedCommit) -> Candidate {
        let candidate = prepared.candidate();
        self.apply_commit(prepared);
        self.deferred_batch_root = Some(candidate.clone());
        candidate
    }
}

fn encode_root(
    magic: &[u8; 8],
    generation: u64,
    manifest_offset: u64,
    manifest_len: u64,
    commit_checksum: u32,
) -> [u8; ROOT_LEN] {
    let mut root = [0u8; ROOT_LEN];
    root[..8].copy_from_slice(magic);
    root[8..16].copy_from_slice(&generation.to_be_bytes());
    root[16..24].copy_from_slice(&manifest_offset.to_be_bytes());
    root[24..32].copy_from_slice(&manifest_len.to_be_bytes());
    root[32..36].copy_from_slice(&commit_checksum.to_be_bytes());
    let root_checksum = checksum(&[ROOT_DOMAIN, &root[..ROOT_BODY_LEN]]);
    root[36..40].copy_from_slice(&root_checksum.to_be_bytes());
    root
}

#[derive(Clone, Copy, Debug)]
struct Root {
    generation: u64,
    manifest_offset: u64,
    manifest_len: u64,
    commit_checksum: u32,
}

fn decode_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    if encoded.iter().all(|byte| *byte == 0) || &encoded[..8] != ROOT_MAGIC {
        return None;
    }
    let root_checksum = u32::from_be_bytes(encoded[36..40].try_into().unwrap());
    if root_checksum != checksum(&[ROOT_DOMAIN, &encoded[..ROOT_BODY_LEN]]) {
        return None;
    }
    let generation = u64::from_be_bytes(encoded[8..16].try_into().unwrap());
    let manifest_offset = u64::from_be_bytes(encoded[16..24].try_into().unwrap());
    let manifest_len = u64::from_be_bytes(encoded[24..32].try_into().unwrap());
    let commit_checksum = u32::from_be_bytes(encoded[32..36].try_into().unwrap());
    (generation != 0).then_some(Root {
        generation,
        manifest_offset,
        manifest_len,
        commit_checksum,
    })
}

fn decode_prepared_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    if encoded.iter().all(|byte| *byte == 0) || &encoded[..8] != PREPARED_ROOT_MAGIC {
        return None;
    }
    let root_checksum = u32::from_be_bytes(encoded[36..40].try_into().unwrap());
    if root_checksum != checksum(&[ROOT_DOMAIN, &encoded[..ROOT_BODY_LEN]]) {
        return None;
    }
    let generation = u64::from_be_bytes(encoded[8..16].try_into().unwrap());
    let manifest_offset = u64::from_be_bytes(encoded[16..24].try_into().unwrap());
    let manifest_len = u64::from_be_bytes(encoded[24..32].try_into().unwrap());
    let commit_checksum = u32::from_be_bytes(encoded[32..36].try_into().unwrap());
    (generation != 0).then_some(Root {
        generation,
        manifest_offset,
        manifest_len,
        commit_checksum,
    })
}

struct ManifestFields {
    generation: u64,
    logical_len: u64,
    payload_end: u64,
}

fn encode_manifest(
    fields: ManifestFields,
    entries: &[(u64, u64, Option<u64>)],
) -> io::Result<Vec<u8>> {
    if entries.len() > MAX_MANIFEST_ENTRIES {
        return Err(invalid_input("atomic manifest has too many entries"));
    }
    let entry_bytes = entries
        .len()
        .checked_mul(MANIFEST_ENTRY_LEN)
        .ok_or_else(|| invalid_input("atomic manifest entry length overflow"))?;
    let mut encoded = vec![0u8; MANIFEST_HEADER_LEN + entry_bytes];
    encoded[..8].copy_from_slice(MANIFEST_MAGIC);
    encoded[8..16].copy_from_slice(&fields.generation.to_be_bytes());
    encoded[16..24].copy_from_slice(&fields.logical_len.to_be_bytes());
    encoded[24..32].copy_from_slice(&fields.payload_end.to_be_bytes());
    encoded[32..40].copy_from_slice(&(entries.len() as u64).to_be_bytes());
    for (index, &(start, end, physical)) in entries.iter().enumerate() {
        let physical = physical
            .ok_or_else(|| invalid_input("atomic checkpoint entries require a physical source"))?;
        let offset = MANIFEST_HEADER_LEN + index * MANIFEST_ENTRY_LEN;
        encoded[offset..offset + 8].copy_from_slice(&start.to_be_bytes());
        encoded[offset + 8..offset + 16].copy_from_slice(&(end - start).to_be_bytes());
        encoded[offset + 16..offset + 24].copy_from_slice(&physical.to_be_bytes());
    }
    Ok(encoded)
}

#[derive(Debug)]
struct Manifest {
    generation: u64,
    logical_len: u64,
    payload_end: u64,
    entries: Vec<(u64, u64, Option<u64>)>,
}

fn decode_manifest(encoded: &[u8]) -> io::Result<Manifest> {
    if encoded.len() < MANIFEST_HEADER_LEN
        || encoded.len() > MAX_MANIFEST_LEN
        || &encoded[..8] != MANIFEST_MAGIC
    {
        return Err(invalid_data("invalid atomic manifest header"));
    }
    let entry_count = u64::from_be_bytes(encoded[32..40].try_into().unwrap());
    let entry_count = usize::try_from(entry_count)
        .map_err(|_| invalid_data("atomic manifest entry count overflow"))?;
    if entry_count > MAX_MANIFEST_ENTRIES {
        return Err(invalid_data("atomic manifest has too many entries"));
    }
    let expected = MANIFEST_HEADER_LEN
        .checked_add(
            entry_count
                .checked_mul(MANIFEST_ENTRY_LEN)
                .ok_or_else(|| invalid_data("atomic manifest length overflow"))?,
        )
        .ok_or_else(|| invalid_data("atomic manifest length overflow"))?;
    if encoded.len() != expected {
        return Err(invalid_data("atomic manifest has the wrong length"));
    }

    let mut entries = Vec::with_capacity(entry_count);
    let mut previous_end = 0;
    for index in 0..entry_count {
        let offset = MANIFEST_HEADER_LEN + index * MANIFEST_ENTRY_LEN;
        let start = u64::from_be_bytes(encoded[offset..offset + 8].try_into().unwrap());
        let len = u64::from_be_bytes(encoded[offset + 8..offset + 16].try_into().unwrap());
        let end = checked_end(start, len).map_err(|_| invalid_data("manifest range overflow"))?;
        let physical = u64::from_be_bytes(encoded[offset + 16..offset + 24].try_into().unwrap());
        if len == 0 || start < previous_end {
            return Err(invalid_data("atomic manifest entries overlap or are empty"));
        }
        if physical == u64::MAX {
            return Err(invalid_data(
                "atomic checkpoint entry has no physical source",
            ));
        }
        previous_end = end;
        entries.push((start, end, Some(physical)));
    }

    Ok(Manifest {
        generation: u64::from_be_bytes(encoded[8..16].try_into().unwrap()),
        logical_len: u64::from_be_bytes(encoded[16..24].try_into().unwrap()),
        payload_end: u64::from_be_bytes(encoded[24..32].try_into().unwrap()),
        entries,
    })
}

fn recover_root(
    file: &File,
    data_offset: u64,
    raw_len: u64,
    root_offset: u64,
    root: Root,
) -> io::Result<State> {
    if ROOT_OFFSETS[(root.generation as usize) & 1] != root_offset {
        return Err(invalid_data("atomic root generation is in the wrong slot"));
    }
    if root.manifest_len > MAX_MANIFEST_LEN as u64 {
        return Err(invalid_data("atomic manifest is too large"));
    }
    let manifest_end = root
        .manifest_offset
        .checked_add(root.manifest_len)
        .ok_or_else(|| invalid_data("atomic root range overflows"))?;
    let inline_offset = root_offset + ROOT_LEN as u64;
    let inline = root.manifest_offset == inline_offset;
    if inline {
        if manifest_end > root_offset + ROOT_SLOT_LEN {
            return Err(invalid_data(
                "atomic inline checkpoint exceeds its root slot",
            ));
        }
    } else {
        if root.manifest_len <= ROOT_SLOT_LEN - ROOT_LEN as u64 {
            return Err(invalid_data("small atomic checkpoint is not inline"));
        }
        if root.manifest_offset < data_offset || manifest_end > raw_len {
            return Err(invalid_data("atomic root points outside the blob"));
        }
    }

    let manifest_len = usize::try_from(root.manifest_len)
        .map_err(|_| invalid_data("atomic manifest is too large"))?;
    let mut encoded = vec![0u8; manifest_len];
    read_exact_at(file, root.manifest_offset, &mut encoded)?;
    if checksum(&[CHECKPOINT_DOMAIN, &encoded]) != root.commit_checksum {
        return Err(invalid_data("atomic manifest checksum mismatch"));
    }
    let manifest = decode_manifest(&encoded)?;
    if manifest.generation != root.generation {
        return Err(invalid_data("atomic checkpoint generation mismatch"));
    }
    if manifest.payload_end < data_offset || manifest.payload_end > raw_len {
        return Err(invalid_data("atomic payload end is invalid"));
    }
    if !inline && manifest.payload_end != root.manifest_offset {
        return Err(invalid_data(
            "external atomic checkpoint is not after its payload",
        ));
    }

    let mut physical_ranges = Vec::with_capacity(manifest.entries.len());
    for &(start, end, physical) in &manifest.entries {
        if end > manifest.logical_len {
            return Err(invalid_data(
                "atomic checkpoint entry exceeds logical length",
            ));
        }
        let physical = physical
            .ok_or_else(|| invalid_data("atomic checkpoint entry has no physical source"))?;
        let physical_end = physical
            .checked_add(end - start)
            .ok_or_else(|| invalid_data("atomic checkpoint source overflows"))?;
        if physical < data_offset || physical_end > manifest.payload_end {
            return Err(invalid_data(
                "atomic checkpoint source is outside the payload log",
            ));
        }
        physical_ranges.push((physical, physical_end - physical));
    }
    normalize_ranges(
        data_offset,
        manifest.payload_end - data_offset,
        physical_ranges,
    )
    .map_err(|_| invalid_data("atomic checkpoint sources overlap or are out of bounds"))?;

    let mut state = State::empty(data_offset);
    for &(start, end, physical) in &manifest.entries {
        replace_extent(&mut state.extents, start, end, physical);
    }
    state.logical_len = manifest.logical_len;
    state.generation = manifest.generation;
    state.append_offset = if inline {
        manifest.payload_end
    } else {
        manifest_end
    };
    state.epoch_start = state.append_offset;
    Ok(state)
}

/// Write a small publication record and make that write durable before returning.
pub(super) fn write_durable_at(file: &File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    let tracked_write = (offset, bytes.len());

    #[cfg(target_os = "linux")]
    {
        let mut offset = offset;
        let mut bytes = bytes;
        while !bytes.is_empty() {
            let offset_i64 = i64::try_from(offset)
                .map_err(|_| invalid_input("durable write offset exceeds off_t"))?;
            let iovec = libc::iovec {
                iov_base: bytes.as_ptr().cast_mut().cast(),
                iov_len: bytes.len(),
            };
            // SAFETY: `iovec` references readable `bytes` for the duration of the syscall, the file
            // descriptor remains open, and the checked offset is representable by the ABI.
            let written = unsafe {
                libc::pwritev2(
                    file.as_raw_fd(),
                    &raw const iovec,
                    1,
                    offset_i64,
                    libc::RWF_DSYNC,
                )
            };
            if written < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if written == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "durable publication write made no progress",
                ));
            }
            let written = written as usize;
            offset = checked_end(offset, written as u64)?;
            bytes = &bytes[written..];
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        file.write_all_at(bytes, offset)?;
        file.sync_all()?;
    }

    #[cfg(test)]
    TRACKED_DURABLE_WRITES.with(|tracked| {
        if let Some(writes) = tracked.borrow_mut().as_mut() {
            writes.push(tracked_write);
        }
    });
    Ok(())
}

/// Validate and install a transaction-bound candidate without reading payload bytes.
///
/// A prepared root is deliberately invisible to ordinary blob recovery. A durable coordinator
/// decision supplies the exact prepared and committed headers, allowing replay to verify the
/// candidate's self-contained checkpoint and publish it idempotently.
pub(super) fn install_candidate(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
) -> io::Result<()> {
    let committed = decode_root(&candidate.committed_root)
        .ok_or_else(|| invalid_data("transaction candidate has an invalid committed root"))?;
    let prepared = decode_prepared_root(&candidate.prepared_root)
        .ok_or_else(|| invalid_data("transaction candidate has an invalid prepared root"))?;
    if committed.generation
        != candidate
            .base_generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("transaction candidate generation overflow"))?
        || committed.generation != prepared.generation
        || committed.manifest_offset != prepared.manifest_offset
        || committed.manifest_len != prepared.manifest_len
        || committed.commit_checksum != prepared.commit_checksum
        || ROOT_OFFSETS[(committed.generation as usize) & 1] != candidate.root_offset
    {
        return Err(invalid_data("transaction candidate roots do not match"));
    }

    let raw_len = file.metadata()?.len();
    if raw_len < data_offset {
        return Err(invalid_data(
            "transaction candidate blob is shorter than its header",
        ));
    }

    let mut installed = [0u8; ROOT_LEN];
    read_exact_at(file, candidate.root_offset, &mut installed)?;
    // The durable coordinator descriptor is the authority for this exact self-contained
    // candidate. Its prior base root may already have been reused while preparing a later batch,
    // so installation must not depend on finding that base in the other root slot.
    if installed == candidate.committed_root {
        recover_root(file, data_offset, raw_len, candidate.root_offset, committed)?;
        return write_durable_at(file, candidate.root_offset, &candidate.committed_root);
    }
    let torn_transition = installed
        .iter()
        .zip(
            candidate
                .prepared_root
                .iter()
                .zip(&candidate.committed_root),
        )
        .all(|(installed, (prepared, committed))| installed == prepared || installed == committed);
    if !torn_transition {
        return Err(invalid_data(
            "transaction candidate root is not a recoverable publication transition",
        ));
    }

    recover_root(file, data_offset, raw_len, candidate.root_offset, committed)?;
    write_durable_at(file, candidate.root_offset, &candidate.committed_root)
}

fn creation_path(live_path: &Path) -> io::Result<std::path::PathBuf> {
    let file_name = live_path
        .file_name()
        .ok_or_else(|| invalid_input("atomic blob has no file name"))?;
    let mut staging_name = OsString::from(CREATION_PREFIX);
    staging_name.push(file_name);
    Ok(live_path.with_file_name(staging_name))
}

pub(super) fn is_creation_file_name(name: &OsStr) -> bool {
    name.as_encoded_bytes()
        .starts_with(CREATION_PREFIX.as_bytes())
}

/// Create and durably initialize a new V2 live inode.
///
/// The live name is published only after its complete header is durable. A crash can therefore
/// leave either no live name or a parseable V2 file, without broadening legacy torn-header
/// recovery to cover the larger V2 header region.
pub(super) fn create_live(
    root: &Path,
    _partition: &str,
    _name: &[u8],
    live_path: &Path,
    region: &[u8],
) -> io::Result<File> {
    let creation_path = creation_path(live_path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&creation_path)?;
    file.write_all(region)?;
    file.sync_all()?;
    fs::rename(&creation_path, live_path)?;
    let parent = live_path
        .parent()
        .ok_or_else(|| invalid_input("atomic blob has no parent directory"))?;
    File::open(parent)?.sync_all()?;
    File::open(root)?.sync_all()?;
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

/// Discard a V2 creation inode left before publication.
pub(super) fn discard(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
    let live_path = root.join(partition).join(hex(name));
    let creation_path = creation_path(&live_path)?;
    match fs::remove_file(creation_path) {
        Ok(()) => File::open(
            live_path
                .parent()
                .ok_or_else(|| invalid_input("atomic blob has no parent directory"))?,
        )?
        .sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// V2 state is contained in the live inode, so partition removal needs no sidecar cleanup.
pub(super) const fn discard_partition(_root: &Path, _partition: &str) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    const DATA_OFFSET: u64 = 12288;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir()
            .join(format!(
                "commonware-uno-log-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ))
            .with_extension(label)
    }

    fn test_file() -> (std::path::PathBuf, File) {
        let path = test_path("blob");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.set_len(DATA_OFFSET).unwrap();
        file.sync_all().unwrap();
        (path, file)
    }

    fn file_bytes(file: &File) -> Vec<u8> {
        let mut bytes = vec![0; file.metadata().unwrap().len() as usize];
        read_exact_at(file, 0, &mut bytes).unwrap();
        bytes
    }

    fn append(file: &File, state: &mut State, offset: u64, bytes: &[u8], len: u64) {
        let prepared = state
            .prepare_write(offset, IoBufs::from(bytes.to_vec()), Some(len))
            .unwrap()
            .unwrap();
        file.write_all_at(
            prepared.data.as_single().unwrap().as_ref(),
            prepared.file_offset,
        )
        .unwrap();
        state.finish_mutation(prepared.mutation);
    }

    fn write_prepared(file: &File, prepared: &PreparedCommit) {
        if !prepared.manifest.is_empty() {
            file.write_all_at(&prepared.manifest, prepared.manifest_offset)
                .unwrap();
        }
        file.write_all_at(&prepared.prepared_root, prepared.root_offset)
            .unwrap();
    }

    fn prepare_commit(file: &File, state: &mut State) -> PreparedCommit {
        let (payload_start, payload_len, payload_ranges) = state.pending_payload().unwrap();
        reclaim_shadowed_payload(file, payload_start, payload_len, &payload_ranges).unwrap();
        state.prepare_commit().unwrap().unwrap()
    }

    fn finish_prepared(file: &File, state: &mut State, prepared: PreparedCommit) {
        write_prepared(file, &prepared);
        file.sync_all().unwrap();
        file.write_all_at(&prepared.committed_root, prepared.root_offset)
            .unwrap();
        file.sync_all().unwrap();
        state.finish_commit(prepared);
    }

    fn commit(file: &File, state: &mut State) {
        let prepared = prepare_commit(file, state);
        finish_prepared(file, state, prepared);
    }

    fn read(file: &File, state: &State) -> Vec<u8> {
        let mut out = vec![0u8; state.logical_len as usize];
        for span in state.read_plan(0, out.len()).unwrap() {
            match span.source {
                ReadSource::Zero => out[span.destination..span.destination + span.len].fill(0),
                ReadSource::File(offset) => read_exact_at(
                    file,
                    offset,
                    &mut out[span.destination..span.destination + span.len],
                )
                .unwrap(),
            }
        }
        out
    }

    #[test]
    fn repeated_overwrite_condenses_live_extents() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        for value in 0..1000u32 {
            append(&file, &mut state, 0, &value.to_be_bytes(), 4);
        }
        assert_eq!(state.extent_count(), 1);
        assert_eq!(state.pending_extent_count(), 1);
        assert_eq!(read(&file, &state), 999u32.to_be_bytes());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn contiguous_appends_coalesce_into_one_extent() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"one", 3);
        append(&file, &mut state, 3, b"two", 6);
        append(&file, &mut state, 6, b"three", 11);

        assert_eq!(state.extent_count(), 1);
        assert_eq!(state.pending_extent_count(), 1);
        assert_eq!(state.tail_extension_count(), 2);
        assert_eq!(state.append_offset, DATA_OFFSET + 11);
        assert_eq!(read(&file, &state), b"onetwothree");

        commit(&file, &mut state);
        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"onetwothree");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recovery_does_not_hash_payload_bytes() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        let payload = vec![7; 4 * 1024 * 1024];
        append(&file, &mut state, 0, &payload, payload.len() as u64);
        commit(&file, &mut state);

        let ((recovered, durable_writes), read_bytes) = track_read_bytes(|| {
            track_durable_writes(|| State::recover(&file, DATA_OFFSET).unwrap())
        });

        assert_eq!(recovered.logical_len(), payload.len() as u64);
        assert_eq!(
            durable_writes,
            vec![(ROOT_OFFSETS[(recovered.generation as usize) & 1], ROOT_LEN)]
        );
        assert_eq!(
            read_bytes,
            (ROOT_LEN * 2 + MANIFEST_HEADER_LEN + MANIFEST_ENTRY_LEN) as u64
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn prepared_candidate_requires_coordinator_installation() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"old", 3);
        commit(&file, &mut state);

        append(&file, &mut state, 0, b"new", 3);
        let prepared = prepare_commit(&file, &mut state);
        write_prepared(&file, &prepared);
        file.sync_all().unwrap();

        let undecided_path = test_path("undecided");
        fs::copy(&path, &undecided_path).unwrap();
        let undecided = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&undecided_path)
            .unwrap();
        let recovered = State::recover(&undecided, DATA_OFFSET).unwrap();
        assert_eq!(read(&undecided, &recovered), b"old");

        let candidate = prepared.candidate();
        install_candidate(&file, DATA_OFFSET, &candidate).unwrap();
        state.finish_commit(prepared);
        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"new");

        let (_, durable_writes) = track_durable_writes(|| {
            install_candidate(&file, DATA_OFFSET, &candidate).unwrap();
        });
        assert_eq!(durable_writes, vec![(candidate.root_offset, ROOT_LEN)]);

        fs::remove_file(undecided_path).unwrap();
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn every_torn_candidate_installation_is_repaired_from_coordinator_identity() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"new", 3);
        let prepared = prepare_commit(&file, &mut state);
        write_prepared(&file, &prepared);
        file.sync_all().unwrap();

        let candidate = prepared.candidate();
        let differing = candidate
            .prepared_root
            .iter()
            .zip(&candidate.committed_root)
            .enumerate()
            .filter_map(|(index, (prepared, committed))| (prepared != committed).then_some(index))
            .collect::<Vec<_>>();
        assert!(!differing.is_empty());
        assert!(differing.len() < usize::BITS as usize);
        let source = file_bytes(&file);

        for mask in 0..1usize << differing.len() {
            let case_path = test_path("candidate-install");
            fs::write(&case_path, &source).unwrap();
            let case = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&case_path)
                .unwrap();
            let mut torn = candidate.prepared_root;
            for (bit, &index) in differing.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    torn[index] = candidate.committed_root[index];
                }
            }
            case.write_all_at(&torn, candidate.root_offset).unwrap();
            case.sync_all().unwrap();

            install_candidate(&case, DATA_OFFSET, &candidate).unwrap();
            let recovered = State::recover(&case, DATA_OFFSET).unwrap();
            assert_eq!(read(&case, &recovered), b"new", "subset {mask:#b}");
            fs::remove_file(case_path).unwrap();
        }

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn coordinator_candidate_survives_next_prepare_reusing_base_slot() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"old", 3);
        commit(&file, &mut state);

        append(&file, &mut state, 0, b"new", 3);
        let prepared = prepare_commit(&file, &mut state);
        write_prepared(&file, &prepared);
        file.sync_all().unwrap();

        let candidate = prepared.candidate();
        let base_offset = ROOT_OFFSETS[(candidate.base_generation as usize) & 1];
        assert_ne!(base_offset, candidate.root_offset);
        let differing = candidate
            .prepared_root
            .iter()
            .zip(&candidate.committed_root)
            .enumerate()
            .filter_map(|(index, (prepared, committed))| (prepared != committed).then_some(index))
            .collect::<Vec<_>>();
        assert!(!differing.is_empty());
        assert!(differing.len() < usize::BITS as usize);
        let source = file_bytes(&file);
        let committed = decode_root(&candidate.committed_root).unwrap();
        let next_prepared_root = encode_root(
            PREPARED_ROOT_MAGIC,
            committed.generation.checked_add(1).unwrap(),
            committed.manifest_offset,
            committed.manifest_len,
            committed.commit_checksum,
        );

        for mask in 0..1usize << differing.len() {
            let case_path = test_path("reused-base-root");
            fs::write(&case_path, &source).unwrap();
            let case = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&case_path)
                .unwrap();
            let mut torn = candidate.prepared_root;
            for (bit, &index) in differing.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    torn[index] = candidate.committed_root[index];
                }
            }
            case.write_all_at(&torn, candidate.root_offset).unwrap();
            case.write_all_at(&next_prepared_root, base_offset)
                .unwrap();
            case.sync_all().unwrap();

            install_candidate(&case, DATA_OFFSET, &candidate).unwrap();
            let recovered = State::recover(&case, DATA_OFFSET).unwrap();
            assert_eq!(read(&case, &recovered), b"new", "subset {mask:#b}");
            fs::remove_file(case_path).unwrap();
        }

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn inline_checkpoints_keep_sync_epochs_physically_contiguous() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);

        append(&file, &mut state, 0, &[1; 4096], 4096);
        commit(&file, &mut state);
        assert_eq!(state.append_offset, DATA_OFFSET + 4096);
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 4096);

        append(&file, &mut state, 4096, &[2; 4096], 8192);
        commit(&file, &mut state);
        assert_eq!(state.extent_count(), 1);
        assert_eq!(state.append_offset, DATA_OFFSET + 8192);
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 8192);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(recovered.extent_count(), 1);
        assert_eq!(
            read(&file, &recovered),
            [vec![1; 4096], vec![2; 4096]].concat()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn external_checkpoints_are_self_contained_fallback_roots() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        let logical_len = 336;
        for offset in (0..logical_len - 2).step_by(2) {
            append(&file, &mut state, offset, &[1], logical_len);
        }
        let boundary = prepare_commit(&file, &mut state);
        assert!(boundary.manifest.is_empty());
        assert!(boundary.prepared_root.len() <= ROOT_SLOT_LEN as usize);

        append(&file, &mut state, logical_len - 2, &[1], logical_len);

        let first = prepare_commit(&file, &mut state);
        assert!(!first.manifest.is_empty());
        finish_prepared(&file, &mut state, first);

        append(&file, &mut state, 0, &[2], logical_len);
        let second = prepare_commit(&file, &mut state);
        assert!(!second.manifest.is_empty());
        finish_prepared(&file, &mut state, second);
        let second_end = state.append_offset;
        let expected = read(&file, &state);

        append(&file, &mut state, 2, &[3], logical_len);
        let third = prepare_commit(&file, &mut state);
        assert!(!third.manifest.is_empty());
        write_prepared(&file, &third);
        file.sync_all().unwrap();
        file.write_all_at(&third.committed_root, third.root_offset)
            .unwrap();
        file.sync_all().unwrap();
        file.write_all_at(b"X", third.manifest_offset).unwrap();
        file.sync_all().unwrap();

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), expected);
        assert_eq!(file.metadata().unwrap().len(), second_end);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn oversized_manifest_entry_count_is_rejected_before_allocation() {
        let mut encoded = [0u8; MANIFEST_HEADER_LEN];
        encoded[..8].copy_from_slice(MANIFEST_MAGIC);
        encoded[32..40].copy_from_slice(&((MAX_MANIFEST_ENTRIES as u64) + 1).to_be_bytes());
        assert!(decode_manifest(&encoded).is_err());
    }

    #[test]
    fn operational_io_errors_do_not_invalidate_a_root_candidate() {
        assert!(invalid_candidate(&invalid_data("checksum mismatch")));
        assert!(invalid_candidate(&io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "torn record",
        )));
        assert!(!invalid_candidate(&io::Error::from_raw_os_error(libc::EIO)));
        assert!(!invalid_candidate(&io::Error::from_raw_os_error(
            libc::EINTR
        )));
    }

    #[test]
    fn pending_payload_contains_only_canonical_live_ranges() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, &[1; 4096], 4096);
        append(&file, &mut state, 0, &[2; 8192], 8192);

        let (payload_start, payload_len, ranges) = state.pending_payload().unwrap();
        assert_eq!(payload_start, DATA_OFFSET);
        assert_eq!(payload_len, 12288);
        assert_eq!(ranges, vec![(DATA_OFFSET + 4096, 8192)]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn repeated_epoch_page_writes_reuse_speculative_space() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        for value in 0..100u8 {
            append(&file, &mut state, 0, &[value; 4096], 4096);
        }

        assert_eq!(state.append_offset, DATA_OFFSET + 4096);
        assert_eq!(read(&file, &state), vec![99; 4096]);
        commit(&file, &mut state);
        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), vec![99; 4096]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn dense_pages_preserve_aligned_visibility_and_sparse_fallback() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 4096, &[1; 4096], 8192);
        state.enable_dense_for_test();
        assert!(state.dense.is_some());
        assert_eq!(read(&file, &state), [vec![0; 4096], vec![1; 4096]].concat());

        append(&file, &mut state, 1, &[2; 2], 8192);
        assert!(state.dense.is_none());
        let visible = read(&file, &state);
        assert_eq!(&visible[..4], &[0, 2, 2, 0]);
        assert_eq!(&visible[4096..], &[1; 4096]);
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), visible);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn dense_shrink_then_grow_keeps_truncated_pages_zero() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, &[1; 8192], 8192);
        state.enable_dense_for_test();
        assert!(state.dense.is_some());
        state.resize(4096);
        state.resize(8192);
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(
            read(&file, &recovered),
            [vec![1; 4096], vec![0; 4096]].concat()
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn dense_shrink_then_sparse_regrow_keeps_truncated_bytes_zero() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, &[1; 8192], 8192);
        state.enable_dense_for_test();
        commit(&file, &mut state);

        state.resize(4096);
        append(&file, &mut state, 4097, &[2], 8192);
        assert!(state.dense.is_none());
        let expected = [vec![1; 4096], vec![0, 2], vec![0; 4094]].concat();
        assert_eq!(read(&file, &state), expected);
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), expected);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn fragmented_aligned_pages_materialize_dense_index() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        let logical_len = (DENSE_MIN_EXTENTS as u64 * 2 + 1) * DENSE_PAGE_LEN;
        for page in 0..=DENSE_MIN_EXTENTS {
            append(
                &file,
                &mut state,
                page as u64 * 2 * DENSE_PAGE_LEN,
                &[page as u8; DENSE_PAGE_LEN as usize],
                logical_len,
            );
        }

        assert!(state.dense.is_some());
        assert_eq!(state.pending_extent_count(), DENSE_MIN_EXTENTS + 1);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recovery_ignores_shadowed_payload_bytes() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, &[1; 4096], 4096);
        append(&file, &mut state, 0, &[2; 8192], 8192);
        commit(&file, &mut state);

        file.write_all_at(&[3; 4096], DATA_OFFSET).unwrap();
        file.sync_all().unwrap();
        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), vec![2; 8192]);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recovery_uses_latest_complete_root() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"old", 3);
        commit(&file, &mut state);
        append(&file, &mut state, 0, b"new value", 9);
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"new value");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recovery_does_not_replace_established_corrupt_roots_with_empty_state() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"old", 3);
        commit(&file, &mut state);
        append(&file, &mut state, 0, b"new", 3);
        commit(&file, &mut state);
        let raw_len = file.metadata().unwrap().len();

        for offset in ROOT_OFFSETS {
            file.write_all_at(&[0], offset).unwrap();
        }
        file.sync_all().unwrap();

        assert!(State::recover(&file, DATA_OFFSET).is_err());
        assert_eq!(file.metadata().unwrap().len(), raw_len);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn torn_first_root_falls_back_to_implicit_empty_state() {
        let (path, file) = test_file();
        file.write_all_at(b"partial", DATA_OFFSET).unwrap();
        file.write_all_at(b"torn", ROOT_OFFSETS[1]).unwrap();
        file.sync_all().unwrap();

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(recovered.logical_len(), 0);
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn complete_first_root_with_torn_checkpoint_falls_back_to_empty() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"new", 3);
        let prepared = prepare_commit(&file, &mut state);
        assert!(prepared.manifest.is_empty());
        file.write_all_at(&prepared.committed_root, prepared.root_offset)
            .unwrap();
        file.sync_all().unwrap();

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(recovered.logical_len(), 0);
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn zero_second_slot_does_not_hide_invalid_established_state() {
        let (path, file) = test_file();
        file.write_all_at(b"invalid established root", ROOT_OFFSETS[0])
            .unwrap();
        file.sync_all().unwrap();

        assert!(State::recover(&file, DATA_OFFSET).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn root_generation_must_match_its_physical_slot() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"new", 3);
        let prepared = prepare_commit(&file, &mut state);
        assert_eq!(prepared.root_offset, ROOT_OFFSETS[1]);
        assert!(prepared.manifest.is_empty());

        file.write_all_at(&prepared.committed_root, ROOT_OFFSETS[0])
            .unwrap();
        file.write_all_at(
            &prepared.prepared_root[ROOT_LEN..],
            prepared.manifest_offset,
        )
        .unwrap();
        file.sync_all().unwrap();

        assert!(State::recover(&file, DATA_OFFSET).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn torn_latest_epoch_falls_back_to_previous_root() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"old", 3);
        commit(&file, &mut state);
        let previous_end = state.append_offset;

        append(&file, &mut state, 0, b"new value", 9);
        let (payload_start, payload_len, payload_ranges) = state.pending_payload().unwrap();
        reclaim_shadowed_payload(&file, payload_start, payload_len, &payload_ranges).unwrap();
        let prepared = state.prepare_commit().unwrap().unwrap();
        write_prepared(&file, &prepared);
        file.sync_all().unwrap();
        file.write_all_at(b"X", prepared.manifest_offset).unwrap();
        file.sync_all().unwrap();

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"old");
        assert_eq!(file.metadata().unwrap().len(), previous_end);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn arbitrary_latest_write_subsets_recover_exactly_old_or_new() {
        let (source_path, source) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&source, &mut state, 0, b"old-state", 9);
        commit(&source, &mut state);
        let old_end = state.append_offset;
        let old_image = file_bytes(&source);

        append(&source, &mut state, 0, b"new-state", 9);
        let (payload_start, payload_len, payload_ranges) = state.pending_payload().unwrap();
        reclaim_shadowed_payload(&source, payload_start, payload_len, &payload_ranges).unwrap();
        let prepared = state.prepare_commit().unwrap().unwrap();
        assert!(prepared.manifest.is_empty());
        let new_end = source.metadata().unwrap().len();
        let mut new_tail = vec![0; (new_end - old_end) as usize];
        read_exact_at(&source, old_end, &mut new_tail).unwrap();

        // Before the prepare barrier, no subset of payload or prepared-checkpoint bytes can
        // publish the new generation.
        for mask in 0u16..=255 {
            let path = test_path("crash");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all_at(&old_image, 0).unwrap();
            file.set_len(new_end).unwrap();

            for (index, byte) in new_tail.iter().enumerate() {
                if mask & (1 << (index % 8)) != 0 {
                    file.write_all_at(&[*byte], old_end + index as u64).unwrap();
                }
            }
            for (index, byte) in prepared.prepared_root.iter().enumerate() {
                if mask & (1 << ((index + 3) % 8)) != 0 {
                    file.write_all_at(&[*byte], prepared.root_offset + index as u64)
                        .unwrap();
                }
            }
            file.sync_all().unwrap();

            let recovered = State::recover(&file, DATA_OFFSET).unwrap();
            assert_eq!(read(&file, &recovered), b"old-state", "mask {mask:#x}");
            assert_eq!(file.metadata().unwrap().len(), old_end, "mask {mask:#x}");
            drop(file);
            fs::remove_file(path).unwrap();
        }

        // Once prepare is durable, an arbitrary subset of the commit-header overwrite recovers
        // either the old generation or the complete new generation without reading payload data.
        write_prepared(&source, &prepared);
        source.sync_all().unwrap();
        let prepared_image = file_bytes(&source);
        for mask in 0u16..=255 {
            let path = test_path("commit-crash");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all_at(&prepared_image, 0).unwrap();
            for (index, byte) in prepared.committed_root.iter().enumerate() {
                if mask & (1 << (index % 8)) != 0 {
                    file.write_all_at(&[*byte], prepared.root_offset + index as u64)
                        .unwrap();
                }
            }
            file.sync_all().unwrap();

            let persisted = file_bytes(&file);
            let complete_new = persisted
                [prepared.root_offset as usize..prepared.root_offset as usize + ROOT_LEN]
                == prepared.committed_root;
            let recovered = State::recover(&file, DATA_OFFSET).unwrap();
            assert_eq!(
                read(&file, &recovered),
                if complete_new {
                    b"new-state".as_slice()
                } else {
                    b"old-state".as_slice()
                },
                "mask {mask:#x}"
            );
            assert_eq!(
                file.metadata().unwrap().len(),
                if complete_new { new_end } else { old_end },
                "mask {mask:#x}"
            );
            drop(file);
            fs::remove_file(path).unwrap();
        }

        source
            .write_all_at(&prepared.committed_root, prepared.root_offset)
            .unwrap();
        source.sync_all().unwrap();
        let recovered = State::recover(&source, DATA_OFFSET).unwrap();
        assert_eq!(read(&source, &recovered), b"new-state");
        assert_eq!(source.metadata().unwrap().len(), new_end);
        fs::remove_file(source_path).unwrap();
    }

    #[test]
    fn torn_reused_speculative_slot_never_exposes_intermediate_data() {
        let (source_path, source) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&source, &mut state, 0, b"old-state", 9);
        commit(&source, &mut state);
        let old_end = state.append_offset;
        let old_image = file_bytes(&source);

        append(&source, &mut state, 0, b"interim!!", 9);
        assert_eq!(state.append_offset, old_end + 9);
        append(&source, &mut state, 0, b"new-state", 9);
        assert_eq!(state.append_offset, old_end + 9);
        let prepared = state.prepare_commit().unwrap().unwrap();

        for mask in 0u16..=255 {
            let path = test_path("reused-crash");
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            file.write_all_at(&old_image, 0).unwrap();
            file.write_all_at(b"interim!!", old_end).unwrap();
            for (index, byte) in b"new-state".iter().enumerate() {
                if mask & (1 << (index % 8)) != 0 {
                    file.write_all_at(&[*byte], old_end + index as u64).unwrap();
                }
            }
            write_prepared(&file, &prepared);
            file.sync_all().unwrap();

            let recovered = State::recover(&file, DATA_OFFSET).unwrap();
            assert_eq!(read(&file, &recovered), b"old-state", "mask {mask:#x}");
            drop(file);
            fs::remove_file(path).unwrap();
        }

        write_prepared(&source, &prepared);
        source.sync_all().unwrap();
        source
            .write_all_at(&prepared.committed_root, prepared.root_offset)
            .unwrap();
        source.sync_all().unwrap();
        let recovered = State::recover(&source, DATA_OFFSET).unwrap();
        assert_eq!(read(&source, &recovered), b"new-state");

        fs::remove_file(source_path).unwrap();
    }

    #[test]
    fn shrink_then_grow_keeps_truncated_bytes_zero() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, 0, b"abcdef", 6);
        commit(&file, &mut state);
        state.resize(2);
        state.resize(6);
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"ab\0\0\0\0");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn staged_creation_publishes_only_a_complete_inode() {
        let root = test_path("root");
        let partition = "partition";
        let parent = root.join(partition);
        fs::create_dir_all(&parent).unwrap();
        let name = b"blob";
        let live = parent.join(hex(name));
        let region = vec![0x5a; DATA_OFFSET as usize];

        let file = create_live(&root, partition, name, &live, &region).unwrap();
        assert_eq!(file_bytes(&file), region);
        assert!(!creation_path(&live).unwrap().exists());
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn discard_removes_an_unpublished_creation_inode() {
        let root = test_path("root");
        let partition = "partition";
        let parent = root.join(partition);
        fs::create_dir_all(&parent).unwrap();
        let name = b"blob";
        let live = parent.join(hex(name));
        let staging = creation_path(&live).unwrap();
        File::create(&staging).unwrap().sync_all().unwrap();

        discard(&root, partition, name).unwrap();
        assert!(!staging.exists());
        fs::remove_dir_all(root).unwrap();
    }
}

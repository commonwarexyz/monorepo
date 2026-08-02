//! Append-only storage for epoch-atomic blobs.
//!
//! Payload bytes occupy their final logical offsets and are never copied. Appends may accumulate
//! until a sync publishes a new logical length. Rewinding unpublished appends may reuse their tail
//! immediately. Rewinding committed bytes fences further appends until the shorter length is
//! durably published, after which the file is truncated in place. This keeps physical and logical
//! offsets identical without an extent map, hole punching, or compaction.
//!
//! Recovery reads two fixed, self-contained roots. An unresolved speculative batch may
//! additionally checksum a bounded appended suffix, but never scans historical payload.
//!
//! # V2 root slots
//!
//! A V2 file reserves one immutable header page followed by two 4 KiB root slots. Root generation
//! parity selects the slot, so publishing a generation never overwrites its immediate fallback.
//! Payload begins after both slots.
//!
//! ```text
//! +----------------------+ offset 0
//! | immutable V2 header  | 4 KiB
//! +----------------------+ offset 4 KiB
//! | root slot 0          | 4 KiB
//! +----------------------+ offset 8 KiB
//! | root slot 1          | 4 KiB
//! +----------------------+ offset 12 KiB
//! | payload log          |
//! +----------------------+
//! ```
//!
//! An ordinary root slot contains a self-contained 40-byte root header. A batch-prepared slot also
//! stores a 16-byte witness header and the exact group descriptor immediately after the root. The
//! witness header contains magic, descriptor length, and a domain-separated CRC32C.
//!
//! ```text
//! +-------------+---------------+------------+-----------------------------+
//! | root header | magic/len/CRC | descriptor |            unused           |
//! +-------------+---------------+------------+-----------------------------+
//! 0            40              56                                      4096
//! ```
//!
//! The batch-prepared root spelling is deliberately invisible to ordinary recovery. Once the group
//! decision is known, materialization durably rewrites only the 40-byte header to an independently
//! recoverable spelling and leaves the descriptor witness available to repair peers. The batch
//! recovery protocol and its crash outcomes are documented in `storage::batch::coordinator`.

use crate::IoBufs;
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_formatting::hex;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd as _;
use std::{
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::{self, Seek as _, SeekFrom, Write as _},
    os::unix::fs::FileExt,
    path::Path,
};

#[cfg(test)]
type DurableRecord = (u64, Vec<u8>);

#[cfg(test)]
std::thread_local! {
    static TRACKED_READ_BYTES: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
    static TRACKED_DURABLE_WRITES: std::cell::RefCell<Option<Vec<(u64, usize)>>> = const {
        std::cell::RefCell::new(None)
    };
    static TRACKED_DURABLE_RECORDS: std::cell::RefCell<Option<Vec<DurableRecord>>> = const {
        std::cell::RefCell::new(None)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const DATA_OFFSET: u64 = 12_288;
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn test_file() -> (std::path::PathBuf, File) {
        let path = std::env::temp_dir().join(format!(
            "commonware-atomic-append-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
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

    fn append(file: &File, state: &mut State, data: &[u8]) -> u64 {
        let offset = state.logical_len();
        let prepared = state
            .prepare_append(IoBufs::from(data.to_vec()))
            .unwrap()
            .unwrap();
        let mut physical = prepared.file_offset;
        prepared.data.for_each_chunk(|chunk| {
            file.write_all_at(chunk, physical).unwrap();
            physical += chunk.len() as u64;
        });
        state.finish_mutation(prepared.mutation);
        offset
    }

    fn commit(file: &File, state: &mut State) {
        let Some(prepared) = state.prepare_commit().unwrap() else {
            return;
        };
        file.write_all_at(&prepared.prepared_root, prepared.root_offset)
            .unwrap();
        file.sync_all().unwrap();
        write_durable_at(file, prepared.root_offset, &prepared.committed_root).unwrap();
        if prepared.requires_truncate() {
            file.set_len(prepared.raw_len()).unwrap();
        }
        state.finish_commit(prepared);
    }

    fn read(file: &File, state: &State) -> Vec<u8> {
        let mut data = vec![0; state.logical_len() as usize];
        if !data.is_empty() {
            file.read_exact_at(&mut data, DATA_OFFSET).unwrap();
        }
        data
    }

    #[test]
    fn contiguous_appends_round_trip_without_a_map() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        assert_eq!(append(&file, &mut state, b"abc"), 0);
        assert_eq!(append(&file, &mut state, b"def"), 3);
        assert_eq!(read(&file, &state), b"abcdef");
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(recovered.logical_len(), 6);
        assert_eq!(read(&file, &recovered), b"abcdef");
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 6);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn unpublished_rewind_reuses_the_physical_tail() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, b"base");
        commit(&file, &mut state);

        append(&file, &mut state, b"abcdef");
        state.rewind(7).unwrap();
        assert_eq!(append(&file, &mut state, b"XYZ"), 7);
        assert_eq!(read(&file, &state), b"baseabcXYZ");
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 10);
        commit(&file, &mut state);

        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"baseabcXYZ");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn committed_rewind_fences_append_until_commit() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, b"abcdef");
        commit(&file, &mut state);

        state.rewind(3).unwrap();
        assert!(
            state
                .prepare_append(IoBufs::from(b"x".to_vec()))
                .is_err()
        );
        commit(&file, &mut state);
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 3);
        assert_eq!(append(&file, &mut state, b"XYZ"), 3);
        assert_eq!(read(&file, &state), b"abcXYZ");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn recovery_repeats_a_committed_rewind_truncate() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, b"abcdef");
        commit(&file, &mut state);

        state.rewind(3).unwrap();
        let prepared = state.prepare_commit().unwrap().unwrap();
        file.write_all_at(&prepared.prepared_root, prepared.root_offset)
            .unwrap();
        file.sync_all().unwrap();
        write_durable_at(&file, prepared.root_offset, &prepared.committed_root).unwrap();

        // Simulate a crash after the shorter root became durable but before the in-place truncate.
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 6);
        let recovered = State::recover(&file, DATA_OFFSET).unwrap();
        assert_eq!(read(&file, &recovered), b"abc");
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET + 3);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn oversized_pending_epoch_can_be_preflushed() {
        let mut state = State::empty(DATA_OFFSET);
        state.logical_len = MAX_VALIDATED_PAYLOAD_LEN;
        state.payload_checksum.len = MAX_VALIDATED_PAYLOAD_LEN;
        state.dirty = true;
        let prepared = state
            .prepare_append(IoBufs::from(vec![1]))
            .unwrap()
            .unwrap();
        state.finish_mutation(prepared.mutation);
        let mut commit = state.prepare_commit().unwrap().unwrap();
        assert_eq!(
            commit.payload_checksum(),
            PayloadChecksumEligibility::Ineligible
        );
        commit.mark_payload_preflushed();
        assert_eq!(
            commit.payload_checksum(),
            PayloadChecksumEligibility::Eligible(None)
        );
        assert_eq!(commit.payload_start(), commit.raw_len());
    }

    #[test]
    fn batch_witness_write_is_not_padded_to_the_root_slot() {
        let mut state = State::empty(DATA_OFFSET);
        let append = state
            .prepare_append(IoBufs::from(b"new".to_vec()))
            .unwrap()
            .unwrap();
        state.finish_mutation(append.mutation);
        let mut prepared = state.prepare_commit().unwrap().unwrap();
        prepared.mark_batch_prepared();
        let descriptor = b"group descriptor";
        prepared.attach_batch_witness(descriptor).unwrap();

        assert_eq!(
            prepared.prepared_root.len(),
            ROOT_LEN + BATCH_WITNESS_HEADER_LEN + descriptor.len()
        );
        let mut slot = [0; ROOT_SLOT_LEN as usize];
        slot[..prepared.prepared_root.len()].copy_from_slice(&prepared.prepared_root);
        assert_eq!(
            decode_batch_witness(&slot),
            Some((ROOT_LEN + BATCH_WITNESS_HEADER_LEN, descriptor.as_slice()))
        );
    }

    #[test]
    fn only_a_committed_rewind_requires_truncation_at_publication() {
        let mut state = State::empty(DATA_OFFSET);
        let append = state
            .prepare_append(IoBufs::from(b"abc".to_vec()))
            .unwrap()
            .unwrap();
        state.finish_mutation(append.mutation);
        let prepared = state.prepare_commit().unwrap().unwrap();
        assert!(!prepared.requires_truncate());
        state.finish_commit(prepared);

        state.rewind(2).unwrap();
        let prepared = state.prepare_commit().unwrap().unwrap();
        assert!(prepared.requires_truncate());
    }

    #[test]
    fn reopen_reads_bounded_metadata() {
        let (path, file) = test_file();
        let mut state = State::empty(DATA_OFFSET);
        append(&file, &mut state, &vec![0x5a; 4 * 1024 * 1024]);
        commit(&file, &mut state);
        let ((recovered, read_bytes), durable_writes) =
            track_durable_writes(|| track_read_bytes(|| State::recover(&file, DATA_OFFSET)));
        assert_eq!(recovered.unwrap().logical_len(), 4 * 1024 * 1024);
        assert!(read_bytes < 1024, "recovery read {read_bytes} bytes");
        assert!(durable_writes.is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn staged_creation_publishes_only_a_complete_inode() {
        let root = std::env::temp_dir().join(format!(
            "commonware-atomic-create-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = root.join("partition");
        fs::create_dir_all(&parent).unwrap();
        let live = parent.join(hex(b"blob"));
        let region = vec![0x5a; DATA_OFFSET as usize];
        let file = create_live(&root, "partition", b"blob", &live, &region).unwrap();
        assert_eq!(file.metadata().unwrap().len(), DATA_OFFSET);
        assert!(!creation_path(&live).unwrap().exists());
        drop(file);
        fs::remove_dir_all(root).unwrap();
    }
}

const ROOT_MAGIC: &[u8; 8] = b"CWUNOR11";
const PREPARED_ROOT_MAGIC: &[u8; 8] = b"CWUNOP11";
const BATCH_PREPARED_ROOT_MAGIC: &[u8; 8] = b"CWUNOB11";
const MATERIALIZED_ROOT_MAGIC: &[u8; 8] = b"CWUNOM11";
const BATCH_WITNESS_MAGIC: &[u8; 8] = b"CWUNOW11";
const CREATION_PREFIX: &str = ".commonware-uno-create-";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_LOG_ROOT";
const BATCH_WITNESS_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_BATCH_WITNESS";
const ROOT_BODY_LEN: usize = 36;
pub(super) const ROOT_LEN: usize = 40;
const ROOT_SLOT_LEN: u64 = 4096;
const BATCH_WITNESS_HEADER_LEN: usize = 16;
const ROOT_OFFSETS: [u64; 2] = [4096, 8192];
pub(super) const MAX_VALIDATED_PAYLOAD_LEN: u64 = 64 * 1024 * 1024;
const PAYLOAD_CHECKSUM_READ_LEN: usize = 64 * 1024;
#[cfg(target_os = "linux")]
const MIN_WRITEBACK_HINT_LEN: u64 = 64 * 1024;
pub(super) type PendingPayload = (u64, u64);

/// Checksum of one physically contiguous payload range.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PayloadChecksum {
    pub(crate) offset: u64,
    pub(crate) len: u64,
    pub(crate) checksum: u32,
}

/// Whether a prepared epoch can be verified without its first durability barrier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PayloadChecksumEligibility {
    /// The optional checksum is absent when the eligible epoch appended no payload bytes.
    Eligible(Option<PayloadChecksum>),
    Ineligible,
}

#[derive(Debug)]
struct PayloadChecksumTracker {
    offset: u64,
    len: u64,
    hasher: Crc32,
    eligible: bool,
}

impl PayloadChecksumTracker {
    fn new(offset: u64) -> Self {
        Self {
            offset,
            len: 0,
            hasher: Crc32::default(),
            eligible: true,
        }
    }

    fn update(&mut self, physical: u64, data_len: u64, data: &IoBufs) {
        if !self.eligible {
            return;
        }
        if self.offset.checked_add(self.len) != Some(physical) {
            self.eligible = false;
            return;
        }
        let Some(next_len) = self.len.checked_add(data_len) else {
            self.eligible = false;
            return;
        };
        if next_len > MAX_VALIDATED_PAYLOAD_LEN {
            self.eligible = false;
            return;
        }
        data.for_each_chunk(|chunk| {
            self.hasher.update(chunk);
        });
        self.len = next_len;
    }
}
fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
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

#[cfg(test)]
pub(super) fn track_durable_records<T>(operation: impl FnOnce() -> T) -> (T, Vec<DurableRecord>) {
    TRACKED_DURABLE_RECORDS.with(|tracked| {
        assert!(tracked.borrow_mut().replace(Vec::new()).is_none());
    });
    let result = operation();
    let records = TRACKED_DURABLE_RECORDS.with(|tracked| tracked.borrow_mut().take().unwrap());
    (result, records)
}

/// Start Linux writeback for the current payload while its root is built.
#[cfg(target_os = "linux")]
pub(super) fn begin_payload_writeback(file: &File, offset: u64, len: u64) -> io::Result<()> {
    // The syscall is only a scheduling hint. For small epochs its fixed cost exceeds any overlap
    // with root construction; the following inode sync remains the ordering barrier either way.
    if len < MIN_WRITEBACK_HINT_LEN {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadSource {
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
    truncate: bool,
}

/// Durable per-blob candidate named by an exact multi-blob decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Candidate {
    pub(crate) base_generation: u64,
    pub(crate) root_offset: u64,
    pub(crate) prepared_root: [u8; ROOT_LEN],
    pub(crate) committed_root: [u8; ROOT_LEN],
}

/// A transaction candidate recovered with its participant-embedded batch descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct EmbeddedBatchCandidate {
    pub(crate) candidate: Candidate,
    pub(crate) descriptor: Vec<u8>,
}

/// Payload bounds recovered while validating a transaction candidate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct CandidateMetadata {
    payload_end: u64,
}

pub(super) struct PreparedCommit {
    payload_start: u64,
    pub(super) root_offset: u64,
    /// Transaction-ineligible root written before the prepare barrier.
    pub(super) prepared_root: Vec<u8>,
    /// Root header published only after the prepare barrier succeeds.
    pub(super) committed_root: [u8; ROOT_LEN],
    payload_checksum: PayloadChecksumEligibility,
    commit: Commit,
}

impl PreparedCommit {
    fn available_batch_witness_capacity(&self) -> Option<usize> {
        let used = ROOT_LEN.checked_add(BATCH_WITNESS_HEADER_LEN)?;
        (ROOT_SLOT_LEN as usize)
            .checked_sub(used)
            .map(|capacity| capacity.min(u32::MAX as usize))
    }

    /// Return the first physical byte in this commit's payload epoch.
    pub(super) const fn payload_start(&self) -> u64 {
        self.payload_start
    }

    /// Return whether this epoch's payload can be verified speculatively.
    pub(super) const fn payload_checksum(&self) -> PayloadChecksumEligibility {
        self.payload_checksum
    }

    /// Return the physical file length named by this commit.
    pub(super) const fn raw_len(&self) -> u64 {
        self.commit.append_offset
    }

    /// Return whether publishing this root must discard a committed suffix.
    pub(super) const fn requires_truncate(&self) -> bool {
        self.commit.truncate
    }

    /// Mark the complete payload prefix durable before its root is staged.
    ///
    /// Descriptor recovery may then trust the payload without rereading it because the root write
    /// is issued only after the preflush barrier completes.
    pub(super) const fn mark_payload_preflushed(&mut self) {
        self.payload_start = self.commit.append_offset;
        self.payload_checksum = PayloadChecksumEligibility::Eligible(None);
    }

    /// Mark this commit as carrying a participant-embedded batch witness.
    pub(super) fn mark_batch_prepared(&mut self) {
        self.prepared_root[..8].copy_from_slice(BATCH_PREPARED_ROOT_MAGIC);
        let root_checksum = checksum(&[ROOT_DOMAIN, &self.prepared_root[..ROOT_BODY_LEN]]);
        self.prepared_root[36..ROOT_LEN].copy_from_slice(&root_checksum.to_be_bytes());
    }

    /// Maximum descriptor bytes that can follow this root and its wrapper.
    pub(super) fn batch_witness_capacity(&self) -> usize {
        self.available_batch_witness_capacity().unwrap_or(0)
    }

    /// Return whether a descriptor can be embedded in this commit's root slot.
    pub(super) fn batch_witness_fits(&self, descriptor_len: usize) -> bool {
        u32::try_from(descriptor_len).is_ok()
            && self
                .available_batch_witness_capacity()
                .is_some_and(|capacity| descriptor_len <= capacity)
    }

    /// Append a checksummed batch descriptor immediately after this root.
    pub(super) fn attach_batch_witness(&mut self, descriptor: &[u8]) -> io::Result<()> {
        if self.prepared_root.get(..8) != Some(BATCH_PREPARED_ROOT_MAGIC) {
            return Err(invalid_input(
                "atomic batch witness requires a batch-prepared root",
            ));
        }
        if self.prepared_root.len() != ROOT_LEN {
            return Err(invalid_input(
                "atomic batch-prepared root already has trailing bytes",
            ));
        }
        if !self.batch_witness_fits(descriptor.len()) {
            return Err(invalid_input("atomic batch witness exceeds its root slot"));
        }

        let descriptor_len = u32::try_from(descriptor.len())
            .map_err(|_| invalid_input("atomic batch witness length exceeds u32"))?;
        let descriptor_len = descriptor_len.to_be_bytes();
        let descriptor_checksum = checksum(&[
            BATCH_WITNESS_DOMAIN,
            BATCH_WITNESS_MAGIC,
            &descriptor_len,
            descriptor,
        ]);
        self.prepared_root.extend_from_slice(BATCH_WITNESS_MAGIC);
        self.prepared_root.extend_from_slice(&descriptor_len);
        self.prepared_root
            .extend_from_slice(&descriptor_checksum.to_be_bytes());
        self.prepared_root.extend_from_slice(descriptor);
        debug_assert!(self.prepared_root.len() <= ROOT_SLOT_LEN as usize);
        Ok(())
    }

    /// Return the fixed-size identity needed to validate and install this candidate after a group
    /// decision. The logical length is self-contained in the root.
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

}

/// Mutable state for one append-only atomic blob generation.
#[derive(Debug)]
pub(super) struct State {
    data_offset: u64,
    logical_len: u64,
    committed_len: u64,
    generation: u64,
    payload_checksum: PayloadChecksumTracker,
    deferred_batch_root: Option<Candidate>,
    dirty: bool,
    poisoned: bool,
}

impl State {
    fn empty(data_offset: u64) -> Self {
        Self {
            data_offset,
            logical_len: 0,
            committed_len: 0,
            generation: 0,
            payload_checksum: PayloadChecksumTracker::new(data_offset),
            deferred_batch_root: None,
            dirty: false,
            poisoned: false,
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
                roots.push((root, offset));
            }
        }
        roots.sort_by_key(|(root, _)| std::cmp::Reverse(root.generation));

        let mut recovered = None;
        for (root, root_offset) in roots {
            match recover_root(file, data_offset, raw_len, root_offset, root) {
                Ok((candidate, _)) => {
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
        let selected_len = state.raw_len()?;
        if raw_len != selected_len {
            // The selected root is the durable authority. A crash may lose this truncate, but the
            // same root makes recovery repeat it before any discarded offset can be reused.
            file.set_len(selected_len)?;
        }
        state.dirty = false;
        Ok(state)
    }

    pub(super) fn raw_len(&self) -> io::Result<u64> {
        checked_end(self.data_offset, self.logical_len)
    }

    pub(super) const fn logical_len(&self) -> u64 {
        self.logical_len
    }

    pub(super) const fn committed_len(&self) -> u64 {
        self.committed_len
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
        if self.logical_len < self.committed_len {
            let end = self.raw_len()?;
            return Ok((end, 0));
        }
        let start = checked_end(self.data_offset, self.committed_len)?;
        let len = self.logical_len - self.committed_len;
        Ok((start, len))
    }

    /// Discard speculative checksum state after reusing an unpublished tail.
    pub(super) const fn invalidate_payload_checksum(&mut self) {
        self.payload_checksum.eligible = false;
    }

    fn prepare_payload_checksum(
        &mut self,
        payload_start: u64,
        payload_end: u64,
    ) -> io::Result<PayloadChecksumEligibility> {
        let payload_len = payload_end
            .checked_sub(payload_start)
            .ok_or_else(|| invalid_data("atomic payload epoch is inverted"))?;
        if payload_len == 0 {
            return Ok(PayloadChecksumEligibility::Eligible(None));
        }
        let tracker = &mut self.payload_checksum;
        if !tracker.eligible {
            return Ok(PayloadChecksumEligibility::Ineligible);
        }
        tracker.eligible = false;
        if tracker.offset != payload_start || tracker.len != payload_len {
            return Ok(PayloadChecksumEligibility::Ineligible);
        }
        let checksum = std::mem::take(&mut tracker.hasher).finalize().1.as_u32();
        Ok(PayloadChecksumEligibility::Eligible(Some(
            PayloadChecksum {
                offset: payload_start,
                len: payload_len,
                checksum,
            },
        )))
    }

    pub(super) const fn poison(&mut self) {
        self.poisoned = true;
    }

    /// Reserve the current tail for one append.
    pub(super) fn prepare_append(&mut self, data: IoBufs) -> io::Result<Option<PreparedMutation>> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        let data_len = u64::try_from(data.len())
            .map_err(|_| invalid_input("atomic append length does not fit in u64"))?;
        if data_len == 0 {
            return Ok(None);
        }
        if self.logical_len < self.committed_len {
            return Err(invalid_input(
                "atomic append requires syncing the committed rewind first",
            ));
        }
        let logical_start = self.logical_len;
        let logical_end = checked_end(logical_start, data_len)?;
        let physical = checked_end(self.data_offset, logical_start)?;
        self.payload_checksum.update(physical, data_len, &data);
        Ok(Some(PreparedMutation {
            file_offset: physical,
            data,
            mutation: Mutation {
                logical_start,
                logical_end,
                physical,
            },
        }))
    }

    pub(super) fn finish_mutation(&mut self, mutation: Mutation) {
        debug_assert_eq!(mutation.logical_start, self.logical_len);
        debug_assert_eq!(
            mutation.physical,
            self.data_offset + mutation.logical_start
        );
        self.logical_len = mutation.logical_end;
        self.dirty = true;
    }

    /// Rewind to an existing logical offset.
    ///
    /// Crossing the committed frontier fences appends until this shorter length is published.
    pub(super) fn validate_rewind(&self, len: u64) -> io::Result<()> {
        if self.poisoned {
            return Err(invalid_data("atomic blob generation is poisoned"));
        }
        if len > self.logical_len {
            return Err(invalid_input("atomic rewind cannot extend a blob"));
        }
        Ok(())
    }

    pub(super) fn rewind(&mut self, len: u64) -> io::Result<()> {
        self.validate_rewind(len)?;
        if len == self.logical_len {
            return Ok(());
        }
        self.logical_len = len;
        let frontier = checked_end(self.data_offset, self.committed_len)?;
        if len < self.committed_len {
            self.payload_checksum = PayloadChecksumTracker::new(self.raw_len()?);
            self.dirty = true;
        } else if len == self.committed_len {
            self.payload_checksum = PayloadChecksumTracker::new(frontier);
            self.dirty = false;
        } else {
            // CRC32 cannot be rewound. The large-epoch preflush path will make the retained
            // unpublished prefix durable before a root can name it.
            self.invalidate_payload_checksum();
            self.dirty = true;
        }
        Ok(())
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
        if len == 0 {
            return Ok(Vec::new());
        }
        Ok(vec![ReadSpan {
            destination: 0,
            len,
            source: ReadSource::File(checked_end(self.data_offset, offset)?),
        }])
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
        let payload_end = self.raw_len()?;
        let root_offset = ROOT_OFFSETS[(generation as usize) & 1];
        let committed_root = encode_root(ROOT_MAGIC, generation, self.logical_len);
        let prepared_root = encode_root(PREPARED_ROOT_MAGIC, generation, self.logical_len).to_vec();

        let payload_start = if self.logical_len < self.committed_len {
            payload_end
        } else {
            checked_end(self.data_offset, self.committed_len)?
        };
        let payload_checksum = self.prepare_payload_checksum(payload_start, payload_end)?;
        Ok(Some(PreparedCommit {
            payload_start,
            root_offset,
            prepared_root,
            committed_root,
            payload_checksum,
            commit: Commit {
                generation,
                append_offset: payload_end,
                truncate: self.logical_len < self.committed_len,
            },
        }))
    }

    fn apply_commit(&mut self, prepared: PreparedCommit) {
        self.generation = prepared.commit.generation;
        self.committed_len = self.logical_len;
        self.payload_checksum = PayloadChecksumTracker::new(prepared.commit.append_offset);
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

fn encode_root(magic: &[u8; 8], generation: u64, logical_len: u64) -> [u8; ROOT_LEN] {
    let mut root = [0u8; ROOT_LEN];
    root[..8].copy_from_slice(magic);
    root[8..16].copy_from_slice(&generation.to_be_bytes());
    root[16..24].copy_from_slice(&logical_len.to_be_bytes());
    let root_checksum = checksum(&[ROOT_DOMAIN, &root[..ROOT_BODY_LEN]]);
    root[36..40].copy_from_slice(&root_checksum.to_be_bytes());
    root
}

#[derive(Clone, Copy, Debug)]
struct Root {
    generation: u64,
    logical_len: u64,
}

fn decode_root_with_magic(encoded: &[u8; ROOT_LEN], magic: &[u8; 8]) -> Option<Root> {
    if &encoded[..8] != magic {
        return None;
    }
    let root_checksum = u32::from_be_bytes(encoded[36..40].try_into().unwrap());
    if root_checksum != checksum(&[ROOT_DOMAIN, &encoded[..ROOT_BODY_LEN]]) {
        return None;
    }
    decode_root_fields(encoded)
}

fn decode_root_fields(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    let generation = u64::from_be_bytes(encoded[8..16].try_into().unwrap());
    let logical_len = u64::from_be_bytes(encoded[16..24].try_into().unwrap());
    (generation != 0 && encoded[24..36].iter().all(|byte| *byte == 0)).then_some(Root {
        generation,
        logical_len,
    })
}

fn decode_committed_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_root_with_magic(encoded, ROOT_MAGIC)
}

fn decode_materialized_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_root_with_magic(encoded, MATERIALIZED_ROOT_MAGIC)
}

fn decode_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_committed_root(encoded).or_else(|| decode_materialized_root(encoded))
}

fn decode_prepared_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_root_with_magic(encoded, PREPARED_ROOT_MAGIC)
        .or_else(|| decode_root_with_magic(encoded, BATCH_PREPARED_ROOT_MAGIC))
}

fn decode_batch_prepared_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    decode_root_with_magic(encoded, BATCH_PREPARED_ROOT_MAGIC)
}

fn decode_batch_witness(slot: &[u8]) -> Option<(usize, &[u8])> {
    let header_end = ROOT_LEN.checked_add(BATCH_WITNESS_HEADER_LEN)?;
    let header = slot.get(ROOT_LEN..header_end)?;
    if &header[..8] != BATCH_WITNESS_MAGIC {
        return None;
    }
    let descriptor_len = u32::from_be_bytes(header[8..12].try_into().unwrap());
    let descriptor_len = usize::try_from(descriptor_len).ok()?;
    let descriptor_offset = header_end;
    let descriptor_end = descriptor_offset.checked_add(descriptor_len)?;
    let descriptor = slot.get(descriptor_offset..descriptor_end)?;
    let stored_checksum = u32::from_be_bytes(header[12..16].try_into().unwrap());
    let expected_checksum = checksum(&[BATCH_WITNESS_DOMAIN, &header[..12], descriptor]);
    (stored_checksum == expected_checksum).then_some((descriptor_offset, descriptor))
}

fn read_root_slot(
    file: &File,
    root_offset: u64,
) -> io::Result<Option<[u8; ROOT_SLOT_LEN as usize]>> {
    let mut slot = [0u8; ROOT_SLOT_LEN as usize];
    match read_exact_at(file, root_offset, &mut slot) {
        Ok(()) => Ok(Some(slot)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(error) => Err(error),
    }
}

fn candidate_roots_match(candidate: &Candidate, prepared: Root, committed: Root) -> bool {
    candidate.base_generation.checked_add(1) == Some(committed.generation)
        && committed.generation == prepared.generation
        && committed.logical_len == prepared.logical_len
        && ROOT_OFFSETS[(committed.generation as usize) & 1] == candidate.root_offset
}

fn candidate_materialized_root(candidate: &Candidate) -> Option<[u8; ROOT_LEN]> {
    let prepared = decode_batch_prepared_root(&candidate.prepared_root)?;
    let committed = decode_committed_root(&candidate.committed_root)?;
    if !candidate_roots_match(candidate, prepared, committed) {
        return None;
    }
    Some(encode_root(
        MATERIALIZED_ROOT_MAGIC,
        committed.generation,
        committed.logical_len,
    ))
}

/// Return the independently recoverable spelling of a valid batch candidate root.
pub(super) fn materialized_candidate_root(candidate: &Candidate) -> io::Result<[u8; ROOT_LEN]> {
    candidate_materialized_root(candidate)
        .ok_or_else(|| invalid_data("transaction candidate cannot be materialized"))
}

fn candidate_root_is_transition(installed: &[u8; ROOT_LEN], candidate: &Candidate) -> bool {
    installed
        .iter()
        .zip(
            candidate
                .prepared_root
                .iter()
                .zip(&candidate.committed_root),
        )
        .all(|(installed, (prepared, committed))| installed == prepared || installed == committed)
}

fn candidate_root_is_batch_transition(installed: &[u8; ROOT_LEN], candidate: &Candidate) -> bool {
    let Some(materialized) = candidate_materialized_root(candidate) else {
        return candidate_root_is_transition(installed, candidate);
    };
    installed
        .iter()
        .zip(
            candidate
                .prepared_root
                .iter()
                .zip(&candidate.committed_root)
                .zip(materialized),
        )
        .all(|(installed, ((prepared, committed), materialized))| {
            installed == prepared || installed == committed || *installed == materialized
        })
}

fn embedded_batch_candidates_with_materialized(
    file: &File,
    data_offset: u64,
    include_materialized: bool,
) -> io::Result<Vec<EmbeddedBatchCandidate>> {
    if data_offset < ROOT_OFFSETS[1] + ROOT_SLOT_LEN {
        return Err(invalid_input(
            "V2 data offset does not reserve both root slots",
        ));
    }
    let raw_len = file.metadata()?.len();
    if raw_len < data_offset {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::with_capacity(ROOT_OFFSETS.len());
    for root_offset in ROOT_OFFSETS {
        let Some(slot) = read_root_slot(file, root_offset)? else {
            continue;
        };
        let encoded: [u8; ROOT_LEN] = slot[..ROOT_LEN]
            .try_into()
            .expect("root slots contain a complete root header");
        let Some(root) = decode_root_fields(&encoded) else {
            continue;
        };
        let prepared_root = encode_root(
            BATCH_PREPARED_ROOT_MAGIC,
            root.generation,
            root.logical_len,
        );
        let committed_root = encode_root(ROOT_MAGIC, root.generation, root.logical_len);
        let candidate = Candidate {
            base_generation: root.generation - 1,
            root_offset,
            prepared_root,
            committed_root,
        };
        let Some(materialized_root) = candidate_materialized_root(&candidate) else {
            continue;
        };
        if encoded == materialized_root && !include_materialized {
            continue;
        }
        if !candidate_root_is_batch_transition(&encoded, &candidate) {
            continue;
        }
        let Some((descriptor_offset, descriptor)) = decode_batch_witness(&slot) else {
            continue;
        };
        if ROOT_OFFSETS[(root.generation as usize) & 1] != root_offset {
            continue;
        }
        if descriptor_offset < ROOT_LEN {
            continue;
        }
        if checked_end(data_offset, root.logical_len)
            .ok()
            .is_none_or(|end| end > raw_len)
        {
            continue;
        }
        candidates.push(EmbeddedBatchCandidate {
            candidate,
            descriptor: descriptor.to_vec(),
        });
    }
    candidates.sort_by_key(|embedded| std::cmp::Reverse(embedded.candidate.base_generation));
    Ok(candidates)
}

/// Discover intact participant-embedded descriptors without reading payload.
pub(crate) fn embedded_batch_candidates(
    file: &File,
    data_offset: u64,
) -> io::Result<Vec<EmbeddedBatchCandidate>> {
    embedded_batch_candidates_with_materialized(file, data_offset, false)
}

/// Discover descriptors retained beside independently recoverable roots.
///
/// Unresolved-candidate selection ignores these stale witnesses. A separate transfer pass uses
/// them to make dependent peers independently recoverable before this witness is reused or removed.
pub(crate) fn materialized_batch_candidates(
    file: &File,
    data_offset: u64,
) -> io::Result<Vec<EmbeddedBatchCandidate>> {
    let candidates = embedded_batch_candidates_with_materialized(file, data_offset, true)?;
    let mut materialized = Vec::with_capacity(candidates.len());
    for embedded in candidates {
        let Some(expected) = candidate_materialized_root(&embedded.candidate) else {
            continue;
        };
        let Some(slot) = read_root_slot(file, embedded.candidate.root_offset)? else {
            continue;
        };
        if slot[..ROOT_LEN] == expected {
            materialized.push(embedded);
        }
    }
    Ok(materialized)
}

/// Verify that an exact descriptor remains beside a known batch candidate's root transition.
pub(crate) fn candidate_has_embedded_batch_witness(
    file: &File,
    candidate: &Candidate,
    descriptor: &[u8],
) -> io::Result<bool> {
    let Some(prepared) = decode_batch_prepared_root(&candidate.prepared_root) else {
        return Ok(false);
    };
    let Some(committed) = decode_committed_root(&candidate.committed_root) else {
        return Ok(false);
    };
    if !candidate_roots_match(candidate, prepared, committed) {
        return Ok(false);
    }
    if descriptor.len()
        > (ROOT_SLOT_LEN as usize)
            .saturating_sub(ROOT_LEN)
            .saturating_sub(BATCH_WITNESS_HEADER_LEN)
    {
        return Ok(false);
    }

    let mut candidate_slot = None;
    for root_offset in ROOT_OFFSETS {
        let Some(slot) = read_root_slot(file, root_offset)? else {
            continue;
        };
        let encoded: [u8; ROOT_LEN] = slot[..ROOT_LEN]
            .try_into()
            .expect("root slots contain a complete root header");
        if decode_root(&encoded).is_some_and(|root| {
            ROOT_OFFSETS[(root.generation as usize) & 1] == root_offset
                && root.generation > committed.generation
        }) {
            return Ok(false);
        }
        if root_offset == candidate.root_offset {
            candidate_slot = Some(slot);
        }
    }
    let Some(slot) = candidate_slot else {
        return Ok(false);
    };
    let installed: [u8; ROOT_LEN] = slot[..ROOT_LEN]
        .try_into()
        .expect("root slots contain a complete root header");
    if !candidate_root_is_batch_transition(&installed, candidate) {
        return Ok(false);
    }
    Ok(decode_batch_witness(&slot)
        .is_some_and(|(offset, found)| offset >= ROOT_LEN && found == descriptor))
}

/// Return whether a candidate's exact committed header is installed in its generation slot.
pub(crate) fn candidate_is_committed(file: &File, candidate: &Candidate) -> io::Result<bool> {
    let Some(prepared) = decode_prepared_root(&candidate.prepared_root) else {
        return Ok(false);
    };
    let Some(committed) = decode_committed_root(&candidate.committed_root) else {
        return Ok(false);
    };
    if !candidate_roots_match(candidate, prepared, committed) {
        return Ok(false);
    }

    let mut installed = [0u8; ROOT_LEN];
    match read_exact_at(file, candidate.root_offset, &mut installed) {
        Ok(()) => Ok(installed == candidate.committed_root),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

/// Return whether a batch candidate's exact materialized header is installed.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn candidate_is_materialized(file: &File, candidate: &Candidate) -> io::Result<bool> {
    let Some(materialized_root) = candidate_materialized_root(candidate) else {
        return Ok(false);
    };

    let mut installed = [0u8; ROOT_LEN];
    match read_exact_at(file, candidate.root_offset, &mut installed) {
        Ok(()) => Ok(installed == materialized_root),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(error),
    }
}

/// Validate and durably publish a batch candidate as independently recoverable.
pub(crate) fn materialize_candidate(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
) -> io::Result<()> {
    let materialized_root = materialized_candidate_root(candidate)?;
    let metadata = validate_candidate(file, data_offset, candidate)?;
    write_durable_at(file, candidate.root_offset, &materialized_root)?;
    file.set_len(metadata.payload_end)
}

fn recover_root(
    _file: &File,
    data_offset: u64,
    raw_len: u64,
    root_offset: u64,
    root: Root,
) -> io::Result<(State, CandidateMetadata)> {
    if ROOT_OFFSETS[(root.generation as usize) & 1] != root_offset {
        return Err(invalid_data("atomic root generation is in the wrong slot"));
    }
    let payload_end = checked_end(data_offset, root.logical_len)
        .map_err(|_| invalid_data("atomic logical length overflows its data offset"))?;
    if payload_end > raw_len {
        return Err(invalid_data("atomic payload end is invalid"));
    }

    let mut state = State::empty(data_offset);
    state.logical_len = root.logical_len;
    state.committed_len = root.logical_len;
    state.generation = root.generation;
    state.payload_checksum = PayloadChecksumTracker::new(payload_end);
    Ok((state, CandidateMetadata { payload_end }))
}

/// Write a small publication record and make that write durable before returning.
pub(super) fn write_durable_at(file: &File, offset: u64, bytes: &[u8]) -> io::Result<()> {
    #[cfg(test)]
    let tracked_write = (offset, bytes.len());
    #[cfg(test)]
    let tracked_record = (offset, bytes.to_vec());

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
    #[cfg(test)]
    TRACKED_DURABLE_RECORDS.with(|tracked| {
        if let Some(records) = tracked.borrow_mut().as_mut() {
            records.push(tracked_record);
        }
    });
    Ok(())
}

/// Validate a transaction-bound candidate without changing its root.
///
/// A prepared root is deliberately invisible to ordinary blob recovery. An exact durable batch
/// descriptor supplies the prepared and committed headers, allowing validation to accept any
/// bytewise prefix-independent transition between those headers.
pub(super) fn validate_candidate(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
) -> io::Result<CandidateMetadata> {
    let committed = decode_committed_root(&candidate.committed_root)
        .ok_or_else(|| invalid_data("transaction candidate has an invalid committed root"))?;
    let prepared = decode_prepared_root(&candidate.prepared_root)
        .ok_or_else(|| invalid_data("transaction candidate has an invalid prepared root"))?;
    if committed.generation
        != candidate
            .base_generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("transaction candidate generation overflow"))?
        || committed.generation != prepared.generation
        || committed.logical_len != prepared.logical_len
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
    // The durable batch descriptor is the authority for this exact self-contained
    // candidate. Its prior base root may already have been reused while preparing a later batch,
    // so validation must not depend on finding that base in the other root slot.
    let torn_transition = candidate_root_is_batch_transition(&installed, candidate);
    if !torn_transition {
        return Err(invalid_data(
            "transaction candidate root is not a recoverable publication transition",
        ));
    }

    let (_, metadata) = recover_root(file, data_offset, raw_len, candidate.root_offset, committed)?;
    Ok(metadata)
}

/// Verify a bounded speculative payload suffix without publishing its candidate root.
pub(super) fn validate_payload_checksum(
    file: &File,
    data_offset: u64,
    metadata: &CandidateMetadata,
    payload_start: u64,
    checksum: Option<&PayloadChecksum>,
) -> io::Result<()> {
    if payload_start < data_offset || metadata.payload_end < payload_start {
        return Err(invalid_data(
            "transaction payload checksum range is outside its data region",
        ));
    }
    let Some(checksum) = checksum else {
        return (payload_start == metadata.payload_end)
            .then_some(())
            .ok_or_else(|| invalid_data("transaction payload checksum is missing"));
    };
    if checksum.len == 0 {
        return Err(invalid_data(
            "transaction payload checksum has an empty range",
        ));
    }
    if checksum.len > MAX_VALIDATED_PAYLOAD_LEN {
        return Err(invalid_data(
            "transaction payload checksum exceeds the recovery bound",
        ));
    }
    let end = checksum
        .offset
        .checked_add(checksum.len)
        .ok_or_else(|| invalid_data("transaction payload checksum range overflows"))?;
    if checksum.offset != payload_start || end != metadata.payload_end {
        return Err(invalid_data(
            "transaction payload checksum does not cover the candidate payload epoch",
        ));
    }

    let mut hasher = Crc32::default();
    let mut buffer = vec![0u8; PAYLOAD_CHECKSUM_READ_LEN];
    let mut offset = checksum.offset;
    let mut remaining = checksum.len;
    while remaining != 0 {
        let len = usize::try_from(remaining.min(PAYLOAD_CHECKSUM_READ_LEN as u64))
            .expect("checksum chunks fit in usize");
        read_exact_at(file, offset, &mut buffer[..len])?;
        hasher.update(&buffer[..len]);
        offset = offset
            .checked_add(len as u64)
            .expect("validated checksum ranges do not overflow");
        remaining -= len as u64;
    }
    if hasher.finalize().1.as_u32() != checksum.checksum {
        return Err(invalid_data("transaction payload checksum mismatch"));
    }
    Ok(())
}

/// Validate and durably install a transaction-bound candidate.
#[cfg(test)]
pub(super) fn install_candidate(
    file: &File,
    data_offset: u64,
    candidate: &Candidate,
) -> io::Result<()> {
    let metadata = validate_candidate(file, data_offset, candidate)?;
    write_durable_at(file, candidate.root_offset, &candidate.committed_root)?;
    file.set_len(metadata.payload_end)
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

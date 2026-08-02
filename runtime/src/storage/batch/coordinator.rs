//! Fixed-slot coordinator for crash-atomic multi-blob publication.
//!
//! Every participant first makes its transaction-ineligible root and referenced payload durable.
//! The coordinator then publishes one checksummed decision record. The common case needs one
//! ordered durability round for all participants followed by one small coordinator write. A valid
//! decision is sufficient to install every candidate without reading payload bytes; an absent or
//! torn decision leaves every ordinary blob root at the preceding epoch.
//!
//! A write-only decision may remain authoritative after its in-memory state is activated. The next
//! preparation folds each prior committed root into that participant's existing durability
//! barrier, and installs any absent participants before a newer decision supersedes it. Recovery
//! and non-batch namespace operations install the decision and publish an idle root. Decisions
//! containing removals are always installed and retired before recreation can proceed.

use super::{Operation, is_canonical_operations};
use crate::{RemoveTarget, storage::atomic};
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_formatting::hex;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind},
    os::unix::fs::{FileExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

const CONTROL_DIRECTORY: &str = ".commonware";
const COORDINATOR_FILE: &str = "_COMMONWARE_RUNTIME_UNO_COORDINATOR";
const CREATION_FILE: &str = "_COMMONWARE_RUNTIME_UNO_COORDINATOR_CREATING";
const REMOVAL_DIRECTORY_PREFIX: &str = "_COMMONWARE_RUNTIME_UNO_REMOVALS_";
const ROOT_MAGIC: &[u8; 8] = b"CWUNOC06";
const DESCRIPTOR_MAGIC: &[u8; 8] = b"CWUNOD06";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_UNO_COORDINATOR_ROOT";
const ROOT_BODY_LEN: usize = 36;
const ROOT_LEN: usize = 40;
const SLOT_LEN: u64 = 16 * 1024 * 1024;
const ROOT_OFFSETS: [u64; 2] = [0, SLOT_LEN];
const FILE_LEN: u64 = SLOT_LEN * 2;
const MAX_DESCRIPTOR_LEN: usize = SLOT_LEN as usize - ROOT_LEN;
const MAX_RECORDS: usize = 1_000_000;
const DESCRIPTOR_HEADER_LEN: usize = 16;
const TAG_PARTITION_REMOVE: u8 = 0;
const TAG_BLOB_REMOVE: u8 = 1;

#[cfg(test)]
std::thread_local! {
    static TRACKED_READ_BYTES: std::cell::Cell<Option<u64>> = const {
        std::cell::Cell::new(None)
    };
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn checksum(parts: &[&[u8]]) -> u32 {
    let mut hasher = Crc32::default();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().1.as_u32()
}

fn checked_end(offset: u64, len: u64) -> io::Result<u64> {
    offset
        .checked_add(len)
        .ok_or_else(|| invalid_data("coordinator offset overflow"))
}

fn read_exact_at(file: &File, mut offset: u64, mut output: &mut [u8]) -> io::Result<()> {
    while !output.is_empty() {
        let read = match file.read_at(output, offset) {
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        if read == 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "coordinator record is truncated",
            ));
        }
        offset = checked_end(offset, read as u64)?;
        #[cfg(test)]
        TRACKED_READ_BYTES.with(|tracked| {
            if let Some(bytes) = tracked.get() {
                tracked.set(Some(bytes + read as u64));
            }
        });
        output = &mut output[read..];
    }
    Ok(())
}

#[cfg(test)]
fn track_read_bytes<T>(operation: impl FnOnce() -> T) -> (T, u64) {
    TRACKED_READ_BYTES.with(|tracked| {
        assert!(tracked.replace(Some(0)).is_none());
    });
    let result = operation();
    let bytes = TRACKED_READ_BYTES.with(|tracked| tracked.replace(None).unwrap());
    (result, bytes)
}

/// Per-blob durable candidate referenced by a coordinator decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Participant {
    pub(crate) partition: String,
    pub(crate) name: Vec<u8>,
    pub(crate) candidate: atomic::Candidate,
}

impl Participant {
    fn key(&self) -> (&str, &[u8]) {
        (&self.partition, &self.name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Decision {
    participants: Vec<Participant>,
    removals: Vec<RemoveTarget>,
}

impl Decision {
    fn operations(&self) -> Vec<Operation> {
        self.removals
            .iter()
            .cloned()
            .map(Operation::Remove)
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
struct Root {
    generation: u64,
    descriptor_len: usize,
    descriptor_checksum: u32,
}

struct Publication {
    root: Root,
    offset: u64,
    record: Vec<u8>,
}

enum State {
    Idle(Option<Publication>),
    Committed(Publication, Decision),
}

impl State {
    const fn generation(&self) -> u64 {
        match self {
            Self::Idle(Some(publication)) | Self::Committed(publication, _) => {
                publication.root.generation
            }
            Self::Idle(None) => 0,
        }
    }

    fn stabilize(&self, file: &File) -> io::Result<()> {
        let publication = match self {
            Self::Idle(publication) => publication.as_ref(),
            Self::Committed(publication, _) => Some(publication),
        };
        publication.map_or(Ok(()), |publication| {
            atomic::write_durable_at(file, publication.offset, &publication.record)
        })
    }
}

fn encode_root(generation: u64, descriptor: &[u8]) -> io::Result<[u8; ROOT_LEN]> {
    let descriptor_len = u64::try_from(descriptor.len())
        .map_err(|_| invalid_input("coordinator descriptor length overflow"))?;
    if descriptor.len() > MAX_DESCRIPTOR_LEN {
        return Err(invalid_input("coordinator descriptor is too large"));
    }
    let mut encoded = [0u8; ROOT_LEN];
    encoded[..8].copy_from_slice(ROOT_MAGIC);
    encoded[8..16].copy_from_slice(&generation.to_be_bytes());
    encoded[16..24].copy_from_slice(&descriptor_len.to_be_bytes());
    let descriptor_checksum = if descriptor.is_empty() {
        0
    } else {
        Crc32::checksum(descriptor)
    };
    encoded[24..28].copy_from_slice(&descriptor_checksum.to_be_bytes());
    let root_checksum = checksum(&[ROOT_DOMAIN, &encoded[..ROOT_BODY_LEN]]);
    encoded[36..40].copy_from_slice(&root_checksum.to_be_bytes());
    Ok(encoded)
}

fn decode_root(encoded: &[u8; ROOT_LEN]) -> Option<Root> {
    if encoded.iter().all(|byte| *byte == 0) || &encoded[..8] != ROOT_MAGIC {
        return None;
    }
    let expected = u32::from_be_bytes(encoded[36..40].try_into().unwrap());
    if expected != checksum(&[ROOT_DOMAIN, &encoded[..ROOT_BODY_LEN]])
        || encoded[28..36].iter().any(|byte| *byte != 0)
    {
        return None;
    }
    let generation = u64::from_be_bytes(encoded[8..16].try_into().unwrap());
    let descriptor_len = u64::from_be_bytes(encoded[16..24].try_into().unwrap());
    let descriptor_len = usize::try_from(descriptor_len).ok()?;
    if generation == 0 || descriptor_len > MAX_DESCRIPTOR_LEN {
        return None;
    }
    let descriptor_checksum = u32::from_be_bytes(encoded[24..28].try_into().unwrap());
    if descriptor_len == 0 && descriptor_checksum != 0 {
        return None;
    }
    Some(Root {
        generation,
        descriptor_len,
        descriptor_checksum,
    })
}

fn push_len(encoded: &mut Vec<u8>, len: usize, what: &str) -> io::Result<()> {
    let len = u32::try_from(len).map_err(|_| invalid_input(format!("{what} is too large")))?;
    encoded.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn encode_descriptor(
    participants: &[Participant],
    operations: &[Operation],
) -> io::Result<Vec<u8>> {
    if participants.len() > MAX_RECORDS || operations.len() > MAX_RECORDS {
        return Err(invalid_input("coordinator has too many records"));
    }
    let removals = operations
        .iter()
        .filter_map(|operation| match operation {
            Operation::Remove(target) => Some(target),
            Operation::Publish { .. } | Operation::Resize { .. } => None,
        })
        .collect::<Vec<_>>();

    let mut encoded = Vec::new();
    encoded.extend_from_slice(DESCRIPTOR_MAGIC);
    encoded.extend_from_slice(&(participants.len() as u32).to_be_bytes());
    encoded.extend_from_slice(&(removals.len() as u32).to_be_bytes());
    for participant in participants {
        push_len(
            &mut encoded,
            participant.partition.len(),
            "coordinator partition name",
        )?;
        encoded.extend_from_slice(participant.partition.as_bytes());
        push_len(
            &mut encoded,
            participant.name.len(),
            "coordinator blob name",
        )?;
        encoded.extend_from_slice(&participant.name);
        encoded.extend_from_slice(&participant.candidate.base_generation.to_be_bytes());
        encoded.extend_from_slice(&participant.candidate.root_offset.to_be_bytes());
        encoded.extend_from_slice(&participant.candidate.prepared_root);
        encoded.extend_from_slice(&participant.candidate.committed_root);
    }
    for target in removals {
        match target {
            RemoveTarget::Partition(partition) => {
                encoded.push(TAG_PARTITION_REMOVE);
                push_len(&mut encoded, partition.len(), "coordinator partition name")?;
                encoded.extend_from_slice(partition.as_bytes());
            }
            RemoveTarget::Blob { partition, name } => {
                encoded.push(TAG_BLOB_REMOVE);
                push_len(&mut encoded, partition.len(), "coordinator partition name")?;
                encoded.extend_from_slice(partition.as_bytes());
                push_len(&mut encoded, name.len(), "coordinator blob name")?;
                encoded.extend_from_slice(name);
            }
        }
    }
    if encoded.len() > MAX_DESCRIPTOR_LEN {
        return Err(invalid_input("coordinator descriptor is too large"));
    }
    Ok(encoded)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    fn read(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .position
            .checked_add(len)
            .ok_or_else(|| invalid_data("coordinator descriptor length overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_data("coordinator descriptor is truncated"))?;
        self.position = end;
        Ok(bytes)
    }

    fn read_u8(&mut self) -> io::Result<u8> {
        Ok(self.read(1)?[0])
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.read(4)?.try_into().unwrap()))
    }

    fn read_u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_be_bytes(self.read(8)?.try_into().unwrap()))
    }

    fn read_vec(&mut self, what: &str) -> io::Result<Vec<u8>> {
        let len = usize::try_from(self.read_u32()?)
            .map_err(|_| invalid_data(format!("{what} length overflow")))?;
        Ok(self.read(len)?.to_vec())
    }

    fn read_partition(&mut self) -> io::Result<String> {
        let bytes = self.read_vec("coordinator partition")?;
        String::from_utf8(bytes).map_err(|_| invalid_data("coordinator partition is not UTF-8"))
    }
}

fn decode_descriptor(encoded: &[u8]) -> io::Result<Decision> {
    if encoded.len() < DESCRIPTOR_HEADER_LEN || encoded.len() > MAX_DESCRIPTOR_LEN {
        return Err(invalid_data("coordinator descriptor has an invalid length"));
    }
    let mut cursor = Cursor::new(encoded);
    if cursor.read(DESCRIPTOR_MAGIC.len())? != DESCRIPTOR_MAGIC {
        return Err(invalid_data("coordinator descriptor magic mismatch"));
    }
    let participant_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| invalid_data("coordinator participant count overflow"))?;
    let removal_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| invalid_data("coordinator removal count overflow"))?;
    if participant_count > MAX_RECORDS || removal_count > MAX_RECORDS {
        return Err(invalid_data("coordinator has too many records"));
    }
    const MIN_PARTICIPANT_LEN: usize = 4 + 4 + 8 + 8 + atomic::ROOT_LEN * 2;
    const MIN_REMOVAL_LEN: usize = 1 + 4;
    let minimum = participant_count
        .checked_mul(MIN_PARTICIPANT_LEN)
        .and_then(|len| len.checked_add(removal_count.saturating_mul(MIN_REMOVAL_LEN)))
        .ok_or_else(|| invalid_data("coordinator record count overflow"))?;
    if minimum > encoded.len() - DESCRIPTOR_HEADER_LEN {
        return Err(invalid_data(
            "coordinator record count exceeds descriptor length",
        ));
    }

    let mut participants = Vec::with_capacity(participant_count);
    for _ in 0..participant_count {
        let partition = cursor.read_partition()?;
        let name = cursor.read_vec("coordinator blob")?;
        let base_generation = cursor.read_u64()?;
        let root_offset = cursor.read_u64()?;
        let prepared_root = cursor.read(atomic::ROOT_LEN)?.try_into().unwrap();
        let committed_root = cursor.read(atomic::ROOT_LEN)?.try_into().unwrap();
        participants.push(Participant {
            partition,
            name,
            candidate: atomic::Candidate {
                base_generation,
                root_offset,
                prepared_root,
                committed_root,
            },
        });
    }

    let mut removals = Vec::with_capacity(removal_count);
    for _ in 0..removal_count {
        let tag = cursor.read_u8()?;
        let partition = cursor.read_partition()?;
        let target = match tag {
            TAG_PARTITION_REMOVE => RemoveTarget::Partition(partition),
            TAG_BLOB_REMOVE => RemoveTarget::Blob {
                partition,
                name: cursor.read_vec("coordinator blob")?,
            },
            _ => return Err(invalid_data("coordinator removal tag is invalid")),
        };
        removals.push(target);
    }
    if cursor.position != encoded.len() {
        return Err(invalid_data("coordinator descriptor has trailing bytes"));
    }

    validate_decision(&participants, &removals)?;
    Ok(Decision {
        participants,
        removals,
    })
}

fn validate_decision(participants: &[Participant], removals: &[RemoveTarget]) -> io::Result<()> {
    let mut previous = None;
    for participant in participants {
        super::super::validate_partition_name(&participant.partition)
            .map_err(|_| invalid_data("coordinator participant has an invalid partition"))?;
        if let Some(previous) = previous
            && previous >= participant.key()
        {
            return Err(invalid_data(
                "coordinator participants are not strictly ordered",
            ));
        }
        previous = Some(participant.key());
    }

    let removal_operations = removals
        .iter()
        .cloned()
        .map(Operation::Remove)
        .collect::<Vec<_>>();
    let canonical = is_canonical_operations(&removal_operations)
        .map_err(|_| invalid_data("coordinator removals are invalid"))?;
    if !canonical {
        return Err(invalid_data("coordinator removals are not canonical"));
    }
    for participant in participants {
        if removals.iter().any(|target| match target {
            RemoveTarget::Partition(partition) => partition == &participant.partition,
            RemoveTarget::Blob { partition, name } => {
                partition == &participant.partition && name == &participant.name
            }
        }) {
            return Err(invalid_data(
                "coordinator removes one of its publication participants",
            ));
        }
    }
    Ok(())
}

fn control_directory(root: &Path) -> PathBuf {
    root.join(CONTROL_DIRECTORY)
}

fn coordinator_path(root: &Path) -> PathBuf {
    control_directory(root).join(COORDINATOR_FILE)
}

fn creation_path(root: &Path) -> PathBuf {
    control_directory(root).join(CREATION_FILE)
}

fn removal_directory(root: &Path, generation: u64) -> PathBuf {
    control_directory(root).join(format!("{REMOVAL_DIRECTORY_PREFIX}{}", generation & 1))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn require_directory(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(invalid_data("coordinator control path is not a directory")),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn open_existing(root: &Path) -> io::Result<Option<File>> {
    let path = coordinator_path(root);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Err(invalid_data("coordinator path is not a regular file")),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.len() != FILE_LEN {
        return Err(invalid_data("coordinator file has the wrong length"));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(invalid_data("coordinator path is not a regular file"));
    }
    Ok(Some(file))
}

fn open_or_create(root: &Path) -> io::Result<File> {
    if let Some(file) = open_existing(root)? {
        return Ok(file);
    }
    let control = control_directory(root);
    if !require_directory(&control)? {
        fs::create_dir(&control)?;
        sync_directory(root)?;
    }

    let staging = creation_path(root);
    match fs::remove_file(&staging) {
        Ok(()) => sync_directory(&control)?,
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&staging)?;
    file.set_len(FILE_LEN)?;
    file.sync_all()?;
    fs::rename(&staging, coordinator_path(root))?;
    sync_directory(&control)?;
    Ok(file)
}

fn read_state(file: &File) -> io::Result<State> {
    let mut roots = Vec::new();
    let mut has_zero_slot = false;
    for offset in ROOT_OFFSETS {
        let mut encoded = [0u8; ROOT_LEN];
        read_exact_at(file, offset, &mut encoded)?;
        let is_zero = encoded.iter().all(|byte| *byte == 0);
        has_zero_slot |= is_zero;
        if let Some(root) = decode_root(&encoded)
            && ROOT_OFFSETS[(root.generation as usize) & 1] == offset
        {
            roots.push((root, offset, encoded));
        }
    }
    roots.sort_by_key(|(root, _, _)| std::cmp::Reverse(root.generation));

    let mut invalid_committed = None;
    for (root, offset, encoded) in roots {
        if root.descriptor_len == 0 {
            return Ok(State::Idle(Some(Publication {
                root,
                offset,
                record: encoded.to_vec(),
            })));
        }
        let mut descriptor = vec![0u8; root.descriptor_len];
        if let Err(error) = read_exact_at(file, offset + ROOT_LEN as u64, &mut descriptor) {
            if matches!(
                error.kind(),
                ErrorKind::InvalidData | ErrorKind::UnexpectedEof
            ) {
                invalid_committed.get_or_insert(error);
                continue;
            }
            return Err(error);
        }
        if Crc32::checksum(&descriptor) != root.descriptor_checksum {
            invalid_committed
                .get_or_insert_with(|| invalid_data("coordinator descriptor checksum mismatch"));
            continue;
        }
        let decision = decode_descriptor(&descriptor)?;
        let mut record = Vec::with_capacity(ROOT_LEN + descriptor.len());
        record.extend_from_slice(&encoded);
        record.extend_from_slice(&descriptor);
        return Ok(State::Committed(
            Publication {
                root,
                offset,
                record,
            },
            decision,
        ));
    }
    if has_zero_slot {
        return Ok(State::Idle(None));
    }
    Err(invalid_committed.unwrap_or_else(|| invalid_data("coordinator has no recoverable root")))
}

fn validate_v2_header(file: &File) -> io::Result<()> {
    const IMMUTABLE_HEADER_LEN: usize = 4096;
    let mut header = [0u8; IMMUTABLE_HEADER_LEN];
    read_exact_at(file, 0, &mut header)?;
    if &header[..4] != b"CWIL"
        || u16::from_be_bytes(header[4..6].try_into().unwrap()) != 2
        || Crc32::checksum(&header[..8]) != u32::from_be_bytes(header[8..12].try_into().unwrap())
        || header[12..].iter().any(|byte| *byte != 0)
    {
        return Err(invalid_data(
            "coordinator participant is not a valid V2 blob",
        ));
    }
    Ok(())
}

fn install_participant(root: &Path, participant: &Participant) -> io::Result<()> {
    let path = root
        .join(&participant.partition)
        .join(hex(&participant.name));
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.file_type().is_file() {
        return Err(invalid_data(
            "coordinator participant is not a regular file",
        ));
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    validate_v2_header(&file)?;
    atomic::install_candidate(
        &file,
        super::super::Layout::V2.data_offset(),
        &participant.candidate,
    )
}

#[cfg(test)]
fn install_participants(root: &Path, participants: &[Participant]) -> io::Result<()> {
    for participant in participants {
        install_participant(root, participant)?;
    }
    Ok(())
}

/// Make every root from the currently authoritative decision independently durable before the
/// coordinator slot is reused. Roots folded into a later participant preparation already crossed
/// that file's durability barrier; participants absent from the later batch are installed here.
fn materialize_carried_decision(
    root: &Path,
    decision: &Decision,
    materialized: &[Participant],
) -> io::Result<()> {
    let mut materialized = materialized.iter().peekable();
    for participant in &decision.participants {
        // A retained participant can keep its folded marker after a disjoint batch independently
        // installs that older root. Such markers no longer belong to the current decision and are
        // harmless; an equal-key marker must still identify the exact current candidate.
        while materialized
            .peek()
            .is_some_and(|candidate| candidate.key() < participant.key())
        {
            materialized.next();
        }
        match materialized.peek() {
            Some(candidate) if candidate.key() == participant.key() => {
                if candidate.candidate != participant.candidate {
                    return Err(invalid_data(
                        "materialized candidate does not match the carried decision",
                    ));
                }
                materialized.next();
            }
            _ => install_participant(root, participant)?,
        }
    }
    Ok(())
}

#[cfg(not(test))]
fn install_participants(root: &Path, participants: &[Participant]) -> io::Result<()> {
    const MAX_INSTALL_WORKERS: usize = 32;
    for chunk in participants.chunks(MAX_INSTALL_WORKERS) {
        std::thread::scope(|scope| {
            let handles = chunk
                .iter()
                .map(|participant| scope.spawn(move || install_participant(root, participant)))
                .collect::<Vec<_>>();
            for handle in handles {
                match handle.join() {
                    Ok(result) => result?,
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            }
            Ok::<(), io::Error>(())
        })?;
    }
    Ok(())
}

fn path_is_missing(error: &io::Error) -> bool {
    if error.kind() == ErrorKind::NotFound {
        return true;
    }
    error.raw_os_error() == Some(libc::ENAMETOOLONG)
}

fn prepare_removal_directory(root: &Path, generation: u64) -> io::Result<()> {
    let path = removal_directory(root, generation);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            fs::remove_dir_all(&path)?;
            sync_directory(&control_directory(root))?;
        }
        Ok(_) => return Err(invalid_data("coordinator removal path is not a directory")),
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    fs::create_dir(&path)?;
    sync_directory(&control_directory(root))
}

fn remove_target(
    root: &Path,
    generation: u64,
    index: usize,
    target: &RemoveTarget,
) -> io::Result<()> {
    let result = match target {
        RemoveTarget::Blob { partition, name } => {
            if name.is_empty() {
                return Ok(());
            }
            let partition_path = root.join(partition);
            match fs::symlink_metadata(&partition_path) {
                Ok(metadata) if metadata.file_type().is_dir() => {
                    fs::remove_file(partition_path.join(hex(name)))
                }
                Ok(_) => return Err(invalid_data("blob partition path is not a directory")),
                Err(error) if path_is_missing(&error) => Ok(()),
                Err(error) => Err(error),
            }
        }
        RemoveTarget::Partition(partition) => {
            let partition_path = root.join(partition);
            let removed_path = removal_directory(root, generation).join(index.to_string());
            match fs::symlink_metadata(&partition_path) {
                Ok(metadata)
                    if metadata.file_type().is_dir() || metadata.file_type().is_symlink() =>
                {
                    match fs::symlink_metadata(&removed_path) {
                        Ok(_) => {
                            return Err(invalid_data(
                                "coordinator removal destination already exists",
                            ));
                        }
                        Err(error) if error.kind() == ErrorKind::NotFound => {}
                        Err(error) => return Err(error),
                    }
                    fs::rename(partition_path, &removed_path)
                }
                Ok(_) => return Err(invalid_data("partition path is not a directory")),
                Err(error) if path_is_missing(&error) => {
                    match fs::symlink_metadata(&removed_path) {
                        Ok(_) => Ok(()),
                        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
                        Err(error) => Err(error),
                    }
                }
                Err(error) => Err(error),
            }
        }
    };
    match result {
        Ok(()) => Ok(()),
        Err(error) if path_is_missing(&error) => Ok(()),
        Err(error) => Err(error),
    }?;
    match target {
        RemoveTarget::Blob { partition, name } => atomic::discard(root, partition, name),
        RemoveTarget::Partition(partition) => atomic::discard_partition(root, partition),
    }
}

fn sync_removals(root: &Path, generation: u64, removals: &[RemoveTarget]) -> io::Result<()> {
    let partitions = removals
        .iter()
        .filter_map(|target| match target {
            RemoveTarget::Blob { partition, .. } => Some(root.join(partition)),
            RemoveTarget::Partition(_) => None,
        })
        .collect::<BTreeSet<_>>();
    for partition in partitions {
        match fs::symlink_metadata(&partition) {
            Ok(metadata) if metadata.file_type().is_dir() => sync_directory(&partition)?,
            Ok(_) => return Err(invalid_data("blob partition path is not a directory")),
            Err(error) if path_is_missing(&error) => {}
            Err(error) => return Err(error),
        }
    }
    if removals
        .iter()
        .any(|target| matches!(target, RemoveTarget::Partition(_)))
    {
        sync_directory(&removal_directory(root, generation))?;
    }
    sync_directory(root)
}

fn finish_namespace(
    file: &File,
    root: &Path,
    root_record: Root,
    removals: &[RemoveTarget],
) -> io::Result<Option<PathBuf>> {
    for (index, target) in removals.iter().enumerate() {
        remove_target(root, root_record.generation, index, target)?;
    }
    if !removals.is_empty() {
        sync_removals(root, root_record.generation, removals)?;
    }
    let idle_generation = root_record
        .generation
        .checked_add(1)
        .ok_or_else(|| invalid_data("coordinator generation overflow"))?;
    let idle_root = encode_root(idle_generation, &[])?;
    let idle_offset = ROOT_OFFSETS[(idle_generation as usize) & 1];
    atomic::write_durable_at(file, idle_offset, &idle_root)?;
    Ok(removals
        .iter()
        .any(|target| matches!(target, RemoveTarget::Partition(_)))
        .then(|| removal_directory(root, root_record.generation)))
}

fn reclaim_removals(root: &Path, removal_path: Option<PathBuf>) -> io::Result<()> {
    let Some(removal_path) = removal_path else {
        return Ok(());
    };
    fs::remove_dir_all(removal_path)?;
    sync_directory(&control_directory(root))
}

fn finish_decision(
    file: &File,
    root: &Path,
    root_record: Root,
    decision: &Decision,
) -> io::Result<()> {
    install_participants(root, &decision.participants)?;
    finish_namespace(file, root, root_record, &decision.removals)?;
    Ok(())
}

/// Validate that a canonical operation set can fit in one bounded coordinator slot.
pub(crate) fn preflight(operations: &[Operation]) -> io::Result<()> {
    let canonical = is_canonical_operations(operations)
        .map_err(|_| invalid_input("storage batch contains an invalid operation"))?;
    if !canonical {
        return Err(invalid_input("storage batch operations are not canonical"));
    }
    if operations.len() > MAX_RECORDS {
        return Err(invalid_input("storage batch has too many operations"));
    }
    let mut minimum_len = DESCRIPTOR_HEADER_LEN;
    for operation in operations {
        let (partition, name, fixed) = match operation {
            Operation::Remove(RemoveTarget::Partition(partition)) => (partition, None, 1 + 4),
            Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                (partition, Some(name.as_slice()), 1 + 4 + 4)
            }
            Operation::Publish { partition, name }
            | Operation::Resize {
                partition, name, ..
            } => (
                partition,
                Some(name.as_slice()),
                4 + 4 + 8 + 8 + atomic::ROOT_LEN * 2,
            ),
        };
        u32::try_from(partition.len())
            .map_err(|_| invalid_input("storage batch partition name is too large"))?;
        if let Some(name) = name {
            u32::try_from(name.len())
                .map_err(|_| invalid_input("storage batch blob name is too large"))?;
        }
        minimum_len = minimum_len
            .checked_add(fixed + partition.len() + name.map_or(0, <[u8]>::len))
            .ok_or_else(|| invalid_input("storage batch descriptor length overflow"))?;
        if minimum_len > MAX_DESCRIPTOR_LEN {
            return Err(invalid_input("storage batch descriptor is too large"));
        }
    }
    Ok(())
}

/// Bind every existing partition reference to its physical directory spelling.
pub(crate) fn resolve_operation_partitions(
    root: &Path,
    operations: &mut [Operation],
) -> io::Result<()> {
    let requested = operations
        .iter_mut()
        .map(|operation| operation.partition_mut().clone())
        .collect::<BTreeSet<_>>();
    let resolved = resolve_partition_names(root, requested)?;
    for operation in operations {
        let partition = operation.partition_mut();
        partition.clone_from(
            resolved
                .get(partition)
                .expect("every requested partition was resolved"),
        );
    }
    Ok(())
}

fn resolve_partition_names(
    root: &Path,
    requested: BTreeSet<String>,
) -> io::Result<BTreeMap<String, String>> {
    let mut resolved = BTreeMap::new();
    for requested in requested {
        match fs::symlink_metadata(root.join(&requested)) {
            Ok(metadata) if metadata.file_type().is_dir() => {
                let canonical = fs::canonicalize(root.join(&requested))?;
                let actual = canonical
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| invalid_data("storage partition name is not valid UTF-8"))?;
                resolved.insert(requested, actual.to_string());
            }
            Ok(_) => {
                resolved.insert(requested.clone(), requested);
            }
            Err(error) if path_is_missing(&error) => {
                resolved.insert(requested.clone(), requested);
            }
            Err(error) => return Err(error),
        }
    }
    Ok(resolved)
}

/// Resolve the stored spelling of an existing partition without conflating case aliases.
pub(crate) fn resolve_partition_name(root: &Path, requested: &str) -> io::Result<String> {
    let mut resolved = resolve_partition_names(root, BTreeSet::from([requested.to_string()]))?;
    Ok(resolved
        .remove(requested)
        .expect("the requested partition was resolved"))
}

/// Publish and materialize a prepared multi-blob decision.
pub(crate) fn apply_batch_with<C, I>(
    root: &Path,
    participants: &[Participant],
    materialized_previous: &[Participant],
    operations: &[Operation],
    carry_decision: bool,
    on_commit: C,
    install_participants: I,
) -> io::Result<bool>
where
    C: FnOnce(&[Operation]),
    I: FnOnce() -> io::Result<()>,
{
    preflight(operations)?;
    let removals = operations
        .iter()
        .filter_map(|operation| match operation {
            Operation::Remove(target) => Some(target.clone()),
            Operation::Publish { .. } | Operation::Resize { .. } => None,
        })
        .collect::<Vec<_>>();
    validate_decision(participants, &removals)?;
    if participants.is_empty() && removals.is_empty() {
        return Ok(carry_decision);
    }

    let root_metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound && participants.is_empty() => {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    if !root_metadata.is_dir() {
        if participants.is_empty() {
            return Ok(false);
        }
        return Err(invalid_data("storage batch root is not a directory"));
    }

    let file = open_or_create(root)?;
    // Backends recover the coordinator before entering this helper under the namespace lock. An
    // idle root here was therefore stabilized during recovery or durably completed by the prior
    // batch, so the hot path does not need an extra publication barrier.
    let state = read_state(&file)?;
    let current_generation = state.generation();
    let generation = match state {
        State::Idle(_) => current_generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("coordinator generation overflow"))?,
        State::Committed(_, decision) if carry_decision && decision.removals.is_empty() => {
            materialize_carried_decision(root, &decision, materialized_previous)?;
            current_generation
                .checked_add(1)
                .ok_or_else(|| invalid_data("coordinator generation overflow"))?
        }
        State::Committed(_, _) => {
            return Err(invalid_data(
                "a committed coordinator decision must be recovered first",
            ));
        }
    };
    if removals
        .iter()
        .any(|target| matches!(target, RemoveTarget::Partition(_)))
    {
        prepare_removal_directory(root, generation)?;
    }
    let descriptor = encode_descriptor(participants, operations)?;
    let root_record = encode_root(generation, &descriptor)?;
    let mut record = Vec::with_capacity(ROOT_LEN + descriptor.len());
    record.extend_from_slice(&root_record);
    record.extend_from_slice(&descriptor);
    let offset = ROOT_OFFSETS[(generation as usize) & 1];
    atomic::write_durable_at(&file, offset, &record)?;

    on_commit(operations);
    install_participants()?;
    let root_record = decode_root(&root_record).expect("newly encoded coordinator root is valid");
    if removals.is_empty() {
        return Ok(true);
    }
    let removal_path = finish_namespace(&file, root, root_record, &removals)?;
    reclaim_removals(root, removal_path)?;
    Ok(false)
}

fn recover_with<C>(root: &Path, on_commit: C) -> io::Result<()>
where
    C: FnOnce(&[Operation]),
{
    let metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() || !require_directory(&control_directory(root))? {
        return Ok(());
    }
    let Some(file) = open_existing(root)? else {
        return Ok(());
    };
    let state = read_state(&file)?;
    state.stabilize(&file)?;
    let State::Committed(publication, decision) = state else {
        return Ok(());
    };
    let operations = decision.operations();
    on_commit(&operations);
    finish_decision(&file, root, publication.root, &decision)
}

/// Complete a durable decision before exposing the storage namespace.
pub(crate) fn recover(root: &Path) -> io::Result<()> {
    recover_with(root, |_| {})
}

/// Recover and notify after observing a durable decision.
pub(crate) fn recover_notifying<C>(root: &Path, on_commit: C) -> io::Result<()>
where
    C: FnOnce(&[Operation]),
{
    recover_with(root, on_commit)
}

#[cfg(test)]
pub(crate) fn interrupt_committed_for_test(
    root: &Path,
    operations: &[Operation],
    _after_operations: usize,
) -> io::Result<()> {
    apply_batch_with(
        root,
        &[],
        &[],
        operations,
        false,
        |_| {},
        || Err(io::Error::other("injected coordinator interruption")),
    )
    .map(|_| ())
}

#[cfg(all(test, not(feature = "iouring-storage")))]
pub(crate) fn fail_final_control_sync_for_test<C>(
    root: &Path,
    operations: &[Operation],
    on_commit: C,
) -> io::Result<()>
where
    C: FnOnce(&[Operation]),
{
    apply_batch_with(root, &[], &[], operations, false, on_commit, || {
        Err(io::Error::other(
            "injected coordinator materialization failure",
        ))
    })
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{IoBufs, storage::Header};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    fn test_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "commonware-uno-coordinator-{label}-{}-{}",
            std::process::id(),
            NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn candidate(generation: u64) -> atomic::Candidate {
        let mut prepared_root = [0u8; atomic::ROOT_LEN];
        let mut committed_root = [0u8; atomic::ROOT_LEN];
        prepared_root[8..16].copy_from_slice(&generation.to_be_bytes());
        committed_root[8..16].copy_from_slice(&generation.to_be_bytes());
        atomic::Candidate {
            base_generation: generation - 1,
            root_offset: 8192,
            prepared_root,
            committed_root,
        }
    }

    #[test]
    fn descriptor_round_trip_is_bounded_and_canonical() {
        let participants = vec![
            Participant {
                partition: "alpha".into(),
                name: b"one".to_vec(),
                candidate: candidate(1),
            },
            Participant {
                partition: "beta".into(),
                name: b"two".to_vec(),
                candidate: candidate(2),
            },
        ];
        let operations = vec![Operation::Remove(RemoveTarget::Blob {
            partition: "gamma".into(),
            name: b"three".to_vec(),
        })];
        let encoded = encode_descriptor(&participants, &operations).unwrap();
        let decoded = decode_descriptor(&encoded).unwrap();
        assert_eq!(decoded.participants, participants);
        assert_eq!(
            decoded.removals,
            vec![RemoveTarget::Blob {
                partition: "gamma".into(),
                name: b"three".to_vec(),
            }]
        );

        let mut corrupted = encoded;
        corrupted[0] ^= 1;
        assert_eq!(
            decode_descriptor(&corrupted).unwrap_err().kind(),
            ErrorKind::InvalidData
        );
    }

    #[cfg(unix)]
    #[test]
    fn exact_partition_resolution_does_not_read_root_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = test_root("bounded-partition-resolution");
        fs::create_dir_all(root.join("Exact")).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o111)).unwrap();

        let resolved = resolve_partition_name(&root, "Exact");

        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(resolved.unwrap(), "Exact");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn torn_decision_falls_back_to_idle_root() {
        let root = test_root("torn-later");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir(&root).unwrap();
        let file = open_or_create(&root).unwrap();
        let idle = encode_root(2, &[]).unwrap();
        file.write_all_at(&idle, ROOT_OFFSETS[0]).unwrap();
        file.sync_all().unwrap();

        let descriptor = encode_descriptor(
            &[],
            &[Operation::Remove(RemoveTarget::Partition("victim".into()))],
        )
        .unwrap();
        let committed = encode_root(3, &descriptor).unwrap();
        let mut record = committed.to_vec();
        record.extend_from_slice(&descriptor);
        for persisted in 0..record.len() {
            file.write_all_at(&[0u8; ROOT_LEN], ROOT_OFFSETS[1])
                .unwrap();
            file.write_all_at(&record[..persisted], ROOT_OFFSETS[1])
                .unwrap();
            file.sync_all().unwrap();
            let state = read_state(&file).unwrap();
            assert_eq!(state.generation(), 2);
            assert!(matches!(state, State::Idle(_)));
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn torn_first_decision_falls_back_to_implicit_idle() {
        let root = test_root("torn-first");
        fs::create_dir(&root).unwrap();
        let file = open_or_create(&root).unwrap();
        let descriptor = encode_descriptor(
            &[],
            &[Operation::Remove(RemoveTarget::Partition("victim".into()))],
        )
        .unwrap();
        let committed = encode_root(1, &descriptor).unwrap();
        let mut record = committed.to_vec();
        record.extend_from_slice(&descriptor);
        for persisted in 0..record.len() {
            file.write_all_at(&[0u8; ROOT_LEN], ROOT_OFFSETS[1])
                .unwrap();
            file.write_all_at(&record[..persisted], ROOT_OFFSETS[1])
                .unwrap();
            file.sync_all().unwrap();
            let state = read_state(&file).unwrap();
            assert_eq!(state.generation(), 0);
            assert!(matches!(state, State::Idle(_)));
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_nonzero_slots_do_not_become_implicit_idle() {
        let root = test_root("corrupt-nonzero");
        fs::create_dir(&root).unwrap();
        let file = open_or_create(&root).unwrap();
        let descriptor = encode_descriptor(
            &[],
            &[Operation::Remove(RemoveTarget::Partition("victim".into()))],
        )
        .unwrap();
        let committed = encode_root(1, &descriptor).unwrap();
        file.write_all_at(&committed, ROOT_OFFSETS[1]).unwrap();
        let mut corrupted_descriptor = descriptor;
        corrupted_descriptor[0] ^= 1;
        file.write_all_at(&corrupted_descriptor, ROOT_OFFSETS[1] + ROOT_LEN as u64)
            .unwrap();
        file.write_all_at(b"nonzero invalid root", ROOT_OFFSETS[0])
            .unwrap();
        file.sync_all().unwrap();

        let error = match read_state(&file) {
            Ok(_) => panic!("corrupt nonzero coordinator slots must not become idle"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ErrorKind::InvalidData);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn recovery_redurabilizes_selected_idle_root() {
        let root = test_root("idle-redurable");
        fs::create_dir(&root).unwrap();
        let file = open_or_create(&root).unwrap();
        let idle = encode_root(2, &[]).unwrap();
        file.write_all_at(&idle, ROOT_OFFSETS[0]).unwrap();
        file.sync_all().unwrap();

        let (_, durable_writes) = atomic::track_durable_writes(|| recover(&root).unwrap());
        assert_eq!(durable_writes, vec![(ROOT_OFFSETS[0], ROOT_LEN)]);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn committed_group_recovery_reads_only_candidate_metadata() {
        let root = test_root("group-recovery");
        let partition_path = root.join("group");
        fs::create_dir_all(&partition_path).unwrap();
        let payload = vec![7u8; 4 * 1024 * 1024];
        let mut participants = Vec::new();
        let mut files = Vec::new();

        for name in [b"first".as_slice(), b"second".as_slice()] {
            let live_path = partition_path.join(hex(name));
            let region = Header::create_atomic(&(0..=0)).0;
            let file = atomic::create_live(&root, "group", name, &live_path, &region).unwrap();
            let mut state =
                atomic::State::recover(&file, super::super::super::Layout::V2.data_offset())
                    .unwrap();
            let mutation = state
                .prepare_write(0, IoBufs::from(payload.clone()), Some(payload.len() as u64))
                .unwrap()
                .unwrap();
            file.write_all_at(
                mutation.data.as_single().unwrap().as_ref(),
                mutation.file_offset,
            )
            .unwrap();
            state.finish_mutation(mutation.mutation);
            let prepared = state.prepare_commit().unwrap().unwrap();
            if !prepared.manifest.is_empty() {
                file.write_all_at(&prepared.manifest, prepared.manifest_offset)
                    .unwrap();
            }
            file.write_all_at(&prepared.prepared_root, prepared.root_offset)
                .unwrap();
            file.sync_all().unwrap();
            participants.push(Participant {
                partition: "group".into(),
                name: name.to_vec(),
                candidate: prepared.candidate(),
            });
            files.push(file);
        }

        let operations = vec![
            Operation::Publish {
                partition: "group".into(),
                name: b"first".to_vec(),
            },
            Operation::Publish {
                partition: "group".into(),
                name: b"second".to_vec(),
            },
        ];
        let descriptor_len = encode_descriptor(&participants, &operations).unwrap().len();
        assert!(
            apply_batch_with(
                &root,
                &participants,
                &[],
                &operations,
                false,
                |_| {},
                || { Err(io::Error::other("stop after durable decision")) }
            )
            .is_err()
        );

        let (((result, durable_writes), atomic_read_bytes), coordinator_read_bytes) =
            track_read_bytes(|| {
                atomic::track_read_bytes(|| atomic::track_durable_writes(|| recover(&root)))
            });
        result.unwrap();
        assert_eq!(
            durable_writes.first(),
            Some(&(ROOT_OFFSETS[1], ROOT_LEN + descriptor_len))
        );
        assert_eq!(
            atomic_read_bytes,
            2 * (atomic::ROOT_LEN + 40 + 24) as u64
        );
        assert_eq!(
            coordinator_read_bytes,
            (ROOT_LEN * 2 + descriptor_len + 4096 * 2) as u64
        );
        for file in files {
            let recovered =
                atomic::State::recover(&file, super::super::super::Layout::V2.data_offset())
                    .unwrap();
            assert_eq!(recovered.logical_len(), payload.len() as u64);
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn partition_recovery_renames_before_deferred_reclamation() {
        let root = test_root("partition-tombstone");
        let victim = root.join("victim");
        fs::create_dir_all(&victim).unwrap();
        for index in 0..128 {
            fs::write(victim.join(format!("blob-{index}")), [index as u8; 64]).unwrap();
        }
        let operations = vec![Operation::Remove(RemoveTarget::Partition("victim".into()))];
        assert!(interrupt_committed_for_test(&root, &operations, 0).is_err());

        recover(&root).unwrap();
        assert!(!victim.exists());
        let tombstone = removal_directory(&root, 1);
        assert!(tombstone.is_dir());
        assert_eq!(fs::read_dir(&tombstone).unwrap().count(), 1);

        let next = vec![Operation::Remove(RemoveTarget::Partition("missing".into()))];
        apply_batch_with(&root, &[], &[], &next, false, |_| {}, || Ok(())).unwrap();
        assert!(!tombstone.exists());
        fs::remove_dir_all(root).unwrap();
    }
}

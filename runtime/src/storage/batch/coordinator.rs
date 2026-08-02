//! Crash recovery publication for atomic storage batches.
//!
//! This module implements a coordinator-free fast path for batches containing only writes and
//! resizes, plus a fixed-slot coordinator for batches containing namespace removals. Both paths use
//! the same exact descriptor format and candidate validation rules.
//!
//! # Coordinator-free write-only groups
//!
//! Every dirty participant stores the complete descriptor in its own prepared V2 root slot. The
//! descriptor names every participant by partition and blob name, then records its exact candidate
//! root and the CRC32C-covered range of newly appended payload. The descriptor bytes, including the
//! participant order, are identical in every participant.
//!
//! ```text
//! participant A root slot                 participant B root slot
//! +-----------------------------+         +-----------------------------+
//! | prepared root for A         |         | prepared root for B         |
//! | checkpoint                  |         | checkpoint                  |
//! | descriptor { A, B, ... }    |<------->| descriptor { A, B, ... }    |
//! +-----------------------------+         +-----------------------------+
//!              |                                      |
//!              +------ concurrent durability ---------+
//! ```
//!
//! The canonical `CWUNOD08` descriptor has this logical layout. Variable-length partition and blob
//! names carry unsigned 32-bit lengths, and participants are sorted by their exact path.
//!
//! ```text
//! descriptor  = header | participant* | removal*
//! header      = magic | participant_count | removal_count | decision_kind
//! participant = partition | name | base_generation | root_slot
//!             | prepared_root | committed_root
//!             | payload_start | payload_length | payload_crc32c
//! ```
//!
//! The batch prepares all candidates before constructing the descriptor. It then attaches the
//! descriptor, writes each prepared root, and runs the participants' existing durability barriers
//! concurrently. Once every barrier completes, the replicated descriptor set is the durable group
//! decision. On the repeated same-participant hot path, write-only publication performs no
//! coordinator write and requires no additional durability barrier. A participant-set transition
//! may first materialize the preceding decision as described below.
//!
//! # Restart discovery
//!
//! Opening a V2 blob reads its two fixed root slots before ordinary blob recovery. An intact
//! batch-prepared root contains the exact descriptor, so the opened participant identifies the
//! group without an application-supplied transaction identifier or a namespace scan. Recovery
//! checks that the local path and candidate match the descriptor, then opens each peer by its exact
//! path and requires the same descriptor and candidate from every peer. Candidates are considered
//! newest first, with the other root slot retained as a complete fallback.
//!
//! Before installation starts, recovery selects the new group only if every witness, candidate,
//! and bounded payload CRC32C validates. Otherwise it ignores that descriptor and retains the
//! preceding complete generation. Once any candidate has been installed as an independently
//! recoverable root, rollback is no longer safe. Recovery then requires every witness and finishes
//! installing the group. A missing witness after installation starts is corruption.
//!
//! | Durable state found after restart | Recovery result |
//! | --- | --- |
//! | At least one incomplete participant and no installation | Retain the old group |
//! | Every participant is complete | Materialize the new group |
//! | Any participant installation started | Finish materializing every participant |
//!
//! Materialization rewrites only the candidate root header. It leaves the descriptor in that slot
//! until a later generation safely reuses it, which lets any materialized participant finish peers
//! after another crash. Consecutive groups with the same exact participant set can alternate the
//! two root slots. A participant-set change materializes the preceding group before replacing its
//! witness.
//!
//! # Removal-bearing groups
//!
//! A removed blob cannot retain a witness for its own removal. A removal-bearing batch therefore
//! writes one fixed-slot coordinator descriptor concurrently with participant barriers. Recovery
//! accepts that descriptor only when all exact participant witnesses, candidates, and payload
//! checksums validate. A pure-removal descriptor has no participants and is authoritative once its
//! coordinator publication is durable.
//!
//! # Bounds and fault model
//!
//! Coordinator-free recovery is limited to 32 dirty participants and 64 MiB of newly appended
//! payload across the group. Any newly appended participant payload must be representable by one
//! physically contiguous CRC32C range. The complete descriptor must also fit beside any inline
//! checkpoint in every participant's 4 KiB root slot. Ineligible write-only batches fail with
//! `InvalidInput` before a durable group decision.
//!
//! Until a file durability barrier succeeds, a crash may preserve any subset of issued payload,
//! checkpoint, descriptor, or root-overwrite bytes. Prepared roots are invisible to ordinary blob
//! recovery, exact root-transition validation rejects unrelated byte combinations, and payload plus
//! descriptor checksums determine whether the complete new group survived. The trusted local-disk
//! model treats matching CRC32C values as intact, subject to the checksum's collision probability.
//! CRC32C does not authenticate storage against an actor who can also rewrite checksums.

use super::{Operation, is_canonical_operations};
use crate::{RemoveTarget, storage::atomic};
use commonware_cryptography::{Crc32, Hasher as _};
use commonware_formatting::{from_hex, hex};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind},
    os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

const CONTROL_DIRECTORY: &str = ".commonware";
const COORDINATOR_FILE: &str = "_COMMONWARE_RUNTIME_UNO_COORDINATOR";
const CREATION_FILE: &str = "_COMMONWARE_RUNTIME_UNO_COORDINATOR_CREATING";
const REMOVAL_DIRECTORY_PREFIX: &str = "_COMMONWARE_RUNTIME_UNO_REMOVALS_";
const ROOT_MAGIC: &[u8; 8] = b"CWUNOC08";
const DESCRIPTOR_MAGIC: &[u8; 8] = b"CWUNOD08";
const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_UNO_COORDINATOR_ROOT";
const ROOT_BODY_LEN: usize = 36;
const ROOT_LEN: usize = 40;
const SLOT_LEN: u64 = 16 * 1024 * 1024;
const ROOT_OFFSETS: [u64; 2] = [0, SLOT_LEN];
const FILE_LEN: u64 = SLOT_LEN * 2;
const MAX_DESCRIPTOR_LEN: usize = SLOT_LEN as usize - ROOT_LEN;
const MAX_RECORDS: usize = 1_000_000;
const DESCRIPTOR_HEADER_LEN: usize = 20;
const TAG_PARTITION_REMOVE: u8 = 0;
const TAG_BLOB_REMOVE: u8 = 1;
const DECISION_SPECULATIVE: u32 = 1;
const PAYLOAD_CHECKSUM_LEN: usize = 8 + 8 + 4;
const MAX_SPECULATIVE_PARTICIPANTS: usize = 32;
const MAX_SPECULATIVE_BYTES: u64 = atomic::MAX_VALIDATED_PAYLOAD_LEN;

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
        output = &mut output[read..];
    }
    Ok(())
}

/// Per-blob durable candidate named by an exact batch descriptor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Participant {
    pub(crate) partition: String,
    pub(crate) name: Vec<u8>,
    pub(crate) candidate: atomic::Candidate,
    pub(crate) payload_start: u64,
    pub(crate) payload_checksum: Option<atomic::PayloadChecksum>,
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
    encoded.extend_from_slice(&DECISION_SPECULATIVE.to_be_bytes());
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
        if let Some(checksum) = participant.payload_checksum {
            encoded.extend_from_slice(&checksum.offset.to_be_bytes());
            encoded.extend_from_slice(&checksum.len.to_be_bytes());
            encoded.extend_from_slice(&checksum.checksum.to_be_bytes());
        } else {
            encoded.extend_from_slice(&participant.payload_start.to_be_bytes());
            encoded.extend_from_slice(&[0u8; 12]);
        }
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
    if cursor.read_u32()? != DECISION_SPECULATIVE {
        return Err(invalid_data("coordinator decision kind is invalid"));
    }
    if participant_count > MAX_RECORDS || removal_count > MAX_RECORDS {
        return Err(invalid_data("coordinator has too many records"));
    }
    const MIN_PARTICIPANT_LEN: usize = 4 + 4 + 8 + 8 + atomic::ROOT_LEN * 2 + PAYLOAD_CHECKSUM_LEN;
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
        let payload_offset = cursor.read_u64()?;
        let payload_len = cursor.read_u64()?;
        let payload_checksum = cursor.read_u32()?;
        let payload_checksum = match (payload_len, payload_checksum) {
            (0, 0) => None,
            (len, checksum) if len != 0 => Some(atomic::PayloadChecksum {
                offset: payload_offset,
                len,
                checksum,
            }),
            _ => {
                return Err(invalid_data(
                    "coordinator payload checksum has an invalid empty range",
                ));
            }
        };
        if payload_checksum
            .as_ref()
            .is_some_and(|checksum| checksum.offset != payload_offset)
        {
            return Err(invalid_data(
                "coordinator payload checksum start is inconsistent",
            ));
        }
        participants.push(Participant {
            partition,
            name,
            candidate: atomic::Candidate {
                base_generation,
                root_offset,
                prepared_root,
                committed_root,
            },
            payload_start: payload_offset,
            payload_checksum,
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
    if participants.len() > MAX_SPECULATIVE_PARTICIPANTS {
        return Err(invalid_data(
            "speculative batch decision has too many participants",
        ));
    }
    let verified_bytes = participants.iter().try_fold(0u64, |total, participant| {
        total
            .checked_add(
                participant
                    .payload_checksum
                    .as_ref()
                    .map_or(0, |checksum| checksum.len),
            )
            .ok_or_else(|| invalid_data("speculative payload length overflow"))
    })?;
    if verified_bytes > MAX_SPECULATIVE_BYTES {
        return Err(invalid_data(
            "speculative batch payload exceeds the recovery bound",
        ));
    }
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

fn validate_operation_participants(
    participants: &[Participant],
    operations: &[Operation],
) -> io::Result<()> {
    let mut operations = operations.iter().filter_map(|operation| match operation {
        Operation::Publish { partition, name }
        | Operation::Resize {
            partition, name, ..
        } => Some((partition.as_str(), name.as_slice())),
        Operation::Remove(_) => None,
    });
    for participant in participants {
        loop {
            match operations.next() {
                Some(operation) if operation < participant.key() => continue,
                Some(operation) if operation == participant.key() => break,
                _ => {
                    return Err(invalid_input(
                        "storage batch participant has no matching write operation",
                    ));
                }
            }
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

struct ReadStates {
    states: Vec<State>,
    max_generation: u64,
}

fn read_states(file: &File) -> io::Result<ReadStates> {
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
    let max_generation = roots.first().map_or(0, |(root, _, _)| root.generation);

    let mut invalid_committed = None;
    let mut states = Vec::with_capacity(roots.len() + usize::from(has_zero_slot));
    for (root, offset, encoded) in roots {
        if root.descriptor_len == 0 {
            states.push(State::Idle(Some(Publication {
                root,
                offset,
                record: encoded.to_vec(),
            })));
            continue;
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
        states.push(State::Committed(
            Publication {
                root,
                offset,
                record,
            },
            decision,
        ));
    }
    if has_zero_slot {
        states.push(State::Idle(None));
    }
    if !states.is_empty() {
        return Ok(ReadStates {
            states,
            max_generation,
        });
    }
    Err(invalid_committed.unwrap_or_else(|| invalid_data("coordinator has no recoverable root")))
}

fn read_state(file: &File) -> io::Result<State> {
    read_states(file)?
        .states
        .into_iter()
        .next()
        .ok_or_else(|| invalid_data("coordinator has no recoverable root"))
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

fn open_participant(root: &Path, participant: &Participant) -> io::Result<File> {
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
    Ok(file)
}

fn inspect_participant(root: &Path, participant: &Participant) -> io::Result<Option<File>> {
    let path = root
        .join(&participant.partition)
        .join(hex(&participant.name));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => {
            return Err(invalid_data(
                "coordinator participant is not a regular file",
            ));
        }
        Err(error) if path_is_missing(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    if metadata.len() < 6 {
        return Ok(None);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let mut prefix = [0u8; 6];
    read_exact_at(&file, 0, &mut prefix)?;
    if &prefix[..4] != b"CWIL" || u16::from_be_bytes(prefix[4..6].try_into().unwrap()) != 2 {
        return Ok(None);
    }
    validate_v2_header(&file)?;
    Ok(Some(file))
}

fn materialize_participant(root: &Path, participant: &Participant) -> io::Result<()> {
    let file = open_participant(root, participant)?;
    atomic::materialize_candidate(
        &file,
        super::super::Layout::V2.data_offset(),
        &participant.candidate,
    )
}

fn validate_speculative_participant(
    root: &Path,
    participant: &Participant,
    embedded_descriptor: Option<&[u8]>,
) -> io::Result<bool> {
    let file = match open_participant(root, participant) {
        Ok(file) => file,
        Err(error)
            if path_is_missing(&error)
                || matches!(
                    error.kind(),
                    ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    if let Some(descriptor) = embedded_descriptor
        && !atomic::candidate_has_embedded_batch_witness(&file, &participant.candidate, descriptor)?
    {
        return Ok(false);
    }
    let metadata = match atomic::validate_candidate(
        &file,
        super::super::Layout::V2.data_offset(),
        &participant.candidate,
    ) {
        Ok(metadata) => metadata,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::InvalidData | ErrorKind::UnexpectedEof
            ) =>
        {
            return Ok(false);
        }
        Err(error) => return Err(error),
    };
    match atomic::validate_payload_checksum(
        &file,
        super::super::Layout::V2.data_offset(),
        &metadata,
        participant.payload_start,
        participant.payload_checksum.as_ref(),
    ) {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::InvalidData | ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn validate_speculative_decision(
    root: &Path,
    decision: &Decision,
    descriptor: &[u8],
) -> io::Result<bool> {
    for participant in &decision.participants {
        if !validate_speculative_participant(root, participant, Some(descriptor))? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
fn install_participants(root: &Path, participants: &[Participant]) -> io::Result<()> {
    for participant in participants {
        materialize_participant(root, participant)?;
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
                .map(|participant| scope.spawn(move || materialize_participant(root, participant)))
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
    retire_after_generation: u64,
    removals: &[RemoveTarget],
) -> io::Result<Option<PathBuf>> {
    for (index, target) in removals.iter().enumerate() {
        remove_target(root, root_record.generation, index, target)?;
    }
    if !removals.is_empty() {
        sync_removals(root, root_record.generation, removals)?;
    }
    let idle_generation = retire_after_generation
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
    retire_after_generation: u64,
    decision: &Decision,
) -> io::Result<()> {
    install_participants(root, &decision.participants)?;
    let removal_path = finish_namespace(
        file,
        root,
        root_record,
        retire_after_generation,
        &decision.removals,
    )?;
    reclaim_removals(root, removal_path)
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
                4 + 4 + 8 + 8 + atomic::ROOT_LEN * 2 + PAYLOAD_CHECKSUM_LEN,
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

/// Return whether a write-only group fits the bounded speculative recovery path.
pub(crate) fn supports_speculation(
    operations: &[Operation],
    participant_count: usize,
    verified_bytes: u64,
) -> bool {
    participant_count != 0
        && participant_count <= MAX_SPECULATIVE_PARTICIPANTS
        && verified_bytes <= MAX_SPECULATIVE_BYTES
        && operations
            .iter()
            .all(|operation| !matches!(operation, Operation::Remove(_)))
}

/// Encode an exact speculative decision for duplication inside every participant root slot.
pub(crate) fn prepare_embedded(
    participants: &[Participant],
    operations: &[Operation],
) -> io::Result<Vec<u8>> {
    preflight(operations)?;
    if operations
        .iter()
        .any(|operation| matches!(operation, Operation::Remove(_)))
    {
        return Err(invalid_input(
            "removal-bearing batches require namespace publication",
        ));
    }
    validate_operation_participants(participants, operations)?;
    validate_decision(participants, &[]).map_err(|error| {
        if error.kind() == ErrorKind::InvalidData {
            invalid_input(error.to_string())
        } else {
            error
        }
    })?;
    let verified_bytes = participants.iter().try_fold(0u64, |total, participant| {
        total.checked_add(
            participant
                .payload_checksum
                .as_ref()
                .map_or(0, |checksum| checksum.len),
        )
    });
    if !supports_speculation(
        operations,
        participants.len(),
        verified_bytes.ok_or_else(|| invalid_input("speculative payload length overflow"))?,
    ) {
        return Err(invalid_input(
            "storage batch is not eligible for embedded publication",
        ));
    }
    encode_descriptor(participants, operations)
}

/// Return whether a new exact group can replace the preceding embedded decision in two slots.
pub(crate) fn can_supersede_embedded(
    encoded: &[u8],
    participants: &[Participant],
) -> io::Result<bool> {
    let previous = decode_descriptor(encoded)?;
    if !previous.removals.is_empty() {
        return Err(invalid_data("embedded decision is not speculative"));
    }
    Ok(previous.participants.len() == participants.len()
        && previous
            .participants
            .iter()
            .zip(participants)
            .all(|(previous, current)| {
                previous.key() == current.key()
                    && previous.candidate.root_offset != current.candidate.root_offset
                    && previous.candidate.base_generation.checked_add(1)
                        == Some(current.candidate.base_generation)
            }))
}

/// Install a successfully completed embedded decision before its participant set changes.
pub(crate) fn materialize_embedded(root: &Path, encoded: &[u8]) -> io::Result<()> {
    let decision = decode_descriptor(encoded)?;
    if !decision.removals.is_empty() {
        return Err(invalid_data("embedded decision is not speculative"));
    }
    install_participants(root, &decision.participants)
}

/// Resolve participant-embedded decisions before opening one V2 blob's logical state.
///
/// A decision becomes authoritative only when every exact participant retains the same descriptor,
/// candidate metadata, and bounded payload CRC32C. Invalid newest candidates are skipped so the
/// other root slot remains a complete fallback. The local descriptor names every peer directly, so
/// this does not require application transaction state or a namespace scan.
pub(crate) fn recover_embedded(
    root: &Path,
    partition: &str,
    name: &[u8],
    file: &File,
    data_offset: u64,
) -> io::Result<()> {
    for embedded in atomic::embedded_batch_candidates(file, data_offset)? {
        let decision = match decode_descriptor(&embedded.descriptor) {
            Ok(decision) if decision.removals.is_empty() => decision,
            Ok(_) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some(local) = decision
            .participants
            .iter()
            .find(|participant| participant.partition == partition && participant.name == name)
        else {
            continue;
        };
        if local.candidate != embedded.candidate {
            continue;
        }
        if !atomic::candidate_has_embedded_batch_witness(
            file,
            &embedded.candidate,
            &embedded.descriptor,
        )? {
            continue;
        }
        let mut install_started = atomic::candidate_is_committed(file, &embedded.candidate)?;
        let mut witnesses_complete = true;
        for participant in &decision.participants {
            let participant_file = match open_participant(root, participant) {
                Ok(file) => file,
                Err(error)
                    if path_is_missing(&error)
                        || matches!(
                            error.kind(),
                            ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                        ) =>
                {
                    witnesses_complete = false;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if !atomic::candidate_has_embedded_batch_witness(
                &participant_file,
                &participant.candidate,
                &embedded.descriptor,
            )? {
                witnesses_complete = false;
                continue;
            }
            install_started |=
                atomic::candidate_is_committed(&participant_file, &participant.candidate)?
                    || atomic::candidate_is_materialized(
                        &participant_file,
                        &participant.candidate,
                    )?;
        }
        if install_started {
            if !witnesses_complete {
                return Err(invalid_data(
                    "partially materialized embedded group lost a participant witness",
                ));
            }
            install_participants(root, &decision.participants)?;
            return Ok(());
        }

        let mut complete = true;
        for participant in &decision.participants {
            if !validate_speculative_participant(root, participant, Some(&embedded.descriptor))? {
                complete = false;
                break;
            }
        }
        if complete {
            install_participants(root, &decision.participants)?;
            return Ok(());
        }
    }
    recover_materialized_witnesses(root, partition, name, file)
}

fn recover_named_embedded(root: &Path, partition: &str, name: &[u8]) -> io::Result<()> {
    let path = root.join(partition).join(hex(name));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Ok(()),
        Err(error) if path_is_missing(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    if metadata.len() < 6 {
        return Ok(());
    }
    let inspected = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let mut prefix = [0u8; 6];
    read_exact_at(&inspected, 0, &mut prefix)?;
    if &prefix[..4] != b"CWIL" || u16::from_be_bytes(prefix[4..6].try_into().unwrap()) != 2 {
        return Ok(());
    }
    let inspected_metadata = inspected.metadata()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let writable_metadata = file.metadata()?;
    if inspected_metadata.dev() != writable_metadata.dev()
        || inspected_metadata.ino() != writable_metadata.ino()
    {
        return Err(invalid_data("removal target changed during recovery"));
    }
    validate_v2_header(&file)?;
    recover_embedded(
        root,
        partition,
        name,
        &file,
        super::super::Layout::V2.data_offset(),
    )
}

/// Use a materialized participant's retained descriptor to make any dependent peers independent.
///
/// This transfer runs before the local participant can fence or remove the retained witness.
fn recover_materialized_witnesses(
    root: &Path,
    partition: &str,
    name: &[u8],
    file: &File,
) -> io::Result<()> {
    let data_offset = super::super::Layout::V2.data_offset();
    for embedded in atomic::materialized_batch_candidates(file, data_offset)? {
        let decision = match decode_descriptor(&embedded.descriptor) {
            Ok(decision) if decision.removals.is_empty() => decision,
            Ok(_) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        let Some(local) = decision
            .participants
            .iter()
            .find(|participant| participant.partition == partition && participant.name == name)
        else {
            continue;
        };
        if local.candidate != embedded.candidate
            || !atomic::candidate_has_embedded_batch_witness(
                file,
                &embedded.candidate,
                &embedded.descriptor,
            )?
        {
            continue;
        }

        let mut dependent = Vec::new();
        for participant in &decision.participants {
            let participant_file = match inspect_participant(root, participant)? {
                Some(file) => file,
                None => continue,
            };
            if !atomic::candidate_is_materialized(&participant_file, &participant.candidate)?
                && atomic::candidate_has_embedded_batch_witness(
                    &participant_file,
                    &participant.candidate,
                    &embedded.descriptor,
                )?
            {
                dependent.push(participant.clone());
            }
        }
        install_participants(root, &dependent)?;
    }
    Ok(())
}

fn recover_partition_embedded(root: &Path, partition: &str) -> io::Result<()> {
    let path = root.join(partition);
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_dir() => {}
        Ok(_) => return Ok(()),
        Err(error) if path_is_missing(&error) => return Ok(()),
        Err(error) => return Err(error),
    }
    let entries = match fs::read_dir(&path) {
        Ok(entries) => entries,
        Err(error) if path_is_missing(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    for entry in entries {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        let file_name = entry.file_name();
        if atomic::is_creation_file_name(&file_name) {
            continue;
        }
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some(name) = from_hex(file_name) else {
            continue;
        };
        if hex(&name) != file_name {
            continue;
        }
        recover_named_embedded(root, partition, &name)?;
    }
    Ok(())
}

/// Materialize embedded decisions before removing any participant that may witness them.
pub(crate) fn recover_removal_witnesses(root: &Path, operations: &[Operation]) -> io::Result<()> {
    for operation in operations {
        let Operation::Remove(target) = operation else {
            continue;
        };
        match target {
            RemoveTarget::Blob { partition, name } => {
                recover_named_embedded(root, partition, name)?;
            }
            RemoveTarget::Partition(partition) => {
                recover_partition_embedded(root, partition)?;
            }
        }
    }
    Ok(())
}

/// A prepared removal-bearing namespace publication.
pub(crate) struct RemovalPublication(RemovalPublicationInner);

enum RemovalPublicationInner {
    Durable {
        root: PathBuf,
        file: File,
        publication: Publication,
        decision: Decision,
        operations: Vec<Operation>,
    },
    /// The entire storage root is already absent, so removals need no crash witness.
    Satisfied { operations: Vec<Operation> },
}

impl RemovalPublication {
    /// Exact descriptor that mixed-batch participants must carry as their witness.
    pub(crate) fn descriptor(&self) -> &[u8] {
        match self {
            Self(RemovalPublicationInner::Durable { publication, .. }) => {
                &publication.record[ROOT_LEN..]
            }
            Self(RemovalPublicationInner::Satisfied { .. }) => &[],
        }
    }

    /// Durably publish this descriptor after participant staging begins.
    pub(crate) fn persist(&self) -> io::Result<()> {
        match &self.0 {
            RemovalPublicationInner::Durable {
                file, publication, ..
            } => atomic::write_durable_at(file, publication.offset, &publication.record),
            RemovalPublicationInner::Satisfied { .. } => Ok(()),
        }
    }

    /// Notify and idempotently materialize a durably persisted removal decision.
    pub(crate) fn finish<C>(self, on_commit: C) -> io::Result<()>
    where
        C: FnOnce(&[Operation]),
    {
        let RemovalPublicationInner::Durable {
            root,
            file,
            publication,
            decision: prepared_decision,
            operations,
        } = self.0
        else {
            let RemovalPublicationInner::Satisfied { operations } = self.0 else {
                unreachable!()
            };
            on_commit(&operations);
            return Ok(());
        };
        let state = read_state(&file)?;
        let State::Committed(current, decision) = state else {
            return Err(invalid_data("removal publication is not durable"));
        };
        if current.root.generation != publication.root.generation
            || current.record != publication.record
            || decision != prepared_decision
        {
            return Err(invalid_data(
                "durable removal publication does not match its preparation",
            ));
        }

        on_commit(&operations);
        finish_decision(
            &file,
            &root,
            current.root,
            current.root.generation,
            &decision,
        )
    }
}

/// Prepare a speculative removal publication for a concurrent durability stage.
pub(crate) fn prepare_removal_publication(
    root: &Path,
    participants: &[Participant],
    operations: &[Operation],
) -> io::Result<RemovalPublication> {
    preflight(operations)?;
    let removals = operations
        .iter()
        .filter_map(|operation| match operation {
            Operation::Remove(target) => Some(target.clone()),
            Operation::Publish { .. } | Operation::Resize { .. } => None,
        })
        .collect::<Vec<_>>();
    if removals.is_empty() {
        return Err(invalid_input(
            "namespace publication requires at least one removal",
        ));
    }
    validate_operation_participants(participants, operations)?;
    validate_decision(participants, &removals).map_err(|error| {
        if error.kind() == ErrorKind::InvalidData {
            invalid_input(error.to_string())
        } else {
            error
        }
    })?;

    let metadata = match fs::metadata(root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound && participants.is_empty() => {
            return Ok(RemovalPublication(RemovalPublicationInner::Satisfied {
                operations: operations.to_vec(),
            }));
        }
        Err(error) => return Err(error),
    };
    if !metadata.is_dir() {
        return Err(invalid_data("storage batch root is not a directory"));
    }
    let file = open_or_create(root)?;
    let state = read_state(&file)?;
    let current_generation = state.generation();
    let generation = match state {
        State::Idle(_) => current_generation
            .checked_add(1)
            .ok_or_else(|| invalid_data("coordinator generation overflow"))?,
        State::Committed(_, _) => {
            return Err(invalid_data(
                "a committed removal decision must be recovered first",
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
    let encoded_root = encode_root(generation, &descriptor)?;
    let root_record = decode_root(&encoded_root).expect("newly encoded coordinator root is valid");
    let mut record = Vec::with_capacity(ROOT_LEN + descriptor.len());
    record.extend_from_slice(&encoded_root);
    record.extend_from_slice(&descriptor);
    let publication = Publication {
        root: root_record,
        offset: ROOT_OFFSETS[(generation as usize) & 1],
        record,
    };
    Ok(RemovalPublication(RemovalPublicationInner::Durable {
        root: root.to_path_buf(),
        file,
        publication,
        decision: Decision {
            participants: participants.to_vec(),
            removals,
        },
        operations: operations.to_vec(),
    }))
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
    let ReadStates {
        states,
        max_generation,
    } = read_states(&file)?;
    let mut rejected_speculation = false;
    let mut on_commit = Some(on_commit);
    for state in states {
        match state {
            State::Idle(publication) => {
                if rejected_speculation {
                    let idle_generation = max_generation
                        .checked_add(2)
                        .ok_or_else(|| invalid_data("coordinator generation overflow"))?;
                    let idle_root = encode_root(idle_generation, &[])?;
                    // Fence the rejected record in its own parity slot. The older idle slot must
                    // remain intact if this repair is itself torn by another crash.
                    return atomic::write_durable_at(
                        &file,
                        ROOT_OFFSETS[(idle_generation as usize) & 1],
                        &idle_root,
                    );
                }
                return State::Idle(publication).stabilize(&file);
            }
            State::Committed(publication, decision) => {
                let descriptor = publication
                    .record
                    .get(ROOT_LEN..)
                    .expect("committed records contain their descriptor");
                if decision.removals.is_empty()
                    || !validate_speculative_decision(root, &decision, descriptor)?
                {
                    rejected_speculation = true;
                    continue;
                }
                atomic::write_durable_at(&file, publication.offset, &publication.record)?;
                let operations = decision.operations();
                on_commit
                    .take()
                    .expect("coordinator recovery commits at most one decision")(
                    &operations
                );
                return finish_decision(&file, root, publication.root, max_generation, &decision);
            }
        }
    }
    Err(invalid_data(
        "coordinator has no recoverable decision after speculative validation",
    ))
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
    let publication = prepare_removal_publication(root, &[], operations)?;
    publication.persist()?;
    Err(io::Error::other("injected coordinator interruption"))
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
    let publication = prepare_removal_publication(root, &[], operations)?;
    publication.persist()?;
    on_commit(operations);
    Err(io::Error::other(
        "injected coordinator materialization failure",
    ))
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

    fn write_prepared(file: &File, prepared: &atomic::PreparedCommit) {
        if !prepared.manifest.is_empty() {
            file.write_all_at(&prepared.manifest, prepared.manifest_offset)
                .unwrap();
        }
        file.write_all_at(&prepared.prepared_root, prepared.root_offset)
            .unwrap();
    }

    fn write_payload(file: &File, state: &mut atomic::State, offset: u64, data: &[u8]) {
        let prepared = state
            .prepare_write(offset, IoBufs::from(data.to_vec()), None)
            .unwrap()
            .unwrap();
        file.write_all_at(
            prepared.data.as_single().unwrap().as_ref(),
            prepared.file_offset,
        )
        .unwrap();
        state.finish_mutation(prepared.mutation);
    }

    fn commit_state(file: &File, state: &mut atomic::State) {
        let prepared = state.prepare_commit().unwrap().unwrap();
        write_prepared(file, &prepared);
        file.sync_all().unwrap();
        atomic::write_durable_at(file, prepared.root_offset, &prepared.committed_root).unwrap();
        state.finish_commit(prepared);
    }

    fn read_blob_state(file: &File, state: &atomic::State) -> Vec<u8> {
        let mut output = vec![0u8; state.logical_len() as usize];
        for span in state.read_plan(0, output.len()).unwrap() {
            match span.source {
                atomic::ReadSource::Zero => {
                    output[span.destination..span.destination + span.len].fill(0);
                }
                atomic::ReadSource::File(offset) => file
                    .read_exact_at(
                        &mut output[span.destination..span.destination + span.len],
                        offset,
                    )
                    .unwrap(),
            }
        }
        output
    }

    fn prepared_group_parts(
        label: &str,
    ) -> (
        PathBuf,
        Vec<File>,
        Vec<Participant>,
        Vec<Operation>,
        Vec<atomic::PreparedCommit>,
    ) {
        let root = test_root(label);
        let partition_path = root.join("group");
        fs::create_dir_all(&partition_path).unwrap();
        let mut files = Vec::new();
        let mut participants = Vec::new();
        let mut operations = Vec::new();
        let mut prepared_commits = Vec::new();

        for (name, old, new) in [
            (
                b"first".as_slice(),
                b"old-1".as_slice(),
                b"new-1".as_slice(),
            ),
            (
                b"second".as_slice(),
                b"old-2".as_slice(),
                b"new-2".as_slice(),
            ),
        ] {
            let live_path = partition_path.join(hex(name));
            let region = Header::create_atomic(&(0..=0)).0;
            let file = atomic::create_live(&root, "group", name, &live_path, &region).unwrap();
            let mut state =
                atomic::State::recover(&file, super::super::super::Layout::V2.data_offset())
                    .unwrap();
            write_payload(&file, &mut state, 0, old);
            commit_state(&file, &mut state);
            write_payload(&file, &mut state, old.len() as u64, new);
            let mut prepared = state.prepare_commit().unwrap().unwrap();
            prepared.mark_batch_prepared();
            let atomic::PayloadChecksumEligibility::Eligible(payload_checksum) =
                prepared.payload_checksum()
            else {
                panic!("contiguous append must be speculatively verifiable");
            };
            participants.push(Participant {
                partition: "group".into(),
                name: name.to_vec(),
                candidate: prepared.candidate(),
                payload_start: prepared.payload_start(),
                payload_checksum,
            });
            operations.push(Operation::Publish {
                partition: "group".into(),
                name: name.to_vec(),
            });
            files.push(file);
            prepared_commits.push(prepared);
        }
        (root, files, participants, operations, prepared_commits)
    }

    fn prepared_speculative_group(
        label: &str,
    ) -> (PathBuf, Vec<File>, Vec<Participant>, Vec<Operation>) {
        let (root, files, participants, operations, prepared_commits) = prepared_group_parts(label);
        let descriptor = prepare_embedded(&participants, &operations).unwrap();
        for (file, mut prepared) in files.iter().zip(prepared_commits) {
            prepared.attach_batch_witness(&descriptor).unwrap();
            write_prepared(file, &prepared);
        }
        (root, files, participants, operations)
    }

    fn prepared_removal_group(
        label: &str,
    ) -> (
        PathBuf,
        Vec<File>,
        Vec<Participant>,
        RemovalPublication,
        PathBuf,
    ) {
        let (root, files, participants, mut operations, prepared_commits) =
            prepared_group_parts(label);
        let victim_partition = root.join("victim");
        fs::create_dir(&victim_partition).unwrap();
        let victim = victim_partition.join(hex(b"old"));
        fs::write(&victim, b"remove me").unwrap();
        operations.push(Operation::Remove(RemoveTarget::Blob {
            partition: "victim".into(),
            name: b"old".to_vec(),
        }));
        let publication = prepare_removal_publication(&root, &participants, &operations).unwrap();
        for (file, mut prepared) in files.iter().zip(prepared_commits) {
            prepared
                .attach_batch_witness(publication.descriptor())
                .unwrap();
            write_prepared(file, &prepared);
        }
        (root, files, participants, publication, victim)
    }

    #[test]
    fn descriptor_round_trip_is_bounded_and_canonical() {
        let participants = vec![
            Participant {
                partition: "alpha".into(),
                name: b"one".to_vec(),
                candidate: candidate(1),
                payload_start: 100,
                payload_checksum: Some(atomic::PayloadChecksum {
                    offset: 100,
                    len: 10,
                    checksum: 123,
                }),
            },
            Participant {
                partition: "beta".into(),
                name: b"two".to_vec(),
                candidate: candidate(2),
                payload_start: 0,
                payload_checksum: None,
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

    #[test]
    fn publication_surfaces_reject_the_wrong_operation_shape() {
        let removal = vec![Operation::Remove(RemoveTarget::Partition("victim".into()))];
        assert_eq!(
            prepare_embedded(&[], &removal).unwrap_err().kind(),
            ErrorKind::InvalidInput
        );

        let write = vec![Operation::Resize {
            partition: "group".into(),
            name: b"blob".to_vec(),
            len: 1,
        }];
        assert_eq!(
            prepare_removal_publication(Path::new("unused"), &[], &write)
                .err()
                .expect("write-only publication must be rejected")
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn speculative_recovery_commits_only_a_complete_group() {
        let (root, files, _participants, _operations) =
            prepared_speculative_group("speculative-complete");
        for file in &files {
            file.sync_all().unwrap();
        }

        let (result, read_bytes) = atomic::track_read_bytes(|| {
            recover_embedded(
                &root,
                "group",
                b"first",
                &files[0],
                super::super::super::Layout::V2.data_offset(),
            )
        });
        result.unwrap();
        assert!(read_bytes < 64 * 1024);
        for (file, expected) in files.iter().zip([b"old-1new-1", b"old-2new-2"]) {
            let state = atomic::State::recover(file, super::super::super::Layout::V2.data_offset())
                .unwrap();
            assert_eq!(read_blob_state(file, &state), expected);
        }
        let (result, reopened_reads) = atomic::track_read_bytes(|| {
            recover_embedded(
                &root,
                "group",
                b"first",
                &files[0],
                super::super::super::Layout::V2.data_offset(),
            )
        });
        result.unwrap();
        assert!(reopened_reads < 32 * 1024);

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn speculative_recovery_is_atomic_for_every_participant_persistence_subset() {
        const PAYLOAD: u8 = 1;
        const WITNESS: u8 = 2;
        const COMPLETE: u8 = PAYLOAD | WITNESS;

        for first_state in 0..=COMPLETE {
            for second_state in 0..=COMPLETE {
                for opener in 0..2 {
                    let label =
                        format!("speculative-subset-{first_state}-{second_state}-open-{opener}");
                    let (root, files, participants, _operations) =
                        prepared_speculative_group(&label);
                    let persisted = [first_state, second_state];
                    for ((file, participant), state) in
                        files.iter().zip(&participants).zip(persisted)
                    {
                        if state & WITNESS == 0 {
                            file.write_all_at(&[0u8; 4096], participant.candidate.root_offset)
                                .unwrap();
                        }
                        if state & PAYLOAD == 0 {
                            file.set_len(participant.payload_start).unwrap();
                        }
                        file.sync_all().unwrap();
                    }

                    recover_embedded(
                        &root,
                        "group",
                        participants[opener].name.as_slice(),
                        &files[opener],
                        super::super::super::Layout::V2.data_offset(),
                    )
                    .unwrap();
                    recover_embedded(
                        &root,
                        "group",
                        participants[1 - opener].name.as_slice(),
                        &files[1 - opener],
                        super::super::super::Layout::V2.data_offset(),
                    )
                    .unwrap();

                    let committed = persisted == [COMPLETE, COMPLETE];
                    let expected: [&[u8]; 2] = if committed {
                        [b"old-1new-1", b"old-2new-2"]
                    } else {
                        [b"old-1", b"old-2"]
                    };
                    for (file, expected) in files.iter().zip(expected) {
                        let state = atomic::State::recover(
                            file,
                            super::super::super::Layout::V2.data_offset(),
                        )
                        .unwrap();
                        assert_eq!(read_blob_state(file, &state), expected, "{label}");
                    }
                    assert!(!coordinator_path(&root).exists(), "{label}");

                    drop(files);
                    fs::remove_dir_all(root).unwrap();
                }
            }
        }
    }

    #[test]
    fn partial_embedded_materialization_converges_the_whole_group() {
        let (root, files, participants, _operations) =
            prepared_speculative_group("speculative-partial-materialization");
        for file in &files {
            file.sync_all().unwrap();
        }
        let descriptor = atomic::embedded_batch_candidates(
            &files[0],
            super::super::super::Layout::V2.data_offset(),
        )
        .unwrap()
        .remove(0)
        .descriptor;
        for participant in &participants {
            assert!(
                validate_speculative_participant(&root, participant, Some(&descriptor)).unwrap()
            );
        }

        // Simulate a crash after only the first validated participant was durably installed.
        atomic::install_candidate(
            &files[0],
            super::super::super::Layout::V2.data_offset(),
            &participants[0].candidate,
        )
        .unwrap();
        assert!(atomic::candidate_is_committed(&files[0], &participants[0].candidate).unwrap());
        assert!(!atomic::candidate_is_committed(&files[1], &participants[1].candidate).unwrap());

        recover_embedded(
            &root,
            "group",
            b"first",
            &files[0],
            super::super::super::Layout::V2.data_offset(),
        )
        .unwrap();

        for ((file, participant), expected) in files
            .iter()
            .zip(&participants)
            .zip([b"old-1new-1", b"old-2new-2"])
        {
            assert!(atomic::candidate_is_materialized(file, &participant.candidate).unwrap());
            assert!(
                atomic::embedded_batch_candidates(
                    file,
                    super::super::super::Layout::V2.data_offset()
                )
                .unwrap()
                .is_empty()
            );
            let state = atomic::State::recover(file, super::super::super::Layout::V2.data_offset())
                .unwrap();
            assert_eq!(read_blob_state(file, &state), expected);
        }

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn reopening_a_materialized_participant_converges_the_whole_group() {
        let (root, files, participants, _operations) =
            prepared_speculative_group("speculative-materialized-opener");
        for file in &files {
            file.sync_all().unwrap();
        }

        // Production materialization uses a distinct independently recoverable root spelling.
        // Reopening that participant must transfer its retained witness before another local
        // commit can fence the group decision.
        atomic::materialize_candidate(
            &files[0],
            super::super::super::Layout::V2.data_offset(),
            &participants[0].candidate,
        )
        .unwrap();
        assert!(atomic::candidate_is_materialized(&files[0], &participants[0].candidate).unwrap());
        assert!(!atomic::candidate_is_materialized(&files[1], &participants[1].candidate).unwrap());

        recover_embedded(
            &root,
            "group",
            b"first",
            &files[0],
            super::super::super::Layout::V2.data_offset(),
        )
        .unwrap();

        for (file, participant) in files.iter().zip(&participants) {
            assert!(atomic::candidate_is_materialized(file, &participant.candidate).unwrap());
        }

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn removal_retry_transfers_a_materialized_witness_before_delete() {
        let (root, files, participants, _operations) =
            prepared_speculative_group("materialized-removal-retry");
        for file in &files {
            file.sync_all().unwrap();
        }

        // Simulate the first crash after the removal target became independently recoverable,
        // but before its peer was materialized.
        atomic::materialize_candidate(
            &files[0],
            super::super::super::Layout::V2.data_offset(),
            &participants[0].candidate,
        )
        .unwrap();
        assert!(atomic::candidate_is_materialized(&files[0], &participants[0].candidate).unwrap());
        assert!(!atomic::candidate_is_materialized(&files[1], &participants[1].candidate).unwrap());

        recover_removal_witnesses(
            &root,
            &[Operation::Remove(RemoveTarget::Blob {
                partition: "group".into(),
                name: b"first".to_vec(),
            })],
        )
        .unwrap();

        // A retry must transfer the target's witness before unlinking it. A second crash after
        // the unlink must still leave the acknowledged peer independently recoverable.
        assert!(atomic::candidate_is_materialized(&files[1], &participants[1].candidate).unwrap());
        fs::remove_file(root.join("group").join(hex(b"first"))).unwrap();
        let recovered =
            atomic::State::recover(&files[1], super::super::super::Layout::V2.data_offset())
                .unwrap();
        assert_eq!(read_blob_state(&files[1], &recovered), b"old-2new-2");

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_materialized_witness_ignores_a_recreated_legacy_peer() {
        let (root, files, participants, _operations) =
            prepared_speculative_group("materialized-recreated-legacy-peer");
        for file in &files {
            file.sync_all().unwrap();
        }
        recover_embedded(
            &root,
            "group",
            b"first",
            &files[0],
            super::super::super::Layout::V2.data_offset(),
        )
        .unwrap();
        for (file, participant) in files.iter().zip(&participants) {
            assert!(atomic::candidate_is_materialized(file, &participant.candidate).unwrap());
        }

        let second_path = root.join("group").join(hex(b"second"));
        fs::remove_file(&second_path).unwrap();
        fs::write(&second_path, Header::create(&(0..=0)).0).unwrap();

        recover_removal_witnesses(
            &root,
            &[Operation::Remove(RemoveTarget::Blob {
                partition: "group".into(),
                name: b"first".to_vec(),
            })],
        )
        .unwrap();

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn one_bad_speculative_payload_rolls_back_every_participant() {
        let (root, files, participants, _operations) =
            prepared_speculative_group("speculative-rollback");
        for file in &files {
            file.sync_all().unwrap();
        }
        let corrupt_offset = participants[1].payload_checksum.unwrap().offset;
        files[1].write_all_at(&[0xff], corrupt_offset).unwrap();
        files[1].sync_all().unwrap();

        let (result, durable_writes) = atomic::track_durable_writes(|| {
            recover_embedded(
                &root,
                "group",
                b"first",
                &files[0],
                super::super::super::Layout::V2.data_offset(),
            )
        });
        result.unwrap();
        assert!(durable_writes.is_empty(), "no participant may be installed");
        for (file, expected) in files.iter().zip([b"old-1".as_slice(), b"old-2".as_slice()]) {
            let state = atomic::State::recover(file, super::super::super::Layout::V2.data_offset())
                .unwrap();
            assert_eq!(read_blob_state(file, &state), expected);
        }

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mixed_removal_recovery_commits_the_complete_group() {
        let (root, files, _participants, publication, victim) =
            prepared_removal_group("removal-complete");
        for file in &files {
            file.sync_all().unwrap();
        }
        publication.persist().unwrap();
        drop(publication);

        recover(&root).unwrap();
        assert!(!victim.exists());
        for (file, expected) in files.iter().zip([b"old-1new-1", b"old-2new-2"]) {
            let state = atomic::State::recover(file, super::super::super::Layout::V2.data_offset())
                .unwrap();
            assert_eq!(read_blob_state(file, &state), expected);
        }

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn retired_removal_durably_materializes_every_participant() {
        let (root, files, participants, publication, victim) =
            prepared_removal_group("removal-retired-durable-participants");
        for file in &files {
            file.sync_all().unwrap();
        }
        publication.persist().unwrap();
        let (result, durable_records) =
            atomic::track_durable_records(|| publication.finish(|_| {}));
        result.unwrap();
        assert!(!victim.exists());

        recover(&root).unwrap();
        for ((file, participant), expected) in files
            .iter()
            .zip(&participants)
            .zip([b"old-1new-1", b"old-2new-2"])
        {
            let mut materialized = [0u8; atomic::ROOT_LEN];
            read_exact_at(file, participant.candidate.root_offset, &mut materialized).unwrap();
            assert!(atomic::candidate_is_materialized(file, &participant.candidate).unwrap());
            assert!(durable_records.iter().any(|(offset, record)| {
                *offset == participant.candidate.root_offset && record == &materialized
            }));
            let state = atomic::State::recover(file, super::super::super::Layout::V2.data_offset())
                .unwrap();
            assert_eq!(read_blob_state(file, &state), expected);
        }

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn bad_mixed_payload_rolls_back_writes_and_removal() {
        let (root, files, participants, publication, victim) =
            prepared_removal_group("removal-rollback");
        for file in &files {
            file.sync_all().unwrap();
        }
        let corrupt_offset = participants[1].payload_checksum.unwrap().offset;
        files[1].write_all_at(&[0xff], corrupt_offset).unwrap();
        files[1].sync_all().unwrap();
        publication.persist().unwrap();
        drop(publication);

        recover(&root).unwrap();
        assert!(victim.exists());
        for (file, expected) in files.iter().zip([b"old-1".as_slice(), b"old-2".as_slice()]) {
            let state = atomic::State::recover(file, super::super::super::Layout::V2.data_offset())
                .unwrap();
            assert_eq!(read_blob_state(file, &state), expected);
        }

        drop(files);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejected_speculation_fences_its_own_slot() {
        let (root, files, participants, publication, _victim) =
            prepared_removal_group("removal-rejection-fence");
        for file in &files {
            file.sync_all().unwrap();
        }
        let corrupt_offset = participants[1].payload_checksum.unwrap().offset;
        files[1].write_all_at(&[0xff], corrupt_offset).unwrap();
        files[1].sync_all().unwrap();
        let rejected_offset = match &publication.0 {
            RemovalPublicationInner::Durable { publication, .. } => publication.offset,
            RemovalPublicationInner::Satisfied { .. } => unreachable!(),
        };
        publication.persist().unwrap();
        drop(publication);

        let (result, durable_records) = atomic::track_durable_records(|| recover(&root));
        result.unwrap();
        assert_eq!(durable_records.len(), 1);
        assert_eq!(durable_records[0].0, rejected_offset);

        drop(files);
        fs::remove_dir_all(root).unwrap();
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
    fn pure_removal_persists_then_finishes() {
        let root = test_root("pure-removal-finish");
        let partition = root.join("group");
        fs::create_dir_all(&partition).unwrap();
        let name = b"victim";
        let blob = partition.join(hex(name));
        fs::write(&blob, b"old").unwrap();
        let operations = vec![Operation::Remove(RemoveTarget::Blob {
            partition: "group".into(),
            name: name.to_vec(),
        })];
        let publication = prepare_removal_publication(&root, &[], &operations).unwrap();

        let (result, durable_writes) = atomic::track_durable_writes(|| publication.persist());
        result.unwrap();
        assert_eq!(durable_writes.len(), 1);
        publication
            .finish(|committed| assert_eq!(committed, operations.as_slice()))
            .unwrap();
        assert!(!blob.exists());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn durable_partition_removal_replays_and_is_idempotent() {
        let root = test_root("partition-tombstone");
        let victim = root.join("victim");
        fs::create_dir_all(&victim).unwrap();
        for index in 0..128 {
            fs::write(victim.join(format!("blob-{index}")), [index as u8; 64]).unwrap();
        }
        let operations = vec![Operation::Remove(RemoveTarget::Partition("victim".into()))];
        assert!(interrupt_committed_for_test(&root, &operations, 0).is_err());

        let notified = std::cell::Cell::new(false);
        recover_notifying(&root, |recovered| {
            assert_eq!(recovered, operations.as_slice());
            notified.set(true);
        })
        .unwrap();
        assert!(notified.get());
        assert!(!victim.exists());
        let tombstone = removal_directory(&root, 1);
        assert!(!tombstone.exists());
        recover_notifying(&root, |_| panic!("idle recovery must not notify")).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}

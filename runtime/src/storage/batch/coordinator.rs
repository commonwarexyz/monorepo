//! Participant-replicated crash recovery for atomic storage batches.
//!
//! There is no coordinator file. Every dirty V2 participant stores the same canonical descriptor
//! beside its prepared root. The descriptor identifies each exact path creation with a persistent
//! 128-bit incarnation, names its candidate root, and covers any newly appended payload with a
//! bounded CRC32C. Deleted blobs are participants too.
//!
//! ```text
//!       blob A root slot                    blob B root slot
//! +---------------------------+       +---------------------------+
//! | P root | descriptor A,B,C |<----->| P root | descriptor A,B,C |
//! +---------------------------+       +---------------------------+
//!             \                            /
//!              +-- concurrent barriers ---+
//!                         |
//!                    durable decision
//!                         |
//!             +-----------+-----------+
//!             |                       |
//!       retained: P -> M         deleted: P -> T
//!       independent root         payload-preserving tombstone
//!             |                       |
//!             +----- all durable -----+
//!                         |
//!               unlink exact T names
//!               fsync parent directories
//! ```
//!
//! `P` roots are invisible to ordinary blob recovery. `M` roots expose retained candidates as
//! independent blobs. `T` roots remain invisible and preserve the old inode's payload for already
//! open handles. The implementation writes all `M` and `T` roots before the first unlink, and a
//! deletion-bearing batch keeps the namespace and participant guards until the unlinks and parent
//! directory syncs finish. Write-only batches may keep their replicated decision for the next
//! same-participant batch instead of materializing immediately.
//!
//! The canonical `CWUNOD12` descriptor has this logical layout. Names carry unsigned 32-bit
//! lengths, and participants and removals are independently canonicalized.
//!
//! ```text
//! descriptor  = header | participant* | removal*
//! header      = magic | participant_count | removal_count | decision_kind
//! participant = partition | name | incarnation | base_generation | root_slot
//!             | prepared_root | committed_root
//!             | payload_start | payload_length | payload_crc32c
//! ```
//!
//! # Recovery
//!
//! Opening one V2 participant reads only its immutable page and two fixed root slots. An intact
//! witness names every peer directly, so no application transaction identifier, coordinator file,
//! payload scan, or root-wide namespace scan is needed. Partition scans inspect bounded V2 root
//! metadata before returning names so they cannot expose a surviving tombstone.
//!
//! With no exact `M` or `T` root, recovery commits only if every exact incarnation, candidate,
//! descriptor, and required payload suffix validates. Otherwise the other root slot remains the
//! complete fallback. A missing participant alone never proves commitment: an independent remove
//! could erase one member of an incomplete prepare. Once any exact `M` or `T` exists, all barriers
//! necessarily completed, so recovery repairs every surviving exact witness and rolls forward.
//! Missing or differently incarnated delete paths are already applied or recreated and are never
//! unlinked. A later serialized namespace operation may also retire a retained participant after
//! making the group independent; its stale descriptor is safely ignored.
//!
//! Materialization overwrites only the 40-byte root header. Candidate validation accepts any
//! bytewise mixture of the exact `P`, committed, `M`, and `T` spellings, so a crash may retain an
//! arbitrary subset of an in-flight root overwrite rather than a prefix. The checksummed descriptor
//! is decoded independently from that header, allowing another final participant to repair a torn
//! peer. Unlinks begin only after every final-root durability operation returns.
//!
//! The configured recovery cap is 32 dirty participants, but the root slot is tighter: the current
//! encoding fits at most 28 even with empty names, and real names or removals lower that bound. At
//! most 64 MiB of payload is revalidated across a group. Larger or non-contiguous pending append
//! epochs are preflushed before roots are staged. CRC32C detects accidental local-disk crash
//! corruption probabilistically; it does not authenticate storage against an actor that can also
//! rewrite checksums.

use super::{Operation, is_canonical_operations};
use crate::{RemoveTarget, storage::atomic};
use commonware_formatting::{from_hex, hex};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind},
    os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::Path,
};

const DESCRIPTOR_MAGIC: &[u8; 8] = b"CWUNOD12";
const MAX_DESCRIPTOR_LEN: usize = 4096 - atomic::ROOT_LEN - 16;
const MAX_RECORDS: usize = 1_000_000;
const DESCRIPTOR_HEADER_LEN: usize = 20;
const PARTICIPANT_FIXED_LEN: usize = 4
    + 4
    + super::super::header::Header::V2_INCARNATION_LEN
    + 8
    + 8
    + atomic::ROOT_LEN * 2
    + PAYLOAD_CHECKSUM_LEN;
const BLOB_REMOVAL_FIXED_LEN: usize = 1 + 4 + 4;
const TAG_PARTITION_REMOVE: u8 = 0;
const TAG_BLOB_REMOVE: u8 = 1;
const DECISION_SPECULATIVE: u32 = 1;
const PAYLOAD_CHECKSUM_LEN: usize = 8 + 8 + 4;
const MAX_SPECULATIVE_PARTICIPANTS: usize =
    super::super::atomic::MAX_SPECULATIVE_PARTICIPANTS as usize;
const MAX_SPECULATIVE_BYTES: u64 = atomic::MAX_VALIDATED_PAYLOAD_LEN;

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn checked_end(offset: u64, len: u64) -> io::Result<u64> {
    offset
        .checked_add(len)
        .ok_or_else(|| invalid_data("batch descriptor offset overflow"))
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
                "batch descriptor record is truncated",
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
    pub(crate) incarnation: [u8; super::super::header::Header::V2_INCARNATION_LEN],
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
        return Err(invalid_input("batch descriptor has too many records"));
    }
    let removals = operations
        .iter()
        .filter_map(|operation| match operation {
            Operation::Remove(target) => Some(target),
            Operation::Publish { .. } | Operation::Rewind { .. } => None,
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
            "batch participant partition name",
        )?;
        encoded.extend_from_slice(participant.partition.as_bytes());
        push_len(
            &mut encoded,
            participant.name.len(),
            "batch participant blob name",
        )?;
        encoded.extend_from_slice(&participant.name);
        encoded.extend_from_slice(&participant.incarnation);
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
                push_len(
                    &mut encoded,
                    partition.len(),
                    "batch removal partition name",
                )?;
                encoded.extend_from_slice(partition.as_bytes());
            }
            RemoveTarget::Blob { partition, name } => {
                encoded.push(TAG_BLOB_REMOVE);
                push_len(
                    &mut encoded,
                    partition.len(),
                    "batch removal partition name",
                )?;
                encoded.extend_from_slice(partition.as_bytes());
                push_len(&mut encoded, name.len(), "batch removal blob name")?;
                encoded.extend_from_slice(name);
            }
        }
    }
    if encoded.len() > MAX_DESCRIPTOR_LEN {
        return Err(invalid_input("batch descriptor is too large"));
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
            .ok_or_else(|| invalid_data("batch descriptor length overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_data("batch descriptor is truncated"))?;
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
        let bytes = self.read_vec("batch partition")?;
        String::from_utf8(bytes).map_err(|_| invalid_data("batch partition is not UTF-8"))
    }
}

fn decode_descriptor(encoded: &[u8]) -> io::Result<Decision> {
    if encoded.len() < DESCRIPTOR_HEADER_LEN || encoded.len() > MAX_DESCRIPTOR_LEN {
        return Err(invalid_data("batch descriptor has an invalid length"));
    }
    let mut cursor = Cursor::new(encoded);
    if cursor.read(DESCRIPTOR_MAGIC.len())? != DESCRIPTOR_MAGIC {
        return Err(invalid_data("batch descriptor magic mismatch"));
    }
    let participant_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| invalid_data("batch participant count overflow"))?;
    let removal_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| invalid_data("batch removal count overflow"))?;
    if cursor.read_u32()? != DECISION_SPECULATIVE {
        return Err(invalid_data("batch decision kind is invalid"));
    }
    if participant_count > MAX_RECORDS || removal_count > MAX_RECORDS {
        return Err(invalid_data("batch descriptor has too many records"));
    }
    const MIN_PARTICIPANT_LEN: usize = 4
        + 4
        + super::super::header::Header::V2_INCARNATION_LEN
        + 8
        + 8
        + atomic::ROOT_LEN * 2
        + PAYLOAD_CHECKSUM_LEN;
    const MIN_REMOVAL_LEN: usize = 1 + 4;
    let minimum = participant_count
        .checked_mul(MIN_PARTICIPANT_LEN)
        .and_then(|len| len.checked_add(removal_count.saturating_mul(MIN_REMOVAL_LEN)))
        .ok_or_else(|| invalid_data("batch descriptor record count overflow"))?;
    if minimum > encoded.len() - DESCRIPTOR_HEADER_LEN {
        return Err(invalid_data("batch record count exceeds descriptor length"));
    }

    let mut participants = Vec::with_capacity(participant_count);
    for _ in 0..participant_count {
        let partition = cursor.read_partition()?;
        let name = cursor.read_vec("batch participant blob")?;
        let incarnation = cursor
            .read(super::super::header::Header::V2_INCARNATION_LEN)?
            .try_into()
            .expect("V2 incarnations have a fixed length");
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
                    "batch payload checksum has an invalid empty range",
                ));
            }
        };
        if payload_checksum
            .as_ref()
            .is_some_and(|checksum| checksum.offset != payload_offset)
        {
            return Err(invalid_data("batch payload checksum start is inconsistent"));
        }
        participants.push(Participant {
            partition,
            name,
            incarnation,
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
                name: cursor.read_vec("batch removal blob")?,
            },
            _ => return Err(invalid_data("batch removal tag is invalid")),
        };
        removals.push(target);
    }
    if cursor.position != encoded.len() {
        return Err(invalid_data("batch descriptor has trailing bytes"));
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
            .map_err(|_| invalid_data("batch participant has an invalid partition"))?;
        if let Some(previous) = previous
            && previous >= participant.key()
        {
            return Err(invalid_data("batch participants are not strictly ordered"));
        }
        previous = Some(participant.key());
    }

    let removal_operations = removals
        .iter()
        .cloned()
        .map(Operation::Remove)
        .collect::<Vec<_>>();
    let canonical = is_canonical_operations(&removal_operations)
        .map_err(|_| invalid_data("batch removals are invalid"))?;
    if !canonical {
        return Err(invalid_data("batch removals are not canonical"));
    }
    for participant in participants {
        if removals.iter().any(|target| {
            matches!(target, RemoveTarget::Partition(partition) if partition == &participant.partition)
        }) {
            return Err(invalid_data(
                "batch removes a partition containing a publication participant",
            ));
        }
    }
    Ok(())
}

fn validate_operation_participants(
    participants: &[Participant],
    operations: &[Operation],
) -> io::Result<()> {
    let mut matching_operations = operations.iter().filter_map(|operation| match operation {
        Operation::Publish { partition, name }
        | Operation::Rewind {
            partition, name, ..
        }
        | Operation::Remove(RemoveTarget::Blob { partition, name }) => {
            Some((partition.as_str(), name.as_slice()))
        }
        Operation::Remove(RemoveTarget::Partition(_)) => None,
    });
    for participant in participants {
        loop {
            match matching_operations.next() {
                Some(operation) if operation < participant.key() => continue,
                Some(operation) if operation == participant.key() => break,
                _ => {
                    return Err(invalid_input(
                        "storage batch participant has no matching blob operation",
                    ));
                }
            }
        }
    }
    for operation in operations {
        if matches!(operation, Operation::Remove(RemoveTarget::Partition(_))) {
            return Err(invalid_input(
                "atomic batch deletion requires an exact V2 blob participant",
            ));
        }
        if let Operation::Remove(RemoveTarget::Blob { partition, name }) = operation
            && !participants
                .iter()
                .any(|participant| participant.key() == (partition.as_str(), name.as_slice()))
        {
            return Err(invalid_input(
                "atomic batch deletion has no matching V2 participant",
            ));
        }
    }
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn validate_v2_header(
    file: &File,
) -> io::Result<[u8; super::super::header::Header::V2_INCARNATION_LEN]> {
    const IMMUTABLE_HEADER_LEN: usize = 4096;
    let mut header = [0u8; IMMUTABLE_HEADER_LEN];
    read_exact_at(file, 0, &mut header)?;
    let raw_len = file.metadata()?.len();
    let resolved = super::super::header::Header::parse(&header, raw_len, &(0..=u16::MAX))
        .map_err(|error| invalid_data(format!("batch participant header is invalid: {error:?}")))?;
    if resolved.2 != super::super::Layout::V2.data_offset() {
        return Err(invalid_data("batch participant is not a valid V2 blob"));
    }
    super::super::header::Header::atomic_incarnation(&header)
        .ok_or_else(|| invalid_data("batch participant has no V2 incarnation"))
}

fn inspect_participant(root: &Path, participant: &Participant) -> io::Result<Option<File>> {
    let path = root
        .join(&participant.partition)
        .join(hex(&participant.name));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if path_is_missing(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_file() {
        return Ok(None);
    }
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if path_is_missing(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let incarnation = match validate_v2_header(&file) {
        Ok(incarnation) => incarnation,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::InvalidData | ErrorKind::UnexpectedEof
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    if incarnation != participant.incarnation {
        return Ok(None);
    }
    Ok(Some(file))
}

fn open_participant(root: &Path, participant: &Participant) -> io::Result<File> {
    inspect_participant(root, participant)?
        .ok_or_else(|| invalid_data("batch participant is missing or has a different incarnation"))
}

fn participant_is_removed(decision: &Decision, participant: &Participant) -> bool {
    decision.removals.iter().any(|target| {
        matches!(
            target,
            RemoveTarget::Blob { partition, name }
                if partition == &participant.partition && name == &participant.name
        )
    })
}

fn materialize_decision_participant(
    root: &Path,
    decision: &Decision,
    participant: &Participant,
    descriptor: &[u8],
) -> io::Result<()> {
    let removed = participant_is_removed(decision, participant);
    let file = match inspect_participant(root, participant)? {
        Some(file) => file,
        None => return Ok(()),
    };
    if !atomic::candidate_has_embedded_batch_witness(&file, &participant.candidate, descriptor)? {
        // Once any final root proves the decision, a missing witness means this exact participant
        // was independently retired or replaced by a later namespace operation. Prepared and torn
        // installation roots retain the checksummed witness and are repaired here instead.
        return Ok(());
    }
    if removed {
        atomic::materialize_tombstone_candidate(
            &file,
            super::super::Layout::V2.data_offset(),
            &participant.candidate,
        )
    } else {
        atomic::materialize_candidate(
            &file,
            super::super::Layout::V2.data_offset(),
            &participant.candidate,
        )
    }
}

fn materialize_decision_participants(
    root: &Path,
    decision: &Decision,
    descriptor: &[u8],
) -> io::Result<()> {
    const MAX_INSTALL_WORKERS: usize = 32;
    for chunk in decision.participants.chunks(MAX_INSTALL_WORKERS) {
        std::thread::scope(|scope| {
            let handles = chunk
                .iter()
                .map(|participant| {
                    scope.spawn(move || {
                        materialize_decision_participant(root, decision, participant, descriptor)
                    })
                })
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

fn unlink_deleted_participants(
    root: &Path,
    decision: &Decision,
    descriptor: &[u8],
) -> io::Result<()> {
    let mut partitions = BTreeSet::new();
    for target in &decision.removals {
        let RemoveTarget::Blob { partition, name } = target else {
            return Err(invalid_data(
                "embedded decisions cannot remove entire partitions",
            ));
        };
        let participant = decision
            .participants
            .iter()
            .find(|participant| participant.partition == *partition && participant.name == *name)
            .ok_or_else(|| invalid_data("embedded deletion has no participant"))?;
        let path = root.join(partition).join(hex(name));
        let file = match open_participant(root, participant) {
            Ok(file) => file,
            Err(error) if path_is_missing(&error) => continue,
            Err(error)
                if matches!(
                    error.kind(),
                    ErrorKind::InvalidData | ErrorKind::UnexpectedEof
                ) =>
            {
                // The exact old incarnation was already unlinked and this path was recreated.
                continue;
            }
            Err(error) => return Err(error),
        };
        if !atomic::candidate_has_embedded_batch_witness(&file, &participant.candidate, descriptor)?
        {
            // A different incarnation at the same path belongs to a later open/create and must
            // never be removed by replay of this decision.
            continue;
        }
        if !atomic::candidate_is_tombstoned(&file, &participant.candidate)? {
            return Err(invalid_data(
                "embedded deletion participant is not durably tombstoned",
            ));
        }
        let opened = file.metadata()?;
        let current = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if path_is_missing(&error) => continue,
            Err(error) => return Err(error),
        };
        if opened.dev() != current.dev() || opened.ino() != current.ino() {
            continue;
        }
        fs::remove_file(&path)?;
        partitions.insert(root.join(partition));
        atomic::discard(root, partition, name)?;
    }
    for partition in partitions {
        sync_directory(&partition)?;
    }
    Ok(())
}

fn finish_embedded_decision(root: &Path, decision: &Decision, descriptor: &[u8]) -> io::Result<()> {
    materialize_decision_participants(root, decision, descriptor)?;
    unlink_deleted_participants(root, decision, descriptor)
}

fn validate_speculative_participant(
    root: &Path,
    participant: &Participant,
    removed: bool,
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
    let validation = if removed {
        atomic::validate_delete_candidate(
            &file,
            super::super::Layout::V2.data_offset(),
            &participant.candidate,
        )
    } else {
        atomic::validate_candidate(
            &file,
            super::super::Layout::V2.data_offset(),
            &participant.candidate,
        )
    };
    let metadata = match validation {
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

fn path_is_missing(error: &io::Error) -> bool {
    error.kind() == ErrorKind::NotFound || error.raw_os_error() == Some(libc::ENOENT)
}

/// Validate canonical operations and their encoded names before participant locking.
pub(crate) fn preflight(operations: &[Operation]) -> io::Result<()> {
    let canonical = is_canonical_operations(operations)
        .map_err(|_| invalid_input("storage batch contains an invalid operation"))?;
    if !canonical {
        return Err(invalid_input("storage batch operations are not canonical"));
    }
    if operations.len() > MAX_RECORDS {
        return Err(invalid_input("storage batch has too many operations"));
    }
    for operation in operations {
        let (partition, name) = match operation {
            Operation::Remove(RemoveTarget::Partition(partition)) => (partition, None),
            Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                (partition, Some(name.as_slice()))
            }
            Operation::Publish { partition, name }
            | Operation::Rewind {
                partition, name, ..
            } => (partition, Some(name.as_slice())),
        };
        u32::try_from(partition.len())
            .map_err(|_| invalid_input("storage batch partition name is too large"))?;
        if let Some(name) = name {
            u32::try_from(name.len())
                .map_err(|_| invalid_input("storage batch blob name is too large"))?;
        }
    }
    Ok(())
}

/// Validate the exact descriptor size before mutating any participant state.
pub(crate) fn preflight_descriptor<'a>(
    operations: &[Operation],
    participants: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> io::Result<()> {
    preflight(operations)?;
    let mut encoded_len = DESCRIPTOR_HEADER_LEN;
    for (partition, name) in participants {
        encoded_len = encoded_len
            .checked_add(PARTICIPANT_FIXED_LEN)
            .and_then(|len| len.checked_add(partition.len()))
            .and_then(|len| len.checked_add(name.len()))
            .ok_or_else(|| invalid_input("storage batch descriptor length overflow"))?;
    }
    for operation in operations {
        let removal_len = match operation {
            Operation::Remove(RemoveTarget::Partition(partition)) => {
                Some((1 + 4, partition.len(), 0))
            }
            Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                Some((BLOB_REMOVAL_FIXED_LEN, partition.len(), name.len()))
            }
            Operation::Publish { .. } | Operation::Rewind { .. } => None,
        };
        let Some((fixed, partition_len, name_len)) = removal_len else {
            continue;
        };
        encoded_len = encoded_len
            .checked_add(fixed)
            .and_then(|len| len.checked_add(partition_len))
            .and_then(|len| len.checked_add(name_len))
            .ok_or_else(|| invalid_input("storage batch descriptor length overflow"))?;
    }
    if encoded_len > MAX_DESCRIPTOR_LEN {
        return Err(invalid_input("storage batch descriptor is too large"));
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
            .all(|operation| !matches!(operation, Operation::Remove(RemoveTarget::Partition(_))))
}

/// Encode an exact speculative decision for duplication inside every participant root slot.
pub(crate) fn prepare_embedded(
    participants: &[Participant],
    operations: &[Operation],
) -> io::Result<Vec<u8>> {
    preflight(operations)?;
    validate_operation_participants(participants, operations)?;
    let removals = operations
        .iter()
        .filter_map(|operation| match operation {
            Operation::Remove(target) => Some(target.clone()),
            Operation::Publish { .. } | Operation::Rewind { .. } => None,
        })
        .collect::<Vec<_>>();
    validate_decision(participants, &removals).map_err(|error| {
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

/// Encode the self-contained decision used by the one-participant publication fast path.
pub(in crate::storage) fn prepare_single_publish(
    partition: &str,
    name: &[u8],
    incarnation: [u8; super::super::header::Header::V2_INCARNATION_LEN],
    prepared: &atomic::PreparedCommit,
) -> io::Result<(Participant, Vec<u8>)> {
    let atomic::PayloadChecksumEligibility::Eligible(payload_checksum) =
        prepared.payload_checksum()
    else {
        return Err(invalid_input(
            "single-participant publication payload is not recoverable",
        ));
    };
    let participant = Participant {
        partition: partition.to_string(),
        name: name.to_vec(),
        incarnation,
        candidate: prepared.candidate(),
        payload_start: prepared.payload_start(),
        payload_checksum,
    };
    let operations = [Operation::Publish {
        partition: participant.partition.clone(),
        name: participant.name.clone(),
    }];
    let descriptor = prepare_embedded(std::slice::from_ref(&participant), &operations)?;
    Ok((participant, descriptor))
}

/// Return whether a new exact group can replace the preceding embedded decision in two slots.
pub(crate) fn can_supersede_embedded(
    encoded: &[u8],
    participants: &[Participant],
) -> io::Result<bool> {
    let previous = decode_descriptor(encoded)?;
    if !previous.removals.is_empty() {
        return Ok(false);
    }
    Ok(previous.participants.len() == participants.len()
        && previous
            .participants
            .iter()
            .zip(participants)
            .all(|(previous, current)| {
                previous.key() == current.key()
                    && previous.incarnation == current.incarnation
                    && previous.candidate.root_offset != current.candidate.root_offset
                    && previous.candidate.base_generation.checked_add(1)
                        == Some(current.candidate.base_generation)
            }))
}

/// Install a successfully completed embedded decision before its participant set changes.
pub(crate) fn materialize_embedded(root: &Path, encoded: &[u8]) -> io::Result<()> {
    let decision = decode_descriptor(encoded)?;
    finish_embedded_decision(root, &decision, encoded)
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
) -> io::Result<bool> {
    let local_incarnation = validate_v2_header(file)?;
    let mut embedded_decisions = Vec::new();
    for embedded in atomic::embedded_batch_witnesses(file, data_offset)? {
        let decision = match decode_descriptor(&embedded.descriptor) {
            Ok(decision)
                if decision.removals.iter().all(|target| {
                    matches!(target, RemoveTarget::Blob { partition, name }
                    if decision.participants.iter().any(|participant| {
                        participant.partition == partition.as_str()
                            && participant.name == name.as_slice()
                    }))
                }) =>
            {
                decision
            }
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
        if local.incarnation != local_incarnation
            || local.candidate.root_offset != embedded.root_offset
        {
            continue;
        }
        if !atomic::candidate_has_embedded_batch_witness(
            file,
            &local.candidate,
            &embedded.descriptor,
        )? {
            continue;
        }
        embedded_decisions.push((
            local.candidate.base_generation,
            participant_is_removed(&decision, local),
            decision,
            embedded.descriptor,
        ));
    }
    embedded_decisions.sort_by_key(|(generation, _, _, _)| std::cmp::Reverse(*generation));

    for (_, local_deleted, decision, descriptor) in embedded_decisions {
        let mut install_started = false;
        for participant in &decision.participants {
            let removed = participant_is_removed(&decision, participant);
            let participant_file = match inspect_participant(root, participant)? {
                Some(file) => file,
                None if removed => continue,
                None => continue,
            };
            if !atomic::candidate_has_embedded_batch_witness(
                &participant_file,
                &participant.candidate,
                &descriptor,
            )? {
                continue;
            }
            if !removed {
                install_started |=
                    atomic::candidate_is_committed(&participant_file, &participant.candidate)?
                        || atomic::candidate_is_materialized(
                            &participant_file,
                            &participant.candidate,
                        )?;
            } else {
                install_started |=
                    atomic::candidate_is_tombstoned(&participant_file, &participant.candidate)?;
            }
        }
        if install_started {
            finish_embedded_decision(root, &decision, &descriptor)?;
            return Ok(local_deleted);
        }

        let mut complete = true;
        for participant in &decision.participants {
            if !validate_speculative_participant(
                root,
                participant,
                participant_is_removed(&decision, participant),
                Some(&descriptor),
            )? {
                complete = false;
                break;
            }
        }
        if complete {
            finish_embedded_decision(root, &decision, &descriptor)?;
            return Ok(local_deleted);
        }
    }
    recover_materialized_witnesses(root, partition, name, file)?;
    Ok(false)
}

pub(crate) fn recover_named_embedded(
    root: &Path,
    partition: &str,
    name: &[u8],
) -> io::Result<bool> {
    let path = root.join(partition).join(hex(name));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.file_type().is_file() => metadata,
        Ok(_) => return Ok(false),
        Err(error) if path_is_missing(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    if metadata.len() < 6 {
        return Ok(false);
    }
    let inspected = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)?;
    let mut prefix = [0u8; 6];
    read_exact_at(&inspected, 0, &mut prefix)?;
    if &prefix[..4] != b"CWIL" || u16::from_be_bytes(prefix[4..6].try_into().unwrap()) != 2 {
        return Ok(false);
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
            Ok(decision)
                if decision.removals.iter().all(|target| {
                    matches!(target, RemoveTarget::Blob { partition, name }
                    if decision.participants.iter().any(|participant| {
                        participant.partition == partition.as_str()
                            && participant.name == name.as_slice()
                    }))
                }) =>
            {
                decision
            }
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
        if local.incarnation != validate_v2_header(file)?
            || local.candidate != embedded.candidate
            || !atomic::candidate_has_embedded_batch_witness(
                file,
                &embedded.candidate,
                &embedded.descriptor,
            )?
        {
            continue;
        }

        finish_embedded_decision(root, &decision, &embedded.descriptor)?;
        break;
    }
    Ok(())
}

pub(crate) fn recover_partition_embedded(root: &Path, partition: &str) -> io::Result<()> {
    let partition = resolve_partition_name(root, partition)?;
    let path = root.join(&partition);
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
        recover_named_embedded(root, &partition, &name)?;
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

/// Coordinator-free decisions are discovered from the V2 participant being opened.
///
/// Startup has no global manifest to replay. Exact-name opens and partition scans call the
/// participant recovery entry points above, while an in-process carried decision is materialized
/// directly by the namespace owner.
pub(crate) const fn recover(_root: &Path) -> io::Result<()> {
    Ok(())
}

/// No global recovery notification is needed without a coordinator manifest.
pub(crate) fn recover_notifying<C>(_root: &Path, _on_commit: C) -> io::Result<()>
where
    C: FnOnce(&[Operation]),
{
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        IoBufs,
        storage::{Layout, header::Header},
    };
    use commonware_cryptography::{Crc32, Hasher as _};
    use std::{
        path::{Path, PathBuf},
        sync::atomic::{AtomicU64, Ordering},
    };

    const PARTITION: &str = "partition";
    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "commonware-coordinator-{label}-{}-{}",
                std::process::id(),
                NEXT_ROOT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(path.join(PARTITION)).unwrap();
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    struct TestBlob {
        name: Vec<u8>,
        incarnation: [u8; Header::V2_INCARNATION_LEN],
        path: PathBuf,
        file: File,
        state: atomic::State,
    }

    impl TestBlob {
        fn create(root: &Path, name: &[u8], incarnation_seed: u8, payload: &[u8]) -> Self {
            let (region, incarnation) = atomic_region(incarnation_seed);
            let path = root.join(PARTITION).join(hex(name));
            let file = atomic::create_live(root, PARTITION, name, &path, &region).unwrap();
            let state = atomic::State::recover(&file, data_offset()).unwrap();
            let mut blob = Self {
                name: name.to_vec(),
                incarnation,
                path,
                file,
                state,
            };
            if !payload.is_empty() {
                blob.append(payload);
                blob.commit();
            }
            blob
        }

        fn append(&mut self, payload: &[u8]) {
            let prepared = self
                .state
                .prepare_append(IoBufs::from(payload.to_vec()))
                .unwrap()
                .unwrap();
            self.file
                .write_all_at(payload, prepared.file_offset)
                .unwrap();
            self.state.finish_mutation(prepared.mutation, false);
        }

        fn commit(&mut self) {
            let prepared = self.state.prepare_commit().unwrap().unwrap();
            atomic::write_durable_at(&self.file, prepared.root_offset, &prepared.committed_root)
                .unwrap();
            if prepared.requires_truncate() {
                self.file.set_len(prepared.raw_len()).unwrap();
            }
            self.state.finish_commit(prepared);
        }

        fn raw_payload(&self) -> Vec<u8> {
            let len = usize::try_from(self.file.metadata().unwrap().len() - data_offset()).unwrap();
            let mut payload = vec![0; len];
            if len != 0 {
                self.file
                    .read_exact_at(&mut payload, data_offset())
                    .unwrap();
            }
            payload
        }

        fn recovered_payload(&self) -> Vec<u8> {
            let recovered = atomic::State::recover(&self.file, data_offset()).unwrap();
            let mut payload = vec![0; recovered.logical_len() as usize];
            if !payload.is_empty() {
                self.file
                    .read_exact_at(&mut payload, data_offset())
                    .unwrap();
            }
            payload
        }
    }

    enum Role {
        Retain(Vec<u8>),
        Delete,
    }

    struct StagedGroup {
        participants: Vec<Participant>,
        descriptor: Vec<u8>,
        decision: Decision,
        records: Vec<Vec<u8>>,
    }

    impl StagedGroup {
        fn write_mask(&self, blobs: &[TestBlob], mask: u64) {
            for (index, ((blob, participant), record)) in blobs
                .iter()
                .zip(&self.participants)
                .zip(&self.records)
                .enumerate()
            {
                if mask & (1 << index) == 0 {
                    continue;
                }
                blob.file
                    .write_all_at(record, participant.candidate.root_offset)
                    .unwrap();
                blob.file.sync_all().unwrap();
            }
        }

        fn write_all(&self, blobs: &[TestBlob]) {
            self.write_mask(blobs, (1 << blobs.len()) - 1);
        }
    }

    fn data_offset() -> u64 {
        Layout::V2.data_offset()
    }

    fn atomic_region(seed: u8) -> (Vec<u8>, [u8; Header::V2_INCARNATION_LEN]) {
        let (mut region, _) = Header::create_atomic(&(0..=0));
        let mut incarnation = [0; Header::V2_INCARNATION_LEN];
        for (index, byte) in incarnation.iter_mut().enumerate() {
            *byte = seed.wrapping_add(index as u8);
        }
        let incarnation_start = Header::PARSE_LEN;
        let incarnation_end = incarnation_start + incarnation.len();
        region[incarnation_start..incarnation_end].copy_from_slice(&incarnation);

        let mut checksum = Crc32::default();
        checksum.update(&region[..Header::PRELUDE_SIZE]);
        checksum.update(&incarnation);
        region[Header::PRELUDE_SIZE..Header::PARSE_LEN]
            .copy_from_slice(&checksum.finalize().1.as_u32().to_be_bytes());
        assert_eq!(Header::atomic_incarnation(&region), Some(incarnation));
        (region, incarnation)
    }

    fn stage_group(blobs: &mut [TestBlob], roles: &[Role]) -> StagedGroup {
        assert_eq!(blobs.len(), roles.len());
        let mut participants = Vec::with_capacity(blobs.len());
        let mut operations = Vec::with_capacity(blobs.len());
        let mut prepared = Vec::with_capacity(blobs.len());
        for (blob, role) in blobs.iter_mut().zip(roles) {
            let mut commit = match role {
                Role::Retain(payload) => {
                    blob.append(payload);
                    blob.state.prepare_commit().unwrap().unwrap()
                }
                Role::Delete => blob.state.prepare_delete().unwrap(),
            };
            commit.mark_batch_prepared();
            let payload_checksum = match commit.payload_checksum() {
                atomic::PayloadChecksumEligibility::Eligible(checksum) => checksum,
                atomic::PayloadChecksumEligibility::Ineligible => {
                    panic!("test payload unexpectedly ineligible for embedded recovery")
                }
            };
            participants.push(Participant {
                partition: PARTITION.to_string(),
                name: blob.name.clone(),
                incarnation: blob.incarnation,
                candidate: commit.candidate(),
                payload_start: commit.payload_start(),
                payload_checksum,
            });
            operations.push(match role {
                Role::Retain(_) => Operation::Publish {
                    partition: PARTITION.to_string(),
                    name: blob.name.clone(),
                },
                Role::Delete => Operation::Remove(RemoveTarget::Blob {
                    partition: PARTITION.to_string(),
                    name: blob.name.clone(),
                }),
            });
            prepared.push(commit);
        }

        let descriptor = if participants.len() == 1 && matches!(roles[0], Role::Retain(_)) {
            let (participant, descriptor) = prepare_single_publish(
                PARTITION,
                &blobs[0].name,
                blobs[0].incarnation,
                &prepared[0],
            )
            .unwrap();
            assert_eq!(participant, participants[0]);
            descriptor
        } else {
            prepare_embedded(&participants, &operations).unwrap()
        };
        for commit in &mut prepared {
            commit.attach_batch_witness(&descriptor).unwrap();
        }
        let records = prepared
            .into_iter()
            .map(|commit| commit.prepared_root)
            .collect();
        let decision = decode_descriptor(&descriptor).unwrap();
        StagedGroup {
            participants,
            descriptor,
            decision,
            records,
        }
    }

    fn read_candidate_root(
        blob: &TestBlob,
        candidate: &atomic::Candidate,
    ) -> [u8; atomic::ROOT_LEN] {
        let mut root = [0; atomic::ROOT_LEN];
        blob.file
            .read_exact_at(&mut root, candidate.root_offset)
            .unwrap();
        root
    }

    fn recover_from(root: &Path, blob: &TestBlob) -> bool {
        recover_embedded(root, PARTITION, &blob.name, &blob.file, data_offset()).unwrap()
    }

    fn assert_not_final(blob: &TestBlob, participant: &Participant, case: &str) {
        assert!(
            !atomic::candidate_is_materialized(&blob.file, &participant.candidate).unwrap(),
            "unexpected M root: {case}"
        );
        assert!(
            !atomic::candidate_is_tombstoned(&blob.file, &participant.candidate).unwrap(),
            "unexpected T root: {case}"
        );
    }

    #[test]
    fn a_recreated_incarnation_cannot_supersede_a_carried_group() {
        let root = TestRoot::new("supersede-incarnation");
        let mut blobs = vec![TestBlob::create(root.path(), b"a", 1, b"old")];
        let group = stage_group(&mut blobs, &[Role::Retain(b"-new".to_vec())]);
        let mut recreated = group.participants.clone();
        recreated[0].incarnation[0] ^= 0xff;
        recreated[0].candidate.base_generation += 1;
        recreated[0].candidate.root_offset += 1;

        assert!(!can_supersede_embedded(&group.descriptor, &recreated).unwrap());
    }

    #[test]
    fn incomplete_prepares_roll_back_and_missing_delete_is_not_a_decision() {
        for mask in 1..0b111 {
            let root = TestRoot::new("rollback");
            let mut blobs = vec![
                TestBlob::create(root.path(), b"a", 1, b"a-old"),
                TestBlob::create(root.path(), b"b", 21, b"b-old"),
                TestBlob::create(root.path(), b"c", 41, b"c-old"),
            ];
            let group = stage_group(
                &mut blobs,
                &[Role::Retain(b"-new".to_vec()), Role::Delete, Role::Delete],
            );
            group.write_mask(&blobs, mask);

            let local = usize::try_from(mask.trailing_zeros()).unwrap();
            assert!(!recover_from(root.path(), &blobs[local]), "mask {mask:03b}");
            for (blob, participant) in blobs.iter().zip(&group.participants) {
                assert!(blob.path.exists(), "mask {mask:03b}");
                assert_not_final(blob, participant, &format!("mask {mask:03b}"));
            }
            assert_eq!(blobs[0].recovered_payload(), b"a-old", "mask {mask:03b}");
            assert_eq!(blobs[1].recovered_payload(), b"b-old", "mask {mask:03b}");
            assert_eq!(blobs[2].recovered_payload(), b"c-old", "mask {mask:03b}");
        }

        let root = TestRoot::new("missing-delete");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 2, b"a-old"),
            TestBlob::create(root.path(), b"b", 22, b"b-old"),
            TestBlob::create(root.path(), b"c", 42, b"c-old"),
        ];
        let group = stage_group(
            &mut blobs,
            &[Role::Retain(b"-new".to_vec()), Role::Delete, Role::Delete],
        );
        group.write_all(&blobs);
        fs::remove_file(&blobs[2].path).unwrap();

        assert!(!recover_from(root.path(), &blobs[0]));
        assert!(blobs[0].path.exists());
        assert!(blobs[1].path.exists());
        assert!(!blobs[2].path.exists());
        assert_not_final(&blobs[0], &group.participants[0], "missing delete");
        assert_not_final(&blobs[1], &group.participants[1], "missing delete");
        assert_eq!(blobs[0].recovered_payload(), b"a-old");
        assert_eq!(blobs[1].recovered_payload(), b"b-old");
    }

    #[test]
    fn arbitrary_prepared_record_write_subsets_cannot_commit_a_group() {
        let root = TestRoot::new("prepared-record-subsets");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 7, b"a-old"),
            TestBlob::create(root.path(), b"b", 27, b"b-old"),
            TestBlob::create(root.path(), b"c", 47, b"c-old"),
        ];
        let group = stage_group(
            &mut blobs,
            &[Role::Retain(b"-new".to_vec()), Role::Delete, Role::Delete],
        );
        group.write_mask(&blobs, 0b101);

        let record = &group.records[1];
        let mut masks = (0..record.len())
            .map(|prefix| {
                (0..record.len())
                    .map(|index| index < prefix)
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        for missing in record
            .iter()
            .enumerate()
            .filter_map(|(index, byte)| (*byte != 0).then_some(index))
        {
            masks.push((0..record.len()).map(|index| index != missing).collect());
        }
        masks.push((0..record.len()).map(|index| index % 2 == 0).collect());
        masks.push((0..record.len()).map(|index| index % 3 == 1).collect());
        masks.push(
            (0..record.len())
                .map(|index| index.count_ones() % 2 == 0)
                .collect(),
        );

        for (case, mask) in masks.into_iter().enumerate() {
            let partial = record
                .iter()
                .zip(mask)
                .map(|(byte, retained)| if retained { *byte } else { 0 })
                .collect::<Vec<_>>();
            assert_ne!(partial, *record, "case {case} must be observably partial");
            blobs[1]
                .file
                .write_all_at(&partial, group.participants[1].candidate.root_offset)
                .unwrap();
            blobs[1].file.sync_all().unwrap();

            assert!(!recover_from(root.path(), &blobs[0]), "case {case}");
            for (blob, participant) in blobs.iter().zip(&group.participants) {
                assert!(blob.path.exists(), "case {case}");
                assert_not_final(blob, participant, &format!("case {case}"));
            }
        }
    }

    #[test]
    fn arbitrary_payload_write_subsets_cannot_publish_a_partial_group() {
        let root = TestRoot::new("payload-subsets");
        let old = b"a-old";
        let appended = [1, 2, 4, 8, 16, 32, 64, 128];
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 8, old),
            TestBlob::create(root.path(), b"b", 28, b"b-old"),
        ];
        let group = stage_group(
            &mut blobs,
            &[
                Role::Retain(appended.to_vec()),
                Role::Retain(b"-new".to_vec()),
            ],
        );
        group.write_all(&blobs);

        let append_offset = data_offset() + old.len() as u64;
        for mask in 0u16..(1 << appended.len()) - 1 {
            let survived = appended
                .iter()
                .enumerate()
                .map(
                    |(index, byte)| {
                        if mask & (1 << index) == 0 { 0 } else { *byte }
                    },
                )
                .collect::<Vec<_>>();
            blobs[0]
                .file
                .write_all_at(&survived, append_offset)
                .unwrap();
            assert!(
                !recover_from(root.path(), &blobs[0]),
                "payload survival mask {mask:08b}"
            );
        }

        assert_eq!(blobs[0].recovered_payload(), old);
        assert_eq!(blobs[1].recovered_payload(), b"b-old");
    }

    #[test]
    fn single_publish_rejects_arbitrary_payload_write_subsets() {
        let root = TestRoot::new("single-payload-subsets");
        let old = b"old";
        let appended = [1, 2, 4, 8, 16, 32, 64, 128];
        let mut blobs = vec![TestBlob::create(root.path(), b"a", 9, old)];
        let group = stage_group(&mut blobs, &[Role::Retain(appended.to_vec())]);
        group.write_all(&blobs);

        let append_offset = data_offset() + old.len() as u64;
        for mask in 0u16..(1 << appended.len()) - 1 {
            let survived = appended
                .iter()
                .enumerate()
                .map(
                    |(index, byte)| {
                        if mask & (1 << index) == 0 { 0 } else { *byte }
                    },
                )
                .collect::<Vec<_>>();
            blobs[0]
                .file
                .write_all_at(&survived, append_offset)
                .unwrap();
            assert!(
                !recover_from(root.path(), &blobs[0]),
                "payload survival mask {mask:08b}"
            );
        }

        assert_eq!(blobs[0].recovered_payload(), old);
    }

    #[test]
    fn all_delete_materializes_every_tombstone_before_unlink_and_preserves_open_payloads() {
        let root = TestRoot::new("all-delete");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 3, b"a-committed"),
            TestBlob::create(root.path(), b"b", 23, b"b-committed"),
            TestBlob::create(root.path(), b"c", 43, b"c-committed"),
        ];
        blobs[1].append(b"-pending");
        let expected = blobs.iter().map(TestBlob::raw_payload).collect::<Vec<_>>();
        let raw_lens = blobs
            .iter()
            .map(|blob| blob.file.metadata().unwrap().len())
            .collect::<Vec<_>>();
        let group = stage_group(&mut blobs, &[Role::Delete, Role::Delete, Role::Delete]);
        group.write_all(&blobs);

        materialize_decision_participants(root.path(), &group.decision, &group.descriptor).unwrap();
        for ((blob, participant), (payload, raw_len)) in blobs
            .iter()
            .zip(&group.participants)
            .zip(expected.iter().zip(&raw_lens))
        {
            assert!(blob.path.exists());
            assert!(atomic::candidate_is_tombstoned(&blob.file, &participant.candidate).unwrap());
            assert_eq!(blob.file.metadata().unwrap().len(), *raw_len);
            assert_eq!(&blob.raw_payload(), payload);
        }

        unlink_deleted_participants(root.path(), &group.decision, &group.descriptor).unwrap();
        for ((blob, participant), payload) in blobs.iter().zip(&group.participants).zip(&expected) {
            assert!(!blob.path.exists());
            assert!(atomic::candidate_is_tombstoned(&blob.file, &participant.candidate).unwrap());
            assert_eq!(&blob.raw_payload(), payload);
        }

        let recovery_root = TestRoot::new("all-delete-recovery");
        let mut recovery_blobs = vec![
            TestBlob::create(recovery_root.path(), b"a", 4, b"a-old"),
            TestBlob::create(recovery_root.path(), b"b", 24, b"b-old"),
        ];
        let recovery_group = stage_group(&mut recovery_blobs, &[Role::Delete, Role::Delete]);
        recovery_group.write_all(&recovery_blobs);
        assert!(recover_from(recovery_root.path(), &recovery_blobs[0]));
        for (blob, participant) in recovery_blobs.iter().zip(&recovery_group.participants) {
            assert!(!blob.path.exists());
            assert!(atomic::candidate_is_tombstoned(&blob.file, &participant.candidate).unwrap());
        }
    }

    #[test]
    fn a_nonprefix_torn_tombstone_still_proves_a_durable_delete_decision() {
        let root = TestRoot::new("torn-tombstone-authority");
        let mut blobs = vec![TestBlob::create(root.path(), b"a", 6, b"a-old")];
        let group = stage_group(&mut blobs, &[Role::Delete]);
        group.write_all(&blobs);

        let candidate = &group.participants[0].candidate;
        atomic::materialize_tombstone_candidate(&blobs[0].file, data_offset(), candidate).unwrap();
        let tombstone = read_candidate_root(&blobs[0], candidate);
        group.write_all(&blobs);

        let mut torn = candidate.prepared_root;
        let changed = torn
            .iter()
            .zip(tombstone)
            .position(|(prepared, tombstone)| *prepared != tombstone)
            .unwrap();
        torn[changed] = tombstone[changed];
        assert_ne!(torn, candidate.prepared_root);
        assert_ne!(torn, tombstone);
        blobs[0]
            .file
            .write_all_at(&torn, candidate.root_offset)
            .unwrap();
        blobs[0].file.sync_all().unwrap();
        assert!(
            atomic::candidate_has_embedded_batch_witness(
                &blobs[0].file,
                candidate,
                &group.descriptor,
            )
            .unwrap()
        );
        assert!(!atomic::candidate_is_tombstoned(&blobs[0].file, candidate).unwrap());

        assert!(recover_from(root.path(), &blobs[0]));
        assert!(!blobs[0].path.exists());
        assert!(atomic::candidate_is_tombstoned(&blobs[0].file, candidate).unwrap());
    }

    #[test]
    fn nonprefix_torn_final_roots_roll_forward_a_mixed_group() {
        let root = TestRoot::new("torn-mixed-authority");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 9, b"a-old"),
            TestBlob::create(root.path(), b"b", 29, b"b-old"),
        ];
        let group = stage_group(&mut blobs, &[Role::Retain(b"-new".to_vec()), Role::Delete]);
        group.write_all(&blobs);

        let retained = &group.participants[0].candidate;
        let materialized = atomic::materialized_candidate_root(retained).unwrap();
        let deleted = &group.participants[1].candidate;
        atomic::materialize_tombstone_candidate(&blobs[1].file, data_offset(), deleted).unwrap();
        let tombstone = read_candidate_root(&blobs[1], deleted);
        group.write_all(&blobs);

        for (blob, candidate, final_root) in [
            (&blobs[0], retained, materialized),
            (&blobs[1], deleted, tombstone),
        ] {
            let mut torn = candidate.prepared_root;
            let changed = torn
                .iter()
                .zip(final_root)
                .position(|(prepared, final_byte)| *prepared != final_byte)
                .unwrap();
            torn[changed] = final_root[changed];
            assert_ne!(torn, candidate.prepared_root);
            assert_ne!(torn, final_root);
            blob.file
                .write_all_at(&torn, candidate.root_offset)
                .unwrap();
            blob.file.sync_all().unwrap();
            assert!(
                atomic::candidate_has_embedded_batch_witness(
                    &blob.file,
                    candidate,
                    &group.descriptor,
                )
                .unwrap()
            );
        }
        assert!(!atomic::candidate_is_materialized(&blobs[0].file, retained).unwrap());
        assert!(!atomic::candidate_is_tombstoned(&blobs[1].file, deleted).unwrap());

        assert!(!recover_from(root.path(), &blobs[0]));
        assert!(atomic::candidate_is_materialized(&blobs[0].file, retained).unwrap());
        assert_eq!(blobs[0].recovered_payload(), b"a-old-new");
        assert!(!blobs[1].path.exists());
        assert!(atomic::candidate_is_tombstoned(&blobs[1].file, deleted).unwrap());
    }

    #[test]
    fn exact_final_witness_repairs_arbitrary_torn_delete_root() {
        let root = TestRoot::new("torn-final-root");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 5, b"a-old"),
            TestBlob::create(root.path(), b"b", 25, b"b-old"),
            TestBlob::create(root.path(), b"c", 45, b"c-old"),
        ];
        let group = stage_group(
            &mut blobs,
            &[Role::Retain(b"-new".to_vec()), Role::Delete, Role::Delete],
        );
        group.write_all(&blobs);

        let backups = [
            root.path().join(PARTITION).join(".test-backup-b"),
            root.path().join(PARTITION).join(".test-backup-c"),
        ];
        fs::hard_link(&blobs[1].path, &backups[0]).unwrap();
        fs::hard_link(&blobs[2].path, &backups[1]).unwrap();

        let candidate = &group.participants[2].candidate;
        let prepared = candidate.prepared_root;
        let materialized = atomic::materialized_candidate_root(candidate).unwrap();
        atomic::materialize_tombstone_candidate(&blobs[2].file, data_offset(), candidate).unwrap();
        let tombstone = read_candidate_root(&blobs[2], candidate);
        group.write_all(&blobs);

        let mut selectors = (0..=atomic::ROOT_LEN)
            .map(|split| {
                (0..atomic::ROOT_LEN)
                    .map(|index| {
                        if index < split {
                            0
                        } else if (index - split) % 2 == 0 {
                            1
                        } else {
                            2
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        selectors.push((0..atomic::ROOT_LEN).map(|index| index % 3).collect());
        selectors.push(
            (0..atomic::ROOT_LEN)
                .map(|index| (index * 7 + index / 5) % 3)
                .collect(),
        );
        selectors.push(
            (0..atomic::ROOT_LEN)
                .map(|index| index.count_ones() as usize % 3)
                .collect(),
        );

        for (case, selector) in selectors.into_iter().enumerate() {
            for (blob, backup) in blobs[1..].iter().zip(&backups) {
                if !blob.path.exists() {
                    fs::hard_link(backup, &blob.path).unwrap();
                }
            }
            group.write_all(&blobs);

            let mut torn = [0; atomic::ROOT_LEN];
            for (index, source) in selector.into_iter().enumerate() {
                torn[index] = match source {
                    0 => prepared[index],
                    1 => materialized[index],
                    2 => tombstone[index],
                    _ => unreachable!(),
                };
            }
            blobs[2]
                .file
                .write_all_at(&torn, candidate.root_offset)
                .unwrap();
            blobs[2].file.sync_all().unwrap();
            assert!(
                atomic::candidate_has_embedded_batch_witness(
                    &blobs[2].file,
                    candidate,
                    &group.descriptor,
                )
                .unwrap(),
                "case {case}"
            );

            if case % 2 == 0 {
                atomic::materialize_candidate(
                    &blobs[0].file,
                    data_offset(),
                    &group.participants[0].candidate,
                )
                .unwrap();
            } else {
                atomic::materialize_tombstone_candidate(
                    &blobs[1].file,
                    data_offset(),
                    &group.participants[1].candidate,
                )
                .unwrap();
            }

            assert!(!recover_from(root.path(), &blobs[0]), "case {case}");
            assert!(
                atomic::candidate_is_materialized(
                    &blobs[0].file,
                    &group.participants[0].candidate,
                )
                .unwrap(),
                "case {case}"
            );
            for (index, blob) in blobs.iter().enumerate().skip(1) {
                assert!(!blob.path.exists(), "case {case}");
                assert!(
                    atomic::candidate_is_tombstoned(
                        &blob.file,
                        &group.participants[index].candidate,
                    )
                    .unwrap(),
                    "case {case}, participant {index}"
                );
            }
            assert_eq!(blobs[0].recovered_payload(), b"a-old-new", "case {case}");
        }
    }

    #[test]
    fn stale_replay_preserves_recreated_incarnation_and_normal_recovery_is_bounded() {
        let root = TestRoot::new("recreated-incarnation");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 6, b"a-old"),
            TestBlob::create(root.path(), b"b", 26, b"b-old"),
        ];
        let group = stage_group(&mut blobs, &[Role::Retain(b"-new".to_vec()), Role::Delete]);
        group.write_all(&blobs);
        atomic::materialize_candidate(
            &blobs[0].file,
            data_offset(),
            &group.participants[0].candidate,
        )
        .unwrap();
        atomic::materialize_tombstone_candidate(
            &blobs[1].file,
            data_offset(),
            &group.participants[1].candidate,
        )
        .unwrap();
        fs::remove_file(&blobs[1].path).unwrap();

        let replacement = TestBlob::create(root.path(), b"b", 96, b"replacement");
        assert_ne!(replacement.incarnation, blobs[1].incarnation);
        assert!(!recover_from(root.path(), &blobs[0]));
        assert!(replacement.path.exists());
        assert_eq!(replacement.recovered_payload(), b"replacement");
        assert_eq!(
            validate_v2_header(&replacement.file).unwrap(),
            replacement.incarnation
        );
        assert!(
            atomic::candidate_is_tombstoned(&blobs[1].file, &group.participants[1].candidate,)
                .unwrap()
        );
        assert_eq!(blobs[1].raw_payload(), b"b-old");

        let bounded_root = TestRoot::new("bounded-recovery");
        let historical = vec![0x5a; 2 * 1024 * 1024];
        let blob = TestBlob::create(bounded_root.path(), b"large", 7, &historical);
        let raw_len = blob.file.metadata().unwrap().len();
        let (((removed, recovered), read_bytes), durable_writes) =
            atomic::track_durable_writes(|| {
                atomic::track_read_bytes(|| {
                    let removed =
                        recover_named_embedded(bounded_root.path(), PARTITION, &blob.name).unwrap();
                    let recovered = atomic::State::recover(&blob.file, data_offset()).unwrap();
                    (removed, recovered)
                })
            });
        assert!(!removed);
        assert_eq!(recovered.logical_len(), historical.len() as u64);
        assert_eq!(blob.file.metadata().unwrap().len(), raw_len);
        assert!(durable_writes.is_empty());
        let root_metadata_bound = 4 * 4096 + 2 * atomic::ROOT_LEN as u64;
        assert!(
            read_bytes <= root_metadata_bound,
            "normal recovery read {read_bytes} atomic bytes"
        );
        assert!(read_bytes < historical.len() as u64);
    }
}

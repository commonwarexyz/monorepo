//! Participant-linked crash recovery for atomic storage batches.
//!
//! There is no coordinator file. Every dirty V2 participant stores one checksummed local witness
//! beside its prepared root. The witness identifies the batch, describes only this participant's
//! exact candidate, and points to the next exact path incarnation. Participants are ordered
//! lexicographically by partition and then raw blob-name bytes before ordinals and successor links
//! are assigned. This canonical order forms one closed ring; deleted blobs participate with a
//! local removal bit.
//!
//! ```text
//!       blob A                    blob B                    blob C
//! +----------------+       +----------------+       +----------------+
//! | P | A state |--+------>| P | B state |--+------>| P | C state |--+
//! +----------------+       +----------------+       +----------------+ |
//!        ^                                                              |
//!        +--------------------------------------------------------------+
//!                         same group ID, count, ordinals
//! ```
//!
//! A `CWUNOL14` witness contains a fresh 128-bit group ID, participant count, canonical ordinal,
//! local removal bit, local incarnation and candidate roots, the bounded pending-payload CRC32C
//! range, and the successor's partition, blob name, and incarnation. The containing path supplies
//! the local name, so every participant path is encoded once across the whole ring rather than in
//! every root.
//!
//! # Recovery
//!
//! Opening one V2 participant follows exactly the ring's declared number of links. Recovery
//! requires the same group ID and count, consecutive ordinals, unique path incarnations,
//! lexicographically increasing participant keys, and closure back to the opener after exactly the
//! declared count. The count is decoded before traversal, and recovery grows its state only after
//! validating each exact successor. It never scans unrelated names or historical payload. A
//! missing, torn, duplicated, out-of-order, or differently incarnated link leaves a prepared (`P`)
//! root invisible, so ordinary root recovery selects the preceding slot.
//!
//! A complete ring commits only when every candidate root and bounded pending-payload suffix
//! validates. Once installation starts, a materialized (`M`) root or tombstone (`T`) proves that
//! every participant's prepare barrier completed, so the intact ring repairs all remaining roots.
//! Candidate validation accepts arbitrary bytewise mixtures of the exact `P`, committed, `M`, and
//! `T` spellings rather than assuming a prefix survived.
//!
//! Materialization writes and synchronizes every final root before the first unlink:
//!
//! ```text
//! complete durable ring
//!          |
//!          +---- retained: P -> M (independent visible root)
//!          |
//!          +---- deleted:  P -> T (payload-preserving tombstone)
//!          |
//!      every M/T durable
//!          |
//!      unlink T from highest ordinal to zero,
//!      synchronizing its parent after every unlink
//! ```
//!
//! The per-unlink directory barrier turns crash survivors into a prefix of that descending order.
//! Ordinal zero remains until every higher tombstone is durably gone, so it is a bounded recovery
//! anchor for the remaining forward-linked prefix. Every retained `M` root is already independent.
//! Recreated same-name paths are protected by their distinct immutable incarnations. Write-only
//! groups may retain their typed in-memory decision and materialize or supersede it before either
//! root slot is reused.
//!
//! Group membership has no UNO-specific limit and is not coupled to worker fanout; only the `u32`
//! count encoded in each link bounds the format. Each root stores only its local link (336 fixed
//! bytes plus at most 1,584 bytes for one successor path), with 1,920 bytes available in a 2 KiB
//! slot; there is no aggregate name-dependent metadata limit. Installation uses at most 32
//! concurrent workers while
//! processing larger rings in chunks. Total pending append bytes have no protocol batch limit. At
//! most 64 MiB is left for crash-time CRC32C validation across a group; larger epochs make older
//! immutable payload durable while writes continue. CRC32C detects accidental local-disk crash
//! corruption probabilistically and is not an authentication mechanism.

use super::{Operation, is_canonical_operations};
use crate::{RemoveTarget, storage::atomic};
use commonware_formatting::{from_hex, hex};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, ErrorKind},
    os::unix::fs::{FileExt as _, MetadataExt as _, OpenOptionsExt as _},
    path::Path,
    sync::Arc,
};

const LINK_MAGIC: &[u8; 8] = b"CWUNOL14";
const GROUP_ID_LEN: usize = 16;
const PARTICIPANT_CORE_LEN: usize = super::super::header::Header::V2_INCARNATION_LEN
    + 8
    + 8
    + atomic::ROOT_LEN * 2
    + PAYLOAD_CHECKSUM_LEN;
const LINK_REMOVED: u32 = 1;
const LINK_FIXED_LEN: usize = 8
    + GROUP_ID_LEN
    + 4
    + 4
    + 4
    + PARTICIPANT_CORE_LEN
    + 4
    + 4
    + super::super::header::Header::V2_INCARNATION_LEN;
const PAYLOAD_CHECKSUM_LEN: usize = 8 + 8 + 4;
const MAX_SPECULATIVE_BYTES: u64 = atomic::MAX_VALIDATED_PAYLOAD_LEN;

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, message.into())
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidInput, message.into())
}

fn reserve<T>(values: &mut Vec<T>, additional: usize, what: &str) -> io::Result<()> {
    values.try_reserve(additional).map_err(|_| {
        io::Error::new(
            ErrorKind::OutOfMemory,
            format!("unable to reserve memory for {what}"),
        )
    })
}

fn clone_bytes(bytes: &[u8], what: &str) -> io::Result<Vec<u8>> {
    let mut cloned = Vec::new();
    reserve(&mut cloned, bytes.len(), what)?;
    cloned.extend_from_slice(bytes);
    Ok(cloned)
}

fn clone_string(value: &str, what: &str) -> io::Result<String> {
    let bytes = clone_bytes(value.as_bytes(), what)?;
    Ok(String::from_utf8(bytes).expect("cloning a string preserves UTF-8"))
}

fn clone_participant(participant: &Participant) -> io::Result<Participant> {
    Ok(Participant {
        partition: clone_string(&participant.partition, "batch participant partition")?,
        name: clone_bytes(&participant.name, "batch participant name")?,
        incarnation: participant.incarnation,
        candidate: participant.candidate.clone(),
        payload_start: participant.payload_start,
        payload_checksum: participant.payload_checksum,
    })
}

fn clone_remove_target(target: &RemoveTarget) -> io::Result<RemoveTarget> {
    Ok(match target {
        RemoveTarget::Partition(partition) => {
            RemoveTarget::Partition(clone_string(partition, "batch removal partition")?)
        }
        RemoveTarget::Blob { partition, name } => RemoveTarget::Blob {
            partition: clone_string(partition, "batch removal partition")?,
            name: clone_bytes(name, "batch removal name")?,
        },
    })
}

fn clone_location(location: &Location) -> io::Result<Location> {
    Ok(Location {
        partition: clone_string(&location.partition, "batch participant location partition")?,
        name: clone_bytes(&location.name, "batch participant location name")?,
        incarnation: location.incarnation,
    })
}

fn clone_link(link: &Link) -> io::Result<Link> {
    Ok(Link {
        group_id: link.group_id,
        participant_count: link.participant_count,
        ordinal: link.ordinal,
        removed: link.removed,
        participant: clone_participant(&link.participant)?,
        next: clone_location(&link.next)?,
    })
}

fn checked_end(offset: u64, len: u64) -> io::Result<u64> {
    offset
        .checked_add(len)
        .ok_or_else(|| invalid_data("batch witness offset overflow"))
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
                "batch witness record is truncated",
            ));
        }
        offset = checked_end(offset, read as u64)?;
        output = &mut output[read..];
    }
    Ok(())
}

/// Per-blob durable candidate named by an exact batch decision.
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
    group_id: [u8; GROUP_ID_LEN],
    participants: Vec<Participant>,
    removals: Vec<RemoveTarget>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Location {
    partition: String,
    name: Vec<u8>,
    incarnation: [u8; super::super::header::Header::V2_INCARNATION_LEN],
}

impl Location {
    fn key(&self) -> (&str, &[u8]) {
        (&self.partition, &self.name)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Link {
    group_id: [u8; GROUP_ID_LEN],
    participant_count: usize,
    ordinal: usize,
    removed: bool,
    participant: Participant,
    next: Location,
}

/// One in-memory decision and the distinct local witness written beside each participant root.
#[derive(Clone)]
pub(crate) struct EmbeddedBatch {
    decision: Decision,
    witnesses: Arc<[LocalWitness]>,
}

struct LocalWitness {
    partition: String,
    name: Vec<u8>,
    encoded: Arc<[u8]>,
}

impl EmbeddedBatch {
    pub(crate) fn witness(&self, partition: &str, name: &[u8]) -> Option<&[u8]> {
        self.witnesses
            .binary_search_by(|witness| {
                witness
                    .partition
                    .as_str()
                    .cmp(partition)
                    .then_with(|| witness.name.as_slice().cmp(name))
            })
            .ok()
            .map(|index| self.witnesses[index].encoded.as_ref())
    }
}

fn push_len(encoded: &mut Vec<u8>, len: usize, what: &str) -> io::Result<()> {
    let len = u32::try_from(len).map_err(|_| invalid_input(format!("{what} is too large")))?;
    encoded.extend_from_slice(&len.to_be_bytes());
    Ok(())
}

fn encode_participant_core(encoded: &mut Vec<u8>, participant: &Participant) {
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

fn new_group_id() -> [u8; GROUP_ID_LEN] {
    let random = ahash::RandomState::new();
    let mut group_id = [0u8; GROUP_ID_LEN];
    group_id[..8].copy_from_slice(&random.hash_one(0u8).to_be_bytes());
    group_id[8..].copy_from_slice(&random.hash_one(1u8).to_be_bytes());
    group_id
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
            .ok_or_else(|| invalid_data("batch witness length overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or_else(|| invalid_data("batch witness is truncated"))?;
        self.position = end;
        Ok(bytes)
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

fn decode_participant_core(
    cursor: &mut Cursor<'_>,
    partition: String,
    name: Vec<u8>,
) -> io::Result<Participant> {
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
    Ok(Participant {
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
    })
}

fn encode_link(decision: &Decision, ordinal: usize) -> io::Result<Vec<u8>> {
    let participant_count = decision.participants.len();
    if participant_count == 0 {
        return Err(invalid_input("batch participant count is out of range"));
    }
    let participant = decision
        .participants
        .get(ordinal)
        .ok_or_else(|| invalid_input("batch link ordinal is out of range"))?;
    let next = &decision.participants[(ordinal + 1) % participant_count];
    let encoded_len = LINK_FIXED_LEN
        .checked_add(next.partition.len())
        .and_then(|len| len.checked_add(next.name.len()))
        .ok_or_else(|| invalid_input("batch participant link length overflow"))?;
    if encoded_len > atomic::MAX_BATCH_WITNESS_LEN {
        return Err(invalid_input(
            "batch participant link exceeds its root slot",
        ));
    }
    let participant_count = u32::try_from(participant_count)
        .map_err(|_| invalid_input("batch participant count does not fit its encoding"))?;
    let ordinal = u32::try_from(ordinal)
        .map_err(|_| invalid_input("batch participant ordinal does not fit its encoding"))?;
    let mut encoded = Vec::new();
    reserve(&mut encoded, encoded_len, "batch participant link")?;
    encoded.extend_from_slice(LINK_MAGIC);
    encoded.extend_from_slice(&decision.group_id);
    encoded.extend_from_slice(&participant_count.to_be_bytes());
    encoded.extend_from_slice(&ordinal.to_be_bytes());
    let removed = u32::from(participant_is_removed(decision, participant));
    encoded.extend_from_slice(&removed.to_be_bytes());
    encode_participant_core(&mut encoded, participant);
    push_len(
        &mut encoded,
        next.partition.len(),
        "batch successor partition",
    )?;
    encoded.extend_from_slice(next.partition.as_bytes());
    push_len(&mut encoded, next.name.len(), "batch successor blob")?;
    encoded.extend_from_slice(&next.name);
    encoded.extend_from_slice(&next.incarnation);
    debug_assert_eq!(encoded.len(), encoded_len);
    Ok(encoded)
}

fn decode_link(encoded: &[u8], partition: &str, name: &[u8]) -> io::Result<Link> {
    if encoded.len() < LINK_FIXED_LEN || encoded.len() > atomic::MAX_BATCH_WITNESS_LEN {
        return Err(invalid_data("batch participant link has an invalid length"));
    }
    let mut cursor = Cursor::new(encoded);
    if cursor.read(LINK_MAGIC.len())? != LINK_MAGIC {
        return Err(invalid_data("batch participant link magic mismatch"));
    }
    let group_id = cursor
        .read(GROUP_ID_LEN)?
        .try_into()
        .expect("group IDs have a fixed length");
    let participant_count = usize::try_from(cursor.read_u32()?)
        .map_err(|_| invalid_data("batch participant count overflow"))?;
    let ordinal = usize::try_from(cursor.read_u32()?)
        .map_err(|_| invalid_data("batch participant ordinal overflow"))?;
    let flags = cursor.read_u32()?;
    if participant_count == 0 || ordinal >= participant_count || flags & !LINK_REMOVED != 0 {
        return Err(invalid_data("batch participant link header is invalid"));
    }
    let participant = decode_participant_core(
        &mut cursor,
        clone_string(partition, "decoded batch participant partition")?,
        clone_bytes(name, "decoded batch participant name")?,
    )?;
    let next_partition = cursor.read_partition()?;
    let next_name = cursor.read_vec("batch successor blob")?;
    let next_incarnation = cursor
        .read(super::super::header::Header::V2_INCARNATION_LEN)?
        .try_into()
        .expect("V2 incarnations have a fixed length");
    if cursor.position != encoded.len() {
        return Err(invalid_data("batch participant link has trailing bytes"));
    }
    super::super::validate_partition_name(&next_partition)
        .map_err(|_| invalid_data("batch successor has an invalid partition"))?;
    Ok(Link {
        group_id,
        participant_count,
        ordinal,
        removed: flags & LINK_REMOVED != 0,
        participant,
        next: Location {
            partition: next_partition,
            name: next_name,
            incarnation: next_incarnation,
        },
    })
}

fn prepare_links(decision: Decision) -> io::Result<EmbeddedBatch> {
    let mut witnesses = Vec::new();
    reserve(
        &mut witnesses,
        decision.participants.len(),
        "batch participant witnesses",
    )?;
    for (ordinal, participant) in decision.participants.iter().enumerate() {
        witnesses.push(LocalWitness {
            partition: clone_string(&participant.partition, "batch witness partition")?,
            name: clone_bytes(&participant.name, "batch witness name")?,
            encoded: Arc::<[u8]>::from(encode_link(&decision, ordinal)?),
        });
    }
    Ok(EmbeddedBatch {
        decision,
        witnesses: witnesses.into(),
    })
}

fn validate_decision(participants: &[Participant], removals: &[RemoveTarget]) -> io::Result<()> {
    u32::try_from(participants.len())
        .map_err(|_| invalid_data("batch participant count does not fit its encoding"))?;
    u32::try_from(removals.len())
        .map_err(|_| invalid_data("batch removal count does not fit its encoding"))?;
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

    let mut previous_removal = None;
    for removal in removals {
        let RemoveTarget::Blob { partition, name } = removal else {
            return Err(invalid_data(
                "embedded batch decisions cannot remove partitions",
            ));
        };
        super::super::validate_partition_name(partition)
            .map_err(|_| invalid_data("batch removal has an invalid partition"))?;
        let key = (partition.as_str(), name.as_slice());
        if previous_removal.is_some_and(|previous| previous >= key) {
            return Err(invalid_data("batch removals are not canonical"));
        }
        if participants
            .binary_search_by(|participant| participant.key().cmp(&key))
            .is_err()
        {
            return Err(invalid_data("batch removal has no participant"));
        }
        previous_removal = Some(key);
    }
    Ok(())
}

fn validate_operation_participants(
    participants: &[Participant],
    operations: &[Operation],
) -> io::Result<()> {
    let mut participant_index = 0;
    for operation in operations {
        let (key, removed) = match operation {
            Operation::Publish { partition, name }
            | Operation::Rewind {
                partition, name, ..
            } => ((partition.as_str(), name.as_slice()), false),
            Operation::Remove(RemoveTarget::Blob { partition, name }) => {
                ((partition.as_str(), name.as_slice()), true)
            }
            Operation::Remove(RemoveTarget::Partition(_)) => {
                return Err(invalid_input(
                    "atomic batch deletion requires an exact V2 blob participant",
                ));
            }
        };
        if participants
            .get(participant_index)
            .is_some_and(|participant| participant.key() < key)
        {
            return Err(invalid_input(
                "storage batch participant has no matching blob operation",
            ));
        }
        if participants
            .get(participant_index)
            .is_some_and(|participant| participant.key() == key)
        {
            participant_index += 1;
        } else if removed {
            return Err(invalid_input(
                "atomic batch deletion has no matching V2 participant",
            ));
        }
    }
    if participant_index != participants.len() {
        return Err(invalid_input(
            "storage batch participant has no matching blob operation",
        ));
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

fn inspect_location(root: &Path, location: &Location) -> io::Result<Option<File>> {
    let path = root.join(&location.partition).join(hex(&location.name));
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
    if incarnation != location.incarnation {
        return Ok(None);
    }
    Ok(Some(file))
}

fn inspect_participant(root: &Path, participant: &Participant) -> io::Result<Option<File>> {
    inspect_location(
        root,
        &Location {
            partition: clone_string(&participant.partition, "inspected participant partition")?,
            name: clone_bytes(&participant.name, "inspected participant name")?,
            incarnation: participant.incarnation,
        },
    )
}

fn open_participant(root: &Path, participant: &Participant) -> io::Result<File> {
    inspect_participant(root, participant)?
        .ok_or_else(|| invalid_data("batch participant is missing or has a different incarnation"))
}

fn participant_is_removed(decision: &Decision, participant: &Participant) -> bool {
    decision
        .removals
        .binary_search_by(|target| match target {
            RemoveTarget::Blob { partition, name } => (partition.as_str(), name.as_slice())
                .cmp(&(participant.partition.as_str(), participant.name.as_slice())),
            RemoveTarget::Partition(partition) => partition
                .as_str()
                .cmp(participant.partition.as_str())
                .then(std::cmp::Ordering::Less),
        })
        .is_ok()
}

fn matching_link(
    file: &File,
    data_offset: u64,
    location: &Location,
    group_id: &[u8; GROUP_ID_LEN],
    participant_count: usize,
    ordinal: usize,
) -> io::Result<Option<Link>> {
    let mut matching = None;
    for embedded in atomic::embedded_batch_witnesses(file, data_offset)? {
        let link = match decode_link(&embedded.witness, &location.partition, &location.name) {
            Ok(link) => link,
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
        if &link.group_id != group_id
            || link.participant_count != participant_count
            || link.ordinal != ordinal
            || link.participant.incarnation != location.incarnation
            || link.participant.candidate.root_offset != embedded.root_offset
            || !atomic::candidate_has_embedded_batch_witness(
                file,
                &link.participant.candidate,
                &embedded.witness,
            )?
        {
            continue;
        }
        if matching.replace(link).is_some() {
            // A well-formed group installs exactly one generation in each participant. Treat an
            // ambiguous pair of matching slots as an incomplete decision, never as authority.
            return Ok(None);
        }
    }
    Ok(matching)
}

fn matching_materialized_link(
    file: &File,
    data_offset: u64,
    location: &Location,
    group_id: &[u8; GROUP_ID_LEN],
    participant_count: usize,
    ordinal: usize,
) -> io::Result<Option<(Link, Vec<u8>)>> {
    let mut matching = None;
    for embedded in atomic::materialized_batch_candidates(file, data_offset)? {
        let link = match decode_link(&embedded.witness, &location.partition, &location.name) {
            Ok(link) => link,
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
        if &link.group_id != group_id
            || link.participant_count != participant_count
            || link.ordinal != ordinal
            || link.participant.incarnation != location.incarnation
            || link.participant.candidate != embedded.candidate
            || !atomic::candidate_has_embedded_batch_witness(
                file,
                &embedded.candidate,
                &embedded.witness,
            )?
            || if link.removed {
                !atomic::candidate_is_tombstoned(file, &embedded.candidate)?
            } else {
                !atomic::candidate_is_materialized(file, &embedded.candidate)?
            }
        {
            continue;
        }
        if matching.replace((link, embedded.witness)).is_some() {
            return Ok(None);
        }
    }
    Ok(matching)
}

fn recover_linked_decision(
    root: &Path,
    partition: &str,
    name: &[u8],
    file: &File,
    data_offset: u64,
    root_offset: u64,
    witness: &[u8],
) -> io::Result<Option<Decision>> {
    let local_incarnation = validate_v2_header(file)?;
    let first = match decode_link(witness, partition, name) {
        Ok(link) => link,
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
    if first.participant.incarnation != local_incarnation
        || first.participant.candidate.root_offset != root_offset
        || !atomic::candidate_has_embedded_batch_witness(
            file,
            &first.participant.candidate,
            witness,
        )?
    {
        return Ok(None);
    }

    let start = Location {
        partition: clone_string(partition, "recovery start partition")?,
        name: clone_bytes(name, "recovery start name")?,
        incarnation: local_incarnation,
    };
    let participant_count = first.participant_count;
    let start_ordinal = first.ordinal;
    let group_id = first.group_id;
    let mut links = Vec::new();
    let mut current_location = clone_location(&start)?;
    let mut current_link = first;

    for step in 0..participant_count {
        let expected_ordinal = (start_ordinal + step) % participant_count;
        if current_link.group_id != group_id
            || current_link.participant_count != participant_count
            || current_link.ordinal != expected_ordinal
            || current_link.participant.key() != current_location.key()
            || current_link.participant.incarnation != current_location.incarnation
        {
            return Ok(None);
        }

        let next = clone_location(&current_link.next)?;
        reserve(&mut links, 1, "recovered batch participant links")?;
        links.push(current_link);
        if step + 1 == participant_count {
            if next != start {
                return Ok(None);
            }
            break;
        }
        if next == start {
            return Ok(None);
        }
        let Some(next_file) = inspect_location(root, &next)? else {
            return Ok(None);
        };
        let Some(next_link) = matching_link(
            &next_file,
            data_offset,
            &next,
            &group_id,
            participant_count,
            (expected_ordinal + 1) % participant_count,
        )?
        else {
            return Ok(None);
        };
        current_location = next;
        current_link = next_link;
    }

    links.rotate_left((participant_count - start_ordinal) % participant_count);
    for (ordinal, link) in links.iter().enumerate() {
        let next = &links[(ordinal + 1) % participant_count].participant;
        if link.ordinal != ordinal
            || link.next.partition != next.partition
            || link.next.name != next.name
            || link.next.incarnation != next.incarnation
        {
            return Ok(None);
        }
    }

    let mut participants: Vec<Participant> = Vec::new();
    reserve(
        &mut participants,
        participant_count,
        "recovered batch participants",
    )?;
    let removal_count = links.iter().filter(|link| link.removed).count();
    let mut removals = Vec::new();
    reserve(&mut removals, removal_count, "recovered batch removals")?;
    for link in links {
        if link.removed {
            removals.push(RemoveTarget::Blob {
                partition: clone_string(
                    &link.participant.partition,
                    "recovered batch removal partition",
                )?,
                name: clone_bytes(&link.participant.name, "recovered batch removal name")?,
            });
        }
        participants.push(link.participant);
    }
    let decision = Decision {
        group_id,
        participants,
        removals,
    };
    if validate_decision(&decision.participants, &decision.removals).is_err() {
        return Ok(None);
    }
    Ok(Some(decision))
}

fn materialize_decision_participant(
    root: &Path,
    decision: &Decision,
    ordinal: usize,
    participant: &Participant,
) -> io::Result<()> {
    let removed = participant_is_removed(decision, participant);
    let file = match inspect_participant(root, participant)? {
        Some(file) => file,
        None => return Ok(()),
    };
    let witness = encode_link(decision, ordinal)?;
    if !atomic::candidate_has_embedded_batch_witness(&file, &participant.candidate, &witness)? {
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

fn materialize_decision_participants(root: &Path, decision: &Decision) -> io::Result<()> {
    const MAX_INSTALL_WORKERS: usize = 32;
    for (chunk_index, chunk) in decision
        .participants
        .chunks(MAX_INSTALL_WORKERS)
        .enumerate()
    {
        std::thread::scope(|scope| {
            let handles = chunk
                .iter()
                .enumerate()
                .map(|(index, participant)| {
                    let ordinal = chunk_index * MAX_INSTALL_WORKERS + index;
                    scope.spawn(move || {
                        materialize_decision_participant(root, decision, ordinal, participant)
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

fn unlink_deleted_participants(root: &Path, decision: &Decision) -> io::Result<()> {
    for target in decision.removals.iter().rev() {
        let RemoveTarget::Blob { partition, name } = target else {
            return Err(invalid_data(
                "embedded decisions cannot remove entire partitions",
            ));
        };
        let ordinal = decision
            .participants
            .binary_search_by(|participant| {
                participant
                    .key()
                    .cmp(&(partition.as_str(), name.as_slice()))
            })
            .map_err(|_| invalid_data("embedded deletion has no participant"))?;
        let participant = &decision.participants[ordinal];
        let witness = encode_link(decision, ordinal)?;
        unlink_exact_tombstone(root, participant, &witness)?;
    }
    Ok(())
}

fn unlink_exact_tombstone(
    root: &Path,
    participant: &Participant,
    witness: &[u8],
) -> io::Result<()> {
    let path = root
        .join(&participant.partition)
        .join(hex(&participant.name));
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("embedded deletion target has no parent directory"))?;
    let file = match open_participant(root, participant) {
        Ok(file) => file,
        Err(error) if path_is_missing(&error) => return sync_directory(parent),
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::InvalidData | ErrorKind::UnexpectedEof
            ) =>
        {
            // The exact old incarnation was already unlinked and this path was recreated.
            return sync_directory(parent);
        }
        Err(error) => return Err(error),
    };
    if !atomic::candidate_has_embedded_batch_witness(&file, &participant.candidate, witness)? {
        // A different incarnation at the same path belongs to a later open/create and must never
        // be removed by replay of this decision.
        return Ok(());
    }
    if !atomic::candidate_is_tombstoned(&file, &participant.candidate)? {
        return Err(invalid_data(
            "embedded deletion participant is not durably tombstoned",
        ));
    }
    let opened = file.metadata()?;
    let current = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if path_is_missing(&error) => return sync_directory(parent),
        Err(error) => return Err(error),
    };
    if opened.dev() != current.dev() || opened.ino() != current.ino() {
        return sync_directory(parent);
    }

    // Remove an abandoned creation inode before the live tombstone. The live unlink is then made
    // durable before the next ordinal is touched, so any crash leaves a descending-prefix delete
    // frontier and ordinal zero remains the final recovery anchor.
    atomic::discard(root, &participant.partition, &participant.name)?;
    fs::remove_file(&path)?;
    sync_directory(parent)
}

fn finish_embedded_decision(root: &Path, decision: &Decision) -> io::Result<()> {
    // Resolve and durably materialize the whole ring before removing any link. Once this returns,
    // every retained root is independent and every deleted root is a retryable tombstone.
    materialize_decision_participants(root, decision)?;
    unlink_deleted_participants(root, decision)
}

fn validate_speculative_participant(
    root: &Path,
    participant: &Participant,
    removed: bool,
    embedded_witness: Option<&[u8]>,
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
    if let Some(witness) = embedded_witness
        && !atomic::candidate_has_embedded_batch_witness(&file, &participant.candidate, witness)?
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
    u32::try_from(operations.len())
        .map_err(|_| invalid_input("storage batch operation count does not fit its encoding"))?;
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

/// Validate every per-link recovery resource before mutating participant state.
#[commonware_macros::stability(ALPHA)]
pub(crate) fn preflight_embedded<'a>(
    operations: &[Operation],
    participants: impl IntoIterator<Item = (&'a str, &'a [u8])>,
) -> io::Result<()> {
    preflight(operations)?;
    if operations
        .iter()
        .any(|operation| matches!(operation, Operation::Remove(RemoveTarget::Partition(_))))
    {
        return Err(invalid_input(
            "atomic batch deletion requires exact V2 blob participants",
        ));
    }
    let mut participant_paths: Vec<(&'a str, &'a [u8])> = Vec::new();
    for participant in participants {
        reserve(&mut participant_paths, 1, "batch participant preflight")?;
        participant_paths.push(participant);
    }
    u32::try_from(participant_paths.len())
        .map_err(|_| invalid_input("storage batch participant count does not fit its encoding"))?;
    for pair in participant_paths.windows(2) {
        if pair[0] >= pair[1] {
            return Err(invalid_input(
                "storage batch participants are not strictly ordered",
            ));
        }
    }

    for (_, (next_partition, next_name)) in participant_paths
        .iter()
        .zip(participant_paths.iter().cycle().skip(1))
    {
        let link_len = LINK_FIXED_LEN
            .checked_add(next_partition.len())
            .and_then(|len| len.checked_add(next_name.len()))
            .ok_or_else(|| invalid_input("storage batch participant link length overflow"))?;
        if link_len > atomic::MAX_BATCH_WITNESS_LEN {
            return Err(invalid_input(
                "storage batch participant name exceeds its root witness slot",
            ));
        }
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
        && u32::try_from(participant_count).is_ok()
        && verified_bytes <= MAX_SPECULATIVE_BYTES
        && operations
            .iter()
            .all(|operation| !matches!(operation, Operation::Remove(RemoveTarget::Partition(_))))
}

/// Build one exact speculative decision and a distinct linked witness for each participant.
pub(crate) fn prepare_embedded(
    participants: &[Participant],
    operations: &[Operation],
) -> io::Result<EmbeddedBatch> {
    preflight(operations)?;
    validate_operation_participants(participants, operations)?;
    let removal_count = operations
        .iter()
        .filter(|operation| matches!(operation, Operation::Remove(_)))
        .count();
    let mut removals = Vec::new();
    reserve(&mut removals, removal_count, "batch removal decision")?;
    for operation in operations {
        if let Operation::Remove(target) = operation {
            removals.push(clone_remove_target(target)?);
        }
    }
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
    let mut decision_participants = Vec::new();
    reserve(
        &mut decision_participants,
        participants.len(),
        "batch participant decision",
    )?;
    for participant in participants {
        decision_participants.push(clone_participant(participant)?);
    }
    prepare_links(Decision {
        group_id: new_group_id(),
        participants: decision_participants,
        removals,
    })
}

/// Encode the self-contained decision used by the one-participant publication fast path.
pub(in crate::storage) fn prepare_single_publish(
    partition: &str,
    name: &[u8],
    incarnation: [u8; super::super::header::Header::V2_INCARNATION_LEN],
    prepared: &atomic::PreparedCommit,
) -> io::Result<(Participant, EmbeddedBatch)> {
    let atomic::PayloadChecksumEligibility::Eligible(payload_checksum) =
        prepared.payload_checksum()
    else {
        return Err(invalid_input(
            "single-participant publication payload is not recoverable",
        ));
    };
    let participant = Participant {
        partition: clone_string(partition, "single publication partition")?,
        name: clone_bytes(name, "single publication name")?,
        incarnation,
        candidate: prepared.candidate(),
        payload_start: prepared.payload_start(),
        payload_checksum,
    };
    let operations = [Operation::Publish {
        partition: clone_string(&participant.partition, "single publication operation")?,
        name: clone_bytes(&participant.name, "single publication operation")?,
    }];
    let batch = prepare_embedded(std::slice::from_ref(&participant), &operations)?;
    Ok((participant, batch))
}

/// Return whether a new exact group can replace the preceding embedded decision in two slots.
pub(crate) fn can_supersede_embedded(
    previous: &EmbeddedBatch,
    participants: &[Participant],
) -> io::Result<bool> {
    let previous = &previous.decision;
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
pub(crate) fn materialize_embedded(root: &Path, batch: &EmbeddedBatch) -> io::Result<()> {
    finish_embedded_decision(root, &batch.decision)
}

/// Resolve participant-linked decisions before opening one V2 blob's logical state.
pub(crate) fn recover_embedded(
    root: &Path,
    partition: &str,
    name: &[u8],
    file: &File,
    data_offset: u64,
) -> io::Result<bool> {
    let mut embedded_decisions = Vec::new();
    for embedded in atomic::embedded_batch_witnesses(file, data_offset)? {
        let Some(decision) = recover_linked_decision(
            root,
            partition,
            name,
            file,
            data_offset,
            embedded.root_offset,
            &embedded.witness,
        )?
        else {
            continue;
        };
        let Some(local) = decision
            .participants
            .iter()
            .find(|participant| participant.partition == partition && participant.name == name)
        else {
            continue;
        };
        embedded_decisions.push((
            local.candidate.base_generation,
            participant_is_removed(&decision, local),
            decision,
        ));
    }
    embedded_decisions.sort_by_key(|(generation, _, _)| std::cmp::Reverse(*generation));

    for (_, local_deleted, decision) in embedded_decisions {
        let mut install_started = false;
        for (ordinal, participant) in decision.participants.iter().enumerate() {
            let removed = participant_is_removed(&decision, participant);
            let participant_file = match inspect_participant(root, participant)? {
                Some(file) => file,
                None if removed => continue,
                None => continue,
            };
            let witness = encode_link(&decision, ordinal)?;
            if !atomic::candidate_has_embedded_batch_witness(
                &participant_file,
                &participant.candidate,
                &witness,
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
            finish_embedded_decision(root, &decision)?;
            return Ok(local_deleted);
        }

        let mut complete = true;
        for (ordinal, participant) in decision.participants.iter().enumerate() {
            let witness = encode_link(&decision, ordinal)?;
            if !validate_speculative_participant(
                root,
                participant,
                participant_is_removed(&decision, participant),
                Some(&witness),
            )? {
                complete = false;
                break;
            }
        }
        if complete {
            finish_embedded_decision(root, &decision)?;
            return Ok(local_deleted);
        }
    }
    recover_materialized_witnesses(root, partition, name, file)
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

/// Use a materialized participant's retained link to make any dependent peers independent.
///
/// Tombstones are unlinked in descending ordinal order with a directory barrier after each one.
/// Ordinal zero therefore remains a recovery anchor until every higher tombstone is durably gone.
fn recover_materialized_witnesses(
    root: &Path,
    partition: &str,
    name: &[u8],
    file: &File,
) -> io::Result<bool> {
    let data_offset = super::super::Layout::V2.data_offset();
    let local_incarnation = validate_v2_header(file)?;
    for embedded in atomic::materialized_batch_candidates(file, data_offset)? {
        let link = match decode_link(&embedded.witness, partition, name) {
            Ok(link) => link,
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
        if link.participant.incarnation != local_incarnation
            || link.participant.candidate != embedded.candidate
            || !atomic::candidate_has_embedded_batch_witness(
                file,
                &embedded.candidate,
                &embedded.witness,
            )?
        {
            continue;
        }

        if let Some(decision) = recover_linked_decision(
            root,
            partition,
            name,
            file,
            data_offset,
            embedded.candidate.root_offset,
            &embedded.witness,
        )? {
            let local_deleted = participant_is_removed(&decision, &link.participant);
            finish_embedded_decision(root, &decision)?;
            return Ok(local_deleted);
        }

        if link.ordinal == 0
            && recover_ordered_delete_frontier(
                root,
                partition,
                name,
                file,
                &link,
                &embedded.witness,
            )?
        {
            return Ok(link.removed);
        }
        // A non-anchor tombstone remains logically deleted, but cannot unlink itself without
        // creating a hole below the durable descending frontier. Opening ordinal zero or scanning
        // its partition completes the bounded cleanup.
        return Ok(link.removed);
    }
    Ok(false)
}

fn recover_ordered_delete_frontier(
    root: &Path,
    partition: &str,
    name: &[u8],
    file: &File,
    first: &Link,
    first_witness: &[u8],
) -> io::Result<bool> {
    if first.ordinal != 0 || first.participant_count == 0 {
        return Ok(false);
    }
    let data_offset = super::super::Layout::V2.data_offset();
    let start = Location {
        partition: clone_string(partition, "delete recovery start partition")?,
        name: clone_bytes(name, "delete recovery start name")?,
        incarnation: validate_v2_header(file)?,
    };
    if first.participant.key() != start.key() || first.participant.incarnation != start.incarnation
    {
        return Ok(false);
    }

    let mut frontier = Vec::new();
    let mut current = clone_link(first)?;
    let mut current_witness = clone_bytes(first_witness, "ordered delete witness")?;
    for expected_ordinal in 1..first.participant_count {
        let next = clone_location(&current.next)?;
        if next == start {
            return Ok(false);
        }
        reserve(&mut frontier, 1, "ordered delete recovery frontier")?;
        frontier.push((current, current_witness));
        let Some(next_file) = inspect_location(root, &next)? else {
            // Descending, individually synchronized unlinks make the first absent successor the
            // delete frontier. Persist that observed absence before touching the lower prefix, so
            // a retry after an indeterminate directory sync preserves the same ordering invariant.
            sync_directory(&root.join(&next.partition))?;
            for (link, witness) in frontier.into_iter().rev() {
                if link.removed {
                    unlink_exact_tombstone(root, &link.participant, &witness)?;
                }
            }
            return Ok(true);
        };
        let Some((next_link, witness)) = matching_materialized_link(
            &next_file,
            data_offset,
            &next,
            &first.group_id,
            first.participant_count,
            expected_ordinal,
        )?
        else {
            return Ok(false);
        };
        if next_link.participant.key() != next.key()
            || next_link.participant.incarnation != next.incarnation
        {
            return Ok(false);
        }
        current = next_link;
        current_witness = witness;
    }

    // An intact ring is handled by full decision recovery above. A non-closing final chain is not
    // a valid delete frontier and must not authorize namespace changes.
    Ok(false)
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
    let mut cleaned = false;
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
        if recover_named_embedded(root, &partition, &name)? {
            // A confirmed-removed name whose tombstone still lingers: its group's descending
            // frontier was interrupted, and a recreated peer can strand it from ordinal-zero
            // cleanup. Unlink it directly so namespace enumeration never returns a durably-deleted
            // blob. A full partition sweep cleans every removed verdict, so it does not depend on
            // the ring or the descending order remaining intact. recover_named_embedded reports
            // removed only for the exact deleted incarnation, so a blob recreated at the same name
            // is left intact.
            let path = root.join(&partition).join(hex(&name));
            match fs::remove_file(&path) {
                Ok(()) => cleaned = true,
                Err(error) if path_is_missing(&error) => {}
                Err(error) => return Err(error),
            }
        }
    }
    if cleaned {
        sync_directory(&root.join(&partition))?;
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
        batch: EmbeddedBatch,
        decision: Decision,
        records: Vec<Vec<u8>>,
    }

    impl StagedGroup {
        fn write_selected(&self, blobs: &[TestBlob], include: impl Fn(usize) -> bool) {
            for (index, ((blob, participant), record)) in blobs
                .iter()
                .zip(&self.participants)
                .zip(&self.records)
                .enumerate()
            {
                if !include(index) {
                    continue;
                }
                blob.file
                    .write_all_at(record, participant.candidate.root_offset)
                    .unwrap();
                blob.file.sync_all().unwrap();
            }
        }

        fn write_mask(&self, blobs: &[TestBlob], mask: u64) {
            self.write_selected(blobs, |index| mask & (1 << index) != 0);
        }

        fn write_all(&self, blobs: &[TestBlob]) {
            self.write_selected(blobs, |_| true);
        }

        fn witness(&self, ordinal: usize) -> Vec<u8> {
            encode_link(&self.decision, ordinal).unwrap()
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

        let batch = if participants.len() == 1 && matches!(roles[0], Role::Retain(_)) {
            let (participant, batch) = prepare_single_publish(
                PARTITION,
                &blobs[0].name,
                blobs[0].incarnation,
                &prepared[0],
            )
            .unwrap();
            assert_eq!(participant, participants[0]);
            batch
        } else {
            prepare_embedded(&participants, &operations).unwrap()
        };
        for (commit, participant) in prepared.iter_mut().zip(&participants) {
            let witness = batch
                .witness(&participant.partition, &participant.name)
                .expect("every participant has one local link");
            commit.attach_batch_witness(witness).unwrap();
        }
        let records = prepared
            .into_iter()
            .map(|commit| commit.prepared_root)
            .collect();
        let decision = batch.decision.clone();
        StagedGroup {
            participants,
            batch,
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

        assert!(!can_supersede_embedded(&group.batch, &recreated).unwrap());
    }

    #[test]
    fn local_link_path_budget_is_exact_and_preflighted() {
        assert_eq!(LINK_FIXED_LEN, 336);
        assert_eq!(atomic::MAX_BATCH_WITNESS_LEN, 1_920);
        assert_eq!(atomic::MAX_BATCH_WITNESS_LEN - LINK_FIXED_LEN, 1_584);
        let short = b"a".as_slice();
        let exact = vec![b'z'; atomic::MAX_BATCH_WITNESS_LEN - LINK_FIXED_LEN];
        assert_eq!(LINK_FIXED_LEN + exact.len(), atomic::MAX_BATCH_WITNESS_LEN);
        preflight_embedded(&[], [("", short), ("", exact.as_slice())]).unwrap();

        let overlong = vec![b'z'; exact.len() + 1];
        let error = preflight_embedded(&[], [("", short), ("", overlong.as_slice())])
            .expect_err("an oversized successor path must fail before staging");
        assert_eq!(error.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn decoded_link_accepts_the_format_count_and_rejects_invalid_headers() {
        const U32_LEN: usize = std::mem::size_of::<u32>();
        const COUNT_OFFSET: usize = LINK_MAGIC.len() + GROUP_ID_LEN;
        const ORDINAL_OFFSET: usize = COUNT_OFFSET + U32_LEN;

        let root = TestRoot::new("unbounded-count");
        let mut blobs = vec![TestBlob::create(root.path(), b"a", 1, b"old")];
        let group = stage_group(&mut blobs, &[Role::Retain(b"-new".to_vec())]);
        let original = group.witness(0);

        let mut witness = original.clone();
        witness[..LINK_MAGIC.len()].copy_from_slice(b"CWUNOL13");
        let error = decode_link(&witness, PARTITION, &blobs[0].name)
            .expect_err("an older link format must be rejected");
        assert_eq!(error.kind(), ErrorKind::InvalidData);

        let mut witness = original.clone();
        witness[COUNT_OFFSET..COUNT_OFFSET + U32_LEN].copy_from_slice(&0u32.to_be_bytes());
        let error = decode_link(&witness, PARTITION, &blobs[0].name)
            .expect_err("an empty ring must be rejected");
        assert_eq!(error.kind(), ErrorKind::InvalidData);

        let mut witness = original.clone();
        witness[COUNT_OFFSET..COUNT_OFFSET + U32_LEN].copy_from_slice(&u32::MAX.to_be_bytes());
        let decoded = decode_link(&witness, PARTITION, &blobs[0].name)
            .expect("the full format count must not hit a policy cap");
        assert_eq!(decoded.participant_count, u32::MAX as usize);

        let mut witness = original;
        witness[COUNT_OFFSET..COUNT_OFFSET + U32_LEN].copy_from_slice(&2u32.to_be_bytes());
        witness[ORDINAL_OFFSET..ORDINAL_OFFSET + U32_LEN].copy_from_slice(&2u32.to_be_bytes());
        let error = decode_link(&witness, PARTITION, &blobs[0].name)
            .expect_err("an ordinal outside its count must be rejected");
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn participant_ring_beyond_worker_fanout_recovers() {
        const PARTICIPANTS: usize = 64;

        let root = TestRoot::new("maximum-ring");
        let mut blobs = (0..PARTICIPANTS)
            .map(|index| {
                let name = format!("participant-{index:012}");
                assert_eq!(name.len(), 24);
                TestBlob::create(root.path(), name.as_bytes(), index as u8, &[index as u8])
            })
            .collect::<Vec<_>>();
        let roles = (0..PARTICIPANTS)
            .map(|index| Role::Retain(vec![index as u8 ^ 0xff]))
            .collect::<Vec<_>>();
        let group = stage_group(&mut blobs, &roles);
        group.write_all(&blobs);

        assert!(!recover_from(root.path(), &blobs[0]));
        for (index, (blob, participant)) in blobs.iter().zip(&group.participants).enumerate() {
            assert!(atomic::candidate_is_materialized(&blob.file, &participant.candidate).unwrap());
            assert_eq!(blob.recovered_payload(), [index as u8, index as u8 ^ 0xff]);
        }
    }

    #[test]
    fn incomplete_large_ring_rolls_back_across_worker_boundaries() {
        const PARTICIPANTS: usize = 64;

        for missing in [0, 31, 32, PARTICIPANTS - 1] {
            let root = TestRoot::new(&format!("large-incomplete-ring-{missing}"));
            let mut blobs = (0..PARTICIPANTS)
                .map(|index| {
                    let name = format!("participant-{index:012}");
                    TestBlob::create(root.path(), name.as_bytes(), index as u8, &[index as u8])
                })
                .collect::<Vec<_>>();
            let roles = (0..PARTICIPANTS)
                .map(|index| Role::Retain(vec![index as u8 ^ 0xff]))
                .collect::<Vec<_>>();
            let group = stage_group(&mut blobs, &roles);
            group.write_selected(&blobs, |index| index != missing);

            let anchor = (missing + 1) % PARTICIPANTS;
            assert!(
                !recover_from(root.path(), &blobs[anchor]),
                "missing {missing}"
            );
            for (index, (blob, participant)) in blobs.iter().zip(&group.participants).enumerate() {
                assert_not_final(
                    blob,
                    participant,
                    &format!("missing {missing}, index {index}"),
                );
            }
        }
    }

    #[test]
    fn mixed_delete_ring_beyond_worker_fanout_recovers() {
        const PARTICIPANTS: usize = 64;

        let root = TestRoot::new("large-mixed-delete-ring");
        let mut blobs = (0..PARTICIPANTS)
            .map(|index| {
                let name = format!("participant-{index:012}");
                TestBlob::create(root.path(), name.as_bytes(), index as u8, &[index as u8])
            })
            .collect::<Vec<_>>();
        let roles = (0..PARTICIPANTS)
            .map(|index| {
                if index.is_multiple_of(2) {
                    Role::Delete
                } else {
                    Role::Retain(vec![index as u8 ^ 0xff])
                }
            })
            .collect::<Vec<_>>();
        let group = stage_group(&mut blobs, &roles);
        group.write_all(&blobs);

        assert!(recover_from(root.path(), &blobs[0]));
        for (index, blob) in blobs.iter().enumerate() {
            if index.is_multiple_of(2) {
                assert!(!blob.path.exists(), "deleted participant {index}");
            } else {
                assert!(blob.path.exists(), "retained participant {index}");
                assert_eq!(
                    blob.recovered_payload(),
                    [index as u8, index as u8 ^ 0xff],
                    "retained participant {index}"
                );
            }
        }
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

        materialize_decision_participants(root.path(), &group.decision).unwrap();
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

        unlink_deleted_participants(root.path(), &group.decision).unwrap();
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
    fn ordinal_zero_anchor_finishes_after_highest_unlink_breaks_the_ring() {
        let root = TestRoot::new("partial-delete-ring");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 13, b"a-old"),
            TestBlob::create(root.path(), b"b", 33, b"b-old"),
            TestBlob::create(root.path(), b"c", 53, b"c-old"),
        ];
        let group = stage_group(
            &mut blobs,
            &[Role::Retain(b"-new".to_vec()), Role::Delete, Role::Delete],
        );
        group.write_all(&blobs);
        materialize_decision_participants(root.path(), &group.decision).unwrap();

        fs::remove_file(&blobs[2].path).unwrap();
        sync_directory(&root.path().join(PARTITION)).unwrap();
        assert!(blobs[1].path.exists());
        assert!(!blobs[2].path.exists());

        assert!(!recover_from(root.path(), &blobs[0]));
        assert!(!blobs[1].path.exists());
        assert!(!blobs[2].path.exists());
        assert!(blobs[0].path.exists());
        assert!(
            atomic::candidate_is_materialized(&blobs[0].file, &group.participants[0].candidate,)
                .unwrap()
        );
        assert_eq!(blobs[0].recovered_payload(), b"a-old-new");
    }

    #[test]
    fn reverse_ordered_delete_frontier_is_completed_from_ordinal_zero() {
        for durable_unlinks in 1..3 {
            let root = TestRoot::new(&format!("ordered-delete-frontier-{durable_unlinks}"));
            let mut blobs = vec![
                TestBlob::create(root.path(), b"a", 14, b"a-old"),
                TestBlob::create(root.path(), b"b", 34, b"b-old"),
                TestBlob::create(root.path(), b"c", 54, b"c-old"),
            ];
            let group = stage_group(&mut blobs, &[Role::Delete, Role::Delete, Role::Delete]);
            group.write_all(&blobs);
            materialize_decision_participants(root.path(), &group.decision).unwrap();

            // Every durable crash frontier is a prefix of descending ordinals. Ordinal zero
            // remains an anchor that must enumerate and finish all lower-ordinal tombstones.
            for blob in blobs.iter().rev().take(durable_unlinks) {
                fs::remove_file(&blob.path).unwrap();
                sync_directory(&root.path().join(PARTITION)).unwrap();
            }

            assert!(recover_from(root.path(), &blobs[0]));
            for blob in &blobs {
                assert!(!blob.path.exists(), "durable unlinks: {durable_unlinks}");
            }
        }
    }

    /// A blob atomically deleted as a non-anchor (ring ordinal != 0) participant of a multi-blob
    /// group must not reopen with its pre-delete contents after a crash that interrupts the
    /// descending tombstone-unlink phase. The coordinator reports the blob removed, but a non-anchor
    /// tombstone cannot self-clean (only ordinal zero resumes the frontier) and there is no global
    /// startup scan, so its name lingers. Reopening it by name must yield a fresh generation, not
    /// the committed-root fallback that `State::recover` keeps for already-open handles.
    #[tokio::test]
    async fn nonanchor_tombstone_does_not_resurrect_on_open() {
        use crate::AtomicStorage as _;

        let root = TestRoot::new("nonanchor-tombstone-open");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 14, b"a-old"),
            TestBlob::create(root.path(), b"b", 34, b"b-old"),
            TestBlob::create(root.path(), b"c", 54, b"c-old"),
        ];
        let group = stage_group(&mut blobs, &[Role::Delete, Role::Delete, Role::Delete]);
        group.write_all(&blobs);
        materialize_decision_participants(root.path(), &group.decision).unwrap();

        // Crash after the highest-ordinal tombstone (c) is durably unlinked, before b (ordinal 1).
        // The surviving frontier is the descending prefix {a(0), b(1)}; b's successor c is gone, so
        // its ring cannot be reconstructed and, as a non-anchor, it cannot clean up its own name.
        fs::remove_file(&blobs[2].path).unwrap();
        sync_directory(&root.path().join(PARTITION)).unwrap();

        // The coordinator reports b removed, but the non-anchor tombstone lingers on disk.
        assert!(
            recover_from(root.path(), &blobs[1]),
            "b is logically deleted"
        );
        assert!(blobs[1].path.exists(), "non-anchor tombstone name lingers");
        drop(blobs);

        // Open b by name via the real storage API. b was atomically deleted; it must not come back
        // with its pre-delete "b-old" contents.
        let mut registry = crate::telemetry::metrics::Registry::default();
        let pool = crate::BufferPool::new(crate::BufferPoolConfig::for_storage(), &mut registry);
        let storage = crate::storage::tokio::Storage::new(
            crate::storage::tokio::Config::new(root.path().to_path_buf(), 2 * 1024 * 1024),
            pool,
        );
        let (_blob, len) = storage.open_atomic(PARTITION, b"b").await.unwrap();
        assert_eq!(
            len, 0,
            "deleted non-anchor blob b reopened with its pre-delete contents instead of a fresh \
             empty generation",
        );
    }

    /// Same crash scenario as [`nonanchor_tombstone_does_not_resurrect_on_open`], reopened through
    /// the ordinary (non-atomic) `open`. Its create path uses `create_new`, which requires the
    /// lingering tombstone name to be unlinked first, so it must recreate a fresh blob rather than
    /// failing with `AlreadyExists`.
    #[tokio::test]
    async fn nonanchor_tombstone_ordinary_open_creates_fresh() {
        use crate::Storage as _;

        let root = TestRoot::new("nonanchor-tombstone-ordinary-open");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 14, b"a-old"),
            TestBlob::create(root.path(), b"b", 34, b"b-old"),
            TestBlob::create(root.path(), b"c", 54, b"c-old"),
        ];
        let group = stage_group(&mut blobs, &[Role::Delete, Role::Delete, Role::Delete]);
        group.write_all(&blobs);
        materialize_decision_participants(root.path(), &group.decision).unwrap();
        fs::remove_file(&blobs[2].path).unwrap();
        sync_directory(&root.path().join(PARTITION)).unwrap();
        drop(blobs);

        let mut registry = crate::telemetry::metrics::Registry::default();
        let pool = crate::BufferPool::new(crate::BufferPoolConfig::for_storage(), &mut registry);
        let storage = crate::storage::tokio::Storage::new(
            crate::storage::tokio::Config::new(root.path().to_path_buf(), 2 * 1024 * 1024),
            pool,
        );
        let (_blob, len) = storage.open(PARTITION, b"b").await.unwrap();
        assert_eq!(
            len, 0,
            "ordinary open of a removed non-anchor blob must create a fresh generation",
        );
    }

    /// Reopening a lower non-anchor recreates it with a new incarnation, which breaks the
    /// ordinal-zero frontier walk (it stops at the recreated incarnation). A later scan must still
    /// not enumerate a higher tombstone whose deletion `start_apply` already reported durable:
    /// partition recovery has to clean every removed verdict, not rely on the ring staying intact.
    #[tokio::test]
    async fn scan_does_not_return_a_stranded_non_anchor_tombstone() {
        use crate::{AtomicStorage as _, Storage as _};

        let root = TestRoot::new("stranded-non-anchor-tombstone");
        let mut blobs = vec![
            TestBlob::create(root.path(), b"a", 14, b"a-old"),
            TestBlob::create(root.path(), b"b", 34, b"b-old"),
            TestBlob::create(root.path(), b"c", 54, b"c-old"),
            TestBlob::create(root.path(), b"d", 74, b"d-old"),
        ];
        // Retain ordinal 0 (a); delete ordinals 1, 2, 3 (b, c, d).
        let group = stage_group(
            &mut blobs,
            &[
                Role::Retain(b"a-new".to_vec()),
                Role::Delete,
                Role::Delete,
                Role::Delete,
            ],
        );
        group.write_all(&blobs);
        materialize_decision_participants(root.path(), &group.decision).unwrap();
        // Crash after the highest-ordinal tombstone (d) is durably unlinked, before c and b.
        fs::remove_file(&blobs[3].path).unwrap();
        sync_directory(&root.path().join(PARTITION)).unwrap();
        drop(blobs);

        let mut registry = crate::telemetry::metrics::Registry::default();
        let pool = crate::BufferPool::new(crate::BufferPoolConfig::for_storage(), &mut registry);
        let storage = crate::storage::tokio::Storage::new(
            crate::storage::tokio::Config::new(root.path().to_path_buf(), 2 * 1024 * 1024),
            pool,
        );
        // Reopen the lower non-anchor b, recreating it and stranding c from ordinal-zero cleanup.
        let _ = storage.open_atomic(PARTITION, b"b").await.unwrap();

        let names = storage.scan(PARTITION).await.unwrap();
        assert!(
            !names.contains(&b"c".to_vec()),
            "scan returned durably-deleted non-anchor blob c: {names:?}",
        );
    }

    #[test]
    fn every_mixed_delete_frontier_recovers_in_descending_order() {
        const NAMES: [&[u8]; 4] = [b"a", b"b", b"c", b"d"];
        for removal_mask in 1u8..(1 << NAMES.len()) {
            let removal_count = removal_mask.count_ones() as usize;
            for durable_unlinks in 0..=removal_count {
                let root = TestRoot::new(&format!(
                    "mixed-delete-{removal_mask:04b}-{durable_unlinks}"
                ));
                let mut blobs = NAMES
                    .iter()
                    .enumerate()
                    .map(|(ordinal, name)| {
                        TestBlob::create(
                            root.path(),
                            name,
                            70 + ordinal as u8,
                            &[b'0' + ordinal as u8],
                        )
                    })
                    .collect::<Vec<_>>();
                let roles = (0..NAMES.len())
                    .map(|ordinal| {
                        if removal_mask & (1 << ordinal) != 0 {
                            Role::Delete
                        } else {
                            Role::Retain(vec![b'A' + ordinal as u8])
                        }
                    })
                    .collect::<Vec<_>>();
                let group = stage_group(&mut blobs, &roles);
                group.write_all(&blobs);
                materialize_decision_participants(root.path(), &group.decision).unwrap();

                let removed = (0..NAMES.len())
                    .filter(|ordinal| removal_mask & (1 << ordinal) != 0)
                    .rev()
                    .take(durable_unlinks);
                for ordinal in removed {
                    unlink_exact_tombstone(
                        root.path(),
                        &group.participants[ordinal],
                        &group.witness(ordinal),
                    )
                    .unwrap();
                }

                // If ordinal zero was removed, every requested removal is already durable because
                // it is always the final delete. Otherwise it remains the bounded recovery anchor.
                if blobs[0].path.exists() {
                    recover_from(root.path(), &blobs[0]);
                }

                for (ordinal, blob) in blobs.iter().enumerate() {
                    if removal_mask & (1 << ordinal) != 0 {
                        assert!(
                            !blob.path.exists(),
                            "mask {removal_mask:04b}, durable unlinks {durable_unlinks}, ordinal {ordinal}"
                        );
                    } else {
                        assert!(blob.path.exists());
                        assert_eq!(
                            blob.recovered_payload(),
                            vec![b'0' + ordinal as u8, b'A' + ordinal as u8]
                        );
                    }
                }
            }
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
                &group.witness(0),
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

        for (ordinal, (blob, candidate, final_root)) in [
            (&blobs[0], retained, materialized),
            (&blobs[1], deleted, tombstone),
        ]
        .into_iter()
        .enumerate()
        {
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
                    &group.witness(ordinal),
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
                    &group.witness(2),
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

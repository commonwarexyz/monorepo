//! Pure witness encoding, candidate binding, and transition classification.

use super::*;

const WITNESS_BINDING_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_BATCH_BINDING";
const WITNESS_HEADER_LEN: usize = 4;
const LINK_MAGIC: &[u8; 8] = b"CWUNOL15";
pub(super) const GROUP_ID_LEN: usize = 16;
const LINK_REMOVED: u32 = 1;
const PAYLOAD_DESCRIPTOR_LEN: usize = 40;
const LINK_FIXED_LEN: usize = 8
    + GROUP_ID_LEN
    + 4
    + INCARNATION_LEN
    + ROOT_LEN
    + PAYLOAD_DESCRIPTOR_LEN
    + 4
    + 4
    + INCARNATION_LEN;
pub(super) const MAX_LINK_LEN: usize = ROOT_SLOT_SIZE - ROOT_LEN - WITNESS_HEADER_LEN;
pub(super) const MAX_LOCATION_LEN: usize = 1_640;
const _: () = assert!(MAX_LOCATION_LEN <= MAX_LINK_LEN - LINK_FIXED_LEN);

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct PayloadDescriptor {
    pub(super) start: u64,
    pub(super) checksum: PayloadDigest,
}

impl PayloadDescriptor {
    pub(super) const fn empty(logical_len: u64) -> Self {
        Self {
            start: logical_len,
            checksum: [0; 32],
        }
    }

    fn decode(encoded: &[u8], logical_len: u64) -> io::Result<Self> {
        let descriptor = Self {
            start: u64::from_be_bytes(encoded[..8].try_into().unwrap()),
            checksum: encoded[8..].try_into().unwrap(),
        };
        descriptor.validate(logical_len)?;
        Ok(descriptor)
    }

    fn encode(self) -> [u8; PAYLOAD_DESCRIPTOR_LEN] {
        let mut encoded = [0u8; PAYLOAD_DESCRIPTOR_LEN];
        encoded[..8].copy_from_slice(&self.start.to_be_bytes());
        encoded[8..].copy_from_slice(&self.checksum);
        encoded
    }

    fn validate(self, logical_len: u64) -> io::Result<()> {
        if self.len(logical_len).is_some() {
            return Ok(());
        }
        Err(invalid_input_io("batch payload descriptor is invalid"))
    }

    pub(super) fn len(self, logical_len: u64) -> Option<u64> {
        let len = logical_len.checked_sub(self.start)?;
        if (len == 0 && self.checksum == [0; 32]) || (len != 0 && len <= MAX_UNSYNCED_PAYLOAD_LEN) {
            Some(len)
        } else {
            None
        }
    }

    pub(super) fn is_empty(self, logical_len: u64) -> bool {
        self.len(logical_len) == Some(0)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Candidate {
    pub(super) prepared_root: [u8; ROOT_LEN],
    pub(super) payload: PayloadDescriptor,
}

impl Candidate {
    #[cfg(test)]
    pub(super) fn new(root: Root) -> io::Result<Self> {
        Self::with_payload(root, PayloadDescriptor::empty(root.logical_len))
    }

    pub(super) fn with_payload(root: Root, payload: PayloadDescriptor) -> io::Result<Self> {
        root.generation
            .checked_sub(1)
            .ok_or_else(|| invalid_input_io("batch candidates require a nonzero generation"))?;
        payload.validate(root.logical_len)?;
        Ok(Self {
            prepared_root: encode_root_value(RootState::BatchPrepared, root),
            payload,
        })
    }

    fn bind(&mut self, witness: &[u8]) {
        let root = self
            .root()
            .expect("batch candidates are validated before witness binding");
        self.prepared_root =
            encode_root_with_binding(RootState::BatchPrepared, root, witness_binding(witness));
    }

    fn template_prepared_root(&self) -> Option<[u8; ROOT_LEN]> {
        let root = self.root()?;
        Some(encode_root_value(RootState::BatchPrepared, root))
    }

    pub(super) fn root(&self) -> Option<Root> {
        let prepared = decode_root(&self.prepared_root, RootState::BatchPrepared)?;
        self.payload
            .validate(prepared.logical_len)
            .is_ok()
            .then_some(prepared)
    }

    pub(super) fn base_generation(&self) -> Option<u64> {
        self.root()?.generation.checked_sub(1)
    }

    pub(super) fn root_offset(&self) -> Option<u64> {
        let root = self.root()?;
        Some(ROOT_OFFSETS[(root.generation as usize) & 1])
    }

    pub(super) fn payload_len(&self) -> Option<u64> {
        let root = self.root()?;
        self.payload.len(root.logical_len)
    }

    pub(super) fn final_root(&self) -> Option<[u8; ROOT_LEN]> {
        let root = self.root()?;
        Some(encode_root_with_binding(
            RootState::Finalized,
            root,
            root_binding(&self.prepared_root),
        ))
    }

    pub(super) fn status(&self, installed: &[u8; ROOT_LEN]) -> Option<CandidateStatus> {
        let final_root = self.final_root()?;
        if installed == &self.prepared_root {
            return Some(CandidateStatus::Prepared);
        }
        for (actual, (prepared, final_value)) in installed
            .iter()
            .zip(self.prepared_root.iter().zip(final_root))
        {
            if actual != prepared && *actual != final_value {
                return None;
            }
        }
        // Exact prepared was handled above. A remaining compatible image may be a torn final write
        // or a stale byte that happens to equal the final target. It has no local authority: group
        // recovery still validates the complete bound ring and every payload obligation.
        Some(CandidateStatus::Transition)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CandidateStatus {
    Prepared,
    Transition,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Participant {
    pub(super) partition: String,
    pub(super) name: Vec<u8>,
    pub(super) incarnation: [u8; INCARNATION_LEN],
    pub(super) candidate: Candidate,
    pub(super) removed: bool,
}

impl Participant {
    pub(super) fn key(&self) -> (&str, &[u8]) {
        (&self.partition, &self.name)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Location {
    pub(super) partition: String,
    pub(super) name: Vec<u8>,
    pub(super) incarnation: [u8; INCARNATION_LEN],
}

#[cfg(test)]
impl Location {
    pub(super) fn key(&self) -> (&str, &[u8]) {
        (&self.partition, &self.name)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Link {
    pub(super) group_id: [u8; GROUP_ID_LEN],
    pub(super) participant: Participant,
    pub(super) next: Location,
}

#[derive(Clone)]
pub(super) struct PreparedGroup {
    pub(super) participants: Vec<Participant>,
    pub(super) slots: Vec<RootSlot>,
}

fn invalid_input_io(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn encoded_u32(value: usize, field: &'static str) -> io::Result<u32> {
    u32::try_from(value).map_err(|_| invalid_input_io(format!("batch {field} exceeds u32")))
}

fn push_len(encoded: &mut Vec<u8>, len: usize) -> io::Result<()> {
    encoded.extend_from_slice(&encoded_u32(len, "path component length")?.to_be_bytes());
    Ok(())
}

fn witness_binding(witness: &[u8]) -> RootBinding {
    // Recovery treats a matching 160-bit prefix as equality of the reachable witness and relies on
    // truncated SHA-256 collision resistance for distinct records and old/new mosaics.
    let digest = Sha256::hash(&[WITNESS_BINDING_DOMAIN, witness]);
    let mut binding = [0u8; ROOT_BINDING_LEN];
    binding.copy_from_slice(&digest.as_ref()[..ROOT_BINDING_LEN]);
    binding
}

fn link_len(partition_len: usize, name_len: usize) -> io::Result<usize> {
    LINK_FIXED_LEN
        .checked_add(partition_len)
        .and_then(|len| len.checked_add(name_len))
        .ok_or_else(|| invalid_input_io("batch link length overflow"))
}

pub(super) fn validate_location(partition: &str, name: &[u8]) -> io::Result<()> {
    let len = partition
        .len()
        .checked_add(name.len())
        .ok_or_else(|| invalid_input_io("atomic location length overflow"))?;
    if len > MAX_LOCATION_LEN {
        return Err(invalid_input_io("atomic location exceeds its root slot"));
    }
    Ok(())
}

fn encode_link(
    group_id: [u8; GROUP_ID_LEN],
    participants: &[Participant],
    index: usize,
) -> io::Result<Vec<u8>> {
    let participant = participants
        .get(index)
        .ok_or_else(|| invalid_input_io("batch participant index is out of range"))?;
    let participant_root = participant
        .candidate
        .root()
        .ok_or_else(|| invalid_input_io("invalid batch candidate"))?;
    if participant.removed
        && !participant
            .candidate
            .payload
            .is_empty(participant_root.logical_len)
    {
        return Err(invalid_input_io(
            "removed batch participants cannot describe payload",
        ));
    }
    let next = &participants[(index + 1) % participants.len()];
    validate_location(&next.partition, &next.name)?;
    let len = link_len(next.partition.len(), next.name.len())?;
    debug_assert!(len <= MAX_LINK_LEN);
    let mut encoded = Vec::with_capacity(len);
    encoded.extend_from_slice(LINK_MAGIC);
    encoded.extend_from_slice(&group_id);
    encoded.extend_from_slice(&u32::from(participant.removed).to_be_bytes());
    encoded.extend_from_slice(&participant.incarnation);
    encoded.extend_from_slice(
        &participant
            .candidate
            .template_prepared_root()
            .ok_or(invalid_input_io("invalid batch candidate"))?,
    );
    encoded.extend_from_slice(&participant.candidate.payload.encode());
    push_len(&mut encoded, next.partition.len())?;
    encoded.extend_from_slice(next.partition.as_bytes());
    push_len(&mut encoded, next.name.len())?;
    encoded.extend_from_slice(&next.name);
    encoded.extend_from_slice(&next.incarnation);
    debug_assert_eq!(encoded.len(), len);
    Ok(encoded)
}

pub(super) fn prepare_with_group_id(
    mut participants: Vec<Participant>,
    group_id: [u8; GROUP_ID_LEN],
) -> io::Result<PreparedGroup> {
    if participants.is_empty() {
        return Err(invalid_input_io("batch requires at least one participant"));
    }
    participants.sort_by(|left, right| left.key().cmp(&right.key()));
    if participants
        .windows(2)
        .any(|pair| pair[0].key() >= pair[1].key())
    {
        return Err(invalid_input_io("batch participants are not unique"));
    }
    let mut slots = Vec::with_capacity(participants.len());
    for index in 0..participants.len() {
        let link = encode_link(group_id, &participants, index)?;
        let participant = &mut participants[index];
        participant.candidate.bind(&link);
        slots.push(encode_slot(&participant.candidate, &link)?);
    }
    Ok(PreparedGroup {
        participants,
        slots,
    })
}

#[cfg(test)]
pub(super) fn prepare(participants: Vec<Participant>) -> io::Result<PreparedGroup> {
    prepare_with_group_id(participants, [0xa5; GROUP_ID_LEN])
}

fn encode_slot(candidate: &Candidate, witness: &[u8]) -> io::Result<RootSlot> {
    if candidate.root().is_none()
        || root_binding(&candidate.prepared_root) != witness_binding(witness)
        || witness.len() > MAX_LINK_LEN
    {
        return Err(invalid_input_io("invalid batch candidate"));
    }
    let mut slot = [0u8; ROOT_SLOT_SIZE];
    slot[..ROOT_LEN].copy_from_slice(&candidate.prepared_root);
    let len = encoded_u32(witness.len(), "witness length")?.to_be_bytes();
    slot[ROOT_LEN..ROOT_LEN + WITNESS_HEADER_LEN].copy_from_slice(&len);
    slot[ROOT_LEN + WITNESS_HEADER_LEN..ROOT_LEN + WITNESS_HEADER_LEN + witness.len()]
        .copy_from_slice(witness);
    Ok(slot)
}

pub(super) fn witness(slot: &[u8]) -> Option<&[u8]> {
    if slot.len() != ROOT_SLOT_SIZE {
        return None;
    }
    let header = slot.get(ROOT_LEN..ROOT_LEN + WITNESS_HEADER_LEN)?;
    let len = usize::try_from(u32::from_be_bytes(header.try_into().unwrap())).ok()?;
    if len > MAX_LINK_LEN {
        return None;
    }
    let end = ROOT_LEN + WITNESS_HEADER_LEN + len;
    let witness = slot.get(ROOT_LEN + WITNESS_HEADER_LEN..end)?;
    if slot.get(end..)?.iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(witness)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| invalid_data("batch witness length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid_data("batch witness is truncated"))?;
        self.offset = end;
        Ok(value)
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = self.u32()? as usize;
        Ok(self.take(len)?.to_vec())
    }
}

pub(super) fn decode_link_at(
    encoded: &[u8],
    partition: &str,
    name: &[u8],
    root_offset: u64,
) -> io::Result<Link> {
    if !(LINK_FIXED_LEN..=MAX_LINK_LEN).contains(&encoded.len()) {
        return Err(invalid_data("batch link has an invalid length"));
    }
    let mut cursor = Cursor {
        bytes: encoded,
        offset: 0,
    };
    if cursor.take(8)? != LINK_MAGIC {
        return Err(invalid_data("batch link magic mismatch"));
    }
    let group_id = cursor.take(GROUP_ID_LEN)?.try_into().unwrap();
    let flags = cursor.u32()?;
    if flags & !LINK_REMOVED != 0 {
        return Err(invalid_data("batch link header is invalid"));
    }
    let incarnation = cursor.take(INCARNATION_LEN)?.try_into().unwrap();
    let prepared_root = cursor.take(ROOT_LEN)?.try_into().unwrap();
    let root = decode_root(&prepared_root, RootState::BatchPrepared)
        .ok_or_else(|| invalid_data("batch participant candidate is invalid"))?;
    if ROOT_OFFSETS[(root.generation as usize) & 1] != root_offset {
        return Err(invalid_data(
            "batch participant candidate is in the wrong slot",
        ));
    }
    let payload = PayloadDescriptor::decode(cursor.take(PAYLOAD_DESCRIPTOR_LEN)?, root.logical_len)
        .map_err(|_| invalid_data("batch participant payload descriptor is invalid"))?;
    if flags & LINK_REMOVED != 0 && !payload.is_empty(root.logical_len) {
        return Err(invalid_data("removed batch participant describes payload"));
    }
    let next_partition = String::from_utf8(cursor.bytes()?)
        .map_err(|_| invalid_data("batch successor partition is not UTF-8"))?;
    crate::storage::validate_partition_name(&next_partition)
        .map_err(|_| invalid_data("batch successor partition is invalid"))?;
    let next_name = cursor.bytes()?;
    validate_location(&next_partition, &next_name)
        .map_err(|_| invalid_data("batch successor location exceeds its root slot"))?;
    let next_incarnation = cursor.take(INCARNATION_LEN)?.try_into().unwrap();
    if cursor.offset != encoded.len() {
        return Err(invalid_data("batch link has trailing bytes"));
    }
    let mut candidate = Candidate {
        prepared_root,
        payload,
    };
    candidate.bind(encoded);
    Ok(Link {
        group_id,
        participant: Participant {
            partition: partition.to_string(),
            name: name.to_vec(),
            incarnation,
            candidate,
            removed: flags & LINK_REMOVED != 0,
        },
        next: Location {
            partition: next_partition,
            name: next_name,
            incarnation: next_incarnation,
        },
    })
}

pub(super) fn link_at(slot: &[u8], partition: &str, name: &[u8], root_offset: u64) -> Option<Link> {
    let link = decode_link_at(witness(slot)?, partition, name, root_offset).ok()?;
    let installed: &[u8; ROOT_LEN] = slot.get(..ROOT_LEN)?.try_into().ok()?;
    link.participant.candidate.status(installed)?;
    Some(link)
}

#[cfg(test)]
pub(super) fn link(slot: &[u8], partition: &str, name: &[u8]) -> Option<Link> {
    let link = decode_link(witness(slot)?, partition, name).ok()?;
    let installed: &[u8; ROOT_LEN] = slot.get(..ROOT_LEN)?.try_into().ok()?;
    link.participant.candidate.status(installed)?;
    Some(link)
}

#[cfg(test)]
fn decode_link(encoded: &[u8], partition: &str, name: &[u8]) -> io::Result<Link> {
    let prepared_offset = 8 + GROUP_ID_LEN + 4 + INCARNATION_LEN;
    let prepared: &[u8; ROOT_LEN] = encoded
        .get(prepared_offset..prepared_offset + ROOT_LEN)
        .ok_or_else(|| invalid_data("batch link is truncated"))?
        .try_into()
        .unwrap();
    let root = decode_root(prepared, RootState::BatchPrepared)
        .ok_or_else(|| invalid_data("batch participant candidate is invalid"))?;
    decode_link_at(
        encoded,
        partition,
        name,
        ROOT_OFFSETS[(root.generation as usize) & 1],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const FLAGS_OFFSET: usize = 8 + GROUP_ID_LEN;
    const CANDIDATE_OFFSET: usize = FLAGS_OFFSET + 4 + INCARNATION_LEN;
    const PREPARED_OFFSET: usize = CANDIDATE_OFFSET;
    const PAYLOAD_OFFSET: usize = PREPARED_OFFSET + ROOT_LEN;
    const NEXT_PARTITION_LEN_OFFSET: usize = PAYLOAD_OFFSET + PAYLOAD_DESCRIPTOR_LEN;

    fn participant(name: &[u8], incarnation: u8, generation: u64, removed: bool) -> Participant {
        Participant {
            partition: "partition".to_string(),
            name: name.to_vec(),
            incarnation: [incarnation; INCARNATION_LEN],
            candidate: Candidate::new(Root::unbound(
                generation,
                generation,
                [incarnation; ATOMIC_BLOB_TAG_LEN],
            ))
            .unwrap(),
            removed,
        }
    }

    fn valid_link_bytes() -> (Participant, Vec<u8>) {
        let group = prepare(vec![
            participant(b"b", 2, 2, true),
            participant(b"a", 1, 2, false),
        ])
        .unwrap();
        let participant = group.participants[0].clone();
        let encoded = witness(&group.slots[0]).unwrap().to_vec();
        (participant, encoded)
    }

    #[test]
    fn candidates_validate_lineage_and_classify_every_reachable_transition() {
        assert!(Candidate::new(Root::unbound(0, 0, [0; ATOMIC_BLOB_TAG_LEN])).is_err());

        let candidate = participant(b"a", 1, 2, false).candidate;
        let root = candidate.root().unwrap();
        assert_eq!(root.generation, 2);
        let finalized = candidate.final_root().unwrap();
        assert!(decode_root(&finalized, RootState::Finalized).is_some());
        assert_eq!(
            candidate.status(&candidate.prepared_root),
            Some(CandidateStatus::Prepared)
        );
        assert_eq!(
            candidate.status(&finalized),
            Some(CandidateStatus::Transition)
        );

        let changed = candidate
            .prepared_root
            .iter()
            .zip(finalized)
            .position(|(prepared, final_byte)| *prepared != final_byte)
            .unwrap();
        let mut torn = candidate.prepared_root;
        torn[changed] = finalized[changed];
        assert_eq!(candidate.status(&torn), Some(CandidateStatus::Transition));
        torn[changed] = (0..=u8::MAX)
            .find(|byte| *byte != candidate.prepared_root[changed] && *byte != finalized[changed])
            .unwrap();
        assert_eq!(candidate.status(&torn), None);

        let mut bad_prepared = candidate.clone();
        bad_prepared.prepared_root[0] ^= 1;
        assert!(bad_prepared.root().is_none());
        assert!(bad_prepared.final_root().is_none());
        assert!(bad_prepared.status(&candidate.prepared_root).is_none());

        assert_eq!(candidate.base_generation(), Some(1));
        assert_eq!(candidate.root_offset(), Some(ROOT_OFFSETS[0]));
    }

    #[test]
    fn payload_descriptors_derive_a_canonical_bounded_suffix() {
        for logical_len in [0, 7] {
            let empty = PayloadDescriptor::empty(logical_len);
            assert_eq!(empty.len(logical_len), Some(0));
            assert_eq!(
                PayloadDescriptor::decode(&empty.encode(), logical_len).unwrap(),
                empty
            );
        }

        let full = PayloadDescriptor {
            start: 0,
            checksum: [1; 32],
        };
        assert_eq!(
            full.len(MAX_UNSYNCED_PAYLOAD_LEN),
            Some(MAX_UNSYNCED_PAYLOAD_LEN)
        );
        assert!(full.validate(MAX_UNSYNCED_PAYLOAD_LEN + 1).is_err());

        let past_end = PayloadDescriptor {
            start: 8,
            checksum: [1; 32],
        };
        assert!(past_end.validate(7).is_err());

        let noncanonical_empty = PayloadDescriptor {
            start: 7,
            checksum: [1; 32],
        };
        assert!(noncanonical_empty.validate(7).is_err());
    }

    #[test]
    fn prepared_groups_are_canonical_closed_rings_and_reject_invalid_inputs() {
        assert!(prepare(Vec::new()).is_err());
        let duplicate = participant(b"same", 1, 1, false);
        assert!(prepare(vec![duplicate.clone(), duplicate]).is_err());

        let group = prepare(vec![
            participant(b"c", 3, 1, false),
            participant(b"a", 1, 1, false),
            participant(b"b", 2, 1, true),
        ])
        .unwrap();
        assert_eq!(
            group
                .participants
                .iter()
                .map(|participant| participant.name.as_slice())
                .collect::<Vec<_>>(),
            [b"a".as_slice(), b"b".as_slice(), b"c".as_slice()]
        );
        for (ordinal, slot) in group.slots.iter().enumerate() {
            let link = link(
                slot,
                &group.participants[ordinal].partition,
                &group.participants[ordinal].name,
            )
            .unwrap();
            assert_eq!(link.participant.key(), group.participants[ordinal].key());
            assert_eq!(link.next.key(), group.participants[(ordinal + 1) % 3].key());
            assert_eq!(link.participant.removed, ordinal == 1);
        }

        let oversized = participant(&vec![b'x'; MAX_LINK_LEN], 1, 1, false);
        assert!(prepare(vec![oversized]).is_err());
        let mut removed_with_payload = participant(b"removed", 1, 1, true);
        removed_with_payload.candidate.payload = PayloadDescriptor {
            start: 0,
            checksum: [0; 32],
        };
        assert!(prepare(vec![removed_with_payload]).is_err());
        assert!(encode_link([0; GROUP_ID_LEN], &group.participants, 3).is_err());
        assert!(link_len(usize::MAX, 1).is_err());
        #[cfg(target_pointer_width = "64")]
        assert!(encoded_u32(u32::MAX as usize + 1, "value").is_err());

        let mut invalid_candidate = group.participants[0].candidate.clone();
        invalid_candidate.prepared_root[0] ^= 1;
        assert!(encode_slot(&invalid_candidate, b"witness").is_err());
        assert!(
            encode_slot(&group.participants[0].candidate, &vec![0; MAX_LINK_LEN + 1],).is_err()
        );
    }

    #[test]
    fn witness_frame_rejects_every_noncanonical_shape() {
        let group = prepare(vec![participant(b"a", 1, 1, false)]).unwrap();
        let valid = group.slots[0];
        assert!(witness(&valid).is_some());
        assert!(witness(&valid[..ROOT_SLOT_SIZE - 1]).is_none());

        let mut oversized = valid;
        oversized[ROOT_LEN..ROOT_LEN + WITNESS_HEADER_LEN]
            .copy_from_slice(&(MAX_LINK_LEN as u32 + 1).to_be_bytes());
        assert!(witness(&oversized).is_none());

        let mut suffix = valid;
        suffix[ROOT_SLOT_SIZE - 1] = 1;
        assert!(witness(&suffix).is_none());

        let mut malformed_link = valid;
        let link_start = ROOT_LEN + WITNESS_HEADER_LEN;
        malformed_link[link_start] ^= 1;
        assert!(link(&malformed_link, "partition", b"a").is_none());
    }

    #[test]
    fn prepared_root_binds_the_exact_local_witness() {
        let old = prepare_with_group_id(
            vec![
                participant(b"a", 1, 2, false),
                participant(b"c", 3, 2, false),
            ],
            [1; GROUP_ID_LEN],
        )
        .unwrap();
        let new = prepare_with_group_id(
            vec![
                participant(b"a", 1, 4, false),
                participant(b"b", 2, 4, false),
                participant(b"c", 3, 4, false),
            ],
            [2; GROUP_ID_LEN],
        )
        .unwrap();

        let mut retained_subset = new.slots[0];
        let witness_start = ROOT_LEN + WITNESS_HEADER_LEN;
        let old_witness = witness(&old.slots[0]).unwrap();
        let new_witness = witness(&new.slots[0]).unwrap();
        assert_eq!(old_witness.len(), new_witness.len());
        retained_subset
            [witness_start + NEXT_PARTITION_LEN_OFFSET..witness_start + new_witness.len()]
            .copy_from_slice(&old_witness[NEXT_PARTITION_LEN_OFFSET..]);
        assert!(
            retained_subset
                .iter()
                .zip(old.slots[0].iter().zip(&new.slots[0]))
                .all(|(actual, (old, new))| actual == old || actual == new)
        );
        let retained_witness = witness(&retained_subset).unwrap();
        let retained_link = decode_link(retained_witness, "partition", b"a").unwrap();
        assert_eq!(retained_link.next.name, b"c");
        assert!(
            link(&retained_subset, "partition", b"a").is_none(),
            "a retained old successor must not match the newer root",
        );
    }

    #[test]
    fn link_decoder_rejects_malformed_and_adversarial_fields() {
        let (expected_participant, valid) = valid_link_bytes();
        let decoded = decode_link(
            &valid,
            &expected_participant.partition,
            &expected_participant.name,
        )
        .unwrap();
        assert_eq!(decoded.participant, expected_participant);
        assert!(
            decode_link_at(
                &valid,
                &expected_participant.partition,
                &expected_participant.name,
                ROOT_OFFSETS[1],
            )
            .is_err()
        );
        assert!(decode_link(&valid[..LINK_FIXED_LEN - 1], "partition", b"a").is_err());

        let mut bad_magic = valid.clone();
        bad_magic[0] ^= 1;
        assert!(decode_link(&bad_magic, "partition", b"a").is_err());

        let mut bad_flags = valid.clone();
        bad_flags[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&2u32.to_be_bytes());
        assert!(decode_link(&bad_flags, "partition", b"a").is_err());

        let mut bad_candidate = valid.clone();
        bad_candidate[PREPARED_OFFSET] ^= 1;
        assert!(decode_link(&bad_candidate, "partition", b"a").is_err());

        let mut bad_payload = valid.clone();
        bad_payload[PAYLOAD_OFFSET] = 1;
        assert!(decode_link(&bad_payload, "partition", b"a").is_err());

        let removed = prepare(vec![participant(b"removed", 3, 1, true)]).unwrap();
        let mut removed_with_payload = witness(&removed.slots[0]).unwrap().to_vec();
        removed_with_payload[PAYLOAD_OFFSET + 8..PAYLOAD_OFFSET + 16]
            .copy_from_slice(&1u64.to_be_bytes());
        assert!(decode_link(&removed_with_payload, "partition", b"removed").is_err());

        let partition_len = u32::from_be_bytes(
            valid[NEXT_PARTITION_LEN_OFFSET..NEXT_PARTITION_LEN_OFFSET + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let partition_start = NEXT_PARTITION_LEN_OFFSET + 4;
        let mut non_utf8 = valid.clone();
        non_utf8[partition_start] = 0xff;
        assert!(decode_link(&non_utf8, "partition", b"a").is_err());

        let mut invalid_partition = valid.clone();
        invalid_partition[partition_start..partition_start + partition_len].fill(b'/');
        assert!(decode_link(&invalid_partition, "partition", b"a").is_err());

        let mut truncated_path = valid.clone();
        truncated_path[NEXT_PARTITION_LEN_OFFSET..NEXT_PARTITION_LEN_OFFSET + 4]
            .copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(decode_link(&truncated_path, "partition", b"a").is_err());

        let name_len_offset = NEXT_PARTITION_LEN_OFFSET + 4 + partition_len;
        let name_len = u32::from_be_bytes(
            valid[name_len_offset..name_len_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        let extra = MAX_LOCATION_LEN + 1 - partition_len - name_len;
        let name_end = name_len_offset + 4 + name_len;
        let mut oversized_location = valid.clone();
        oversized_location[name_len_offset..name_len_offset + 4]
            .copy_from_slice(&u32::try_from(name_len + extra).unwrap().to_be_bytes());
        oversized_location.splice(name_end..name_end, std::iter::repeat_n(0, extra));
        assert!(oversized_location.len() <= MAX_LINK_LEN);
        assert!(decode_link(&oversized_location, "partition", b"a").is_err());

        let mut trailing = valid;
        trailing.push(0);
        assert!(decode_link(&trailing, "partition", b"a").is_err());

        let mut cursor = Cursor {
            bytes: &[],
            offset: usize::MAX,
        };
        assert!(cursor.take(1).is_err());
    }
}

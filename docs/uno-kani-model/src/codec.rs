//! Concrete byte model for candidate slots and embedded batch witnesses.

#![cfg_attr(kani, allow(dead_code))]

#[cfg(any(test, kani))]
use crate::composed::{self, BridgeCandidate, Operation as ComposedOperation};

const PARTICIPANTS: usize = 3;
const ROOT_LEN: usize = 112;
#[cfg(not(kani))]
const ROOT_BODY_LEN: usize = 108;
const WRAPPER_LEN: usize = 16;
const LINK_LEN: usize = 338;
const SLOT_USED_LEN: usize = ROOT_LEN + WRAPPER_LEN + LINK_LEN;
#[cfg(kani)]
const SLOT_LEN: usize = SLOT_USED_LEN;
#[cfg(not(kani))]
const SLOT_LEN: usize = 2_048;
const PAYLOAD_LEN: usize = 4;

const ROOT_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_LOG_ROOT";
const WITNESS_DOMAIN: &[u8] = b"_COMMONWARE_RUNTIME_ATOMIC_BATCH_WITNESS";
const ROOT_MAGIC: &[u8; 7] = b"CWUNO14";
const WRAPPER_MAGIC: &[u8; 8] = b"CWUNOW13";
const LINK_MAGIC: &[u8; 8] = b"CWUNOL14";

const H_GROUP: [u8; 16] = [
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];
const C_GROUP: [u8; 16] = [
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
];
const G_GROUP: [u8; 16] = [
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0x00, 0x00, 0x1a, 0x0a,
];

const ROOT_OFFSET: u64 = 6_144;
const PAYLOAD_OFFSET: u64 = 8_192;
const PAYLOAD_END: u64 = PAYLOAD_OFFSET + PAYLOAD_LEN as u64;
const MIXED_APPEND_END: u64 = PAYLOAD_END + PAYLOAD_LEN as u64;

const OLD_PAYLOADS: [[u8; PAYLOAD_LEN]; PARTICIPANTS] = [
    [0x40, 0x50, 0x60, 0x70],
    [0x41, 0x51, 0x61, 0x71],
    [0x42, 0x52, 0x62, 0x72],
];
const NEW_PAYLOADS: [[u8; PAYLOAD_LEN]; PARTICIPANTS] = [
    [0xb4, 0x11, 0xef, 0x36],
    [0x04, 0xd1, 0x99, 0xd3],
    [0xab, 0x9b, 0xe0, 0x9b],
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RootState {
    Prepared,
    Recovered,
    Aborted,
    Materialized,
    Tombstone,
}

impl RootState {
    const fn index(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Recovered => 2,
            Self::Aborted => 3,
            Self::Materialized => 4,
            Self::Tombstone => 5,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Root {
    generation: u64,
    logical_len: u64,
    integrity_start: u64,
    integrity_checksum: u32,
    tag: [u8; 64],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Link {
    group_id: [u8; 16],
    participant_count: u32,
    ordinal: u32,
    removed: bool,
    incarnation: [u8; 16],
    base_generation: u64,
    root_offset: u64,
    logical_len: u64,
    payload_offset: u64,
    payload_len: u64,
    payload_checksum: u32,
    next_partition: u8,
    next_name: u8,
    next_incarnation: [u8; 16],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Observation {
    Old,
    New,
    Absent,
    Unavailable,
}

const fn incarnation(participant: usize) -> [u8; 16] {
    [0x31 + participant as u8; 16]
}

const fn name(participant: usize) -> u8 {
    b'a' + participant as u8
}

const fn state_guard(generation: u64, state: RootState) -> u8 {
    1 + 6 * (generation % 3) as u8 + state.index()
}

#[cfg(not(kani))]
const fn crc32c_reference(parts: &[&[u8]]) -> u32 {
    let mut crc = !0u32;
    let mut part_index = 0;
    while part_index < parts.len() {
        let part = parts[part_index];
        let mut byte_index = 0;
        while byte_index < part.len() {
            crc ^= part[byte_index] as u32;
            let mut bit = 0;
            while bit < 8 {
                let mask = 0u32.wrapping_sub(crc & 1);
                crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
                bit += 1;
            }
            byte_index += 1;
        }
        part_index += 1;
    }
    !crc
}

#[cfg(not(kani))]
const fn crc32c_update(mut crc: u32, bytes: &[u8], len: usize) -> u32 {
    let mut byte_index = 0;
    while byte_index < len {
        crc ^= bytes[byte_index] as u32;
        let mut bit = 0;
        while bit < 8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0x82f6_3b78 & mask);
            bit += 1;
        }
        byte_index += 1;
    }
    crc
}

#[cfg(kani)]
const fn metadata_checksum(_parts: &[&[u8]]) -> u32 {
    // Wrapper-checksum validation is removed in the proof model. This over-approximates accepted
    // torn witnesses, so ordering proofs may not rely on CRC32C rejecting a witness tear.
    0
}

#[cfg(not(kani))]
const fn metadata_checksum(parts: &[&[u8]]) -> u32 {
    crc32c_reference(parts)
}

#[cfg(kani)]
fn witness_checksum_valid(_wrapper: &[u8], _link: &[u8]) -> bool {
    true
}

#[cfg(not(kani))]
fn witness_checksum_valid(wrapper: &[u8], link: &[u8]) -> bool {
    read_u32(&wrapper[12..16]) == metadata_checksum(&[WITNESS_DOMAIN, &wrapper[..12], link])
}

#[cfg(kani)]
const fn encoded_root_checksum(root: &[u8; ROOT_LEN]) -> u32 {
    // Preserve a state-colored byte token for final-write provenance. Kani does not use this token
    // to reject a decoded root: a byte-spliced stored checksum may equal the CRC of a torn body
    // without being either endpoint checksum, so accepting every stored checksum is the sound
    // over-approximation when CRC32C arithmetic is not bit-blasted.
    u32::from_be_bytes([root[7]; 4])
}

#[cfg(not(kani))]
const fn encoded_root_checksum(root: &[u8; ROOT_LEN]) -> u32 {
    let crc = crc32c_update(!0, ROOT_DOMAIN, ROOT_DOMAIN.len());
    !crc32c_update(crc, root, ROOT_BODY_LEN)
}

#[cfg(kani)]
fn root_checksum_valid(_root: &[u8; ROOT_LEN]) -> bool {
    true
}

#[cfg(not(kani))]
fn root_checksum_valid(root: &[u8; ROOT_LEN]) -> bool {
    read_u32(&root[108..112]) == encoded_root_checksum(root)
}

#[cfg(kani)]
const fn encoded_witness_checksum(
    _wrapped: &[u8; WRAPPER_LEN + LINK_LEN],
    _link: &[u8; LINK_LEN],
) -> u32 {
    0
}

#[cfg(not(kani))]
const fn encoded_witness_checksum(
    wrapped: &[u8; WRAPPER_LEN + LINK_LEN],
    link: &[u8; LINK_LEN],
) -> u32 {
    let crc = crc32c_update(!0, WITNESS_DOMAIN, WITNESS_DOMAIN.len());
    let crc = crc32c_update(crc, wrapped, 12);
    !crc32c_update(crc, link, LINK_LEN)
}

const fn repeated_byte(value: u8) -> u32 {
    u32::from_be_bytes([value; 4])
}

fn abstract_payload_checksum(parts: &[&[u8]]) -> u32 {
    for participant in 0..PARTICIPANTS {
        if parts == [&OLD_PAYLOADS[participant][..]] {
            return repeated_byte(0x10 + participant as u8);
        }
        if parts == [&NEW_PAYLOADS[participant][..]] {
            return repeated_byte(0x20 + participant as u8);
        }
        if parts == [&OLD_PAYLOADS[participant][..2]] {
            return repeated_byte(0x30 + participant as u8);
        }
        if parts
            == [
                &OLD_PAYLOADS[participant][..],
                &NEW_PAYLOADS[participant][..],
            ]
        {
            return repeated_byte(0x40 + participant as u8);
        }
    }
    0
}

#[cfg(kani)]
fn payload_checksum(parts: &[&[u8]]) -> u32 {
    // The specification assumes no checksum collision. A distinct opaque token for every modeled
    // logical value encodes exactly that assumption without bit-blasting CRC32C in every harness.
    abstract_payload_checksum(parts)
}

#[cfg(not(kani))]
fn payload_checksum(parts: &[&[u8]]) -> u32 {
    crc32c_reference(parts)
}

const fn copy_into<const N: usize>(out: &mut [u8; N], offset: usize, input: &[u8]) {
    let mut index = 0;
    while index < input.len() {
        out[offset + index] = input[index];
        index += 1;
    }
}

const fn write_u32<const N: usize>(out: &mut [u8; N], offset: usize, value: u32) {
    copy_into(out, offset, &value.to_be_bytes());
}

const fn write_u64<const N: usize>(out: &mut [u8; N], offset: usize, value: u64) {
    copy_into(out, offset, &value.to_be_bytes());
}

fn read_u32(input: &[u8]) -> u32 {
    u32::from_be_bytes([input[0], input[1], input[2], input[3]])
}

fn read_u64(input: &[u8]) -> u64 {
    u64::from_be_bytes([
        input[0], input[1], input[2], input[3], input[4], input[5], input[6], input[7],
    ])
}

const fn build_tag(participant: usize, new: bool) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut index = 0;
    while index < out.len() {
        out[index] = if new {
            (0x80usize + 11 * participant + 3 * index) as u8
        } else {
            (0x10usize + 7 * participant + index) as u8
        };
        index += 1;
    }
    out
}

const OLD_TAGS: [[u8; 64]; PARTICIPANTS] = [
    build_tag(0, false),
    build_tag(1, false),
    build_tag(2, false),
];
const NEW_TAGS: [[u8; 64]; PARTICIPANTS] =
    [build_tag(0, true), build_tag(1, true), build_tag(2, true)];

fn tag(participant: usize, new: bool) -> [u8; 64] {
    if new {
        NEW_TAGS[participant]
    } else {
        OLD_TAGS[participant]
    }
}

const fn encode_root(
    participant: usize,
    generation: u64,
    state: RootState,
    payload_checksum: u32,
    new: bool,
) -> [u8; ROOT_LEN] {
    encode_root_fields(
        participant,
        generation,
        state,
        PAYLOAD_LEN as u64,
        payload_checksum,
        new,
    )
}

const fn encode_root_fields(
    participant: usize,
    generation: u64,
    state: RootState,
    logical_len: u64,
    integrity_checksum: u32,
    new_tag: bool,
) -> [u8; ROOT_LEN] {
    let mut root = [0u8; ROOT_LEN];
    copy_into(&mut root, 0, ROOT_MAGIC);
    root[7] = state_guard(generation, state);
    write_u64(&mut root, 8, generation);
    write_u64(&mut root, 16, logical_len);
    write_u64(&mut root, 24, 0);
    write_u32(&mut root, 32, integrity_checksum);
    write_u32(&mut root, 36, 0);
    write_u32(&mut root, 40, 0);
    let root_tag = if new_tag {
        NEW_TAGS[participant]
    } else {
        OLD_TAGS[participant]
    };
    copy_into(&mut root, 44, &root_tag);
    let checksum = encoded_root_checksum(&root);
    write_u32(&mut root, 108, checksum);
    root
}

fn decode_root(encoded: &[u8; ROOT_LEN], state: RootState) -> Option<Root> {
    if &encoded[..7] != ROOT_MAGIC {
        return None;
    }
    let generation = read_u64(&encoded[8..16]);
    if encoded[7] != state_guard(generation, state) {
        return None;
    }
    if !root_checksum_valid(encoded) {
        return None;
    }
    if read_u32(&encoded[36..40]) != 0 || read_u32(&encoded[40..44]) != 0 {
        return None;
    }
    let mut root_tag = [0u8; 64];
    root_tag.copy_from_slice(&encoded[44..108]);
    Some(Root {
        generation,
        logical_len: read_u64(&encoded[16..24]),
        integrity_start: read_u64(&encoded[24..32]),
        integrity_checksum: read_u32(&encoded[32..36]),
        tag: root_tag,
    })
}

#[cfg(kani)]
const fn old_payload_checksum(participant: usize) -> u32 {
    repeated_byte(0x10 + participant as u8)
}

#[cfg(not(kani))]
const fn old_payload_checksum(participant: usize) -> u32 {
    let crc = crc32c_update(!0, &OLD_PAYLOADS[participant], PAYLOAD_LEN);
    !crc
}

#[cfg(kani)]
const fn new_payload_checksum(participant: usize) -> u32 {
    repeated_byte(0x20 + participant as u8)
}

#[cfg(not(kani))]
const fn new_payload_checksum(participant: usize) -> u32 {
    let crc = crc32c_update(!0, &NEW_PAYLOADS[participant], PAYLOAD_LEN);
    !crc
}

#[cfg(kani)]
const fn appended_payload_checksum(participant: usize) -> u32 {
    repeated_byte(0x40 + participant as u8)
}

#[cfg(not(kani))]
const fn appended_payload_checksum(participant: usize) -> u32 {
    let crc = crc32c_update(!0, &OLD_PAYLOADS[participant], PAYLOAD_LEN);
    let crc = crc32c_update(crc, &NEW_PAYLOADS[participant], PAYLOAD_LEN);
    !crc
}

#[cfg(kani)]
const fn retained_payload_checksum(participant: usize) -> u32 {
    repeated_byte(0x30 + participant as u8)
}

#[cfg(not(kani))]
const fn retained_payload_checksum(participant: usize) -> u32 {
    let crc = crc32c_update(!0, &OLD_PAYLOADS[participant], 2);
    !crc
}

const fn build_old_candidate_roots(participant: usize) -> ([u8; ROOT_LEN], [u8; ROOT_LEN]) {
    let checksum = old_payload_checksum(participant);
    (
        encode_root(participant, 1, RootState::Prepared, checksum, false),
        encode_root(participant, 1, RootState::Recovered, checksum, false),
    )
}

const fn build_old_authority_root(participant: usize) -> [u8; ROOT_LEN] {
    encode_root_fields(participant, 2, RootState::Recovered, 0, 0, false)
}

fn old_authority_root(participant: usize) -> [u8; ROOT_LEN] {
    OLD_AUTHORITIES[participant]
}

const fn build_mixed_old_authority_root(participant: usize) -> [u8; ROOT_LEN] {
    encode_root(
        participant,
        2,
        RootState::Recovered,
        old_payload_checksum(participant),
        false,
    )
}

const OLD_AUTHORITIES: [[u8; ROOT_LEN]; PARTICIPANTS] = [
    build_old_authority_root(0),
    build_old_authority_root(1),
    build_old_authority_root(2),
];
const MIXED_OLD_AUTHORITIES: [[u8; ROOT_LEN]; PARTICIPANTS] = [
    build_mixed_old_authority_root(0),
    build_mixed_old_authority_root(1),
    build_mixed_old_authority_root(2),
];

fn mixed_old_authority_root(participant: usize) -> [u8; ROOT_LEN] {
    MIXED_OLD_AUTHORITIES[participant]
}

fn old_authorities() -> [[u8; ROOT_LEN]; PARTICIPANTS] {
    OLD_AUTHORITIES
}

fn mixed_old_authorities() -> [[u8; ROOT_LEN]; PARTICIPANTS] {
    MIXED_OLD_AUTHORITIES
}

fn old_authority_valid(participant: usize, encoded: &[u8; ROOT_LEN]) -> bool {
    *encoded == old_authority_root(participant)
        && decode_root(encoded, RootState::Recovered).is_some()
}

fn mixed_old_authority_valid(participant: usize, encoded: &[u8; ROOT_LEN]) -> bool {
    *encoded == mixed_old_authority_root(participant)
        && decode_root(encoded, RootState::Recovered).is_some()
}

const fn build_new_candidate_roots(participant: usize) -> ([u8; ROOT_LEN], [u8; ROOT_LEN]) {
    let checksum = new_payload_checksum(participant);
    (
        encode_root(participant, 3, RootState::Prepared, checksum, true),
        encode_root(participant, 3, RootState::Recovered, checksum, true),
    )
}

const NEW_CANDIDATE_ROOTS: [([u8; ROOT_LEN], [u8; ROOT_LEN]); PARTICIPANTS] = [
    build_new_candidate_roots(0),
    build_new_candidate_roots(1),
    build_new_candidate_roots(2),
];

fn new_candidate_roots(participant: usize) -> ([u8; ROOT_LEN], [u8; ROOT_LEN]) {
    NEW_CANDIDATE_ROOTS[participant]
}

fn one_phase_candidate_is_append_from_empty(participant: usize) -> bool {
    let Some(authority) = decode_root(&old_authority_root(participant), RootState::Recovered)
    else {
        return false;
    };
    let Some(same_slot_source) = decode_slot_root(&old_slot(participant), RootState::Materialized)
    else {
        return false;
    };
    let Some(candidate) = decode_root(&new_candidate_roots(participant).0, RootState::Prepared)
    else {
        return false;
    };
    let Some(link) = decode_candidate(&new_slot(participant), participant) else {
        return false;
    };
    same_slot_source.generation == 1
        && authority.generation == 2
        && authority.logical_len == 0
        && authority.integrity_checksum == 0
        && candidate.generation == authority.generation + 1
        && candidate.logical_len == PAYLOAD_LEN as u64
        && candidate.integrity_checksum == new_payload_checksum(participant)
        && link.base_generation == authority.generation
        && link.payload_offset == PAYLOAD_OFFSET
        && link.payload_len == PAYLOAD_LEN as u64
        && link.payload_checksum == new_payload_checksum(participant)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MixedOperation {
    Append,
    Rewind,
    Remove,
}

const fn mixed_operation(participant: usize) -> MixedOperation {
    match participant {
        0 => MixedOperation::Append,
        1 => MixedOperation::Rewind,
        _ => MixedOperation::Remove,
    }
}

const fn mixed_root_fields(participant: usize) -> (u64, u32, bool) {
    match mixed_operation(participant) {
        MixedOperation::Append => (8, appended_payload_checksum(participant), true),
        MixedOperation::Rewind => (2, retained_payload_checksum(participant), true),
        MixedOperation::Remove => (4, old_payload_checksum(participant), false),
    }
}

fn mixed_candidate_integrity_valid(participant: usize) -> bool {
    let Some(root) = decode_root(&mixed_candidate_roots(participant).0, RootState::Prepared) else {
        return false;
    };
    match mixed_operation(participant) {
        MixedOperation::Append => {
            root.logical_len == 8
                && root.integrity_checksum == appended_payload_checksum(participant)
        }
        MixedOperation::Rewind => {
            root.logical_len == 2
                && root.integrity_checksum == retained_payload_checksum(participant)
        }
        MixedOperation::Remove => {
            root.logical_len == 4 && root.integrity_checksum == old_payload_checksum(participant)
        }
    }
}

const fn build_mixed_candidate_roots(participant: usize) -> ([u8; ROOT_LEN], [u8; ROOT_LEN]) {
    let (logical_len, integrity_checksum, new_tag) = mixed_root_fields(participant);
    (
        encode_root_fields(
            participant,
            3,
            RootState::Prepared,
            logical_len,
            integrity_checksum,
            new_tag,
        ),
        encode_root_fields(
            participant,
            3,
            RootState::Recovered,
            logical_len,
            integrity_checksum,
            new_tag,
        ),
    )
}

const MIXED_CANDIDATE_ROOTS: [([u8; ROOT_LEN], [u8; ROOT_LEN]); PARTICIPANTS] = [
    build_mixed_candidate_roots(0),
    build_mixed_candidate_roots(1),
    build_mixed_candidate_roots(2),
];

fn mixed_candidate_roots(participant: usize) -> ([u8; ROOT_LEN], [u8; ROOT_LEN]) {
    MIXED_CANDIDATE_ROOTS[participant]
}

const fn mixed_payload_descriptor(participant: usize) -> (u64, u64, u32) {
    match mixed_operation(participant) {
        MixedOperation::Append => (
            PAYLOAD_END,
            PAYLOAD_LEN as u64,
            new_payload_checksum(participant),
        ),
        MixedOperation::Rewind | MixedOperation::Remove => (0, 0, 0),
    }
}

const fn build_link(
    participant: usize,
    group_id: [u8; 16],
    count: u32,
    ordinal: u32,
    next: usize,
    new: bool,
) -> [u8; LINK_LEN] {
    let (prepared_root, recovered_root) = if new {
        build_new_candidate_roots(participant)
    } else {
        build_old_candidate_roots(participant)
    };
    let payload_checksum = if new {
        new_payload_checksum(participant)
    } else {
        old_payload_checksum(participant)
    };
    encode_link_fields(
        participant,
        group_id,
        count,
        ordinal,
        next,
        false,
        if new { 2 } else { 0 },
        prepared_root,
        recovered_root,
        PAYLOAD_OFFSET,
        PAYLOAD_LEN as u64,
        payload_checksum,
    )
}

#[allow(clippy::too_many_arguments)]
const fn encode_link_fields(
    participant: usize,
    group_id: [u8; 16],
    count: u32,
    ordinal: u32,
    next: usize,
    removed: bool,
    base_generation: u64,
    prepared_root: [u8; ROOT_LEN],
    recovered_root: [u8; ROOT_LEN],
    payload_offset: u64,
    payload_len: u64,
    payload_checksum: u32,
) -> [u8; LINK_LEN] {
    let mut encoded = [0u8; LINK_LEN];
    let mut cursor = 0usize;
    copy_into(&mut encoded, cursor, LINK_MAGIC);
    cursor += 8;
    copy_into(&mut encoded, cursor, &group_id);
    cursor += 16;
    write_u32(&mut encoded, cursor, count);
    cursor += 4;
    write_u32(&mut encoded, cursor, ordinal);
    cursor += 4;
    write_u32(&mut encoded, cursor, if removed { 1 } else { 0 });
    cursor += 4;
    copy_into(&mut encoded, cursor, &incarnation(participant));
    cursor += 16;
    write_u64(&mut encoded, cursor, base_generation);
    cursor += 8;
    write_u64(&mut encoded, cursor, ROOT_OFFSET);
    cursor += 8;
    copy_into(&mut encoded, cursor, &prepared_root);
    cursor += ROOT_LEN;
    copy_into(&mut encoded, cursor, &recovered_root);
    cursor += ROOT_LEN;
    write_u64(&mut encoded, cursor, payload_offset);
    cursor += 8;
    write_u64(&mut encoded, cursor, payload_len);
    cursor += 8;
    write_u32(&mut encoded, cursor, payload_checksum);
    cursor += 4;
    write_u32(&mut encoded, cursor, 1);
    cursor += 4;
    encoded[cursor] = b'p';
    cursor += 1;
    write_u32(&mut encoded, cursor, 1);
    cursor += 4;
    encoded[cursor] = name(next);
    cursor += 1;
    copy_into(&mut encoded, cursor, &incarnation(next));
    encoded
}

fn decode_link(
    encoded: &[u8],
    expected_prepared_root: &[u8; ROOT_LEN],
    expected_recovered_root: &[u8; ROOT_LEN],
    logical_len: u64,
) -> Option<Link> {
    if encoded.len() != LINK_LEN || &encoded[..8] != LINK_MAGIC {
        return None;
    }
    let mut cursor = 8usize;
    let mut group_id = [0u8; 16];
    group_id.copy_from_slice(&encoded[cursor..cursor + 16]);
    cursor += 16;
    let participant_count = read_u32(&encoded[cursor..cursor + 4]);
    cursor += 4;
    let ordinal = read_u32(&encoded[cursor..cursor + 4]);
    cursor += 4;
    let flags = read_u32(&encoded[cursor..cursor + 4]);
    cursor += 4;
    if participant_count == 0 || ordinal >= participant_count || flags > 1 {
        return None;
    }
    let mut local_incarnation = [0u8; 16];
    local_incarnation.copy_from_slice(&encoded[cursor..cursor + 16]);
    cursor += 16;
    let base_generation = read_u64(&encoded[cursor..cursor + 8]);
    cursor += 8;
    let root_offset = read_u64(&encoded[cursor..cursor + 8]);
    cursor += 8;
    if &encoded[cursor..cursor + ROOT_LEN] != expected_prepared_root {
        return None;
    }
    cursor += ROOT_LEN;
    if &encoded[cursor..cursor + ROOT_LEN] != expected_recovered_root {
        return None;
    }
    cursor += ROOT_LEN;
    let payload_offset = read_u64(&encoded[cursor..cursor + 8]);
    cursor += 8;
    let payload_len = read_u64(&encoded[cursor..cursor + 8]);
    cursor += 8;
    let payload_checksum = read_u32(&encoded[cursor..cursor + 4]);
    cursor += 4;
    if read_u32(&encoded[cursor..cursor + 4]) != 1 {
        return None;
    }
    cursor += 4;
    let next_partition = encoded[cursor];
    cursor += 1;
    if read_u32(&encoded[cursor..cursor + 4]) != 1 {
        return None;
    }
    cursor += 4;
    let next_name = encoded[cursor];
    cursor += 1;
    let mut next_incarnation = [0u8; 16];
    next_incarnation.copy_from_slice(&encoded[cursor..cursor + 16]);
    cursor += 16;
    if cursor != LINK_LEN {
        return None;
    }
    Some(Link {
        group_id,
        participant_count,
        ordinal,
        removed: flags == 1,
        incarnation: local_incarnation,
        base_generation,
        root_offset,
        logical_len,
        payload_offset,
        payload_len,
        payload_checksum,
        next_partition,
        next_name,
        next_incarnation,
    })
}

const fn wrap_link(link: &[u8; LINK_LEN]) -> [u8; WRAPPER_LEN + LINK_LEN] {
    let mut wrapped = [0u8; WRAPPER_LEN + LINK_LEN];
    copy_into(&mut wrapped, 0, WRAPPER_MAGIC);
    write_u32(&mut wrapped, 8, LINK_LEN as u32);
    let checksum = encoded_witness_checksum(&wrapped, link);
    write_u32(&mut wrapped, 12, checksum);
    copy_into(&mut wrapped, 16, link);
    wrapped
}

fn decode_wrapped_link(
    slot: &[u8; SLOT_LEN],
    expected_prepared_root: &[u8; ROOT_LEN],
    expected_recovered_root: &[u8; ROOT_LEN],
    logical_len: u64,
) -> Option<Link> {
    let wrapper = &slot[ROOT_LEN..ROOT_LEN + WRAPPER_LEN];
    if &wrapper[..8] != WRAPPER_MAGIC || read_u32(&wrapper[8..12]) != LINK_LEN as u32 {
        return None;
    }
    let link = &slot[ROOT_LEN + WRAPPER_LEN..ROOT_LEN + WRAPPER_LEN + LINK_LEN];
    if !witness_checksum_valid(wrapper, link) {
        return None;
    }
    decode_link(
        link,
        expected_prepared_root,
        expected_recovered_root,
        logical_len,
    )
}

const fn old_group_shape(participant: usize) -> ([u8; 16], u32, u32, usize) {
    if participant < 2 {
        (H_GROUP, 2, participant as u32, 1 - participant)
    } else {
        (C_GROUP, 1, 0, 2)
    }
}

const fn build_old_slot(participant: usize) -> [u8; SLOT_LEN] {
    let (group_id, count, ordinal, next) = old_group_shape(participant);
    let root = encode_root(
        participant,
        1,
        RootState::Materialized,
        old_payload_checksum(participant),
        false,
    );
    let wrapped = wrap_link(&build_link(
        participant,
        group_id,
        count,
        ordinal,
        next,
        false,
    ));
    let mut slot = [0u8; SLOT_LEN];
    copy_into(&mut slot, 0, &root);
    copy_into(&mut slot, ROOT_LEN, &wrapped);
    slot
}

const fn build_new_slot(participant: usize) -> [u8; SLOT_LEN] {
    let root = encode_root(
        participant,
        3,
        RootState::Prepared,
        new_payload_checksum(participant),
        true,
    );
    let wrapped = wrap_link(&build_link(
        participant,
        G_GROUP,
        PARTICIPANTS as u32,
        participant as u32,
        (participant + 1) % PARTICIPANTS,
        true,
    ));
    let mut slot = [0u8; SLOT_LEN];
    copy_into(&mut slot, 0, &root);
    copy_into(&mut slot, ROOT_LEN, &wrapped);
    slot
}

const fn build_mixed_new_slot(participant: usize) -> [u8; SLOT_LEN] {
    let (prepared_root, recovered_root) = build_mixed_candidate_roots(participant);
    let (payload_offset, payload_len, payload_checksum) = mixed_payload_descriptor(participant);
    let link = encode_link_fields(
        participant,
        G_GROUP,
        PARTICIPANTS as u32,
        participant as u32,
        (participant + 1) % PARTICIPANTS,
        matches!(mixed_operation(participant), MixedOperation::Remove),
        2,
        prepared_root,
        recovered_root,
        payload_offset,
        payload_len,
        payload_checksum,
    );
    let wrapped = wrap_link(&link);
    let mut slot = [0u8; SLOT_LEN];
    copy_into(&mut slot, 0, &prepared_root);
    copy_into(&mut slot, ROOT_LEN, &wrapped);
    slot
}

const OLD_SLOTS: [[u8; SLOT_LEN]; PARTICIPANTS] =
    [build_old_slot(0), build_old_slot(1), build_old_slot(2)];
const NEW_SLOTS: [[u8; SLOT_LEN]; PARTICIPANTS] =
    [build_new_slot(0), build_new_slot(1), build_new_slot(2)];
const MIXED_NEW_SLOTS: [[u8; SLOT_LEN]; PARTICIPANTS] = [
    build_mixed_new_slot(0),
    build_mixed_new_slot(1),
    build_mixed_new_slot(2),
];

fn old_slot(participant: usize) -> [u8; SLOT_LEN] {
    OLD_SLOTS[participant]
}

fn new_slot(participant: usize) -> [u8; SLOT_LEN] {
    NEW_SLOTS[participant]
}

fn mixed_new_slot(participant: usize) -> [u8; SLOT_LEN] {
    MIXED_NEW_SLOTS[participant]
}

const GUARD_OFFSET: usize = 7;
const SLOT_SELECTOR_WORDS: usize = SLOT_USED_LEN.div_ceil(u64::BITS as usize);
const ROOT_SELECTOR_WORDS: usize = ROOT_LEN.div_ceil(u64::BITS as usize);

fn selector_contains<const N: usize>(selector: &[u64; N], offset: usize) -> bool {
    selector[offset / u64::BITS as usize] & (1u64 << (offset % u64::BITS as usize)) != 0
}

fn prepare_body_after_crash(
    participant: usize,
    survives: &[u64; SLOT_SELECTOR_WORDS],
) -> [u8; SLOT_LEN] {
    let old = old_slot(participant);
    let new = new_slot(participant);
    overlay_with(&old, &new, |offset| {
        offset != GUARD_OFFSET && selector_contains(survives, offset)
    })
}

fn mixed_prepare_body_after_crash(
    participant: usize,
    survives: &[u64; SLOT_SELECTOR_WORDS],
) -> [u8; SLOT_LEN] {
    let old = old_slot(participant);
    let new = mixed_new_slot(participant);
    overlay_with(&old, &new, |offset| {
        offset != GUARD_OFFSET && selector_contains(survives, offset)
    })
}

fn durable_prepare_body(participant: usize) -> [u8; SLOT_LEN] {
    let old = old_slot(participant);
    let new = new_slot(participant);
    overlay_with(&old, &new, |offset| offset != GUARD_OFFSET)
}

fn prepare_guard_after_crash(participant: usize, survives: bool) -> [u8; SLOT_LEN] {
    let mut slot = durable_prepare_body(participant);
    if survives {
        slot[GUARD_OFFSET] = new_slot(participant)[GUARD_OFFSET];
    }
    slot
}

fn mixed_prepare_guard_after_crash(participant: usize, survives: bool) -> [u8; SLOT_LEN] {
    let old = old_slot(participant);
    let new = mixed_new_slot(participant);
    let mut slot = overlay_with(&old, &new, |offset| offset != GUARD_OFFSET);
    if survives {
        slot[GUARD_OFFSET] = new[GUARD_OFFSET];
    }
    slot
}

fn abort_root(participant: usize) -> [u8; ROOT_LEN] {
    encode_root_fields(participant, 3, RootState::Aborted, 0, 0, false)
}

fn mixed_abort_root(participant: usize) -> [u8; ROOT_LEN] {
    encode_root(
        participant,
        3,
        RootState::Aborted,
        old_payload_checksum(participant),
        false,
    )
}

fn final_root(participant: usize) -> [u8; ROOT_LEN] {
    let state = if participant == 2 {
        RootState::Tombstone
    } else {
        RootState::Materialized
    };
    let (logical_len, integrity_checksum, new_tag) = mixed_root_fields(participant);
    encode_root_fields(
        participant,
        3,
        state,
        logical_len,
        integrity_checksum,
        new_tag,
    )
}

fn root_body_after_crash(
    source: &[u8; SLOT_LEN],
    target: &[u8; ROOT_LEN],
    survives: &[u64; ROOT_SELECTOR_WORDS],
) -> [u8; SLOT_LEN] {
    let mut disk = *source;
    for offset in 0..ROOT_LEN {
        if offset != GUARD_OFFSET && selector_contains(survives, offset) {
            disk[offset] = target[offset];
        }
    }
    disk
}

fn durable_root_body(source: &[u8; SLOT_LEN], target: &[u8; ROOT_LEN]) -> [u8; SLOT_LEN] {
    let mut disk = *source;
    for offset in 0..ROOT_LEN {
        if offset != GUARD_OFFSET {
            disk[offset] = target[offset];
        }
    }
    disk
}

fn root_guard_after_crash(
    source: &[u8; SLOT_LEN],
    target: &[u8; ROOT_LEN],
    survives: bool,
) -> [u8; SLOT_LEN] {
    let mut disk = durable_root_body(source, target);
    if survives {
        disk[GUARD_OFFSET] = target[GUARD_OFFSET];
    }
    disk
}

fn root_after_crash(
    source: &[u8; SLOT_LEN],
    target: &[u8; ROOT_LEN],
    survives: &[u64; ROOT_SELECTOR_WORDS],
) -> [u8; SLOT_LEN] {
    let mut disk = *source;
    for offset in 0..ROOT_LEN {
        if selector_contains(survives, offset) {
            disk[offset] = target[offset];
        }
    }
    disk
}

fn final_transition_proves_decision(
    source: &[u8; SLOT_LEN],
    target: &[u8; ROOT_LEN],
    disk: &[u8; SLOT_LEN],
) -> bool {
    if disk[ROOT_LEN..] != source[ROOT_LEN..] {
        return false;
    }
    for offset in 0..ROOT_LEN {
        if disk[offset] != source[offset] && disk[offset] != target[offset] {
            return false;
        }
    }
    if disk[..ROOT_LEN] == source[..ROOT_LEN] {
        return true;
    }
    (0..ROOT_LEN).any(|offset| target[offset] != source[offset] && disk[offset] == target[offset])
}

fn decode_slot_root(slot: &[u8; SLOT_LEN], state: RootState) -> Option<Root> {
    let mut root = [0u8; ROOT_LEN];
    root.copy_from_slice(&slot[..ROOT_LEN]);
    decode_root(&root, state)
}

const fn in_closed_range(offset: usize, start: usize, end: usize) -> bool {
    offset >= start && offset <= end
}

const fn fixture_survives(participant: usize, offset: usize) -> bool {
    if participant >= 2 {
        return false;
    }
    matches!(offset, 7 | 15 | 187 | 203 | 211 | 315 | 323)
        || in_closed_range(offset, 32, 35)
        || in_closed_range(offset, 44, 111)
        || in_closed_range(offset, 228, 231)
        || in_closed_range(offset, 240, 307)
        || in_closed_range(offset, 340, 343)
        || in_closed_range(offset, 352, 419)
        || in_closed_range(offset, 436, 439)
        || (participant == 0 && offset == 127)
        || (participant == 1 && offset == 125)
}

fn overlay_with(
    old: &[u8; SLOT_LEN],
    new: &[u8; SLOT_LEN],
    mut survives: impl FnMut(usize) -> bool,
) -> [u8; SLOT_LEN] {
    let mut disk = *old;
    for offset in 0..SLOT_USED_LEN {
        disk[offset] = if survives(offset) {
            new[offset]
        } else {
            old[offset]
        };
    }
    disk
}

const fn build_fixture_slot(participant: usize) -> [u8; SLOT_LEN] {
    let old = OLD_SLOTS[participant];
    let new = NEW_SLOTS[participant];
    let mut disk = old;
    let mut offset = 0;
    while offset < SLOT_USED_LEN {
        if fixture_survives(participant, offset) {
            disk[offset] = new[offset];
        }
        offset += 1;
    }
    disk
}

const FIXTURE_SLOTS: [[u8; SLOT_LEN]; PARTICIPANTS] = [
    build_fixture_slot(0),
    build_fixture_slot(1),
    build_fixture_slot(2),
];

fn fixture_slot(participant: usize) -> [u8; SLOT_LEN] {
    FIXTURE_SLOTS[participant]
}

fn decode_candidate(slot: &[u8; SLOT_LEN], participant: usize) -> Option<Link> {
    let mut encoded_root = [0u8; ROOT_LEN];
    encoded_root.copy_from_slice(&slot[..ROOT_LEN]);
    let root = decode_root(&encoded_root, RootState::Prepared)?;
    if root.generation != 3
        || root.logical_len != PAYLOAD_LEN as u64
        || root.integrity_start != 0
        || root.tag != tag(participant, true)
    {
        return None;
    }
    let expected_recovered = new_candidate_roots(participant).1;
    let link = decode_wrapped_link(slot, &encoded_root, &expected_recovered, root.logical_len)?;
    if !candidate_link_matches(
        &link,
        participant,
        false,
        PAYLOAD_OFFSET,
        PAYLOAD_LEN as u64,
        root.integrity_checksum,
    ) {
        return None;
    }
    Some(link)
}

#[allow(clippy::too_many_arguments)]
fn candidate_link_matches(
    link: &Link,
    participant: usize,
    removed: bool,
    payload_offset: u64,
    payload_len: u64,
    payload_checksum: u32,
) -> bool {
    !(link.incarnation != incarnation(participant)
        || link.ordinal != participant as u32
        || link.base_generation != 2
        || link.root_offset != ROOT_OFFSET
        || link.removed != removed
        || link.payload_offset != payload_offset
        || link.payload_len != payload_len
        || link.payload_checksum != payload_checksum
        || link.next_partition != b'p')
}

fn decode_mixed_candidate(slot: &[u8; SLOT_LEN], participant: usize) -> Option<Link> {
    let mut encoded_root = [0u8; ROOT_LEN];
    encoded_root.copy_from_slice(&slot[..ROOT_LEN]);
    let root = decode_root(&encoded_root, RootState::Prepared)?;
    let (logical_len, integrity_checksum, new_tag) = mixed_root_fields(participant);
    if root.generation != 3
        || root.logical_len != logical_len
        || root.integrity_start != 0
        || root.integrity_checksum != integrity_checksum
        || root.tag != tag(participant, new_tag)
    {
        return None;
    }
    let expected_recovered = mixed_candidate_roots(participant).1;
    let link = decode_wrapped_link(slot, &encoded_root, &expected_recovered, root.logical_len)?;
    let (payload_offset, payload_len, payload_checksum) = mixed_payload_descriptor(participant);
    if !candidate_link_matches(
        &link,
        participant,
        mixed_operation(participant) == MixedOperation::Remove,
        payload_offset,
        payload_len,
        payload_checksum,
    ) {
        return None;
    }
    Some(link)
}

#[cfg(any(test, kani))]
const fn composed_operation(operation: MixedOperation) -> ComposedOperation {
    match operation {
        MixedOperation::Append => ComposedOperation::Append,
        MixedOperation::Rewind => ComposedOperation::Rewind,
        MixedOperation::Remove => ComposedOperation::Remove,
    }
}

#[cfg(any(test, kani))]
fn physical_mixed_projection(participant: usize) -> Option<BridgeCandidate> {
    let slot = mixed_new_slot(participant);
    let mut encoded_root = [0u8; ROOT_LEN];
    encoded_root.copy_from_slice(&slot[..ROOT_LEN]);
    let root = decode_root(&encoded_root, RootState::Prepared)?;
    let expected_recovered = mixed_candidate_roots(participant).1;
    let link = decode_wrapped_link(&slot, &encoded_root, &expected_recovered, root.logical_len)?;
    let operation = mixed_operation(participant);
    let (logical_len, integrity_checksum, new_tag) = mixed_root_fields(participant);
    let (payload_offset, payload_len, payload_checksum) = mixed_payload_descriptor(participant);
    let physical_len = [MIXED_APPEND_END, PAYLOAD_END, PAYLOAD_END][participant];
    let next = participant_for_name(link.next_name).unwrap_or(PARTICIPANTS);
    let extent_valid = if link.payload_len == 0 {
        physical_len >= PAYLOAD_OFFSET + root.logical_len
    } else {
        physical_len >= link.payload_offset + link.payload_len
    };
    Some(BridgeCandidate {
        group_is_new: link.group_id == G_GROUP,
        count: link.participant_count,
        ordinal: link.ordinal,
        next,
        base_generation: link.base_generation,
        operation: composed_operation(operation),
        removed: link.removed,
        logical_evidence_valid: root.generation == 3
            && root.logical_len == logical_len
            && root.integrity_start == 0
            && root.integrity_checksum == integrity_checksum
            && root.tag == tag(participant, new_tag)
            && mixed_logical_payload_valid(
                participant,
                &OLD_PAYLOADS[participant],
                &NEW_PAYLOADS[participant],
                physical_len,
            ),
        suffix_evidence_valid: link.payload_offset == payload_offset
            && link.payload_len == payload_len
            && link.payload_checksum == payload_checksum,
        suffix_len: link.payload_len,
        logical_len: root.logical_len,
        extent_valid,
    })
}

#[cfg(any(test, kani))]
fn physical_mixed_ring_matches_composed_decoder() -> bool {
    let (Some(a), Some(b), Some(c)) = (
        physical_mixed_projection(0),
        physical_mixed_projection(1),
        physical_mixed_projection(2),
    ) else {
        return false;
    };
    composed::bridge_ring_decodes(
        [a, b, c],
        [
            ComposedOperation::Append,
            ComposedOperation::Rewind,
            ComposedOperation::Remove,
        ],
    )
}

fn decode_mixed_final(slot: &[u8; SLOT_LEN], participant: usize) -> bool {
    let target = final_root(participant);
    if slot[..ROOT_LEN] != target {
        return false;
    }
    let state = if mixed_operation(participant) == MixedOperation::Remove {
        RootState::Tombstone
    } else {
        RootState::Materialized
    };
    if decode_slot_root(slot, state).is_none() {
        return false;
    }
    let (prepared_root, recovered_root) = mixed_candidate_roots(participant);
    let logical_len = mixed_root_fields(participant).0;
    let Some(link) = decode_wrapped_link(slot, &prepared_root, &recovered_root, logical_len) else {
        return false;
    };
    let (payload_offset, payload_len, payload_checksum) = mixed_payload_descriptor(participant);
    link.group_id == G_GROUP
        && link.participant_count == PARTICIPANTS as u32
        && candidate_link_matches(
            &link,
            participant,
            mixed_operation(participant) == MixedOperation::Remove,
            payload_offset,
            payload_len,
            payload_checksum,
        )
}

fn participant_for_name(value: u8) -> Option<usize> {
    match value {
        b'a' => Some(0),
        b'b' => Some(1),
        b'c' => Some(2),
        _ => None,
    }
}

fn payload_valid(link: &Link, payload: &[u8; PAYLOAD_LEN], physical_len: u64) -> bool {
    link.payload_len == PAYLOAD_LEN as u64
        && physical_len >= link.payload_offset + link.payload_len
        && link.payload_checksum == payload_checksum(&[payload])
}

fn old_payload_image_valid(
    participant: usize,
    base_payload: &[u8; PAYLOAD_LEN],
    physical_len: u64,
) -> bool {
    physical_len >= PAYLOAD_END
        && payload_checksum(&[base_payload]) == old_payload_checksum(participant)
}

fn mixed_logical_payload_valid(
    participant: usize,
    base_payload: &[u8; PAYLOAD_LEN],
    suffix_payload: &[u8; PAYLOAD_LEN],
    physical_len: u64,
) -> bool {
    if !old_payload_image_valid(participant, base_payload, physical_len) {
        return false;
    }
    match mixed_operation(participant) {
        MixedOperation::Append => {
            physical_len >= MIXED_APPEND_END
                && payload_checksum(&[base_payload, suffix_payload])
                    == appended_payload_checksum(participant)
        }
        MixedOperation::Rewind => {
            physical_len >= PAYLOAD_OFFSET + 2
                && payload_checksum(&[&base_payload[..2]]) == retained_payload_checksum(participant)
        }
        MixedOperation::Remove => true,
    }
}

fn mixed_payload_valid(
    participant: usize,
    link: &Link,
    base_payload: &[u8; PAYLOAD_LEN],
    suffix_payload: &[u8; PAYLOAD_LEN],
    physical_len: u64,
) -> bool {
    if !mixed_logical_payload_valid(participant, base_payload, suffix_payload, physical_len) {
        return false;
    }
    match mixed_operation(participant) {
        MixedOperation::Append => {
            link.logical_len == 8 && payload_valid(link, suffix_payload, physical_len)
        }
        MixedOperation::Rewind => {
            link.logical_len == 2
                && link.payload_offset == 0
                && link.payload_len == 0
                && link.payload_checksum == 0
        }
        MixedOperation::Remove => {
            link.logical_len == 4
                && link.payload_offset == 0
                && link.payload_len == 0
                && link.payload_checksum == 0
        }
    }
}

fn validate_ring(
    slots: &[[u8; SLOT_LEN]; PARTICIPANTS],
    payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    physical_lengths: &[u64; PARTICIPANTS],
    authorities: &[[u8; ROOT_LEN]; PARTICIPANTS],
    start: usize,
) -> Option<u8> {
    validate_ring_kind(
        slots,
        payloads,
        payloads,
        physical_lengths,
        authorities,
        start,
        false,
    )
}

fn validate_mixed_ring(
    slots: &[[u8; SLOT_LEN]; PARTICIPANTS],
    base_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    suffix_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    physical_lengths: &[u64; PARTICIPANTS],
    authorities: &[[u8; ROOT_LEN]; PARTICIPANTS],
) -> Option<u8> {
    validate_ring_kind(
        slots,
        base_payloads,
        suffix_payloads,
        physical_lengths,
        authorities,
        0,
        true,
    )
}

fn validate_ring_kind(
    slots: &[[u8; SLOT_LEN]; PARTICIPANTS],
    base_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    suffix_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    physical_lengths: &[u64; PARTICIPANTS],
    authorities: &[[u8; ROOT_LEN]; PARTICIPANTS],
    start: usize,
    mixed: bool,
) -> Option<u8> {
    fn decode_member(
        slots: &[[u8; SLOT_LEN]; PARTICIPANTS],
        participant: usize,
        mixed: bool,
    ) -> Option<Link> {
        match (participant, mixed) {
            (0, false) => decode_candidate(&slots[0], 0),
            (1, false) => decode_candidate(&slots[1], 1),
            (2, false) => decode_candidate(&slots[2], 2),
            (0, true) => decode_mixed_candidate(&slots[0], 0),
            (1, true) => decode_mixed_candidate(&slots[1], 1),
            (2, true) => decode_mixed_candidate(&slots[2], 2),
            _ => None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn validate_member(
        link: &Link,
        participant: usize,
        expected_ordinal: usize,
        first_group: [u8; 16],
        count: usize,
        base_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
        suffix_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
        physical_lengths: &[u64; PARTICIPANTS],
        authorities: &[[u8; ROOT_LEN]; PARTICIPANTS],
        mixed: bool,
    ) -> Option<usize> {
        if link.group_id != first_group
            || link.participant_count as usize != count
            || link.ordinal as usize != expected_ordinal
            || if mixed {
                !mixed_old_authority_valid(participant, &authorities[participant])
            } else {
                !old_authority_valid(participant, &authorities[participant])
            }
            || (!mixed && link.removed)
            || (mixed
                && !mixed_payload_valid(
                    participant,
                    link,
                    &base_payloads[participant],
                    &suffix_payloads[participant],
                    physical_lengths[participant],
                ))
            || (!mixed
                && !payload_valid(
                    link,
                    &suffix_payloads[participant],
                    physical_lengths[participant],
                ))
        {
            return None;
        }
        let next = participant_for_name(link.next_name)?;
        if link.next_incarnation != incarnation(next) {
            return None;
        }
        Some(next)
    }

    if start != 0 {
        return None;
    }
    let first = decode_member(slots, 0, mixed)?;
    let count = usize::try_from(first.participant_count).ok()?;
    if count == 0
        || count > PARTICIPANTS
        || first.ordinal != 0
        || (mixed && (first.group_id != G_GROUP || count != PARTICIPANTS))
    {
        return None;
    }
    let second_index = validate_member(
        &first,
        0,
        0,
        first.group_id,
        count,
        base_payloads,
        suffix_payloads,
        physical_lengths,
        authorities,
        mixed,
    )?;
    if count == 1 {
        return (second_index == 0).then_some(0b001);
    }
    if second_index == 0 {
        return None;
    }
    let second = decode_member(slots, second_index, mixed)?;
    let third_index = validate_member(
        &second,
        second_index,
        1,
        first.group_id,
        count,
        base_payloads,
        suffix_payloads,
        physical_lengths,
        authorities,
        mixed,
    )?;
    let visited = 0b001 | (1 << second_index);
    if count == 2 {
        return (third_index == 0).then_some(visited);
    }
    if third_index == 0 || visited & (1 << third_index) != 0 {
        return None;
    }
    let third = decode_member(slots, third_index, mixed)?;
    let next = validate_member(
        &third,
        third_index,
        2,
        first.group_id,
        count,
        base_payloads,
        suffix_payloads,
        physical_lengths,
        authorities,
        mixed,
    )?;
    let visited = visited | (1 << third_index);
    (next == 0 && visited == 0b111).then_some(visited)
}

fn recover_members(
    slots: &[[u8; SLOT_LEN]; PARTICIPANTS],
    payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    physical_lengths: &[u64; PARTICIPANTS],
    authorities: &[[u8; ROOT_LEN]; PARTICIPANTS],
) -> u8 {
    validate_ring(slots, payloads, physical_lengths, authorities, 0).unwrap_or(0)
}

fn code_last_recovered(guard_survives: [bool; PARTICIPANTS]) -> u8 {
    let slots = core::array::from_fn(|participant| {
        prepare_guard_after_crash(participant, guard_survives[participant])
    });
    recover_members(
        &slots,
        &NEW_PAYLOADS,
        &[PAYLOAD_END; PARTICIPANTS],
        &old_authorities(),
    )
}

fn recover_mixed_members(
    slots: &[[u8; SLOT_LEN]; PARTICIPANTS],
    base_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    suffix_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    physical_lengths: &[u64; PARTICIPANTS],
    authorities: &[[u8; ROOT_LEN]; PARTICIPANTS],
) -> u8 {
    validate_mixed_ring(
        slots,
        base_payloads,
        suffix_payloads,
        physical_lengths,
        authorities,
    )
    .unwrap_or(0)
}

fn mixed_code_last_recovered(guard_survives: [bool; PARTICIPANTS]) -> u8 {
    let slots = core::array::from_fn(|participant| {
        mixed_prepare_guard_after_crash(participant, guard_survives[participant])
    });
    recover_mixed_members(
        &slots,
        &OLD_PAYLOADS,
        &NEW_PAYLOADS,
        &[MIXED_APPEND_END, PAYLOAD_END, PAYLOAD_END],
        &mixed_old_authorities(),
    )
}

fn observations(
    recovered: u8,
    authorities: &[[u8; ROOT_LEN]; PARTICIPANTS],
) -> [Observation; PARTICIPANTS] {
    core::array::from_fn(|participant| {
        if recovered & (1 << participant) != 0 {
            Observation::New
        } else if old_authority_valid(participant, &authorities[participant]) {
            Observation::Old
        } else {
            Observation::Unavailable
        }
    })
}

fn atomic_observation(value: &[Observation; PARTICIPANTS]) -> bool {
    value.iter().all(|entry| *entry == Observation::Old)
        || value.iter().all(|entry| *entry == Observation::New)
}

fn mixed_observations(
    recovered: u8,
    authorities: &[[u8; ROOT_LEN]; PARTICIPANTS],
    base_payloads: &[[u8; PAYLOAD_LEN]; PARTICIPANTS],
    physical_lengths: &[u64; PARTICIPANTS],
) -> [Observation; PARTICIPANTS] {
    core::array::from_fn(|participant| {
        if recovered & (1 << participant) == 0 {
            if mixed_old_authority_valid(participant, &authorities[participant])
                && old_payload_image_valid(
                    participant,
                    &base_payloads[participant],
                    physical_lengths[participant],
                )
            {
                Observation::Old
            } else {
                Observation::Unavailable
            }
        } else if mixed_operation(participant) == MixedOperation::Remove {
            Observation::Absent
        } else {
            Observation::New
        }
    })
}

fn mixed_atomic_observation(value: &[Observation; PARTICIPANTS]) -> bool {
    *value == [Observation::Old; PARTICIPANTS]
        || *value == [Observation::New, Observation::New, Observation::Absent]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32c_check_vector() {
        assert_eq!(crc32c_reference(&[b"123456789"]), 0xe306_9283);
    }

    #[test]
    fn abstract_payload_checksums_are_distinct_for_the_modeled_values() {
        let mut checksums = [0u32; PARTICIPANTS * 4];
        for participant in 0..PARTICIPANTS {
            checksums[4 * participant] = abstract_payload_checksum(&[&OLD_PAYLOADS[participant]]);
            checksums[4 * participant + 1] =
                abstract_payload_checksum(&[&NEW_PAYLOADS[participant]]);
            checksums[4 * participant + 2] =
                abstract_payload_checksum(&[&OLD_PAYLOADS[participant][..2]]);
            checksums[4 * participant + 3] = abstract_payload_checksum(&[
                &OLD_PAYLOADS[participant],
                &NEW_PAYLOADS[participant],
            ]);
        }
        for (index, checksum) in checksums.iter().enumerate() {
            assert_ne!(*checksum, 0);
            assert!(!checksums[..index].contains(checksum));
        }
        assert_eq!(abstract_payload_checksum(&[&[0u8; PAYLOAD_LEN]]), 0);
    }

    #[test]
    fn slot_padding_is_identical_and_unobserved() {
        for participant in 0..PARTICIPANTS {
            assert!(
                old_slot(participant)[SLOT_USED_LEN..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert!(
                new_slot(participant)[SLOT_USED_LEN..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert!(
                mixed_new_slot(participant)[SLOT_USED_LEN..]
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }

    #[test]
    fn physical_fixture_matches_independent_constants() {
        assert_eq!(old_payload_checksum(0), 0xa502_9878);
        assert_eq!(old_payload_checksum(1), 0x3ccf_bbca);
        assert_eq!(new_payload_checksum(0), 0x0023_8212);
        assert_eq!(new_payload_checksum(1), 0x20d7_20b2);
        assert_eq!(new_payload_checksum(2), 0x0000_0000);

        let old_a = old_slot(0);
        let old_b = old_slot(1);
        let new_a = new_slot(0);
        let new_b = new_slot(1);
        assert_eq!(read_u32(&old_a[108..112]), 0xe286_7e2f);
        assert_eq!(read_u32(&old_b[108..112]), 0x7d38_0279);
        assert_eq!(read_u32(&new_a[108..112]), 0x1104_98f3);
        assert_eq!(read_u32(&new_b[108..112]), 0x055d_4a11);
        assert_eq!(read_u32(&new_a[124..128]), 0xc3bc_b36c);
        assert_eq!(read_u32(&new_b[124..128]), 0x4777_5580);
        assert_eq!(read_u32(&old_a[124..128]), 0x47ad_25a0);
        assert_eq!(read_u32(&old_b[124..128]), 0x73a8_b16e);

        let hybrid_a = fixture_slot(0);
        let hybrid_b = fixture_slot(1);
        assert_eq!(read_u32(&hybrid_a[124..128]), 0x47ad_256c);
        assert_eq!(read_u32(&hybrid_b[124..128]), 0x7377_b16e);
        assert!(decode_candidate(&hybrid_a, 0).is_some());
        assert!(decode_candidate(&hybrid_b, 1).is_some());
    }

    #[test]
    fn one_phase_fixture_recovers_mixed_vector() {
        let slots = [fixture_slot(0), fixture_slot(1), fixture_slot(2)];
        let payloads = [NEW_PAYLOADS[0], NEW_PAYLOADS[1], OLD_PAYLOADS[2]];
        let lengths = [PAYLOAD_END; PARTICIPANTS];
        let recovered = recover_members(&slots, &payloads, &lengths, &old_authorities());
        assert_eq!(recovered, 0b011);
        assert_eq!(
            observations(recovered, &old_authorities()),
            [Observation::New, Observation::New, Observation::Old]
        );
        assert!(!atomic_observation(&observations(
            recovered,
            &old_authorities()
        )));
    }

    #[test]
    fn one_phase_fixture_is_an_append_from_an_empty_authority() {
        for participant in 0..PARTICIPANTS {
            assert!(one_phase_candidate_is_append_from_empty(participant));
        }
    }

    #[test]
    fn code_last_prepare_accepts_only_the_complete_ring() {
        let payloads = NEW_PAYLOADS;
        let lengths = [PAYLOAD_END; PARTICIPANTS];
        for participant in 0..PARTICIPANTS {
            for survives in [[0u64; SLOT_SELECTOR_WORDS], [u64::MAX; SLOT_SELECTOR_WORDS]] {
                assert!(
                    decode_candidate(
                        &prepare_body_after_crash(participant, &survives),
                        participant,
                    )
                    .is_none()
                );
            }
        }
        for mask in 0u8..8 {
            let slots = core::array::from_fn(|participant| {
                prepare_guard_after_crash(participant, mask & (1 << participant) != 0)
            });
            let recovered = recover_members(&slots, &payloads, &lengths, &old_authorities());
            assert_eq!(recovered, if mask == 0b111 { 0b111 } else { 0 });
            assert!(atomic_observation(&observations(
                recovered,
                &old_authorities()
            )));
        }
    }

    #[test]
    fn all_append_code_last_uses_its_empty_generation_two_authorities() {
        assert_eq!(code_last_recovered([true; PARTICIPANTS]), 0b111);
    }

    #[test]
    fn code_last_abort_and_final_repair_decode_from_bytes() {
        let source = mixed_new_slot(0);
        let all = [u64::MAX; ROOT_SELECTOR_WORDS];
        let abort = mixed_abort_root(0);
        let abort_body = root_body_after_crash(&source, &abort, &all);
        assert!(decode_slot_root(&abort_body, RootState::Aborted).is_none());
        let aborted = root_guard_after_crash(&source, &abort, true);
        assert!(decode_slot_root(&aborted, RootState::Aborted).is_some());

        let final_header = final_root(0);
        let finalized = root_after_crash(&source, &final_header, &all);
        assert!(decode_slot_root(&finalized, RootState::Materialized).is_some());
        assert!(decode_mixed_final(&finalized, 0));
        assert_eq!(
            &finalized[ROOT_LEN..],
            &source[ROOT_LEN..],
            "final repair must preserve the decision witness"
        );
    }

    #[test]
    fn abort_root_preserves_the_empty_authority_projection() {
        for participant in 0..PARTICIPANTS {
            let authority = decode_root(&old_authority_root(participant), RootState::Recovered)
                .expect("the empty predecessor authority must decode");
            let abort = decode_root(&abort_root(participant), RootState::Aborted)
                .expect("the abort root must decode");

            assert_eq!(abort.logical_len, authority.logical_len);
            assert_eq!(abort.integrity_start, authority.integrity_start);
            assert_eq!(abort.integrity_checksum, authority.integrity_checksum);
            assert_eq!(abort.tag, authority.tag);
        }
    }

    #[test]
    fn mixed_code_last_workload_decodes_from_full_slots() {
        let base_payloads = OLD_PAYLOADS;
        let suffix_payloads = NEW_PAYLOADS;
        let lengths = [MIXED_APPEND_END, PAYLOAD_END, PAYLOAD_END];
        for participant in 0..PARTICIPANTS {
            let survives = [u64::MAX; SLOT_SELECTOR_WORDS];
            assert!(
                decode_mixed_candidate(
                    &mixed_prepare_body_after_crash(participant, &survives),
                    participant,
                )
                .is_none()
            );
        }
        for mask in 0u8..8 {
            let slots = core::array::from_fn(|participant| {
                mixed_prepare_guard_after_crash(participant, mask & (1 << participant) != 0)
            });
            let recovered = recover_mixed_members(
                &slots,
                &base_payloads,
                &suffix_payloads,
                &lengths,
                &mixed_old_authorities(),
            );
            assert_eq!(recovered, if mask == 0b111 { 0b111 } else { 0 });
            assert!(mixed_atomic_observation(&mixed_observations(
                recovered,
                &mixed_old_authorities(),
                &base_payloads,
                &lengths,
            )));
        }
    }

    #[test]
    fn mixed_code_last_uses_its_length_four_generation_two_authorities() {
        assert_eq!(mixed_code_last_recovered([true; PARTICIPANTS]), 0b111);
    }

    #[test]
    fn mixed_ring_rejects_corrupted_retained_payload() {
        let slots = core::array::from_fn(mixed_new_slot);
        let mut base_payloads = OLD_PAYLOADS;
        base_payloads[1][0] ^= 1;
        let lengths = [MIXED_APPEND_END, PAYLOAD_END, PAYLOAD_END];

        assert_eq!(
            recover_mixed_members(
                &slots,
                &base_payloads,
                &NEW_PAYLOADS,
                &lengths,
                &mixed_old_authorities(),
            ),
            0,
            "the rewind member must prove its retained prefix from disk bytes"
        );
        assert_eq!(
            mixed_observations(0, &mixed_old_authorities(), &base_payloads, &lengths),
            [Observation::Old, Observation::Unavailable, Observation::Old],
            "an exact authority root cannot stand in for corrupted fallback payload bytes"
        );
    }

    #[test]
    fn encoded_mixed_roots_are_self_consistent() {
        for participant in 0..PARTICIPANTS {
            assert!(mixed_candidate_integrity_valid(participant));
        }
    }

    #[test]
    fn old_fallback_requires_an_exact_authority_root() {
        let mut authorities = old_authorities();
        authorities[1][0] ^= 1;
        assert_eq!(
            observations(0, &authorities),
            [Observation::Old, Observation::Unavailable, Observation::Old]
        );
    }

    #[test]
    fn crc_only_final_tear_retains_disk_decision_evidence() {
        let source = mixed_new_slot(0);
        let target = final_root(0);
        let checksum_offset = (108..ROOT_LEN)
            .find(|offset| source[*offset] != target[*offset])
            .expect("prepared and final roots must have different checksums");
        let mut survives = [0u64; ROOT_SELECTOR_WORDS];
        survives[checksum_offset / u64::BITS as usize] |=
            1 << (checksum_offset % u64::BITS as usize);
        let disk = root_after_crash(&source, &target, &survives);

        assert_ne!(disk[..ROOT_LEN], source[..ROOT_LEN]);
        assert_ne!(disk[..ROOT_LEN], target);
        assert_eq!(disk[GUARD_OFFSET], source[GUARD_OFFSET]);
        assert!(final_transition_proves_decision(&source, &target, &disk));
    }

    #[test]
    fn physical_mixed_ring_matches_the_composed_decoder() {
        assert!(physical_mixed_ring_matches_composed_decoder());
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn checksum_erased_splice_projection_decodes_expected_members() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let candidate = decode_candidate(&fixture_slot(participant), participant);
        if participant < 2 {
            let Some(link) = candidate else {
                assert!(false, "the physical splice member must decode");
                return;
            };
            assert_eq!(link.group_id, H_GROUP);
            assert_eq!(link.participant_count, 2);
            assert_eq!(link.ordinal, participant as u32);
            assert_eq!(link.next_name, name(1 - participant));
            assert_eq!(link.payload_checksum, new_payload_checksum(participant));
        } else {
            assert!(candidate.is_none());
        }
    }

    #[kani::proof]
    fn physical_all_append_candidate_fields_are_self_consistent() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let slot = new_slot(participant);
        let Some(link) = decode_candidate(&slot, participant) else {
            assert!(false, "the exact candidate must decode");
            return;
        };
        assert_eq!(link.group_id, G_GROUP);
        assert_eq!(link.participant_count, PARTICIPANTS as u32);
        assert_eq!(link.ordinal, participant as u32);
        assert_eq!(link.next_name, name((participant + 1) % PARTICIPANTS));
        assert_eq!(link.payload_checksum, new_payload_checksum(participant));
    }

    #[kani::proof]
    fn physical_mixed_candidate_matches_composed_ring() {
        assert!(physical_mixed_ring_matches_composed_decoder());
    }

    #[kani::proof]
    fn every_prepare_body_tear_is_guardless() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let survives: [u64; SLOT_SELECTOR_WORDS] = kani::any();
        let slot = prepare_body_after_crash(participant, &survives);
        assert!(decode_candidate(&slot, participant).is_none());
    }

    #[kani::proof]
    fn every_mixed_prepare_body_tear_is_guardless() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let survives: [u64; SLOT_SELECTOR_WORDS] = kani::any();
        let slot = mixed_prepare_body_after_crash(participant, &survives);
        assert!(decode_mixed_candidate(&slot, participant).is_none());
    }

    #[kani::proof]
    fn every_mixed_old_authority_decodes_exactly() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        assert!(mixed_old_authority_valid(
            participant,
            &MIXED_OLD_AUTHORITIES[participant]
        ));
    }

    #[kani::proof]
    fn encoded_mixed_roots_are_self_consistent() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        assert!(mixed_candidate_integrity_valid(participant));
    }

    #[kani::proof]
    fn old_fallback_requires_an_exact_authority_root() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let offset: usize = kani::any();
        kani::assume(offset < ROOT_LEN);
        let replacement: u8 = kani::any();
        let mut authorities = old_authorities();
        kani::assume(replacement != authorities[participant][offset]);
        authorities[participant][offset] = replacement;
        assert!(!old_authority_valid(participant, &authorities[participant]));
    }

    #[kani::proof]
    fn every_abort_body_tear_is_guardless() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let empty_predecessor: bool = kani::any();
        let source_prepared: bool = kani::any();
        let prepare_survives: [u64; SLOT_SELECTOR_WORDS] = kani::any();
        let source = if empty_predecessor {
            if source_prepared {
                new_slot(participant)
            } else {
                prepare_body_after_crash(participant, &prepare_survives)
            }
        } else if source_prepared {
            mixed_new_slot(participant)
        } else {
            mixed_prepare_body_after_crash(participant, &prepare_survives)
        };
        let target = if empty_predecessor {
            abort_root(participant)
        } else {
            mixed_abort_root(participant)
        };
        let survives: [u64; ROOT_SELECTOR_WORDS] = kani::any();
        let disk = root_body_after_crash(&source, &target, &survives);
        assert!(decode_slot_root(&disk, RootState::Aborted).is_none());
    }

    #[kani::proof]
    fn abort_guard_selects_only_the_exact_abort_root() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let empty_predecessor: bool = kani::any();
        let survives: bool = kani::any();
        let source = if empty_predecessor {
            new_slot(participant)
        } else {
            mixed_new_slot(participant)
        };
        let target = if empty_predecessor {
            abort_root(participant)
        } else {
            mixed_abort_root(participant)
        };
        let disk = root_guard_after_crash(&source, &target, survives);
        assert_eq!(
            decode_slot_root(&disk, RootState::Aborted).is_some(),
            survives
        );
    }

    #[kani::proof]
    fn every_abort_root_preserves_its_exact_predecessor_projection() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let mixed: bool = kani::any();
        let authority = if mixed {
            mixed_old_authority_root(participant)
        } else {
            old_authority_root(participant)
        };
        let target = if mixed {
            mixed_abort_root(participant)
        } else {
            abort_root(participant)
        };
        let Some(authority) = decode_root(&authority, RootState::Recovered) else {
            assert!(false, "the predecessor authority must decode");
            return;
        };
        let Some(abort) = decode_root(&target, RootState::Aborted) else {
            assert!(false, "the abort root must decode");
            return;
        };

        assert_eq!(abort.logical_len, authority.logical_len);
        assert_eq!(abort.integrity_start, authority.integrity_start);
        assert_eq!(abort.integrity_checksum, authority.integrity_checksum);
        assert_eq!(abort.tag, authority.tag);
    }

    #[kani::proof]
    fn every_final_tear_retains_disk_decision_evidence() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let survives: [u64; ROOT_SELECTOR_WORDS] = kani::any();
        let source = mixed_new_slot(participant);
        let target = final_root(participant);
        let disk = root_after_crash(&source, &target, &survives);
        assert_eq!(&disk[ROOT_LEN..], &source[ROOT_LEN..]);
        assert!(final_transition_proves_decision(&source, &target, &disk));
        let exact_prepared = decode_mixed_candidate(&disk, participant).is_some();
        let exact_final = decode_mixed_final(&disk, participant);
        let target_checksum_byte = (108..ROOT_LEN)
            .any(|offset| source[offset] != target[offset] && disk[offset] == target[offset]);
        assert_eq!(exact_final, disk[..ROOT_LEN] == target);
        kani::cover!(exact_final, "the exact final root can survive");
        kani::cover!(
            target_checksum_byte,
            "a target-only checksum byte can retain final-write issuance provenance"
        );
        assert!(exact_prepared || disk[..ROOT_LEN] != source[..ROOT_LEN]);
        assert!(decode_slot_root(&disk, RootState::Recovered).is_none());
        assert!(decode_slot_root(&disk, RootState::Aborted).is_none());
        if participant == 2 {
            assert!(decode_slot_root(&disk, RootState::Materialized).is_none());
        } else {
            assert!(decode_slot_root(&disk, RootState::Tombstone).is_none());
        }
    }

    #[kani::proof]
    fn root_checksum_abstraction_accepts_arbitrary_stored_checksum_bytes() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let mut disk = mixed_new_slot(participant);
        let stored_checksum: [u8; 4] = kani::any();
        disk[108..ROOT_LEN].copy_from_slice(&stored_checksum);

        assert!(decode_slot_root(&disk, RootState::Prepared).is_some());
    }

    #[kani::proof]
    fn wrapper_checksum_abstraction_accepts_arbitrary_stored_checksum_bytes() {
        let participant: usize = kani::any();
        kani::assume(participant < PARTICIPANTS);
        let mut disk = mixed_new_slot(participant);
        let stored_checksum: [u8; 4] = kani::any();
        disk[ROOT_LEN + 12..ROOT_LEN + WRAPPER_LEN].copy_from_slice(&stored_checksum);

        assert!(decode_mixed_candidate(&disk, participant).is_some());
    }

    #[kani::proof]
    fn every_append_payload_tear_requires_exact_suffix_evidence() {
        let survives: [bool; PAYLOAD_LEN] = kani::any();
        let suffix = core::array::from_fn(|offset| {
            if survives[offset] {
                NEW_PAYLOADS[0][offset]
            } else {
                0
            }
        });
        let Some(link) = decode_mixed_candidate(&mixed_new_slot(0), 0) else {
            assert!(false, "the exact append candidate must decode");
            return;
        };
        let accepted = mixed_payload_valid(0, &link, &OLD_PAYLOADS[0], &suffix, MIXED_APPEND_END);
        let exact = survives.iter().all(|survived| *survived);

        kani::cover!(exact, "the complete append suffix is accepted");
        kani::cover!(
            survives == [true, false, true, false],
            "a non-prefix append-byte subset is rejected"
        );
        assert_eq!(accepted, exact);
    }

    #[kani::proof]
    fn rewind_requires_exact_retained_prefix_evidence() {
        let retained_prefix: [u8; 2] = kani::any();
        let mut base_payload = OLD_PAYLOADS[1];
        base_payload[..2].copy_from_slice(&retained_prefix);
        let Some(link) = decode_mixed_candidate(&mixed_new_slot(1), 1) else {
            assert!(false, "the exact rewind candidate must decode");
            return;
        };
        let accepted = mixed_payload_valid(1, &link, &base_payload, &NEW_PAYLOADS[1], PAYLOAD_END);
        let exact = retained_prefix == OLD_PAYLOADS[1][..2];

        kani::cover!(exact, "the exact retained prefix is accepted");
        kani::cover!(!exact, "a corrupted retained prefix is rejected");
        assert_eq!(accepted, exact);
    }

    #[kani::proof]
    fn abort_body_tears_cannot_promote_an_incomplete_prepare_set() {
        let guard_survives: [bool; PARTICIPANTS] = kani::any();
        kani::assume(!guard_survives.iter().all(|survived| *survived));
        let abort_survives: [[u64; ROOT_SELECTOR_WORDS]; PARTICIPANTS] = kani::any();
        let every_member_proves_new = (0..PARTICIPANTS).all(|participant| {
            let source = mixed_prepare_guard_after_crash(participant, guard_survives[participant]);
            let disk = root_body_after_crash(
                &source,
                &mixed_abort_root(participant),
                &abort_survives[participant],
            );
            final_transition_proves_decision(
                &mixed_new_slot(participant),
                &final_root(participant),
                &disk,
            )
        });

        kani::cover!(
            guard_survives.iter().filter(|survived| **survived).count() == 2,
            "two exact prepare guards may survive before abort repair"
        );
        assert!(!every_member_proves_new);
    }
}

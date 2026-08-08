//! Compact byte-level composition of prepare publication, ring recovery, and payload evidence.
//!
//! Each candidate cell is one observable byte-equivalence class. A separate three-cell fallback
//! image represents its authority root, logical payload, and physical extent, all of which must
//! decode exactly before an unrecovered member can observe old. The positive code-last path enters
//! this model only after every body byte and payload extent is exact and durable; independently torn
//! guard bytes are then decoded by the same ring traversal as the negative one-phase path. The
//! larger physical fixture in `codec` checks that the deliberately broken abstract splice has a
//! concrete R14 byte-image witness.

const PARTICIPANTS: usize = 3;
const SLOT_LEN: usize = 12;
const FALLBACK_LEN: usize = 3;

const GUARD: usize = 0;
const GROUP: usize = 1;
const COUNT: usize = 2;
const ORDINAL: usize = 3;
const NEXT: usize = 4;
const BASE_GENERATION: usize = 5;
const OPERATION: usize = 6;
const REMOVED: usize = 7;
const LOGICAL_EVIDENCE: usize = 8;
const SUFFIX_EVIDENCE: usize = 9;
const SUFFIX_LEN: usize = 10;
const LOGICAL_LEN: usize = 11;

const OLD_GUARD: u8 = 6;
const PREPARED_GUARD: u8 = 2;
const OLD_PAIR_GROUP: u8 = 0x31;
const OLD_SINGLETON_GROUP: u8 = 0x32;
const NEW_GROUP: u8 = 0x41;

const FALLBACK_AUTHORITY: usize = 0;
const FALLBACK_LOGICAL: usize = 1;
const FALLBACK_EXTENT: usize = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub(crate) enum Operation {
    Append,
    Rewind,
    Remove,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Observation {
    Old,
    New,
    Absent,
    Unavailable,
}

#[derive(Clone, Copy)]
struct Candidate {
    group: u8,
    count: usize,
    ordinal: usize,
    next: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct BridgeCandidate {
    pub(crate) group_is_new: bool,
    pub(crate) count: u32,
    pub(crate) ordinal: u32,
    pub(crate) next: usize,
    pub(crate) base_generation: u64,
    pub(crate) operation: Operation,
    pub(crate) removed: bool,
    pub(crate) logical_evidence_valid: bool,
    pub(crate) suffix_evidence_valid: bool,
    pub(crate) suffix_len: u64,
    pub(crate) logical_len: u64,
    pub(crate) extent_valid: bool,
}

#[derive(Clone, Copy)]
struct ExternalEvidence {
    logical: [u8; PARTICIPANTS],
    suffix: [u8; PARTICIPANTS],
    physical_lens: [u8; PARTICIPANTS],
}

const fn operation_byte(operation: Operation) -> u8 {
    match operation {
        Operation::Append => 1,
        Operation::Rewind => 2,
        Operation::Remove => 3,
    }
}

const fn decode_operation(encoded: u8) -> Option<Operation> {
    match encoded {
        1 => Some(Operation::Append),
        2 => Some(Operation::Rewind),
        3 => Some(Operation::Remove),
        _ => None,
    }
}

const fn expected_len(operation: Operation) -> u8 {
    match operation {
        Operation::Append => 8,
        Operation::Rewind => 2,
        Operation::Remove => 4,
    }
}

const fn logical_evidence_byte(participant: usize, operation: Operation) -> u8 {
    0x60 + 4 * operation_byte(operation) + participant as u8
}

const fn suffix_evidence_byte(participant: usize, operation: Operation) -> u8 {
    match operation {
        Operation::Append => 0x80 + participant as u8,
        Operation::Rewind | Operation::Remove => 0,
    }
}

const fn suffix_len(operation: Operation) -> u8 {
    match operation {
        Operation::Append => 4,
        Operation::Rewind | Operation::Remove => 0,
    }
}

const fn expected_observation(operation: Operation) -> Observation {
    match operation {
        Operation::Append | Operation::Rewind => Observation::New,
        Operation::Remove => Observation::Absent,
    }
}

const fn member_mask(count: usize) -> u8 {
    (1 << count) - 1
}

const fn new_slot(participant: usize, operation: Operation, count: usize) -> [u8; SLOT_LEN] {
    [
        PREPARED_GUARD,
        NEW_GROUP,
        count as u8,
        participant as u8,
        if participant + 1 < count {
            (participant + 1) as u8
        } else {
            0
        },
        2,
        operation_byte(operation),
        matches!(operation, Operation::Remove) as u8,
        logical_evidence_byte(participant, operation),
        suffix_evidence_byte(participant, operation),
        suffix_len(operation),
        expected_len(operation),
    ]
}

const fn old_splice_source(participant: usize, operation: Operation) -> [u8; SLOT_LEN] {
    let (group, count, ordinal, next) = if participant < 2 {
        (
            OLD_PAIR_GROUP,
            2,
            participant as u8,
            (1 - participant) as u8,
        )
    } else {
        (OLD_SINGLETON_GROUP, 1, 0, 2)
    };
    [
        OLD_GUARD,
        group,
        count,
        ordinal,
        next,
        2,
        operation_byte(operation),
        matches!(operation, Operation::Remove) as u8,
        logical_evidence_byte(participant, operation),
        suffix_evidence_byte(participant, operation),
        suffix_len(operation),
        expected_len(operation),
    ]
}

fn exact_body_slots(
    guard_survives: [bool; PARTICIPANTS],
    operations: [Operation; PARTICIPANTS],
    count: usize,
) -> [[u8; SLOT_LEN]; PARTICIPANTS] {
    core::array::from_fn(|participant| {
        let mut slot = new_slot(participant, operations[participant], count);
        if !guard_survives[participant] {
            slot[GUARD] = OLD_GUARD;
        }
        slot
    })
}

fn torn_one_phase_slots(
    survives: [[bool; SLOT_LEN]; PARTICIPANTS],
    operations: [Operation; PARTICIPANTS],
) -> [[u8; SLOT_LEN]; PARTICIPANTS] {
    let old =
        core::array::from_fn(|participant| old_splice_source(participant, operations[participant]));
    torn_slots(old, survives, operations)
}

fn torn_slots(
    old: [[u8; SLOT_LEN]; PARTICIPANTS],
    survives: [[bool; SLOT_LEN]; PARTICIPANTS],
    operations: [Operation; PARTICIPANTS],
) -> [[u8; SLOT_LEN]; PARTICIPANTS] {
    core::array::from_fn(|participant| {
        let new = new_slot(participant, operations[participant], PARTICIPANTS);
        core::array::from_fn(|offset| {
            if survives[participant][offset] {
                new[offset]
            } else {
                old[participant][offset]
            }
        })
    })
}

fn decode_candidate(
    slot: &[u8; SLOT_LEN],
    participant: usize,
    logical_evidence: u8,
    suffix_evidence: u8,
    physical_len: u8,
) -> Option<Candidate> {
    let operation = decode_operation(slot[OPERATION])?;
    if slot[GUARD] != PREPARED_GUARD
        || slot[BASE_GENERATION] != 2
        || slot[REMOVED] != matches!(operation, Operation::Remove) as u8
        || slot[LOGICAL_EVIDENCE] != logical_evidence_byte(participant, operation)
        || logical_evidence != slot[LOGICAL_EVIDENCE]
        || slot[SUFFIX_EVIDENCE] != suffix_evidence_byte(participant, operation)
        || suffix_evidence != slot[SUFFIX_EVIDENCE]
        || slot[SUFFIX_LEN] != suffix_len(operation)
        || slot[LOGICAL_LEN] != expected_len(operation)
        || physical_len < slot[LOGICAL_LEN]
    {
        return None;
    }
    let count = slot[COUNT] as usize;
    let ordinal = slot[ORDINAL] as usize;
    let next = slot[NEXT] as usize;
    if count == 0 || count > PARTICIPANTS || ordinal >= count || next >= PARTICIPANTS {
        return None;
    }
    Some(Candidate {
        group: slot[GROUP],
        count,
        ordinal,
        next,
    })
}

fn recover_ring(slots: &[[u8; SLOT_LEN]; PARTICIPANTS], evidence: ExternalEvidence) -> u8 {
    fn decode_member(
        participant: usize,
        slots: &[[u8; SLOT_LEN]; PARTICIPANTS],
        evidence: ExternalEvidence,
    ) -> Option<Candidate> {
        match participant {
            0 => decode_candidate(
                &slots[0],
                0,
                evidence.logical[0],
                evidence.suffix[0],
                evidence.physical_lens[0],
            ),
            1 => decode_candidate(
                &slots[1],
                1,
                evidence.logical[1],
                evidence.suffix[1],
                evidence.physical_lens[1],
            ),
            2 => decode_candidate(
                &slots[2],
                2,
                evidence.logical[2],
                evidence.suffix[2],
                evidence.physical_lens[2],
            ),
            _ => None,
        }
    }

    let Some(first) = decode_member(0, slots, evidence) else {
        return 0;
    };
    if first.ordinal != 0 {
        return 0;
    }
    if first.count == 1 {
        return if first.next == 0 { 0b001 } else { 0 };
    }
    if first.next == 0 {
        return 0;
    }
    let Some(second) = decode_member(first.next, slots, evidence) else {
        return 0;
    };
    if second.group != first.group || second.count != first.count || second.ordinal != 1 {
        return 0;
    }
    let visited = 0b001 | (1 << first.next);
    if first.count == 2 {
        return if second.next == 0 { visited } else { 0 };
    }
    if second.next == 0 || visited & (1 << second.next) != 0 {
        return 0;
    }
    let Some(third) = decode_member(second.next, slots, evidence) else {
        return 0;
    };
    if third.group != first.group
        || third.count != first.count
        || third.ordinal != 2
        || third.next != 0
    {
        return 0;
    }
    let visited = visited | (1 << second.next);
    if visited == 0b111 { visited } else { 0 }
}

fn expected_evidence(operations: [Operation; PARTICIPANTS]) -> ExternalEvidence {
    ExternalEvidence {
        logical: core::array::from_fn(|participant| {
            logical_evidence_byte(participant, operations[participant])
        }),
        suffix: core::array::from_fn(|participant| {
            suffix_evidence_byte(participant, operations[participant])
        }),
        physical_lens: operations.map(expected_len),
    }
}

const fn exact_fallback(participant: usize) -> [u8; FALLBACK_LEN] {
    [
        0xa0 + participant as u8,
        0xb0 + participant as u8,
        0xc0 + participant as u8,
    ]
}

fn fallback_decodes(participant: usize, fallback: &[u8; FALLBACK_LEN]) -> bool {
    fallback[FALLBACK_AUTHORITY] == exact_fallback(participant)[FALLBACK_AUTHORITY]
        && fallback[FALLBACK_LOGICAL] == exact_fallback(participant)[FALLBACK_LOGICAL]
        && fallback[FALLBACK_EXTENT] == exact_fallback(participant)[FALLBACK_EXTENT]
}

fn exact_fallbacks() -> [[u8; FALLBACK_LEN]; PARTICIPANTS] {
    core::array::from_fn(exact_fallback)
}

pub(crate) fn bridge_ring_decodes(
    projected: [BridgeCandidate; PARTICIPANTS],
    operations: [Operation; PARTICIPANTS],
) -> bool {
    if projected
        .iter()
        .zip(operations)
        .any(|(candidate, operation)| !candidate.group_is_new || candidate.operation != operation)
    {
        return false;
    }
    let slots = core::array::from_fn(|participant| {
        let candidate = projected[participant];
        [
            PREPARED_GUARD,
            if candidate.group_is_new {
                NEW_GROUP
            } else {
                0xff
            },
            u8::try_from(candidate.count).unwrap_or(0xff),
            u8::try_from(candidate.ordinal).unwrap_or(0xff),
            u8::try_from(candidate.next).unwrap_or(0xff),
            u8::try_from(candidate.base_generation).unwrap_or(0xff),
            operation_byte(candidate.operation),
            candidate.removed as u8,
            if candidate.logical_evidence_valid {
                logical_evidence_byte(participant, candidate.operation)
            } else {
                0xff
            },
            if candidate.suffix_evidence_valid {
                suffix_evidence_byte(participant, candidate.operation)
            } else {
                0xff
            },
            u8::try_from(candidate.suffix_len).unwrap_or(0xff),
            u8::try_from(candidate.logical_len).unwrap_or(0xff),
        ]
    });
    let evidence = ExternalEvidence {
        logical: core::array::from_fn(|participant| slots[participant][LOGICAL_EVIDENCE]),
        suffix: core::array::from_fn(|participant| slots[participant][SUFFIX_EVIDENCE]),
        physical_lens: core::array::from_fn(|participant| {
            if projected[participant].extent_valid {
                slots[participant][LOGICAL_LEN]
            } else {
                0
            }
        }),
    };
    let recovered = recover_ring(&slots, evidence);
    recovered == 0b111
        && atomic(
            observations(recovered, &slots, &exact_fallbacks()),
            operations,
            PARTICIPANTS,
        )
}

fn observations(
    recovered: u8,
    slots: &[[u8; SLOT_LEN]; PARTICIPANTS],
    fallbacks: &[[u8; FALLBACK_LEN]; PARTICIPANTS],
) -> [Observation; PARTICIPANTS] {
    core::array::from_fn(|participant| {
        if recovered & (1 << participant) == 0 {
            if fallback_decodes(participant, &fallbacks[participant]) {
                Observation::Old
            } else {
                Observation::Unavailable
            }
        } else {
            decode_operation(slots[participant][OPERATION])
                .map_or(Observation::Unavailable, expected_observation)
        }
    })
}

fn atomic(
    value: [Observation; PARTICIPANTS],
    operations: [Operation; PARTICIPANTS],
    count: usize,
) -> bool {
    let old = (0..count).all(|participant| value[participant] == Observation::Old);
    let new = (0..count)
        .all(|participant| value[participant] == expected_observation(operations[participant]));
    (1..=PARTICIPANTS).contains(&count) && (old || new)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exact_bridge_candidates(
        operations: [Operation; PARTICIPANTS],
    ) -> [BridgeCandidate; PARTICIPANTS] {
        core::array::from_fn(|participant| BridgeCandidate {
            group_is_new: true,
            count: PARTICIPANTS as u32,
            ordinal: participant as u32,
            next: (participant + 1) % PARTICIPANTS,
            base_generation: 2,
            operation: operations[participant],
            removed: operations[participant] == Operation::Remove,
            logical_evidence_valid: true,
            suffix_evidence_valid: true,
            suffix_len: suffix_len(operations[participant]) as u64,
            logical_len: expected_len(operations[participant]) as u64,
            extent_valid: true,
        })
    }

    #[test]
    fn exact_body_guard_subsets_are_atomic() {
        let operations = [Operation::Append, Operation::Rewind, Operation::Remove];
        for count in 1..=PARTICIPANTS {
            for mask in 0u8..8 {
                let guards = core::array::from_fn(|participant| mask & (1 << participant) != 0);
                let slots = exact_body_slots(guards, operations, count);
                let recovered = recover_ring(&slots, expected_evidence(operations));
                let members = member_mask(count);
                assert_eq!(
                    recovered,
                    if mask & members == members {
                        members
                    } else {
                        0
                    }
                );
                assert!(atomic(
                    observations(recovered, &slots, &exact_fallbacks()),
                    operations,
                    count
                ));
            }
        }
    }

    #[test]
    fn exact_two_member_ring_is_atomic() {
        let operations = [Operation::Append, Operation::Rewind, Operation::Remove];
        let slots = exact_body_slots([true; PARTICIPANTS], operations, 2);

        let recovered = recover_ring(&slots, expected_evidence(operations));
        assert_eq!(recovered, 0b011);
        assert!(atomic(
            observations(recovered, &slots, &exact_fallbacks()),
            operations,
            2
        ));
    }

    #[test]
    fn bridge_rejects_a_mismatched_operation_vector() {
        let operations = [Operation::Append, Operation::Rewind, Operation::Remove];
        let projected = exact_bridge_candidates(operations);

        assert!(bridge_ring_decodes(projected, operations));
        assert!(!bridge_ring_decodes(
            projected,
            [Operation::Rewind, Operation::Append, Operation::Remove]
        ));
    }

    #[test]
    fn bridge_rejects_the_wrong_group_projection() {
        let operations = [Operation::Append, Operation::Rewind, Operation::Remove];
        let mut projected = exact_bridge_candidates(operations);
        for candidate in &mut projected {
            candidate.group_is_new = false;
        }

        assert!(!bridge_ring_decodes(projected, operations));
    }

    #[test]
    fn one_phase_splice_recovers_a_two_member_subgroup() {
        let operations = [Operation::Append; PARTICIPANTS];
        let mut survives = [[false; SLOT_LEN]; PARTICIPANTS];
        survives[0][GUARD] = true;
        survives[1][GUARD] = true;
        let slots = torn_one_phase_slots(survives, operations);
        let recovered = recover_ring(&slots, expected_evidence(operations));
        assert_eq!(recovered, 0b011);
        assert!(!atomic(
            observations(recovered, &slots, &exact_fallbacks()),
            operations,
            PARTICIPANTS
        ));
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    fn every_exact_body_guard_subset_is_atomic() {
        let guards: [bool; PARTICIPANTS] = kani::any();
        let operations: [Operation; PARTICIPANTS] = kani::any();
        let count: usize = kani::any();
        kani::assume((1..=PARTICIPANTS).contains(&count));
        let slots = exact_body_slots(guards, operations, count);
        let recovered = recover_ring(&slots, expected_evidence(operations));
        let all_guards = (0..count).all(|participant| guards[participant]);
        assert_eq!(recovered, if all_guards { member_mask(count) } else { 0 });
        kani::cover!(count == 1, "a one-member code-last ring is checked");
        kani::cover!(count == 2, "a two-member code-last ring is checked");
        kani::cover!(count == 3, "a three-member code-last ring is checked");
        assert!(atomic(
            observations(recovered, &slots, &exact_fallbacks()),
            operations,
            count
        ));
    }

    #[kani::proof]
    fn mixed_append_rewind_remove_guard_subsets_are_atomic() {
        let guards: [bool; PARTICIPANTS] = kani::any();
        let operations = [Operation::Append, Operation::Rewind, Operation::Remove];
        let slots = exact_body_slots(guards, operations, PARTICIPANTS);
        let recovered = recover_ring(&slots, expected_evidence(operations));
        assert!(atomic(
            observations(recovered, &slots, &exact_fallbacks()),
            operations,
            PARTICIPANTS
        ));
    }

    #[kani::proof]
    fn every_pre_guard_body_subset_with_exact_fallbacks_recovers_old() {
        let mut survives: [[bool; SLOT_LEN]; PARTICIPANTS] = kani::any();
        let mut old: [[u8; SLOT_LEN]; PARTICIPANTS] = kani::any();
        for member in &mut survives {
            member[GUARD] = false;
        }
        for member in &mut old {
            member[GUARD] = OLD_GUARD;
        }
        let operations = [Operation::Append, Operation::Rewind, Operation::Remove];
        let evidence = ExternalEvidence {
            logical: kani::any(),
            suffix: kani::any(),
            physical_lens: kani::any(),
        };
        let slots = torn_slots(old, survives, operations);
        let recovered = recover_ring(&slots, evidence);
        assert_eq!(recovered, 0);
        assert_eq!(
            observations(recovered, &slots, &exact_fallbacks()),
            [Observation::Old; PARTICIPANTS]
        );
    }

    #[kani::proof]
    fn old_observation_requires_an_exact_fallback_decode() {
        let operations = [Operation::Append, Operation::Rewind, Operation::Remove];
        let fallbacks: [[u8; FALLBACK_LEN]; PARTICIPANTS] = kani::any();
        let slots = exact_body_slots([false; PARTICIPANTS], operations, PARTICIPANTS);
        let recovered = recover_ring(&slots, expected_evidence(operations));
        assert_eq!(recovered, 0);
        let decoded = observations(recovered, &slots, &fallbacks);
        for participant in 0..PARTICIPANTS {
            assert_eq!(
                decoded[participant],
                if fallback_decodes(participant, &fallbacks[participant]) {
                    Observation::Old
                } else {
                    Observation::Unavailable
                }
            );
        }
    }

    #[kani::proof]
    fn accepted_ring_requires_every_payload_evidence_and_extent() {
        let operations = [Operation::Append, Operation::Rewind, Operation::Remove];
        let evidence = ExternalEvidence {
            logical: kani::any(),
            suffix: kani::any(),
            physical_lens: kani::any(),
        };
        let slots = exact_body_slots([true; PARTICIPANTS], operations, PARTICIPANTS);
        let recovered = recover_ring(&slots, evidence);
        let expected = expected_evidence(operations);
        let all_evidence =
            evidence.logical == expected.logical && evidence.suffix == expected.suffix;
        let all_extents = (0..PARTICIPANTS).all(|participant| {
            evidence.physical_lens[participant] >= expected_len(operations[participant])
        });
        assert_eq!(
            recovered,
            if all_evidence && all_extents {
                0b111
            } else {
                0
            }
        );
    }

    #[kani::proof]
    fn broken_one_phase_atomicity_claim() {
        let guard_survives: [bool; PARTICIPANTS] = kani::any();
        let survives = core::array::from_fn(|participant| {
            core::array::from_fn(|offset| offset == GUARD && guard_survives[participant])
        });
        let operations = [Operation::Append; PARTICIPANTS];
        let slots = torn_one_phase_slots(survives, operations);
        let recovered = recover_ring(&slots, expected_evidence(operations));
        kani::cover!(
            recovered == 0b011,
            "a torn one-phase write reconstructs the old two-member subgroup"
        );
        assert!(atomic(
            observations(recovered, &slots, &exact_fallbacks()),
            operations,
            PARTICIPANTS
        ));
    }
}

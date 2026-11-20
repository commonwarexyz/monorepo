//! The Mallory fault schedule, carried as a prefix of the fuzz input's entropy bytes.
//!
//! Every Mallory decision comes from the input, so a replayed input reproduces its
//! episode exactly on the deterministic runtime: nothing that persists across inputs
//! (the campaign Q-table, the role bandit, the trace cache) influences execution.
//! Those campaign structures only steer the custom mutator ([`super::mutator`]),
//! which writes new schedules into inputs.
//!
//! Layout of `FuzzInput::raw_bytes` for a Mallory episode:
//!
//! ```text
//! raw_bytes[0]                     role byte:    AdversaryRole::from_index(b % COUNT)
//! raw_bytes[1 ..= SCHEDULE_STEPS]  action bytes: step k enacts legal_ids[b_k % legal_ids.len()]
//! raw_bytes[SCHEDULE_LEN ..]       runtime entropy: the deterministic runtime's FuzzRng seed
//! ```
//!
//! Missing bytes read as zero: the Honest role, `NoFault` (catalog id 0, always legal
//! and first among the legal ids), and an empty entropy seed. An action byte is
//! decoded against the step's legal mask, so every byte value names a legal fault
//! and the same byte can name a different fault under a different mask; the mutator
//! encodes a chosen fault against the mask it observed at that step.

use super::{adversary::AdversaryRole, fault::N_FAULTS, policy::ActionId};
use commonware_consensus_fuzz_core::MAX_REQUIRED_CONTAINERS;

/// Number of per-step action bytes: one per possible episode step. The step cap is
/// `max(MALLORY_EPISODE_STEPS, required_containers)`, which never exceeds this.
pub(crate) const SCHEDULE_STEPS: usize = MAX_REQUIRED_CONTAINERS as usize;
/// Length of the schedule prefix: the role byte plus the action bytes.
pub(crate) const SCHEDULE_LEN: usize = 1 + SCHEDULE_STEPS;

const _: () = assert!(N_FAULTS <= 256, "an action byte must index every fault");
const _: () = assert!(
    AdversaryRole::COUNT <= 256,
    "a role byte must index every role"
);

/// The decoded schedule prefix of one input, zero-padded to [`SCHEDULE_LEN`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Schedule {
    bytes: [u8; SCHEDULE_LEN],
}

impl Schedule {
    /// Split `raw` into its schedule prefix (zero-padded) and the runtime entropy
    /// tail (empty when `raw` is shorter than the prefix).
    pub(crate) fn split(raw: &[u8]) -> (Self, &[u8]) {
        let mut bytes = [0u8; SCHEDULE_LEN];
        let n = raw.len().min(SCHEDULE_LEN);
        bytes[..n].copy_from_slice(&raw[..n]);
        (Self { bytes }, &raw[n..])
    }

    /// The episode role the role byte selects.
    pub(crate) fn role(&self) -> AdversaryRole {
        AdversaryRole::from_index(usize::from(self.bytes[0]) % AdversaryRole::COUNT)
    }

    /// The raw action byte of `step`, decoded against the step's legal mask by
    /// [`decode_action`]. Panics past [`SCHEDULE_STEPS`], a caller bug: the runner's
    /// step cap never exceeds it.
    pub(crate) fn action_byte(&self, step: usize) -> u8 {
        self.bytes[1 + step]
    }
}

/// The legal action ids in catalog order. At least one fault must be legal.
pub(crate) fn legal_ids(legal: &[bool]) -> Vec<ActionId> {
    let ids: Vec<ActionId> = legal
        .iter()
        .enumerate()
        .filter_map(|(id, &ok)| ok.then_some(id))
        .collect();
    assert!(!ids.is_empty(), "at least one fault must be legal");
    ids
}

/// The fault a schedule byte selects under `legal`: the byte indexes the legal ids
/// modulo their count, so every byte value is legal.
pub(crate) fn decode_action(byte: u8, legal: &[bool]) -> ActionId {
    let ids = legal_ids(legal);
    ids[usize::from(byte) % ids.len()]
}

/// The smallest schedule byte that selects `action` under `legal`. `action` must be
/// legal, else this is a caller bug.
pub(crate) fn encode_action(action: ActionId, legal: &[bool]) -> u8 {
    let position = legal_ids(legal)
        .iter()
        .position(|&id| id == action)
        .expect("only a legal action can be encoded");
    u8::try_from(position).expect("N_FAULTS fits a byte")
}

/// The role byte that selects `role`.
pub(crate) fn encode_role(role: AdversaryRole) -> u8 {
    u8::try_from(role.index()).expect("AdversaryRole::COUNT fits a byte")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mallory::fault;

    #[test]
    fn split_zero_pads_and_keeps_the_entropy_tail() {
        // A short input is the Honest, all-NoFault schedule with no entropy; a long
        // one keeps every byte past the prefix as entropy.
        let (short, tail) = Schedule::split(&[3, 7]);
        assert!(tail.is_empty());
        assert_eq!(short.role(), AdversaryRole::Nuller);
        assert_eq!(short.action_byte(0), 7);
        assert_eq!(short.action_byte(1), 0);

        let raw: Vec<u8> = (0..(SCHEDULE_LEN as u8 + 4)).collect();
        let (long, tail) = Schedule::split(&raw);
        assert_eq!(tail, &raw[SCHEDULE_LEN..]);
        assert_eq!(long.action_byte(SCHEDULE_STEPS - 1), SCHEDULE_LEN as u8 - 1);
    }

    #[test]
    fn every_byte_decodes_to_a_legal_fault_and_zero_is_nofault() {
        for mask in [
            fault::legal_mask(false, false, false, false),
            fault::legal_mask(true, false, false, false),
            fault::legal_mask(false, true, false, false),
            fault::legal_mask(false, true, false, true),
            fault::legal_mask(false, false, true, false),
        ] {
            assert_eq!(decode_action(0, &mask), fault::Fault::NoFault.id());
            for byte in 0..=u8::MAX {
                assert!(
                    mask[decode_action(byte, &mask)],
                    "byte {byte} must be legal"
                );
            }
        }
    }

    #[test]
    fn encode_then_decode_round_trips_under_the_same_mask() {
        // The mutator encodes against the mask it observed; the runner decodes against
        // the same mask, so the chosen fault is enacted exactly.
        let mask = fault::legal_mask(false, true, false, false);
        for id in 0..fault::N_FAULTS {
            if mask[id] {
                assert_eq!(decode_action(encode_action(id, &mask), &mask), id);
            }
        }
        for i in 0..AdversaryRole::COUNT {
            let role = AdversaryRole::from_index(i);
            let (schedule, _) = Schedule::split(&[encode_role(role)]);
            assert_eq!(schedule.role(), role);
        }
    }
}

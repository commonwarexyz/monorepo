//! Randomized twins campaigns: random sides, an adversarial schedule that reorders, duplicates,
//! drops, and crashes, a split that may heal halfway, then a fair suffix that must keep every
//! correct node finalizing.

use super::{Split, twins};
use crate::{
    multimmit::machine::world::{Bytes, Schedule, Verification, World},
    types::View,
};

/// Simulated time the fair suffix may take.
const BUDGET: u64 = 60_000;

/// The first `choices` choices of a schedule.
struct Take<'a, S> {
    inner: &'a mut S,
    choices: usize,
}

impl<S: Schedule> Schedule for Take<'_, S> {
    fn choose(&mut self, bound: usize) -> Option<usize> {
        self.choices = self.choices.checked_sub(1)?;
        self.inner.choose(bound)
    }
}

/// Runs `schedule` with the split in place for its first `split` choices, heals the split when
/// `heal`, runs the rest of the schedule, and then a fair suffix that must resolve three more
/// views at every correct node with a leader block finalized in the last two.
fn campaign(world: &mut World<Split>, schedule: &mut impl Schedule, split: usize, heal: bool) {
    world.adversarial(&mut Take {
        inner: schedule,
        choices: split,
    });
    if heal {
        world.router_mut().heal();
    }
    world.adversarial(schedule);
    let furthest = world.resolved_views().into_iter().max().unwrap_or_default();
    let target = View::new(furthest.get() + 3);
    world.run_to(BUDGET, target, View::new(target.get() - 1));
    world.check_replay();
}

/// Runs one byte-encoded twins campaign at `n = 6, f = 1`: byte 0 selects the Byzantine
/// participant, byte 1 the side of each correct participant (bit `p`), byte 2 whether the split
/// heals halfway, and every later byte one choice of the schedule.
pub(crate) fn exercise(data: &[u8]) {
    let byte = |index: usize| data.get(index).copied().unwrap_or_default();
    let byzantine = u32::from(byte(0)) % 6;
    let sides = byte(1);
    let mut world = twins(
        11,
        6,
        &[byzantine],
        |participant, _| sides >> participant.get() & 1 == 1,
        Verification::Real,
    );
    let rest = data.get(3..).unwrap_or_default();
    campaign(
        &mut world,
        &mut Bytes::new(rest),
        rest.len() / 2,
        byte(2) & 1 == 1,
    );
}

#[cfg(test)]
mod tests {
    use super::{campaign, exercise, twins};
    use crate::{
        multimmit::machine::world::{Seeded, Verification},
        types::Participant,
    };
    use commonware_utils::TestRng;
    use rand::RngExt as _;

    /// Runs campaign `index` at `n = 6`: participant `index mod 6` is Byzantine, the correct
    /// participants' sides and the schedule derive from `index`, and the split heals halfway when
    /// `index` is even.
    fn identity_campaign(index: u32) {
        let rng = &mut TestRng::new(u64::from(index));
        let sides = rng.random::<u8>();
        let mut world = twins(
            300 + u64::from(index),
            6,
            &[index % 6],
            |participant, _| sides >> participant.get() & 1 == 1,
            Verification::Real,
        );
        campaign(
            &mut world,
            &mut Seeded::new(u64::from(index), 3_000),
            1_500,
            index.is_multiple_of(2),
        );
    }

    #[test]
    fn every_byzantine_identity_at_six_leaves_the_correct_nodes_safe_and_live() {
        for index in 0..6 {
            identity_campaign(index);
        }
    }

    #[test]
    fn two_byzantine_identities_at_eleven_leave_the_correct_nodes_safe_and_live() {
        for seed in 0..4u64 {
            let rng = &mut TestRng::new(seed);
            let first = rng.random_range(0..11u32);
            let second = (first + rng.random_range(1..11u32)) % 11;
            let sides = rng.random::<u16>();
            let mut world = twins(
                400 + seed,
                11,
                &[first, second],
                |participant: Participant, _| sides >> participant.get() & 1 == 1,
                Verification::Real,
            );
            campaign(
                &mut world,
                &mut Seeded::new(seed, 3_000),
                1_500,
                seed % 2 == 1,
            );
        }
    }

    #[test]
    fn byte_campaigns_leave_the_correct_nodes_safe_and_live() {
        let patterns: [&[u8]; 3] = [
            &[],
            &[
                5,
                0b0001_0101,
                1,
                3,
                15,
                0,
                7,
                4,
                9,
                15,
                2,
                1,
                12,
                5,
                5,
                0,
                0,
                3,
                8,
                8,
                9,
            ],
            &(0..=255).cycle().take(1_024).collect::<Vec<u8>>(),
        ];
        for data in patterns {
            exercise(data);
        }
    }
}

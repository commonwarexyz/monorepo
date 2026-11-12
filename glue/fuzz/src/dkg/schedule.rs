//! The committee schedule of a reshare run and the participants provider that
//! serves it.
//!
//! A run is among one identity more than a committee holds, so exactly one
//! identity is outside every player set. From one epoch's ceremony to the
//! next the set either stays the same or that outside identity replaces one
//! member. The schedule is fixed by the input before any engine starts, so
//! the provider honors its contract: every node, and every call, returns the
//! same set for the same epoch.

use super::{PublicKey, reshare_input::Rotation};
use crate::stateful::runner::unattributed;
use commonware_consensus::types::Epoch;
use commonware_glue::dkg::ParticipantsProvider;
use commonware_utils::{ordered::Set, sequence::Unit};
use std::sync::Arc;

/// The player set of every epoch's ceremony.
#[derive(Clone, Debug)]
pub(crate) struct Schedule {
    /// The first committee, followed by the players of each epoch's ceremony
    /// from epoch zero on.
    sets: Arc<[Set<PublicKey>]>,
}

impl Schedule {
    /// The schedule that starts from the committee of every identity in
    /// `identities` except the one at `outsider`, and applies one of
    /// `rotations` before each epoch's ceremony, from epoch zero on.
    pub(crate) fn new(identities: &[PublicKey], outsider: usize, rotations: &[Rotation]) -> Self {
        let outside = |members: &[PublicKey]| -> PublicKey {
            identities
                .iter()
                .find(|identity| !members.contains(identity))
                .expect("one identity is outside every set")
                .clone()
        };
        let mut members: Vec<PublicKey> = identities
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != outsider % identities.len())
            .map(|(_, identity)| identity.clone())
            .collect();
        let mut sets = vec![Set::from_iter_dedup(members.iter().cloned())];
        for rotation in rotations {
            if let Rotation::Replace(position) = rotation {
                let joining = outside(&members);
                let leaving = usize::from(*position) % members.len();
                members[leaving] = joining;
                members.sort();
            }
            sets.push(Set::from_iter_dedup(members.iter().cloned()));
        }
        Self { sets: sets.into() }
    }

    /// The first committee: the players of the output the run starts from.
    pub(crate) fn committee(&self) -> Set<PublicKey> {
        self.sets[0].clone()
    }

    /// The players of the ceremony of `epoch`. Past the last rotation the set
    /// no longer changes.
    pub(crate) fn players(&self, epoch: Epoch) -> Set<PublicKey> {
        let ceremony = usize::try_from(epoch.get())
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        self.sets[ceremony.min(self.sets.len() - 1)].clone()
    }
}

impl ParticipantsProvider for Schedule {
    type PublicKey = PublicKey;
    type Directory = Unit;

    async fn participants(&mut self, epoch: Epoch) -> Set<Self::PublicKey> {
        // The provider is called inside an engine's task and is the harness's
        // code, not the engine's.
        unattributed(|| self.players(epoch))
    }

    async fn directory(&mut self, _: Epoch, _: Set<Self::PublicKey>) -> Self::Directory {
        Unit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{COMMITTEE, fixtures::identities};

    fn set(members: &[&PublicKey]) -> Set<PublicKey> {
        Set::from_iter_dedup(members.iter().map(|member| (*member).clone()))
    }

    #[test]
    fn unrotated_schedule_keeps_the_first_committee() {
        let identities = identities();
        let schedule = Schedule::new(&identities, 2, &[Rotation::Stay; 3]);
        let committee = set(&[
            &identities[0],
            &identities[1],
            &identities[3],
            &identities[4],
        ]);
        assert_eq!(schedule.committee(), committee);
        for epoch in 0..8 {
            assert_eq!(schedule.players(Epoch::new(epoch)), committee);
        }
    }

    #[test]
    fn rotation_swaps_the_outside_identity_in() {
        let identities = identities();
        let schedule = Schedule::new(
            &identities,
            4,
            &[Rotation::Replace(1), Rotation::Stay, Rotation::Replace(0)],
        );

        // Identity 4 replaces identity 1, then identity 1 replaces identity 0.
        let first = set(&[
            &identities[0],
            &identities[2],
            &identities[3],
            &identities[4],
        ]);
        let last = set(&[
            &identities[1],
            &identities[2],
            &identities[3],
            &identities[4],
        ]);
        assert_eq!(schedule.committee().len(), COMMITTEE.get() as usize);
        assert_eq!(schedule.players(Epoch::new(0)), first);
        assert_eq!(schedule.players(Epoch::new(1)), first);
        assert_eq!(schedule.players(Epoch::new(2)), last);

        // Past the last rotation the set no longer changes.
        assert_eq!(schedule.players(Epoch::new(3)), last);
        assert_eq!(schedule.players(Epoch::new(u64::MAX)), last);
    }

    #[test]
    fn provider_serves_the_schedule() {
        let identities = identities();
        let mut schedule = Schedule::new(&identities, 0, &[Rotation::Replace(3)]);
        let served = futures::executor::block_on(schedule.participants(Epoch::new(5)));
        assert_eq!(served, schedule.players(Epoch::new(5)));
        assert_eq!(served.len(), COMMITTEE.get() as usize);
        assert!(served.position(&identities[0]).is_some());
    }
}

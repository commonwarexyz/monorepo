//! Focused split-header scenario selection.

use super::PublicKeyOf;
use crate::{BYZANTINE_IDX, simplex::Simplex};
use commonware_consensus::{
    simplex::mocks::twins,
    types::{TermLength, View},
};

#[derive(Clone, Copy)]
pub(super) struct AttackLayout {
    pub(super) precursor_view: View,
    pub(super) attack_view: View,
    pub(super) victim: usize,
    pub(super) slow: usize,
    pub(super) fast: usize,
}

fn contains<K: PartialEq>(partition: &[K], participant: &K) -> bool {
    partition.iter().any(|candidate| candidate == participant)
}

/// Find adjacent views that can carry the complete split-header schedule.
///
/// At `W`, two secondary-only validators are delayed during application
/// verification. Together with the secondary twin they can form a
/// nullification, while the primary twin and the remaining fast validator
/// cannot finalize. At `W+1`, the fast validator overlaps both halves and
/// carries the primary proposal to the secondary before the delayed validator
/// completes the good notarization quorum. The victim remains secondary-only
/// and receives the parent-mutated leader header first.
pub(super) fn attack_layout<P: Simplex>(
    scenario: &twins::Scenario,
    participants: &[PublicKeyOf<P>],
) -> Option<AttackLayout> {
    let rounds = scenario.rounds();
    let honest = (0..participants.len())
        .filter(|idx| *idx != BYZANTINE_IDX)
        .collect::<Vec<_>>();

    for attack_idx in 1..rounds.len() {
        if rounds[attack_idx].leader() != BYZANTINE_IDX {
            continue;
        }

        let precursor_number =
            u64::try_from(attack_idx).expect("Twins round index must fit in u64");
        let precursor_view = View::new(precursor_number);
        let attack_view = View::new(precursor_number + 1);
        let (precursor_primary, precursor_secondary) =
            scenario.partitions(precursor_view, TermLength::ONE, participants);
        let (attack_primary, attack_secondary) =
            scenario.partitions(attack_view, TermLength::ONE, participants);

        for &victim in &honest {
            if contains(&precursor_primary, &participants[victim])
                || !contains(&precursor_secondary, &participants[victim])
                || contains(&attack_primary, &participants[victim])
                || !contains(&attack_secondary, &participants[victim])
            {
                continue;
            }

            for &slow in &honest {
                if slow == victim
                    || contains(&precursor_primary, &participants[slow])
                    || !contains(&precursor_secondary, &participants[slow])
                    || !contains(&attack_primary, &participants[slow])
                    || contains(&attack_secondary, &participants[slow])
                {
                    continue;
                }

                let Some(fast) = honest
                    .iter()
                    .copied()
                    .find(|idx| *idx != victim && *idx != slow)
                else {
                    continue;
                };
                if !contains(&precursor_primary, &participants[fast])
                    || contains(&precursor_secondary, &participants[fast])
                    || !contains(&attack_primary, &participants[fast])
                    || !contains(&attack_secondary, &participants[fast])
                {
                    continue;
                }

                let precursor_leader = rounds[attack_idx - 1].leader();
                if precursor_leader != fast {
                    continue;
                }

                return Some(AttackLayout {
                    precursor_view,
                    attack_view,
                    victim,
                    slow,
                    fast,
                });
            }
        }
    }
    None
}

//! Simplex-specific Twins wiring over the shared scenario generator.
//!
//! The scenario space, recipient masks, symmetry reduction, and sampling live
//! in [`crate::twins`]. This module adds only the pieces that depend on
//! Simplex's leader election, and re-exports the shared machinery so existing
//! Simplex tests keep one import path.

pub use crate::twins::*;
use crate::{
    simplex::elector::{self, Terms},
    types::{Participant, Round},
};
use commonware_cryptography::PublicKey;
use commonware_utils::ordered::Set;
use std::sync::Arc;

/// Twins leader-election config that follows scripted scenario leaders before
/// delegating to a fallback elector.
#[derive(Clone, Debug)]
pub struct Elector<C> {
    fallback: C,
    round_leaders: Arc<[Participant]>,
}

impl<C: Default> Default for Elector<C> {
    fn default() -> Self {
        Self {
            fallback: C::default(),
            round_leaders: Arc::from(Vec::new()),
        }
    }
}

impl<C> Elector<C> {
    /// Create a twins elector from a scenario and fallback elector.
    ///
    /// # Panics
    ///
    /// Panics if any scenario leader is outside `0..participants`.
    pub fn new(fallback: C, scenario: &Scenario, participants: usize) -> Self {
        let round_leaders: Vec<_> = scenario
            .rounds()
            .iter()
            .map(|round| {
                assert!(
                    round.leader() < participants,
                    "scenario leader out of bounds"
                );
                Participant::from_usize(round.leader())
            })
            .collect();
        Self {
            fallback,
            round_leaders: Arc::from(round_leaders),
        }
    }
}

/// Initialized twins leader elector built from [`Elector`].
#[derive(Clone, Debug)]
pub struct ElectorState<E> {
    fallback: E,
    round_leaders: Arc<[Participant]>,
}

impl<P, Evidence, C> elector::Config<P, Evidence> for Elector<C>
where
    P: PublicKey,
    C: elector::Config<P, Evidence>,
{
    type Elector = ElectorState<C::Elector>;

    fn build(self, participants: &Set<P>) -> Self::Elector {
        ElectorState {
            fallback: self.fallback.build(participants),
            round_leaders: self.round_leaders,
        }
    }
}

impl<Evidence, E> elector::Elector<Evidence> for ElectorState<E>
where
    E: elector::Elector<Evidence>,
{
    fn terms(&self) -> Terms {
        self.fallback.terms()
    }

    fn elect(&self, round: Round, evidence: Option<&Evidence>) -> Participant {
        let idx = term_index(round.view(), self.fallback.terms().length());
        if let Some(&leader) = self.round_leaders.get(idx) {
            return leader;
        }

        // After the scripted attack prefix, intentionally resume the caller's
        // fallback elector rather than forcing an honest-only suffix. Twins
        // campaigns should not prevent the protocol from timing out in
        // later views (if a twin is elected).
        self.fallback.elect(round, evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        types::{Epoch, TermLength, View, ViewDelta},
        simplex::elector::RoundRobin,
    };
    use commonware_cryptography::{
        Sha256, Signer,
        ed25519::{PrivateKey, PublicKey as Ed25519PublicKey},
    };
    use commonware_utils::{NZU32, test_rng};
    use std::time::Duration;

    #[test]
    fn twins_elector_uses_scenario_leaders_then_fallback_suffix() {
        let framework = Framework {
            participants: 5,
            faults: 1,
            rounds: 3,
            mode: Mode::Sampled,
            max_cases: 1,
        };
        let case = cases(&mut test_rng(), framework)
            .into_iter()
            .next()
            .expect("expected at least one generated twins case");
        let participants: Vec<_> = (0..framework.participants as u64)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        let participants = Set::try_from(participants).expect("participants should be unique");
        let twins = <Elector<RoundRobin<Sha256>> as elector::Config<Ed25519PublicKey, ()>>::build(
            Elector::new(
                RoundRobin::<Sha256>::default(),
                &case.scenario,
                framework.participants,
            ),
            &participants,
        );
        let fallback = <RoundRobin<Sha256> as elector::Config<Ed25519PublicKey, ()>>::build(
            RoundRobin::<Sha256>::default(),
            &participants,
        );

        for (round_idx, round_scenario) in case.scenario.rounds().iter().enumerate() {
            let round = Round::new(Epoch::new(0), View::new((round_idx as u64) + 1));
            assert_eq!(
                elector::Elector::<()>::elect(&twins, round, None),
                Participant::from_usize(round_scenario.leader()),
                "unexpected leader in scripted attack round"
            );
        }

        for view in (framework.rounds as u64 + 1)..=20 {
            let round = Round::new(Epoch::new(333), View::new(view));
            assert_eq!(
                elector::Elector::<()>::elect(&twins, round, None),
                elector::Elector::<()>::elect(&fallback, round, None)
            );
        }
    }

    #[test]
    fn twins_elector_uses_scenario_leaders_by_term() {
        let scenario = Scenario::new(vec![
            RoundScenario::new(0, 0b001, 0b010),
            RoundScenario::new(2, 0b100, 0b011),
        ]);
        let participants: Vec<_> = (0..3)
            .map(|seed| PrivateKey::from_seed(seed).public_key())
            .collect();
        let participants = Set::try_from(participants).expect("participants should be unique");
        let term_length = TermLength::new(NZU32!(3));
        let twins = <Elector<RoundRobin<Sha256>> as elector::Config<Ed25519PublicKey, ()>>::build(
            Elector::new(
                RoundRobin::<Sha256>::default().with_term(
                    term_length,
                    Duration::from_secs(10),
                    ViewDelta::new(0),
                ),
                &scenario,
                3,
            ),
            &participants,
        );
        let fallback = <RoundRobin<Sha256> as elector::Config<Ed25519PublicKey, ()>>::build(
            RoundRobin::<Sha256>::default().with_term(
                term_length,
                Duration::from_secs(10),
                ViewDelta::new(0),
            ),
            &participants,
        );

        for view in 1..=3 {
            let round = Round::new(Epoch::new(0), View::new(view));
            assert_eq!(
                elector::Elector::<()>::elect(&twins, round, None),
                Participant::new(0)
            );
        }
        for view in 4..=6 {
            let round = Round::new(Epoch::new(0), View::new(view));
            assert_eq!(
                elector::Elector::<()>::elect(&twins, round, None),
                Participant::new(2)
            );
        }

        let round = Round::new(Epoch::new(333), View::new(7));
        assert_eq!(
            elector::Elector::<()>::elect(&twins, round, None),
            elector::Elector::<()>::elect(&fallback, round, None)
        );
    }
}

//! Simplex leader election for [Twins](crate::twins) scenarios.
//!
//! [`Elector`] makes each scripted round's view elect the scenario's leader and hands later views
//! to a fallback elector. The scenario generator and routing helpers are re-exported from
//! [`crate::twins`].

pub use crate::twins::*;
use crate::{
    simplex::elector::{self, Terms},
    types::{Participant, Round},
};
use commonware_cryptography::certificate::Scheme;
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

impl<S, C> elector::Config<S> for Elector<C>
where
    S: Scheme,
    C: elector::Config<S>,
{
    type Elector = ElectorState<C::Elector>;

    fn build(self, participants: &Set<S::PublicKey>) -> Self::Elector {
        ElectorState {
            fallback: self.fallback.build(participants),
            round_leaders: self.round_leaders,
        }
    }
}

impl<S, E> elector::Elector<S> for ElectorState<E>
where
    S: Scheme,
    E: elector::Elector<S>,
{
    fn terms(&self) -> Terms {
        self.fallback.terms()
    }

    fn elect(&self, round: Round, certificate: Option<&S::Certificate>) -> Participant {
        let idx = term_index(round.view(), self.fallback.terms().length());
        if let Some(&leader) = self.round_leaders.get(idx) {
            return leader;
        }

        // After the scripted attack prefix, intentionally resume the caller's
        // fallback elector rather than forcing an honest-only suffix. Twins
        // campaigns should not prevent the protocol from timing out in
        // later views (if a twin is elected).
        self.fallback.elect(round, certificate)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        simplex::{
            elector::{Elector as _, RoundRobin},
            scheme::ed25519,
        },
        types::{Epoch, TermLength, View, ViewDelta},
    };
    use commonware_cryptography::{Sha256, Signer, ed25519::PrivateKey};
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
        let twins = <Elector<RoundRobin<Sha256>> as elector::Config<ed25519::Scheme>>::build(
            Elector::new(
                RoundRobin::<Sha256>::default(),
                &case.scenario,
                framework.participants,
            ),
            &participants,
        );
        let fallback = <RoundRobin<Sha256> as elector::Config<ed25519::Scheme>>::build(
            RoundRobin::<Sha256>::default(),
            &participants,
        );

        for (round_idx, round_scenario) in case.scenario.rounds().iter().enumerate() {
            let round = Round::new(Epoch::new(0), View::new((round_idx as u64) + 1));
            assert_eq!(
                twins.elect(round, None),
                Participant::from_usize(round_scenario.leader()),
                "unexpected leader in scripted attack round"
            );
        }

        for view in (framework.rounds as u64 + 1)..=20 {
            let round = Round::new(Epoch::new(333), View::new(view));
            assert_eq!(twins.elect(round, None), fallback.elect(round, None));
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
        let twins = <Elector<RoundRobin<Sha256>> as elector::Config<ed25519::Scheme>>::build(
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
        let fallback = <RoundRobin<Sha256> as elector::Config<ed25519::Scheme>>::build(
            RoundRobin::<Sha256>::default().with_term(
                term_length,
                Duration::from_secs(10),
                ViewDelta::new(0),
            ),
            &participants,
        );

        for view in 1..=3 {
            let round = Round::new(Epoch::new(0), View::new(view));
            assert_eq!(twins.elect(round, None), Participant::new(0));
        }
        for view in 4..=6 {
            let round = Round::new(Epoch::new(0), View::new(view));
            assert_eq!(twins.elect(round, None), Participant::new(2));
        }

        let round = Round::new(Epoch::new(333), View::new(7));
        assert_eq!(twins.elect(round, None), fallback.elect(round, None));
    }
}

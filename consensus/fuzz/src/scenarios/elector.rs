//! Elector that pins node 0 as leader of one live view above the scenario floor.
//!
//! The engines start above the prefix floor, so the built-in
//! `ByzantineFirstLeaderRoundRobin` (which pins node 0 at view 1) never gives the
//! adversary a leader turn in the live phase. This elector pins node 0
//! ([`BYZANTINE_IDX`]) as the leader of a chosen live `attack_view` and falls back
//! to round-robin everywhere else, so the byzantine leader fault actually runs.

use crate::BYZANTINE_IDX;
use commonware_consensus::{
    simplex::{
        elector::{Config as ElectorConfig, Elector, RoundRobin, Terms},
        scheme::Scheme,
    },
    types::{Participant, Round, View},
};
use commonware_cryptography::{Sha256, sha256::Digest as Sha256Digest};

#[derive(Clone)]
pub(crate) struct ByzantineLeaderAtView {
    pub(crate) attack_view: View,
}

impl Default for ByzantineLeaderAtView {
    fn default() -> Self {
        // Never used: the elector is always constructed with an explicit view.
        Self {
            attack_view: View::zero(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct ByzantineLeaderAtViewElector<S: Scheme<Sha256Digest>> {
    attack_view: View,
    fallback: <RoundRobin<Sha256> as ElectorConfig<S>>::Elector,
}

impl<S: Scheme<Sha256Digest>> ElectorConfig<S> for ByzantineLeaderAtView {
    type Elector = ByzantineLeaderAtViewElector<S>;

    fn build(self, participants: &commonware_utils::ordered::Set<S::PublicKey>) -> Self::Elector {
        ByzantineLeaderAtViewElector {
            attack_view: self.attack_view,
            fallback: RoundRobin::<Sha256>::default().build(participants),
        }
    }
}

impl<S: Scheme<Sha256Digest>> Elector<S> for ByzantineLeaderAtViewElector<S> {
    fn terms(&self) -> Terms {
        self.fallback.terms()
    }

    fn elect(&self, round: Round, certificate: Option<&S::Certificate>) -> Participant {
        if round.view() == self.attack_view {
            return Participant::from_usize(BYZANTINE_IDX);
        }
        self.fallback.elect(round, certificate)
    }
}

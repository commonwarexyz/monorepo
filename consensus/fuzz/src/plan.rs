//! Plans for connected Simplex property checks.

use crate::{
    FuzzInput, HANDOFF_DECISIONS, N4F1C3, Standard, fuzz, simplex::Simplex,
    strategy::StrategyChoice, utils::Partition,
};
use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus::{
    Handoff,
    types::{TermLength, ViewDelta},
};
use commonware_utils::NZU32;

pub(crate) const TERM_LENGTH_BOUNDARIES: [TermLength; 2] =
    [TermLength::ONE, TermLength::new(NZU32!(5))];

pub(crate) fn connected_input(seed: u64, containers: u64, term_length: TermLength) -> FuzzInput {
    FuzzInput {
        raw_bytes: seed.to_be_bytes().to_vec(),
        partition: Partition::Connected,
        configuration: N4F1C3,
        required_containers: containers,
        term_length,
        optimistic_views: ViewDelta::new(term_length.get()),
        heterogeneous_optimism: true,
        handoff: Handoff::Wait,
        degraded_network: false,
        strategy: StrategyChoice::AnyScope,
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct ConnectedPlan {
    pub(crate) seed: u64,
    pub(crate) term_length: TermLength,
    pub(crate) handoff: Handoff<()>,
}

impl Arbitrary<'_> for ConnectedPlan {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let term_length = *u.choose(&TERM_LENGTH_BOUNDARIES)?;
        let handoff = *u.choose(&HANDOFF_DECISIONS)?;
        let seed = u64::from_be_bytes(u.bytes(size_of::<u64>())?.try_into().unwrap());
        Ok(Self {
            seed,
            term_length,
            handoff,
        })
    }
}

impl ConnectedPlan {
    pub(crate) fn run<P: Simplex>(self) {
        const CONTAINERS: u64 = 30;
        fuzz::<P, Standard>(FuzzInput {
            handoff: self.handoff,
            ..connected_input(self.seed, CONTAINERS, self.term_length)
        });
    }
}

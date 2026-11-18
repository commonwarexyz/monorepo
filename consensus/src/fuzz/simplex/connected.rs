//! Plans for connected Simplex property checks.

use super::{
    FuzzInput, HANDOFF_DECISIONS, Mode, N4F1C3, Scheme, strategy::StrategyChoice, utils::Partition,
};
use crate::{
    Handoff,
    types::{TermLength, ViewDelta},
};
use arbitrary::{Arbitrary, Unstructured};
use commonware_utils::NZU32;

pub(super) const TERM_LENGTH_BOUNDARIES: [TermLength; 2] =
    [TermLength::ONE, TermLength::new(NZU32!(5))];

pub(super) fn connected_input(seed: u64, containers: u64, term_length: TermLength) -> FuzzInput {
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
        strategy: StrategyChoice::Any,
    }
}

#[derive(Clone, Copy, Debug)]
pub(in crate::fuzz) struct ConnectedPlan {
    pub(in crate::fuzz) seed: u64,
    pub(in crate::fuzz) term_length: TermLength,
    pub(in crate::fuzz) handoff: Handoff<()>,
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
    pub(in crate::fuzz) fn run(self, scheme: Scheme) {
        const CONTAINERS: u64 = 30;
        let input = FuzzInput {
            handoff: self.handoff,
            ..connected_input(self.seed, CONTAINERS, self.term_length)
        };
        scheme.run(input, Mode::Standard);
    }
}

//! Twins campaigns over real machines.
//!
//! A Byzantine participant runs as two halves: two machines holding its keys, each producing,
//! voting, and leading as a correct node would. A [`Split`] router keeps the halves apart: every
//! correct node sits on one side and exchanges messages and retrievals only with the half of
//! each Byzantine participant on its side, until the split heals. Correct nodes therefore see one
//! identity sign conflicting headers, votes, and leader blocks, and the world's oracle checks that
//! the correct nodes stay safe, never quarantine a correct participant, and keep finalizing.

mod randomized;
#[cfg(test)]
mod scripted;

use crate::{
    multimmit::{
        config::Tuning,
        machine::world::{Config, Router, Verification, World, WorldArtifact},
        mocks::Committee,
    },
    types::Participant,
};
use commonware_cryptography::bls12381::primitives::variant::MinPk;
#[cfg(feature = "mocks")]
pub(crate) use randomized::exercise;
use std::{collections::BTreeSet, sync::Arc};

/// Where one node of a twins world sits.
#[derive(Clone, Debug)]
enum Seat {
    /// A correct node, on one side of each Byzantine participant, in `byzantine` order.
    Correct(Vec<bool>),
    /// One half of the Byzantine participant at `twin` in `byzantine` order.
    Half { twin: usize, side: bool },
}

/// Splits correct nodes between the two halves of every Byzantine participant.
#[derive(Clone, Debug)]
pub(crate) struct Split {
    seats: Vec<Seat>,
    /// Whether every node exchanges with every other.
    healed: bool,
}

impl Split {
    /// Returns whether nodes `a` and `b` exchange messages and retrievals: correct nodes always,
    /// a correct node and a half when the node sits on the half's side, and two halves unless
    /// they are the two halves of one participant.
    fn links(&self, a: usize, b: usize) -> bool {
        if self.healed {
            return true;
        }
        match (&self.seats[a], &self.seats[b]) {
            (Seat::Correct(_), Seat::Correct(_)) => true,
            (Seat::Correct(sides), Seat::Half { twin, side })
            | (Seat::Half { twin, side }, Seat::Correct(sides)) => sides[*twin] == *side,
            (Seat::Half { twin: a, .. }, Seat::Half { twin: b, .. }) => a != b,
        }
    }

    /// Lets every node exchange with every other from now on.
    pub(crate) const fn heal(&mut self) {
        self.healed = true;
    }
}

impl Router for Split {
    fn recipients(&mut self, nodes: usize, from: usize, _: &[Arc<WorldArtifact>]) -> Vec<usize> {
        (0..nodes)
            .filter(|to| *to != from && self.links(from, *to))
            .collect()
    }

    fn serves(&self, server: usize, client: usize) -> bool {
        self.links(server, client)
    }
}

/// Returns a twins world of `participants` in which each of `byzantine` runs as two halves, and
/// correct participant `p` sits on the side `side(p, t)` of the `t`-th of them.
pub(crate) fn twins(
    seed: u64,
    participants: u32,
    byzantine: &[u32],
    side: impl Fn(Participant, usize) -> bool,
    verification: Verification,
) -> World<Split> {
    let committee = Committee::<MinPk>::builder(seed, participants).build();
    let mut nodes = Vec::new();
    let mut seats = Vec::new();
    for participant in (0..participants).map(Participant::new) {
        if let Some(twin) = byzantine.iter().position(|b| *b == participant.get()) {
            for side in [false, true] {
                nodes.push(participant);
                seats.push(Seat::Half { twin, side });
            }
        } else {
            nodes.push(participant);
            seats.push(Seat::Correct(
                (0..byzantine.len())
                    .map(|twin| side(participant, twin))
                    .collect(),
            ));
        }
    }
    let config = Config {
        committee,
        nodes,
        byzantine: byzantine
            .iter()
            .copied()
            .map(Participant::new)
            .collect::<BTreeSet<_>>(),
        tuning: Tuning::default(),
        verification,
    };
    World::new(
        config,
        Split {
            seats,
            healed: false,
        },
    )
}

//! Deterministic scheduler exercise shared by unit property tests and fuzz targets.

use super::{
    IngressLimits,
    lanes::{Group, LaneId, Lanes},
};
use crate::{
    multimmit::{
        machine::Artifact,
        types::{Attestation, NoVote},
    },
    types::{Epoch, Round, View},
};
use commonware_codec::types::lazy::Lazy;
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, Variant},
    ed25519::{PrivateKey, PublicKey},
    sha256::Digest as Sha256Digest,
};
use commonware_math::algebra::Additive as _;
use commonware_utils::Participant;
use std::{num::NonZeroUsize, time::Duration};

const CHAINS: usize = 4;
const PEERS: usize = 4;

const fn limits() -> IngressLimits {
    IngressLimits {
        cohort_items: NonZeroUsize::new(4).unwrap(),
        lane_items: NonZeroUsize::new(3).unwrap(),
        lane_bytes: NonZeroUsize::new(4096).unwrap(),
        inflight_jobs: NonZeroUsize::new(1).unwrap(),
        coalesce: Duration::ZERO,
    }
}

fn artifact(marker: u8) -> Artifact<MinPk, Sha256Digest> {
    let novote = NoVote::new(
        Round::new(Epoch::new(1), View::new(u64::from(marker) + 1)),
        Attestation::new(
            Participant::new(u32::from(marker % 8)),
            Lazy::from(<MinPk as Variant>::Signature::zero()),
        ),
    )
    .expect("live view is valid");
    Artifact::NoVote(novote)
}

/// Exercises the bounded lane scheduler against arbitrary operation schedules.
///
/// Panics when any bound, accounting, ordering, or exactly-once invariant is violated. Both the
/// unit property test and the cargo-fuzz entry point run this interpreter.
pub fn exercise_lanes(input: &[u8]) {
    use commonware_cryptography::Signer as _;

    let peers: Vec<PublicKey> = (0..PEERS as u64)
        .map(|seed| PrivateKey::from_seed(seed).public_key())
        .collect();
    let bounds = limits();
    let mut lanes: Lanes<PublicKey, MinPk, Sha256Digest> = Lanes::new(CHAINS, PEERS, bounds);

    let mut buffered = 0usize;

    for chunk in input.chunks_exact(3) {
        let (op, a, b) = (chunk[0], chunk[1], chunk[2]);
        match op % 3 {
            0 => {
                let lane = match a % 6 {
                    0 => LaneId::Consensus,
                    1 => LaneId::Certificate,
                    chain => LaneId::Data(usize::from(chain - 2) % CHAINS),
                };
                let peer = peers[usize::from(b) % PEERS].clone();
                let artifact = artifact(b);
                let artifact = (artifact.id::<commonware_cryptography::Sha256>(), artifact);
                if lanes.push_group(lane, peer, Group::one(artifact)).is_ok() {
                    buffered += 1;
                }
            }
            1 => {
                let peer = peers[usize::from(b) % PEERS].clone();
                let artifacts = [artifact(b), artifact(b.wrapping_add(1))]
                    .map(|artifact| (artifact.id::<commonware_cryptography::Sha256>(), artifact));
                if lanes
                    .push_group(LaneId::Consensus, peer, Group::pair(artifacts))
                    .is_ok()
                {
                    buffered += 2;
                }
            }
            _ => {
                let budget = usize::from(a % 8);
                let cohort = lanes.flush(budget);
                assert!(
                    cohort.len() <= budget.saturating_add(1),
                    "flush split a group"
                );
                buffered -= cohort.len();
            }
        }

        assert_eq!(lanes.items(), buffered, "lane accounting diverged");
    }

    // Every buffered artifact drains, in bounded cohorts.
    loop {
        let cohort = lanes.flush(bounds.cohort_items.get());
        if cohort.is_empty() {
            break;
        }
        assert!(cohort.len() <= bounds.cohort_items.get().saturating_add(1));
        buffered -= cohort.len();
    }
    assert_eq!(buffered, 0, "artifacts were lost or duplicated");
    assert_eq!(lanes.items(), 0);
}

#[cfg(test)]
mod tests {
    use super::exercise_lanes;
    use commonware_utils::{TestRng, test_rng};
    use rand_core::Rng as _;

    #[test]
    fn exercises_random_schedules() {
        let mut rng: TestRng = test_rng();
        for _ in 0..64 {
            let mut input = vec![0u8; 3 * 64];
            rng.fill_bytes(&mut input);
            exercise_lanes(&input);
        }
    }
}

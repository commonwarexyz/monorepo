//! Leader-finality facts for tests that consume finality reports.

use crate::{
    multimmit::types::{BlockRef, CertificateId, FinalityFact, FinalityId, Position},
    types::{Height, Round},
};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest as Sha256Digest};

/// Returns a leader-finality fact for `round` that finalizes the chain tips `blocks`, whose
/// leader proposed up to `proposed` on each chain, supported by `votes` votes.
///
/// The fact's identity, leader, and parent derive from `round`, and every chain is settled at
/// position zero.
///
/// # Panics
///
/// Panics unless `blocks` and `proposed` name the same number of chains.
pub fn finality_fact(
    round: Round,
    votes: usize,
    blocks: Vec<BlockRef<Sha256Digest>>,
    proposed: Vec<Height>,
) -> FinalityFact<Sha256Digest> {
    assert_eq!(
        blocks.len(),
        proposed.len(),
        "a fact names one tip and one proposed height per chain"
    );
    let label = |kind: &[u8]| {
        Sha256::hash(&[
            kind,
            &round.epoch().get().to_be_bytes(),
            &round.view().get().to_be_bytes(),
        ])
    };
    let chains = blocks.len();
    FinalityFact::new(
        FinalityId::Direct(label(b"finality")),
        round,
        label(b"leader"),
        CertificateId::new(label(b"parent")),
        votes,
        blocks,
        proposed,
        vec![Position::new(0); chains],
        vec![true; chains],
    )
}

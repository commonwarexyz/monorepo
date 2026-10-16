//! Certificate fixtures shared by marshal tests.

use crate::{
    multimmit::{mocks::Committee, types::Lqc},
    types::{Participant, View},
};
use commonware_cryptography::{
    Sha256, bls12381::primitives::variant::MinPk, sha256::Digest as Sha256Digest,
};

/// Returns the L-QC of `signers` for the genesis-anchored leader block of `view` that commits to
/// the tips-history commitment `history`.
///
/// The certificate needs exactly `n - f` signers; [`Committee::lqc_with`] covers the first `n - f`.
pub(super) fn lqc(
    committee: &Committee<MinPk>,
    view: u64,
    history: Sha256Digest,
    signers: impl IntoIterator<Item = usize>,
) -> Lqc<MinPk, Sha256Digest> {
    let view = View::new(view);
    let leader = committee
        .leader_block_with(view, committee.genesis().vqc(), history)
        .block()
        .clone();
    let content = committee.content(
        view,
        Some(leader.digest::<Sha256>()),
        false,
        committee.genesis_endorsement(),
    );
    let contents = signers
        .into_iter()
        .map(|signer| (Participant::from_usize(signer), content.clone()))
        .collect();
    committee.lqc_from(leader, contents)
}

//! Commitment-typed Byzantine actor for coding end-to-end targets.

use super::{
    coding_stack::CommitmentOf,
    twins::{PublicKeyOf, SchemeOf},
};
use crate::{
    simplex::Simplex,
    strategy::{AnyScope, FutureScope, SmallScope, Strategy as _, StrategyChoice},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_consensus::{
    Viewable,
    simplex::{
        scheme::Scheme as SimplexScheme,
        types::{Finalize, Notarize, Nullify, Proposal, Vote},
    },
    types::{Epoch, Round, View},
};
use commonware_cryptography::{Digest, Hasher as _, Sha256, sha256::Digest as Sha256Digest};
use commonware_p2p::{Receiver, Recipients, Sender};
use commonware_runtime::{Spawner as _, Supervisor as _, deterministic};
use std::collections::HashSet;

fn fault_views(
    strategy: StrategyChoice,
    required_containers: u64,
    context: &mut deterministic::Context,
) -> Option<Vec<View>> {
    match strategy {
        StrategyChoice::SmallScope {
            fault_rounds,
            fault_rounds_bound,
        } => SmallScope {
            fault_rounds,
            fault_rounds_bound,
        }
        .disrupter_faults(required_containers, context),
        StrategyChoice::FutureScope {
            fault_rounds,
            fault_rounds_bound,
        } => FutureScope {
            fault_rounds,
            fault_rounds_bound,
        }
        .disrupter_faults(required_containers, context),
        StrategyChoice::AnyScope
        | StrategyChoice::HeaderScope { .. }
        | StrategyChoice::SplitHeader { .. } => {
            AnyScope.disrupter_faults(required_containers, context)
        }
    }
}

fn conflicting_proposal<P: Simplex>(
    proposal: &Proposal<CommitmentOf<P>>,
) -> Proposal<CommitmentOf<P>> {
    let payload = proposal.payload;
    let block: Sha256Digest = payload.block();
    let conflicting_block = Sha256::hash(&[b"coding-twin", block.as_ref()]);
    let payload = CommitmentOf::<P>::from((
        conflicting_block,
        payload.root(),
        payload.context(),
        payload.config(),
    ));
    Proposal::new(proposal.round, proposal.parent, payload)
}

fn send_notarize<P: Simplex>(
    scheme: &SchemeOf<P>,
    sender: &mut impl Sender<PublicKey = PublicKeyOf<P>>,
    proposal: Proposal<CommitmentOf<P>>,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let Some(vote) = Notarize::sign(scheme, proposal) else {
        return;
    };
    let message = Vote::<SchemeOf<P>, CommitmentOf<P>>::Notarize(vote).encode();
    let _ = sender.send(Recipients::All, message, true);
}

fn send_finalize<P: Simplex>(
    scheme: &SchemeOf<P>,
    sender: &mut impl Sender<PublicKey = PublicKeyOf<P>>,
    proposal: Proposal<CommitmentOf<P>>,
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let Some(vote) = Finalize::sign(scheme, proposal) else {
        return;
    };
    let message = Vote::<SchemeOf<P>, CommitmentOf<P>>::Finalize(vote).encode();
    let _ = sender.send(Recipients::All, message, true);
}

async fn drain<P: Simplex>(mut receiver: impl Receiver<PublicKey = PublicKeyOf<P>>) {
    while receiver.recv().await.is_ok() {}
}

/// Start an actor that signs conflicting coding proposals with a Byzantine
/// identity's real key.
pub(crate) fn start<P: Simplex>(
    mut context: deterministic::Context,
    scheme: SchemeOf<P>,
    strategy: StrategyChoice,
    required_containers: u64,
    vote_network: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    certificate_network: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
    resolver_network: (
        impl Sender<PublicKey = PublicKeyOf<P>>,
        impl Receiver<PublicKey = PublicKeyOf<P>>,
    ),
) where
    SchemeOf<P>: SimplexScheme<CommitmentOf<P>>,
{
    let seed = CommitmentOf::<P>::from((
        Sha256::hash(&[b"coding-disrupter-seed-block"]),
        Sha256::hash(&[b"coding-disrupter-seed-root"]),
        Sha256::hash(&[b"coding-disrupter-seed-context"]),
        commonware_consensus::marshal::mocks::harness::GENESIS_CODING_CONFIG,
    ));
    let faulty_views = fault_views(strategy, required_containers, &mut context);
    let proactive_views = faulty_views
        .clone()
        .unwrap_or_else(|| (1..=required_containers.max(1)).map(View::new).collect());
    let (_, certificate_receiver) = certificate_network;
    context
        .child("certificate_drain")
        .spawn(move |_| drain::<P>(certificate_receiver));
    let (_, resolver_receiver) = resolver_network;
    context
        .child("resolver_drain")
        .spawn(move |_| drain::<P>(resolver_receiver));

    let (mut vote_sender, mut vote_receiver) = vote_network;
    context.spawn(move |_| async move {
        let mut emitted = HashSet::new();
        for view in proactive_views {
            let proposal = Proposal::new(
                Round::new(Epoch::zero(), view),
                View::new(view.get().saturating_sub(1)),
                seed,
            );
            for proposal in [proposal.clone(), conflicting_proposal::<P>(&proposal)] {
                emitted.insert((0u8, proposal.clone()));
                send_notarize::<P>(&scheme, &mut vote_sender, proposal);
            }
        }
        while let Ok((_, message)) = vote_receiver.recv().await {
            let Ok(vote) = Vote::<SchemeOf<P>, CommitmentOf<P>>::decode(message) else {
                continue;
            };
            if faulty_views
                .as_ref()
                .is_some_and(|views| !views.contains(&vote.view()))
            {
                continue;
            }
            match vote {
                Vote::Notarize(vote) => {
                    let proposals = [
                        vote.proposal.clone(),
                        conflicting_proposal::<P>(&vote.proposal),
                    ];
                    for proposal in proposals {
                        if emitted.insert((0u8, proposal.clone())) {
                            send_notarize::<P>(&scheme, &mut vote_sender, proposal);
                        }
                    }
                }
                Vote::Finalize(vote) => {
                    let proposals = [
                        vote.proposal.clone(),
                        conflicting_proposal::<P>(&vote.proposal),
                    ];
                    for proposal in proposals {
                        if emitted.insert((1u8, proposal.clone())) {
                            send_finalize::<P>(&scheme, &mut vote_sender, proposal);
                        }
                    }
                }
                Vote::Nullify(vote) => {
                    if !emitted.insert((
                        2u8,
                        Proposal::new(vote.round, View::zero(), CommitmentOf::<P>::EMPTY),
                    )) {
                        continue;
                    }
                    let Some(vote) = Nullify::sign::<CommitmentOf<P>>(&scheme, vote.round) else {
                        continue;
                    };
                    let message = Vote::<SchemeOf<P>, CommitmentOf<P>>::Nullify(vote).encode();
                    let _ = vote_sender.send(Recipients::All, message, true);
                }
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimplexCertificateMock;

    type TestCommitment = CommitmentOf<SimplexCertificateMock>;

    #[test]
    fn conflicting_coding_proposal_preserves_shape_but_changes_payload() {
        let digest = Sha256::hash(&[b"block"]);
        let payload = TestCommitment::from((
            digest,
            Sha256::hash(&[b"root"]),
            Sha256::hash(&[b"context"]),
            commonware_consensus::marshal::mocks::harness::GENESIS_CODING_CONFIG,
        ));
        let proposal = Proposal::new(
            Round::new(Epoch::zero(), View::new(1)),
            View::zero(),
            payload,
        );

        let conflicting = conflicting_proposal::<SimplexCertificateMock>(&proposal);
        assert_eq!(conflicting.round, proposal.round);
        assert_eq!(conflicting.parent, proposal.parent);
        assert_ne!(conflicting.payload, proposal.payload);
        assert_eq!(conflicting.payload.config(), proposal.payload.config());
    }
}

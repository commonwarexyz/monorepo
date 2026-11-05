//! DA-certificate recovery: certificates carried by view certificates and fetched from peers.

use super::fixtures::{
    Harness, TestMachine, da_run_headers, genesis_tip_history, observe, start_profile,
    symbolic_da_certificate, symbolic_nullification, view_vote, vqc,
};
use crate::{
    Epochable as _,
    multimmit::{
        machine::{
            capability::{Capabilities, Capability, ResolverCommand},
            input::Input,
            resolution::{CertificateCompletion, CertificateJob},
            testing::{Drive as _, Until},
            verification::VerifyJob,
        },
        mocks::Bls,
        types::{
            Anchor, Artifact, ChainId, ChainProposal, DaQuorum, LeaderBlock, PathLimits,
            TransactionBlockHeader, ViewMessage,
        },
    },
    types::{Height, Round, View},
};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, sha256::Digest};

const CHAIN: ChainId = ChainId::new(1);

/// Starts a validator that does not produce chain 1, a receipt chain with `d = 0` and `e = 0`,
/// and exits view 1 on a V-QC whose leader block placed chain 1's first block through its
/// certificate. The validator never saw that leader block. Returns the machine, the placed header,
/// and the capabilities the exit issued.
fn exit_on_a_certified_placement() -> (
    TestMachine,
    TransactionBlockHeader<Digest>,
    Capabilities<Bls<MinPk>, Digest>,
) {
    let mut chain_limits = vec![PathLimits::new(2, 1); 6];
    chain_limits[CHAIN.get() as usize] = PathLimits::new(0, 0);
    let harness = |participant: u32| {
        Harness::validator(participant)
            .participants(6)
            .chain_limits(chain_limits.clone())
            .da_quorum(DaQuorum::Binding)
    };
    let producer = harness(0)
        .profile()
        .protocol()
        .producer(CHAIN)
        .expect("chain 1 has a producer");
    let validator = (0..6).find(|participant| *participant != producer.get()).unwrap();
    let (mut machine, started) = start_profile(harness(validator).profile());
    machine.drain_persisting(started);
    let header = da_run_headers(&machine, CHAIN.get(), 1, "placed")[0].clone();

    let protocol = machine.profile().protocol().clone();
    let codec = protocol.codec_config();
    let proposals = protocol
        .genesis()
        .tips()
        .iter()
        .map(|tip| {
            let anchor = if tip.chain() == CHAIN {
                Anchor::Certificate(symbolic_da_certificate(header.clone(), 1))
            } else {
                Anchor::Tip(*tip)
            };
            ChainProposal::new(tip.chain(), anchor, Vec::new(), codec.pipeline_depth()).unwrap()
        })
        .collect();
    let placing = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(1)),
        protocol.genesis().vqc(),
        genesis_tip_history(&protocol),
        proposals,
        codec,
    )
    .unwrap();
    let messages = (0..5)
        .map(|signer| ViewMessage::Vote(view_vote(&machine, &placing, signer)))
        .collect::<Vec<_>>();
    let certificate = vqc(&machine, placing, &messages);
    let verification = observe(&mut machine, Artifact::Vqc(certificate));
    let exited = machine.verify(&verification, true, Until::CursorAdvance);
    let mut effects = exited.capabilities().to_vec();
    effects.extend(machine.drain_persisting(exited));
    assert_eq!(machine.durable.state.view, View::new(2));
    assert_eq!(machine.durable.state.certified_height(CHAIN), Some(Height::zero()));
    (machine, header, effects)
}

/// Returns the verification issued for a DA certificate among `effects`.
fn certificate_verification(
    effects: &[Capability<Bls<MinPk>, Digest>],
) -> Option<VerifyJob<Bls<MinPk>, Digest>> {
    effects.iter().find_map(|effect| match effect {
        Capability::Verify(job)
            if job.items().iter().any(|item| {
                matches!(item.shared_artifact().as_ref(), Artifact::DaCertificate(_))
            }) =>
        {
            Some(job.clone())
        }
        _ => None,
    })
}

/// Returns the DA-certificate request among `effects`.
fn certificate_request(effects: &[Capability<Bls<MinPk>, Digest>]) -> Option<CertificateJob> {
    effects.iter().find_map(|effect| match effect {
        Capability::Resolver(ResolverCommand::ResolveCertificate(job)) => Some(*job),
        _ => None,
    })
}

#[test]
fn a_certificate_a_view_certificate_carries_is_admitted_without_its_leader_block() {
    let (mut machine, header, effects) = exit_on_a_certified_placement();
    let job = certificate_verification(&effects).expect("the carried certificate is verified");
    let verified = machine.verify(&job, true, Until::CursorAdvance);
    let effects = machine.drain_persisting(verified);
    assert_eq!(
        machine.durable.state.certified_height(CHAIN),
        Some(header.height())
    );
    assert!(certificate_request(&effects).is_none());
}

#[test]
fn a_node_placed_above_every_certificate_it_holds_fetches_one_after_a_view() {
    let (mut machine, header, effects) = exit_on_a_certified_placement();
    assert!(certificate_request(&effects).is_none());

    // The carried certificate is invalid, so nothing this node holds covers the placement. The
    // chain is behind from view 2, and no request goes out within that view.
    let job = certificate_verification(&effects).expect("the carried certificate is verified");
    let rejected = machine.verify(&job, false, Until::CursorAdvance);
    let mut effects = rejected.capabilities().to_vec();
    effects.extend(machine.drain_persisting(rejected));
    assert!(certificate_request(&effects).is_none());

    // A view later the chain is still behind, so the node asks peers for a certificate above its
    // durable certified height.
    let nullification = symbolic_nullification(&machine, View::new(2), 7);
    let verification = observe(&mut machine, Artifact::Nullification(nullification));
    let exited = machine.verify(&verification, true, Until::CursorAdvance);
    let mut effects = exited.capabilities().to_vec();
    effects.extend(machine.drain_persisting(exited));
    assert_eq!(machine.durable.state.view, View::new(3));
    let request = certificate_request(&effects).expect("the behind chain is requested");
    assert_eq!(request.chain(), CHAIN);
    assert_eq!(request.after(), Height::zero());

    // The fetched certificate is admitted like any other; once it is verified and durable, the
    // chain is no longer behind and the request is retired.
    let completed = machine
        .step(Input::CertificateResolved(CertificateCompletion::new(
            request,
            symbolic_da_certificate(header.clone(), 2),
        )))
        .unwrap();
    let completed = machine.settle(completed, Until::CursorAdvance);
    let verification = certificate_verification(completed.capabilities())
        .expect("the fetched certificate is verified");
    let verified = machine.verify(&verification, true, Until::CursorAdvance);
    let mut effects = verified.capabilities().to_vec();
    effects.extend(machine.drain_persisting(verified));
    assert_eq!(
        machine.durable.state.certified_height(CHAIN),
        Some(header.height())
    );
    assert!(effects.iter().any(|effect| matches!(
        effect,
        Capability::Resolver(ResolverCommand::CancelCertificate(job)) if *job == request
    )));
}

#[test]
fn a_fetched_certificate_must_answer_the_open_request() {
    let (mut machine, header, _) = exit_on_a_certified_placement();
    // No request is open, so a completion is stale.
    let stale = CertificateJob::issue(99, machine.generation(), CHAIN, Height::zero());
    let step = machine
        .step(Input::CertificateResolved(CertificateCompletion::new(
            stale,
            symbolic_da_certificate(header, 3),
        )))
        .unwrap();
    assert!(step.capabilities().is_empty());
}

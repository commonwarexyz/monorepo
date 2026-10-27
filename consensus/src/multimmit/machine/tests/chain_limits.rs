//! Per-chain path limits: certified-only chains, per-chain extension bounds, the forwarding of
//! unplaced certificates, and receipt chains, whose certificates every validator recovers.

use super::fixtures::{
    Harness, TestMachine, attestation, da_run_headers, digest, genesis_tip_history, observe,
    start_profile, symbolic_da_certificate, symbolic_nullification, threshold_share,
    validate_block,
};
use crate::{
    Epochable as _,
    multimmit::{
        config::{Profile, ProposalPolicy},
        machine::{
            capability::{Capability, ChainCommand},
            chain::ChainState,
            durability::{Change, PersistDirective, SendRequest},
            input::{CryptoCompletion, Input, ObservationStatus, Rejection, Step, StepStatus},
            reducer::machine::Machine,
            testing::{CapabilitiesExt as _, Drive as _, Until, cohort},
        },
        types::{
            Anchor, Artifact, ChainId, ChainProposal, DaQuorum, DaVote, LeaderBlock, PathLimits,
            SignedTransactionBlock, TransactionBlockHeader,
        },
    },
    types::{Height, Participant, Round, View},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk, sha256::Digest};

/// The certified-only chain in these profiles.
const RECEIPTS: ChainId = ChainId::new(1);

/// A six-validator profile whose chain 1 places only certified blocks and the rest pipeline.
fn profile(participant: u32) -> Profile<Digest> {
    let mut limits = vec![PathLimits::new(2, 1); 6];
    limits[RECEIPTS.get() as usize] = PathLimits::new(0, 0);
    Harness::validator(participant)
        .participants(6)
        .chain_limits(limits)
        .profile()
}

/// Returns the header at `height` on `chain` above `parent`.
fn header(
    profile: &Profile<Digest>,
    chain: ChainId,
    height: u64,
    parent: Digest,
) -> TransactionBlockHeader<Digest> {
    TransactionBlockHeader::new(
        profile.protocol().epoch(),
        chain,
        Height::new(height),
        parent,
        digest(format!("chain {} height {height}", chain.get()).as_bytes()),
    )
    .unwrap()
}

#[test]
fn certified_only_chain_proposes_only_its_highest_certificate() {
    let mut machine = Machine::new(profile(0));
    let start = machine.step(Input::Start).unwrap();
    machine.persist(&start.persist_job(), Until::CursorAdvance);
    let genesis = machine.profile().protocol().genesis().tips()[RECEIPTS.get() as usize];
    let first = header(machine.profile(), RECEIPTS, 1, genesis.digest());
    let second = header(
        machine.profile(),
        RECEIPTS,
        2,
        first.block_ref::<Sha256>().digest(),
    );

    // The pipeline window of a certified-only chain is one block: the first block is DA-voted at
    // once, and the second only after the first is certified.
    let first_choice = validate_block(&mut machine, first.clone(), 1);
    machine.persist(&first_choice.persist_job(), Until::CursorAdvance);
    let certificate = symbolic_da_certificate(first, 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate.clone()));
    let advanced = machine.verify(&verification, true, Until::CursorAdvance);
    machine.persist(&advanced.persist_job(), Until::CursorAdvance);
    let second_choice = validate_block(&mut machine, second, 1);
    machine.persist(&second_choice.persist_job(), Until::CursorAdvance);
    assert_eq!(
        machine.chain.da.chains[RECEIPTS.get() as usize]
            .local_da_votes
            .last_key_value()
            .map(|(height, _)| *height),
        Some(Height::new(2))
    );

    // Even the endorsed policy, which appends the DA-voted suffix, names only the certificate.
    assert_eq!(machine.chain.proposal_policy, ProposalPolicy::Endorsed);
    let proposal = machine.chain.propose_chain(genesis).unwrap();
    assert_eq!(proposal.anchor(), &Anchor::Certificate(certificate));
    assert!(proposal.payloads().is_empty());
}

#[test]
fn vote_bodies_extend_each_chain_to_its_own_bound() {
    let profile = profile(0);
    let protocol = profile.protocol();
    let mut chain = ChainState::<MinPk, Digest>::new(&profile);
    let headers = [ChainId::new(0), RECEIPTS]
        .into_iter()
        .map(|id| header(&profile, id, 1, protocol.genesis().tips()[id.get() as usize].digest()))
        .collect::<Vec<_>>();
    chain
        .da
        .reconcile_choices::<Sha256>(headers.clone())
        .unwrap();

    let codec = protocol.codec_config();
    let proposals = protocol
        .genesis()
        .tips()
        .iter()
        .map(|tip| {
            ChainProposal::new(tip.chain(), Anchor::Tip(*tip), Vec::new(), codec.pipeline_depth())
                .unwrap()
        })
        .collect();
    let leader = LeaderBlock::new(
        Round::new(protocol.epoch(), View::new(1)),
        protocol.genesis().vqc(),
        genesis_tip_history(protocol),
        proposals,
        codec,
    )
    .unwrap();
    let body = chain.vote_body::<Sha256>(&leader).unwrap();
    assert_eq!(body.extensions()[0].payloads(), &[headers[0].body_digest()]);
    assert!(body.extensions()[RECEIPTS.get() as usize].is_empty());
}

#[test]
fn unplaced_certificates_are_forwarded_after_a_full_view() {
    let profile = profile(0);
    let protocol = profile.protocol();
    let genesis = protocol.genesis().tips().to_vec();
    let mut chain = ChainState::<MinPk, Digest>::new(&profile);
    let certify = |chain_state: &mut ChainState<MinPk, Digest>, id: ChainId| {
        let header = header(&profile, id, 1, genesis[id.get() as usize].digest());
        let certificate = symbolic_da_certificate(header, u64::from(id.get()));
        chain_state
            .compact_certified::<Sha256>(&certificate, Height::new(1))
            .unwrap();
        certificate
    };
    let certificate = certify(&mut chain, RECEIPTS);
    // A pipelined chain is placed through its proposals, so its certificates are never forwarded.
    certify(&mut chain, ChainId::new(0));

    // First seen unplaced: the leader may still receive it in time.
    assert!(chain.unplaced_certificates(&genesis).is_empty());
    // Still unplaced a view later: forwarded, and again at every later entry.
    assert_eq!(chain.unplaced_certificates(&genesis), vec![certificate.clone()]);
    assert_eq!(chain.unplaced_certificates(&genesis), vec![certificate.clone()]);

    // Once placed, it is no longer forwarded.
    let mut placed = genesis.clone();
    placed[RECEIPTS.get() as usize] = certificate.block_ref::<Sha256>();
    assert!(chain.unplaced_certificates(&placed).is_empty());
    assert!(chain.unplaced_certificates(&genesis).is_empty());
}

/// Exits the current view by a nullification and returns every capability the exit released.
fn nullify(machine: &mut TestMachine, view: u64) -> Vec<Capability<MinPk, Digest>> {
    let artifact =
        Artifact::Nullification(symbolic_nullification(machine, View::new(view), view));
    let verification = observe(machine, artifact);
    let mut step = machine.verify(&verification, true, Until::CursorAdvance);
    let mut capabilities = Vec::new();
    for _ in 0..8 {
        capabilities.extend(step.effects().iter().cloned());
        let Some(job) = step.find(|effect| match effect {
            Capability::Journal(PersistDirective { job, .. }) => Some(job.clone()),
            _ => None,
        }) else {
            break;
        };
        step = machine.persist(&job, Until::CursorAdvance);
    }
    capabilities
}

/// Returns the forwarding requests among `capabilities`.
fn forwarded(capabilities: &[Capability<MinPk, Digest>]) -> Vec<SendRequest<MinPk, Digest>> {
    capabilities
        .iter()
        .filter_map(|capability| match capability {
            Capability::Forward(requests) => Some(requests.iter().cloned()),
            _ => None,
        })
        .flatten()
        .collect()
}

#[test]
fn view_entry_forwards_an_unplaced_certificate_to_the_next_leader() {
    let (mut machine, _) = start_profile(profile(0));
    let genesis = machine.profile().protocol().genesis().tips()[RECEIPTS.get() as usize];
    let certificate = symbolic_da_certificate(header(machine.profile(), RECEIPTS, 1, genesis.digest()), 0);
    let verification = observe(&mut machine, Artifact::DaCertificate(certificate.clone()));
    let held: Step<MinPk, Digest> = machine.verify(&verification, true, Until::CursorAdvance);
    machine.persist(&held.persist_job(), Until::CursorAdvance);

    // Entering view 2 records the unplaced certificate; entering view 3 forwards it to the
    // leader of view 4, who proposes after this node's send arrives.
    assert!(forwarded(&nullify(&mut machine, 1)).is_empty());
    let requests = forwarded(&nullify(&mut machine, 2));
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].recipient(),
        machine.profile().protocol().leader(View::new(4))
    );
    assert_ne!(requests[0].recipient(), Participant::new(0));
    assert_eq!(
        requests[0].artifact().as_ref(),
        &Artifact::DaCertificate(certificate)
    );
}

/// A six-validator profile at `participant` whose chain 1 has `receipt` limits, under `quorum`.
fn receipt_profile(participant: u32, receipt: PathLimits, quorum: DaQuorum) -> Profile<Digest> {
    let mut limits = vec![PathLimits::new(2, 1); 6];
    limits[RECEIPTS.get() as usize] = receipt;
    Harness::validator(participant)
        .participants(6)
        .chain_limits(limits)
        .da_quorum(quorum)
        .profile()
}

/// Returns the status of observing `artifact`.
fn observation(machine: &mut TestMachine, artifact: Artifact<MinPk, Digest>) -> ObservationStatus {
    let step = machine.step(cohort::<Sha256, _>(vec![artifact])).unwrap();
    let StepStatus::Observed(results) = step.status() else {
        panic!("one observed artifact must return an observation result");
    };
    results[0].status()
}

/// Verifies chain `chain`'s first block at `machine` and returns its header.
fn verified_header(machine: &mut TestMachine, chain: u32) -> TransactionBlockHeader<Digest> {
    let header = da_run_headers(machine, chain, 1, "receipt").remove(0);
    let block = observe(
        machine,
        Artifact::TransactionBlock(SignedTransactionBlock::new(
            header.clone(),
            attestation(chain),
        )),
    );
    machine.verify(&block, true, Until::CursorAdvance);
    header
}

#[test]
fn receipt_chain_votes_reach_every_validators_recovery() {
    // Validator 5 produces neither chain 1 nor chain 2.
    let (mut machine, _) = start_profile(receipt_profile(
        5,
        PathLimits::new(0, 0),
        DaQuorum::Binding,
    ));
    let receipt = verified_header(&mut machine, RECEIPTS.get());
    let vote = DaVote::new(receipt, threshold_share(2));
    let verification = observe(&mut machine, Artifact::DaVote(vote.clone()));
    let verified = machine.verify(&verification, true, Until::CursorAdvance);
    assert!(verified.has(|capability| matches!(
        capability,
        Capability::ChainDa(chain, ChainCommand::Observe(share))
            if *chain == RECEIPTS && share.as_ref() == &vote
    )));

    // Another producer's chain keeps the default route: its votes are only its producer's.
    let pipelined = verified_header(&mut machine, 2);
    assert_eq!(
        observation(&mut machine, Artifact::DaVote(DaVote::new(pipelined, threshold_share(3)))),
        ObservationStatus::Rejected(Rejection::Unsolicited)
    );
}

#[test]
fn receipt_chains_need_binding_certificates_and_no_uncertified_placement() {
    for (receipt, quorum) in [
        (PathLimits::new(0, 0), DaQuorum::Available),
        (PathLimits::new(0, 1), DaQuorum::Binding),
        (PathLimits::new(1, 0), DaQuorum::Binding),
    ] {
        let profile = receipt_profile(5, receipt, quorum);
        assert!(!profile.protocol().receipt_chain(RECEIPTS));
        let (mut machine, _) = start_profile(profile);
        let header = verified_header(&mut machine, RECEIPTS.get());
        assert_eq!(
            observation(&mut machine, Artifact::DaVote(DaVote::new(header, threshold_share(2)))),
            ObservationStatus::Rejected(Rejection::Unsolicited)
        );
    }
}

#[test]
fn receipt_chain_certificates_are_recovered_without_a_publication() {
    let (mut machine, _) = start_profile(receipt_profile(
        5,
        PathLimits::new(0, 0),
        DaQuorum::Binding,
    ));
    let pipelined = verified_header(&mut machine, 2);
    let receipt = verified_header(&mut machine, RECEIPTS.get());

    // A recovered certificate of a chain this node neither produces nor recovers is stale.
    let ignored = machine
        .step(Input::Crypto(CryptoCompletion::DaCertificate {
            block: pipelined.block_ref::<Sha256>(),
            certificate: symbolic_da_certificate(pipelined, 0),
        }))
        .unwrap();
    let ignored = machine.settle(ignored, Until::Persist);
    assert!(!ignored.has(|capability| matches!(capability, Capability::Journal(_))));

    // A receipt chain's certificate is admitted, and only its producer publishes it.
    let certificate = symbolic_da_certificate(receipt.clone(), 1);
    let recovered = machine
        .step(Input::Crypto(CryptoCompletion::DaCertificate {
            block: receipt.block_ref::<Sha256>(),
            certificate: certificate.clone(),
        }))
        .unwrap();
    let recovered = machine.settle(recovered, Until::CursorAdvance);
    assert!(matches!(
        recovered.persist_job().events()[0].change(),
        Change::DaCertificateAdvanced {
            publication: None,
            artifact,
            ..
        } if matches!(artifact.as_ref(), Artifact::DaCertificate(actual) if actual == &certificate)
    ));
    assert!(recovered.has(|capability| matches!(
        capability,
        Capability::ChainDa(chain, ChainCommand::AnchorAdvanced(height))
            if *chain == RECEIPTS && *height == receipt.height()
    )));
}

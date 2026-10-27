//! Per-chain path limits and binding DA quorums.

use super::*;
use crate::multimmit::types::{DaQuorum, Error as TypesError, genesis_tip_commitment};

/// Pipelined chains everywhere except chain 0, which places only certified blocks.
fn receipt_limits() -> Vec<PathLimits> {
    let mut limits = vec![PathLimits::new(2, 2); PARTICIPANTS as usize];
    limits[0] = PathLimits::new(0, 0);
    limits
}

/// Returns committees with the same keys: one holding chain 0 to `d = 0` and `e = 0`, and one
/// bounding every chain by the other's largest limits.
fn committees<V: Variant>() -> (Committee<V>, Committee<V>) {
    let receipts = Committee::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 2))
        .chain_limits(receipt_limits())
        .build();
    let uniform = Committee::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 2))
        .build();
    assert_eq!(receipts.codec(), uniform.codec());
    (receipts, uniform)
}

/// Returns a leader block for `view` above genesis with `payloads` blocks on every chain.
fn leader<V: Variant>(committee: &Committee<V>, view: View, payloads: usize) -> LeaderBlock<V, Digest> {
    let codec = committee.codec();
    let genesis = committee.config.genesis();
    let proposals = genesis
        .tips()
        .iter()
        .enumerate()
        .map(|(chain, tip)| {
            ChainProposal::new(
                ChainId::new(chain as u32),
                Anchor::Tip(*tip),
                (0..payloads)
                    .map(|index| digest(b"payload", (chain * 10 + index) as u64))
                    .collect(),
                codec.pipeline_depth(),
            )
            .unwrap()
        })
        .collect();
    LeaderBlock::new(
        Round::new(committee.config.epoch(), view),
        genesis.vqc(),
        genesis_tip_commitment::<Sha256>(genesis),
        proposals,
        codec,
    )
    .unwrap()
}

fn chains_are_held_to_their_own_pipeline_depth<V: Variant>() {
    let (receipts, uniform) = committees::<V>();
    let view = View::new(1);
    let signer = receipts.config.leader(view).get() as usize;

    // A proposal within the largest depth but above chain 0's is unsigned and unverifiable.
    let deep = leader(&receipts, view, 1);
    assert_eq!(
        receipts.signers[signer]
            .sign_leader_block(deep.clone())
            .unwrap_err(),
        Error::Types(TypesError::ProposalLength)
    );
    let forged = uniform.signers[signer].sign_leader_block(deep).unwrap();
    assert!(uniform.verifier.verify_leader_block(&forged, &Sequential));
    assert!(!receipts.verifier.verify_leader_block(&forged, &Sequential));

    let anchored = leader(&receipts, view, 0);
    let signed = receipts.signers[signer]
        .sign_leader_block(anchored)
        .unwrap();
    assert!(receipts.verifier.verify_leader_block(&signed, &Sequential));
}

#[test]
fn chains_are_held_to_their_own_pipeline_depth_for_both_variants() {
    chains_are_held_to_their_own_pipeline_depth::<MinPk>();
    chains_are_held_to_their_own_pipeline_depth::<MinSig>();
}

fn chains_are_held_to_their_own_extension_bound<V: Variant>() {
    let (receipts, uniform) = committees::<V>();
    let block = leader(&receipts, View::new(1), 0);
    let digested = DigestedLeader::new::<Sha256>(&block);
    let body = |extended: usize| {
        let mut extensions = vec![Extension::empty(); PARTICIPANTS as usize];
        extensions[extended] = Extension::new(vec![digest(b"extension", 0)], 2).unwrap();
        VoteBody::for_leader(
            digested,
            vec![Position::new(0); PARTICIPANTS as usize],
            extensions,
            receipts.codec(),
        )
        .unwrap()
    };

    // An extension within the largest bound but above chain 0's is unsigned and unverifiable.
    assert_eq!(
        receipts.signers[1].sign_vote(body(0)).unwrap_err(),
        Error::Types(TypesError::ExtensionLength)
    );
    let forged = uniform.signers[1].sign_vote(body(0)).unwrap();
    assert!(uniform.verifier.verify_vote(&forged));
    assert!(!receipts.verifier.verify_vote(&forged));

    let vote = receipts.signers[1].sign_vote(body(1)).unwrap();
    assert!(receipts.verifier.verify_vote(&vote));
}

fn certificates_carrying_an_out_of_bound_vote_are_rejected<V: Variant>() {
    let (receipts, uniform) = committees::<V>();
    let block = leader(&receipts, View::new(1), 0);
    let digested = DigestedLeader::new::<Sha256>(&block);
    let votes = |extended: usize| {
        let mut extensions = vec![Extension::empty(); PARTICIPANTS as usize];
        extensions[extended] = Extension::new(vec![digest(b"extension", 0)], 2).unwrap();
        let body = VoteBody::for_leader(
            digested,
            vec![Position::new(0); PARTICIPANTS as usize],
            extensions,
            receipts.codec(),
        )
        .unwrap();
        uniform.signers[..uniform.codec().view_quorum()]
            .iter()
            .map(|signer| signer.sign_vote(body.clone()).unwrap())
            .collect::<Vec<_>>()
    };

    // A quorum that extends chain 0 certifies under the shared bound but not under chain 0's.
    let forged = uniform
        .verifier
        .assemble_lqc::<Sha256, _>(block.clone(), &votes(0), &Sequential)
        .unwrap();
    let mut rng = test_rng();
    assert!(uniform
        .verifier
        .verify_lqc::<_, Sha256, _>(&mut rng, &forged, &Sequential)
        .is_some());
    assert!(receipts
        .verifier
        .verify_lqc::<_, Sha256, _>(&mut rng, &forged, &Sequential)
        .is_none());

    let lqc = uniform
        .verifier
        .assemble_lqc::<Sha256, _>(block.clone(), &votes(1), &Sequential)
        .unwrap();
    assert!(receipts
        .verifier
        .verify_lqc::<_, Sha256, _>(&mut rng, &lqc, &Sequential)
        .is_some());
}

#[test]
fn certificates_carrying_an_out_of_bound_vote_are_rejected_for_both_variants() {
    certificates_carrying_an_out_of_bound_vote_are_rejected::<MinPk>();
    certificates_carrying_an_out_of_bound_vote_are_rejected::<MinSig>();
}

#[test]
fn chains_are_held_to_their_own_extension_bound_for_both_variants() {
    chains_are_held_to_their_own_extension_bound::<MinPk>();
    chains_are_held_to_their_own_extension_bound::<MinSig>();
}

fn binding_da_certificates_need_n_minus_f_shares<V: Variant>() {
    let binding = Committee::<V>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .da_quorum(DaQuorum::Binding)
        .build();
    let codec = binding.codec();
    assert_eq!(codec.da_quorum(), codec.view_quorum());
    assert!(codec.da_quorum() > Fixture::<V>::new().codec.da_quorum());

    let header = binding.transaction_header(ChainId::new(0), digest(b"commitment", 0));
    let votes = binding
        .signers
        .iter()
        .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
        .collect::<Vec<_>>();
    let quorum = codec.da_quorum();
    assert_eq!(
        binding
            .verifier
            .assemble_da_certificate(&votes[..quorum - 1], &Sequential)
            .unwrap_err(),
        Error::Quorum
    );
    let certificate = binding
        .verifier
        .assemble_da_certificate(&votes[..quorum], &Sequential)
        .unwrap();
    assert!(binding.verifier.verify_da_certificate(&certificate));

    // A sharing dealt for one quorum is rejected under the other.
    let available = Committee::<V>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .build();
    assert_eq!(
        Scheme::verifier(
            available.config.parameters(),
            binding.roster.clone(),
            binding.da.clone(),
            binding.nullification.clone(),
        )
        .unwrap_err(),
        Error::Sharing
    );
    assert_eq!(
        Scheme::verifier(
            binding.config.parameters(),
            available.roster,
            available.da,
            available.nullification,
        )
        .unwrap_err(),
        Error::Sharing
    );
}

#[test]
fn binding_da_certificates_need_n_minus_f_shares_for_both_variants() {
    binding_da_certificates_need_n_minus_f_shares::<MinPk>();
    binding_da_certificates_need_n_minus_f_shares::<MinSig>();
}

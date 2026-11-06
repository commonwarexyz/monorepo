//! Per-chain path limits and binding DA quorums.

use super::*;

/// Pipelined chains everywhere except chain 0, which places only certified blocks.
fn receipt_limits() -> Vec<PathLimits> {
    let mut limits = vec![PathLimits::new(2, 2); PARTICIPANTS as usize];
    limits[0] = PathLimits::new(0, 0);
    limits
}

/// Returns committees with the same keys: one holding chain 0 to `d = 0` and `e = 0`, and one
/// bounding every chain by the other's largest limits.
fn committees<S: Suite>() -> (Committee<S>, Committee<S>) {
    let receipts = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 2))
        .chain_limits(receipt_limits())
        .build();
    let uniform = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 2))
        .build();
    assert_eq!(receipts.codec(), uniform.codec());
    (receipts, uniform)
}

/// Returns a leader block for `view` above genesis with `payloads` blocks on every chain.
fn leader<S: Suite>(
    committee: &Committee<S>,
    view: View,
    payloads: usize,
) -> LeaderBlock<S, Digest> {
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

fn chains_are_held_to_their_own_pipeline_depth<S: Suite>() {
    let (receipts, uniform) = committees::<S>();
    let view = View::new(1);
    let signer = receipts.config.leader(view).get() as usize;
    let mut rng = test_rng();

    // A proposal within the largest depth but above chain 0's is unsigned and unverifiable.
    let deep = leader(&receipts, view, 1);
    assert_eq!(
        receipts.signers[signer]
            .sign_leader_block(deep.clone())
            .unwrap_err(),
        Error::Types(TypesError::ProposalLength)
    );
    let forged = uniform.signers[signer].sign_leader_block(deep).unwrap();
    assert!(
        uniform
            .verifier
            .verify_leader_block(&mut rng, &forged, &Sequential)
    );
    assert!(
        !receipts
            .verifier
            .verify_leader_block(&mut rng, &forged, &Sequential)
    );
    let artifact = Artifact::LeaderBlock(forged);
    assert_expanded_artifacts(&receipts.verifier, &[&artifact], &[], &[false]);

    let anchored = leader(&receipts, view, 0);
    let signed = receipts.signers[signer]
        .sign_leader_block(anchored)
        .unwrap();
    assert!(
        receipts
            .verifier
            .verify_leader_block(&mut rng, &signed, &Sequential)
    );
}

#[test]
fn chains_are_held_to_their_own_pipeline_depth_for_both_variants() {
    for_each_suite!(chains_are_held_to_their_own_pipeline_depth);
}

fn equal_chain_limits_admit_what_shared_limits_admit<S: Suite>() {
    let (_, uniform) = committees::<S>();
    let listed = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 2))
        .chain_limits(vec![PathLimits::new(2, 2); PARTICIPANTS as usize])
        .build();

    // Listing every chain's equal limits admits exactly what the shared limits admit.
    let view = View::new(1);
    let signer = listed.config.leader(view).get() as usize;
    let deepest = leader(&listed, view, 2);
    let signed = listed.signers[signer].sign_leader_block(deepest).unwrap();
    let mut rng = test_rng();
    assert!(
        listed
            .verifier
            .verify_leader_block(&mut rng, &signed, &Sequential)
    );
    assert!(
        uniform
            .verifier
            .verify_leader_block(&mut rng, &signed, &Sequential)
    );
}

#[test]
fn equal_chain_limits_admit_what_shared_limits_admit_for_every_suite() {
    for_each_suite!(equal_chain_limits_admit_what_shared_limits_admit);
}

fn chains_are_held_to_their_own_extension_bound<S: Suite>() {
    let (receipts, uniform) = committees::<S>();
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
    let mut rng = test_rng();

    // An extension within the largest bound but above chain 0's is unsigned and unverifiable.
    assert_eq!(
        receipts.signers[1].sign_vote(body(0)).unwrap_err(),
        Error::Types(TypesError::ExtensionLength)
    );
    let forged = uniform.signers[1].sign_vote(body(0)).unwrap();
    assert!(uniform.verifier.verify_vote(&mut rng, &forged, &Sequential));
    assert!(
        !receipts
            .verifier
            .verify_vote(&mut rng, &forged, &Sequential)
    );

    let vote = receipts.signers[1].sign_vote(body(1)).unwrap();
    assert!(receipts.verifier.verify_vote(&mut rng, &vote, &Sequential));
}

#[test]
fn chains_are_held_to_their_own_extension_bound_for_both_variants() {
    for_each_suite!(chains_are_held_to_their_own_extension_bound);
}

fn certificates_carrying_an_out_of_bound_vote_are_rejected<S: Suite>() {
    let (receipts, uniform) = committees::<S>();
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
    let mut rng = test_rng();
    let forged = uniform
        .verifier
        .assemble_lqc::<_, Sha256, _>(&mut rng, block.clone(), &votes(0), &Sequential)
        .unwrap();
    assert!(
        uniform
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut rng, &forged, &Sequential)
            .is_some()
    );
    assert!(
        receipts
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut rng, &forged, &Sequential)
            .is_none()
    );
    assert!(
        receipts
            .verifier
            .assemble_lqc::<_, Sha256, _>(&mut rng, block.clone(), &votes(0), &Sequential)
            .is_err()
    );

    let lqc = uniform
        .verifier
        .assemble_lqc::<_, Sha256, _>(&mut rng, block.clone(), &votes(1), &Sequential)
        .unwrap();
    assert!(
        receipts
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut rng, &lqc, &Sequential)
            .is_some()
    );
}

#[test]
fn certificates_carrying_an_out_of_bound_vote_are_rejected_for_both_variants() {
    for_each_suite!(certificates_carrying_an_out_of_bound_vote_are_rejected);
}

fn vqcs_carrying_an_out_of_bound_conflicting_vote_are_rejected<S: Suite>() {
    // The same keys under uniform limits that admit one extension digest and two.
    let tight = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 1))
        .build();
    let wide = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 2))
        .build();
    let view = View::new(1);
    let block = leader(&tight, view, 0);
    let other = leader(&tight, view, 1);
    assert_ne!(block.digest::<Sha256>(), other.digest::<Sha256>());

    // Designated votes fit both committees; the conflicting vote extends chain 0 by two digests.
    let designated = VoteBody::for_leader(
        DigestedLeader::new::<Sha256>(&block),
        vec![Position::new(0); PARTICIPANTS as usize],
        vec![Extension::empty(); PARTICIPANTS as usize],
        tight.codec(),
    )
    .unwrap();
    let mut extensions = vec![Extension::empty(); PARTICIPANTS as usize];
    extensions[0] =
        Extension::new(vec![digest(b"extension", 0), digest(b"extension", 1)], 2).unwrap();
    let conflict = VoteBody::new(
        block.round(),
        other.digest::<Sha256>(),
        vec![Position::new(0); PARTICIPANTS as usize],
        extensions,
        wide.codec(),
    )
    .unwrap();
    assert!(tight.signers[3].sign_vote(conflict.clone()).is_err());
    let mut messages = wide.signers[..3]
        .iter()
        .map(|signer| ViewMessage::Vote(signer.sign_vote(designated.clone()).unwrap()))
        .collect::<Vec<_>>();
    messages.push(ViewMessage::Vote(
        wide.signers[3].sign_vote(conflict).unwrap(),
    ));
    messages.push(ViewMessage::NoVote(
        wide.signers[4].sign_novote(block.round()).unwrap(),
    ));
    let mut rng = test_rng();
    let certificate = wide
        .verifier
        .assemble_vqc::<_, Sha256, _>(&mut rng, block, &messages, &Sequential)
        .unwrap();
    assert_eq!(certificate.conflicting_votes().len(), 1);

    assert!(
        wide.verifier
            .verify_vqc::<_, Sha256, _>(&mut rng, &certificate, &Sequential)
            .is_some()
    );
    assert!(
        tight
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut rng, &certificate, &Sequential)
            .is_none()
    );
    let artifact = Artifact::Vqc(certificate);
    assert_expanded_artifacts(&wide.verifier, &[&artifact], &[], &[true]);
    assert_expanded_artifacts(&tight.verifier, &[&artifact], &[], &[false]);
}

#[test]
fn vqcs_carrying_an_out_of_bound_conflicting_vote_are_rejected_for_both_variants() {
    for_each_suite!(vqcs_carrying_an_out_of_bound_conflicting_vote_are_rejected);
}

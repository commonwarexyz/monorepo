//! Signing roles, producer ownership, and epoch and namespace binding.

use super::*;

fn ordinary_signatures_are_role_and_domain_bound<S: Suite>()
where
    S::Da: certificate::Scheme<Signature = OrdinarySignature<S>>,
{
    let fixture = Fixture::<S>::new();
    let mut rng = test_rng();
    let header = fixture.header(2, 1);
    assert_eq!(
        fixture.signers[0]
            .sign_transaction_block(header.clone())
            .unwrap_err(),
        Error::Signer
    );
    let block = fixture.signers[2]
        .sign_transaction_block(header.clone())
        .unwrap();
    assert!(
        fixture
            .verifier
            .verify_transaction_block(&mut rng, &block, &Sequential)
    );

    // The producer's DA vote signs the same header, under another key or namespace.
    let da_vote = fixture.signers[2].sign_da_vote(header.clone()).unwrap();
    let wrong_key_and_domain = SignedTransactionBlock::new(
        header,
        Attestation::<S> {
            signer: da_vote.signer(),
            signature: da_vote.attestation().signature.clone(),
        },
    );
    assert!(!fixture.verifier.verify_transaction_block(
        &mut rng,
        &wrong_key_and_domain,
        &Sequential
    ));

    let leader = fixture.leader(1);
    let scheduled = fixture.scheduled(leader.view());
    assert_eq!(
        fixture.signers[(scheduled + 1) % fixture.signers.len()]
            .sign_leader_block(leader.clone())
            .unwrap_err(),
        Error::Signer
    );
    let signed = fixture.signers[scheduled]
        .sign_leader_block(leader.clone())
        .unwrap();
    assert!(
        fixture
            .verifier
            .verify_leader_block(&mut rng, &signed, &Sequential)
    );
    // A leader block signed by a non-scheduled participant fails structurally.
    let impostor = (scheduled + 1) % fixture.signers.len();
    let unscheduled = SignedLeaderBlock::new(
        leader.clone(),
        fixture.signers[impostor]
            .sign_vote(fixture.standard_body(&leader))
            .unwrap()
            .attestation()
            .clone(),
    );
    assert!(
        !fixture
            .verifier
            .verify_leader_block(&mut rng, &unscheduled, &Sequential)
    );

    let vote = fixture.signers[0]
        .sign_vote(fixture.standard_body(&leader))
        .unwrap();
    let novote = fixture.signers[1].sign_novote(fixture.round).unwrap();
    assert!(fixture.verifier.verify_vote(&mut rng, &vote, &Sequential));
    assert!(
        fixture
            .verifier
            .verify_novote(&mut rng, &novote, &Sequential)
    );

    // Verifiers cannot sign.
    assert_eq!(fixture.verifier.me(), None);
    assert_eq!(
        fixture.verifier.sign_novote(fixture.round).unwrap_err(),
        Error::VerifierOnly
    );
    assert_eq!(
        fixture
            .verifier
            .sign_da_vote(fixture.header(0, 1))
            .unwrap_err(),
        Error::VerifierOnly
    );
    assert_eq!(
        fixture.verifier.sign_nullify(fixture.round).unwrap_err(),
        Error::VerifierOnly
    );
    for (index, signer) in fixture.signers.iter().enumerate() {
        assert_eq!(signer.me(), Some(Participant::from_usize(index)));
    }
}

#[test]
fn ordinary_signatures_are_role_and_domain_bound_for_both_variants() {
    for_each_suite!(ordinary_signatures_are_role_and_domain_bound);
}

fn producer_ownership_is_independent_of_participant_index<S: Suite>() {
    let producers = vec![Participant::new(1), Participant::new(4)];
    let fixture = Fixture::<S>::with_producers(producers);
    let mut rng = test_rng();

    let first = fixture.header(0, 401);
    assert_eq!(
        fixture.signers[0]
            .sign_transaction_block(first.clone())
            .unwrap_err(),
        Error::Signer
    );
    let first = fixture.signers[1].sign_transaction_block(first).unwrap();
    assert!(
        fixture
            .verifier
            .verify_transaction_block(&mut rng, &first, &Sequential)
    );

    let second = fixture.header(1, 402);
    assert_eq!(
        fixture.signers[1]
            .sign_transaction_block(second.clone())
            .unwrap_err(),
        Error::Signer
    );
    let second = fixture.signers[4].sign_transaction_block(second).unwrap();
    assert!(
        fixture
            .verifier
            .verify_transaction_block(&mut rng, &second, &Sequential)
    );

    // Participant 0 owns chain 0 in the identity layout, but not here.
    let identity = Fixture::<S>::new();
    let wrong_owner = identity.signers[0]
        .sign_transaction_block(fixture.header(0, 403))
        .unwrap();
    assert!(
        !fixture
            .verifier
            .verify_transaction_block(&mut rng, &wrong_owner, &Sequential)
    );
    let artifacts = [
        &Artifact::TransactionBlock(first),
        &Artifact::TransactionBlock(wrong_owner),
    ];
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &artifacts,
            &[],
            &Sequential
        ),
        vec![true, false]
    );

    let validator_vote = fixture.signers[5]
        .sign_da_vote(fixture.header(1, 404))
        .unwrap();
    assert!(
        fixture
            .verifier
            .verify_da_vote(&mut rng, &validator_vote, &Sequential)
    );
    assert_eq!(
        fixture.signers[4]
            .sign_da_vote(fixture.header(2, 405))
            .unwrap_err(),
        Error::Chain
    );
    assert_eq!(
        fixture.signers[4]
            .sign_transaction_block(fixture.header(2, 406))
            .unwrap_err(),
        Error::Chain
    );
}

#[test]
fn producer_ownership_is_independent_for_both_variants() {
    for_each_suite!(producer_ownership_is_independent_of_participant_index);
}

fn structural_failures_keep_their_source<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let genesis = Round::new(fixture.round.epoch(), View::zero());
    assert_eq!(
        fixture.signers[0].sign_novote(genesis).unwrap_err(),
        Error::Types(TypesError::GenesisView)
    );
    assert_eq!(
        fixture.signers[0].sign_nullify(genesis).unwrap_err(),
        Error::Types(TypesError::GenesisView)
    );
    let other_epoch = Round::new(Epoch::new(fixture.round.epoch().get() + 1), View::new(1));
    assert_eq!(
        fixture.signers[0].sign_novote(other_epoch).unwrap_err(),
        Error::Context
    );
    assert_eq!(
        fixture.signers[0].sign_nullify(other_epoch).unwrap_err(),
        Error::Context
    );
}

#[test]
fn structural_failures_keep_their_source_for_both_variants() {
    for_each_suite!(structural_failures_keep_their_source);
}

/// Returns one valid artifact of every individually signed kind.
fn signed_artifacts<S: Suite>(fixture: &Fixture<S>) -> Vec<Artifact<S, Digest>> {
    let header = fixture.header(0, 301);
    let leader = fixture.leader(302);
    vec![
        Artifact::TransactionBlock(
            fixture.signers[0]
                .sign_transaction_block(header.clone())
                .unwrap(),
        ),
        Artifact::DaVote(fixture.signers[0].sign_da_vote(header.clone()).unwrap()),
        Artifact::DaCertificate(fixture.da_certificate(&header)),
        Artifact::LeaderBlock(fixture.sign_leader(leader.clone())),
        Artifact::Vote(
            fixture.signers[0]
                .sign_vote(fixture.standard_body(&leader))
                .unwrap(),
        ),
        Artifact::NoVote(fixture.signers[0].sign_novote(fixture.round).unwrap()),
        Artifact::Nullify(fixture.signers[0].sign_nullify(fixture.round).unwrap()),
        Artifact::Nullification(fixture.nullification(fixture.round)),
        Artifact::Vqc(fixture.vqc(&leader)),
        Artifact::Lqc(fixture.lqc(&leader)),
    ]
}

fn signatures_are_namespace_bound<S: Suite>() {
    let fixture = Fixture::<S>::new();
    // The same seed deals the same keys and epoch under another namespace.
    let wrong_namespace = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_OTHER")
        .limits(PathLimits::new(2, 2))
        .build();
    assert_eq!(wrong_namespace.config.epoch(), fixture.config.epoch());
    assert_eq!(wrong_namespace.identities.len(), fixture.signers.len());

    let artifacts = signed_artifacts(&fixture);
    let artifacts = artifacts.iter().collect::<Vec<_>>();
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &artifacts,
            &[],
            &Sequential
        ),
        vec![true; artifacts.len()]
    );
    assert_eq!(
        wrong_namespace
            .verifier
            .verify_artifacts::<_, Sha256, Digest>(&mut test_rng(), &artifacts, &[], &Sequential),
        vec![false; artifacts.len()]
    );
}

#[test]
fn signatures_are_namespace_bound_for_every_subject_kind() {
    for_each_suite!(signatures_are_namespace_bound);
}

fn schemes_bind_their_epoch<S: Suite>() {
    let committee = Committee::<S>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .limits(PathLimits::new(2, 2))
        .build();
    // The same key material dealt for the next epoch.
    let config = keys::test_config(
        SEED + 1,
        NAMESPACE,
        PARTICIPANTS,
        committee.config.producers().to_vec(),
        PathLimits::new(2, 2),
    );
    let (signers, other) = S::committee(
        &mut TestRng::new(SEED),
        config.parameters(),
        &committee.network_keys,
    );
    let fixture = Fixture::from_committee(committee);
    assert_ne!(config.epoch(), fixture.config.epoch());
    assert_eq!(other.participants(), fixture.verifier.participants());
    let next = signers[0]
        .sign_novote(Round::new(config.epoch(), fixture.round.view()))
        .unwrap();
    assert!(other.verify_novote(&mut test_rng(), &next, &Sequential));
    assert!(
        !fixture
            .verifier
            .verify_novote(&mut test_rng(), &next, &Sequential)
    );
    // The signed message carries the epoch, so a signature replayed into this epoch fails.
    let replayed = NoVote::new(fixture.round, next.attestation().clone()).unwrap();
    assert!(
        !fixture
            .verifier
            .verify_novote(&mut test_rng(), &replayed, &Sequential)
    );
    let replayed_share = Nullify::new(
        fixture.round,
        signers[0]
            .sign_nullify(Round::new(config.epoch(), fixture.round.view()))
            .unwrap()
            .attestation()
            .clone(),
    )
    .unwrap();
    assert!(
        !fixture
            .verifier
            .verify_nullify(&mut test_rng(), &replayed_share, &Sequential)
    );

    let artifacts = signed_artifacts(&fixture);
    let artifacts = artifacts.iter().collect::<Vec<_>>();
    assert_eq!(
        other.verify_artifacts::<_, Sha256, Digest>(&mut test_rng(), &artifacts, &[], &Sequential),
        vec![false; artifacts.len()]
    );
}

#[test]
fn schemes_bind_their_epoch_for_every_suite() {
    for_each_suite!(schemes_bind_their_epoch);
}

fn independent_keys_verify_nothing<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let artifacts = signed_artifacts(&fixture);
    let artifacts = artifacts.iter().collect::<Vec<_>>();
    let other = other_verifier(&fixture, 7_777);
    assert_eq!(
        other.verify_artifacts::<_, Sha256, Digest>(&mut test_rng(), &artifacts, &[], &Sequential),
        vec![false; artifacts.len()]
    );
}

#[test]
fn independent_keys_verify_nothing_for_every_suite() {
    for_each_suite!(independent_keys_verify_nothing);
}

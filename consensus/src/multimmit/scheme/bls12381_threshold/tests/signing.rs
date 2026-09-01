//! Signing roles, producer ownership, and domain separation.

use super::*;

fn ordinary_signatures_are_role_and_domain_bound<V: Variant>() {
    let fixture = Fixture::<V>::new();
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
    assert!(fixture.verifier.verify_transaction_block(&block));

    let da_vote = fixture.signers[2].sign_da_vote(header.clone()).unwrap();
    let wrong_key_and_domain = SignedTransactionBlock::new(
        header,
        Attestation::new(da_vote.signer(), da_vote.share().lazy_signature().clone()),
    );
    assert!(
        !fixture
            .verifier
            .verify_transaction_block(&wrong_key_and_domain)
    );

    let leader = fixture.leader(1);
    let scheduled = usize::from(
        LeaderSchedule::round_robin(fixture.codec.participants())
            .unwrap()
            .leader(leader.view()),
    );
    assert_eq!(
        fixture.signers[(scheduled + 1) % fixture.signers.len()]
            .sign_leader_block(leader.clone())
            .unwrap_err(),
        Error::Signer
    );
    let signed = fixture.signers[scheduled]
        .sign_leader_block(leader.clone())
        .unwrap();
    assert!(fixture.verifier.verify_leader_block(&signed, &Sequential));

    let vote = fixture.signers[0]
        .sign_vote(fixture.standard_body(&leader))
        .unwrap();
    let novote = fixture.signers[1].sign_novote(fixture.round).unwrap();
    assert!(fixture.verifier.verify_vote(&vote));
    assert!(fixture.verifier.verify_novote(&novote));
}

#[test]
fn ordinary_signatures_are_role_and_domain_bound_for_both_variants() {
    ordinary_signatures_are_role_and_domain_bound::<MinPk>();
    ordinary_signatures_are_role_and_domain_bound::<MinSig>();
}

fn producer_ownership_is_independent_of_participant_index<V: Variant>() {
    let producers = vec![Participant::new(1), Participant::new(4)];
    let fixture = Fixture::<V>::with_producers(producers);

    let first = fixture.header(0, 401);
    assert_eq!(
        fixture.signers[0]
            .sign_transaction_block(first.clone())
            .unwrap_err(),
        Error::Signer
    );
    let first = fixture.signers[1].sign_transaction_block(first).unwrap();
    assert!(fixture.verifier.verify_transaction_block(&first));

    let second = fixture.header(1, 402);
    assert_eq!(
        fixture.signers[1]
            .sign_transaction_block(second.clone())
            .unwrap_err(),
        Error::Signer
    );
    let second = fixture.signers[4].sign_transaction_block(second).unwrap();
    assert!(fixture.verifier.verify_transaction_block(&second));

    let identity = Fixture::<V>::new();
    let wrong_owner = identity.signers[0]
        .sign_transaction_block(fixture.header(0, 403))
        .unwrap();
    assert!(!fixture.verifier.verify_transaction_block(&wrong_owner));
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
    assert!(fixture.verifier.verify_da_vote(&validator_vote));
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
    producer_ownership_is_independent_of_participant_index::<MinPk>();
    producer_ownership_is_independent_of_participant_index::<MinSig>();
}

fn structural_failures_keep_their_source<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let genesis = Round::new(fixture.round.epoch(), View::zero());
    assert_eq!(
        fixture.signers[0].sign_novote(genesis).unwrap_err(),
        Error::Types(TypesError::GenesisView)
    );
    assert_eq!(
        fixture.signers[0].sign_nullify(genesis).unwrap_err(),
        Error::Types(TypesError::GenesisView)
    );
}

#[test]
fn structural_failures_keep_their_source_for_both_variants() {
    structural_failures_keep_their_source::<MinPk>();
    structural_failures_keep_their_source::<MinSig>();
}

fn signatures_are_namespace_bound<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let mut wrong_namespace = fixture.verifier.clone();
    wrong_namespace.namespace = Namespace::new(b"wrong namespace");

    let header = fixture.header(0, 301);
    let transaction = fixture.signers[0]
        .sign_transaction_block(header.clone())
        .unwrap();
    let da_vote = fixture.signers[0].sign_da_vote(header).unwrap();

    let leader = fixture.leader(302);
    let scheduled = usize::from(
        LeaderSchedule::round_robin(fixture.codec.participants())
            .unwrap()
            .leader(leader.view()),
    );
    let signed_leader = fixture.signers[scheduled]
        .sign_leader_block(leader.clone())
        .unwrap();
    let vote = fixture.signers[0]
        .sign_vote(fixture.standard_body(&leader))
        .unwrap();
    let novote = fixture.signers[0].sign_novote(fixture.round).unwrap();
    let nullify = fixture.signers[0].sign_nullify(fixture.round).unwrap();

    assert!(!wrong_namespace.verify_transaction_block(&transaction));
    assert!(!wrong_namespace.verify_da_vote(&da_vote));
    assert!(!wrong_namespace.verify_leader_block(&signed_leader, &Sequential));
    assert!(!wrong_namespace.verify_vote(&vote));
    assert!(!wrong_namespace.verify_novote(&novote));
    assert!(!wrong_namespace.verify_nullify(&nullify));
}

#[test]
fn signatures_are_namespace_bound_for_every_subject_kind() {
    signatures_are_namespace_bound::<MinPk>();
    signatures_are_namespace_bound::<MinSig>();
}

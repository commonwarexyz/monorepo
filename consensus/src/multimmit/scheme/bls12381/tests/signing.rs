//! Signing roles, producer ownership, epoch binding, and domain separation.

use super::*;

/// Returns `committee`'s first header on `chain`.
fn header<V: Variant>(
    committee: &Committee<V>,
    chain: u32,
    marker: u64,
) -> TransactionBlockHeader<Digest> {
    committee.header(
        &committee.genesis().tips()[chain as usize],
        keys::digest(b"body", marker),
    )
}

fn signing_roles_follow_the_configuration<V: Variant>() {
    let committee = test_committee::<V>();
    let header = header(&committee, 2, 1);
    assert_eq!(
        committee.signers[0]
            .sign_transaction_block(header.clone())
            .unwrap_err(),
        Error::Signer
    );
    let block = committee.sign_header(header);
    assert!(committee.verifier.verify_transaction_block(&block));

    let view = View::new(4);
    let scheduled = usize::from(committee.config.leader(view));
    let leader = committee.leader_block(view);
    assert!(committee.verifier.verify_leader_block(&leader));
    assert_eq!(
        committee.signers[(scheduled + 1) % committee.signers.len()]
            .sign_leader_block(leader.block().clone())
            .unwrap_err(),
        Error::Signer
    );

    let content = varied(
        &committee,
        view,
        Some(leader.block().digest::<Sha256>()),
        false,
        2,
    );
    let attestation = committee.sign_vote(Participant::new(5), &content);
    assert!(committee.verifier.verify_vote(&content, &attestation));
    let relabeled = Attestation::new(Participant::new(4), attestation.lazy_signature().clone());
    assert!(!committee.verifier.verify_vote(&content, &relabeled));
    let mutated = varied(
        &committee,
        view,
        Some(leader.block().digest::<Sha256>()),
        true,
        2,
    );
    assert!(!committee.verifier.verify_vote(&mutated, &attestation));
}

both_variants!(
    signing_roles_follow_the_configuration_for_both_variants,
    signing_roles_follow_the_configuration
);

fn producer_ownership_is_independent_of_participant_index<V: Variant>() {
    let committee = Committee::<V>::builder(SEED, PARTICIPANTS)
        .namespace(NAMESPACE)
        .producers(vec![Participant::new(1), Participant::new(4)])
        .build();
    let first = header(&committee, 0, 401);
    assert_eq!(
        committee.signers[0]
            .sign_transaction_block(first.clone())
            .unwrap_err(),
        Error::Signer
    );
    let first = committee.signers[1].sign_transaction_block(first).unwrap();
    assert!(committee.verifier.verify_transaction_block(&first));
    let second = committee.signers[4]
        .sign_transaction_block(header(&committee, 1, 402))
        .unwrap();
    assert!(committee.verifier.verify_transaction_block(&second));

    // Participant 0 owns chain 0 in the identity assignment but not here.
    let identity = test_committee::<V>();
    let wrong_owner = identity.sign_header(header(&identity, 0, 403));
    assert!(!committee.verifier.verify_transaction_block(&wrong_owner));

    let outside = TransactionBlockHeader::new(
        committee.config.epoch(),
        ChainId::new(2),
        Height::new(1),
        keys::digest(b"parent", 0),
        keys::digest(b"body", 0),
    )
    .unwrap();
    assert_eq!(
        committee.signers[4]
            .sign_transaction_block(outside)
            .unwrap_err(),
        Error::Chain
    );
}

both_variants!(
    producer_ownership_is_independent_of_participant_index_for_both_variants,
    producer_ownership_is_independent_of_participant_index
);

fn signatures_bind_their_epoch<V: Variant>() {
    let committee = test_committee::<V>();
    let other = Committee::<V>::builder(SEED + 1, PARTICIPANTS)
        .namespace(NAMESPACE)
        .build();
    let foreign = varied(&other, View::new(1), None, false, 0);
    assert_eq!(
        committee.signers[0].sign_vote(&foreign).unwrap_err(),
        Error::Context
    );

    // A valid signature by a roster key over another epoch's objects is still rejected.
    let private = &committee.privates[0];
    let namespace = Namespace::new(NAMESPACE);
    let foreign_header = header(&other, 0, 1);
    let subject = Subject::transaction_block(&foreign_header);
    let signature =
        ops::sign_message::<V>(private, subject.namespace(&namespace), &subject.message());
    let block = SignedTransactionBlock::new(
        foreign_header,
        Attestation::new(Participant::new(0), signature.into()),
    );
    assert!(!committee.verifier.verify_transaction_block(&block));
    let subject = Subject::vote(&foreign);
    let signature =
        ops::sign_message::<V>(private, subject.namespace(&namespace), &subject.message());
    assert!(!committee.verifier.verify_vote(
        &foreign,
        &Attestation::new(Participant::new(0), signature.into())
    ));
}

both_variants!(
    signatures_bind_their_epoch_for_both_variants,
    signatures_bind_their_epoch
);

fn subject_kinds_are_domain_separated<V: Variant>() {
    let committee = test_committee::<V>();
    let namespace = Namespace::new(NAMESPACE);
    let view = View::new(1);
    let leader = committee.leader_block(view);
    let signer = committee.config.leader(view);
    let private = &committee.privates[usize::from(signer)];
    let header = committee.header(
        &committee.genesis().tips()[usize::from(signer)],
        keys::digest(b"body", 7),
    );
    let content = varied(&committee, view, None, false, 1);

    // Sign each object's canonical encoding under every subject namespace: only its own kind's
    // namespace verifies.
    let namespaces = [
        &namespace.transaction_block,
        &namespace.leader_block,
        &namespace.vote,
        &namespace.proof_of_possession,
    ];
    for (own, signed) in namespaces.iter().enumerate() {
        let sign = |message: &[u8]| {
            Attestation::<V>::new(
                signer,
                ops::sign_message::<V>(private, signed, message).into(),
            )
        };
        let block = SignedTransactionBlock::new(header.clone(), sign(&header.encode()));
        assert_eq!(
            committee.verifier.verify_transaction_block(&block),
            own == 0
        );
        let block = SignedLeaderBlock::new(leader.block().clone(), sign(&leader.block().encode()));
        assert_eq!(committee.verifier.verify_leader_block(&block), own == 1);
        let attestation = sign(&content.encode());
        assert_eq!(
            committee.verifier.verify_vote(&content, &attestation),
            own == 2
        );
    }
}

both_variants!(
    subject_kinds_are_domain_separated_for_both_variants,
    subject_kinds_are_domain_separated
);

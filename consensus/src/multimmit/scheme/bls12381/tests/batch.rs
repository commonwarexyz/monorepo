//! Batch verification isolates invalid items and agrees with individual verification.

use super::*;

fn batch_isolates_invalid_items<V: Variant>() {
    let committee = test_committee::<V>();
    let verifier = &committee.verifier;
    let view = View::new(3);

    let header = committee
        .sign_header(committee.header(&committee.genesis().tips()[1], keys::digest(b"body", 1)));
    let stolen = SignedTransactionBlock::new(
        committee.header(&committee.genesis().tips()[2], keys::digest(b"body", 2)),
        header.attestation().clone(),
    );
    let leader = committee.leader_block(view);
    let unscheduled = SignedLeaderBlock::new(
        leader.block().clone(),
        committee.leader_block(View::new(4)).attestation().clone(),
    );
    let content = varied(
        &committee,
        view,
        Some(leader.block().digest::<Sha256>()),
        false,
        1,
    );
    let attestation = committee.sign_vote(Participant::new(3), &content);
    let mutated = varied(&committee, view, None, false, 1);
    let vqc = committee.vqc_from(
        committee.genesis().vqc(),
        mixed_finals(&committee, view),
        Vec::new(),
    );
    let forged_vqc = Vqc::new(
        vqc.round(),
        vqc.parent(),
        vqc.tally().clone(),
        committee.vqc(view).signature().unwrap().clone(),
        committee.codec(),
    )
    .unwrap();
    let lqc = committee.lqc(view);
    let forged_lqc = Lqc::new(
        lqc.leader().clone(),
        lqc.tally().clone(),
        committee.lqc(View::new(4)).signature().unwrap().clone(),
    );

    let items = [
        Signed::TransactionBlock(&header),
        Signed::TransactionBlock(&stolen),
        Signed::LeaderBlock(&leader),
        Signed::LeaderBlock(&unscheduled),
        Signed::Vote {
            content: &content,
            attestation: &attestation,
        },
        Signed::Vote {
            content: &mutated,
            attestation: &attestation,
        },
        Signed::Vqc(&vqc),
        Signed::Vqc(&forged_vqc),
        Signed::Lqc(&lqc),
        Signed::Lqc(&forged_lqc),
    ];
    let expected = vec![
        Verdict::Valid,
        Verdict::Invalid,
        Verdict::Valid,
        Verdict::Invalid,
        Verdict::Valid,
        Verdict::Invalid,
        Verdict::Certificate(vqc.contents()),
        Verdict::Invalid,
        Verdict::Certificate(lqc.contents::<Sha256>()),
        Verdict::Invalid,
    ];

    // Individual verifiers agree with the expected verdicts.
    let mut rng = test_rng();
    let individual = [
        verifier.verify_transaction_block(&header),
        verifier.verify_transaction_block(&stolen),
        verifier.verify_leader_block(&leader),
        verifier.verify_leader_block(&unscheduled),
        verifier.verify_vote(&content, &attestation),
        verifier.verify_vote(&mutated, &attestation),
        verifier.verify_vqc(&mut rng, &vqc, &Sequential),
        verifier.verify_vqc(&mut rng, &forged_vqc, &Sequential),
        verifier.verify_lqc::<_, Sha256, _>(&mut rng, &lqc, &Sequential),
        verifier.verify_lqc::<_, Sha256, _>(&mut rng, &forged_lqc, &Sequential),
    ];
    assert_eq!(
        individual.to_vec(),
        expected.iter().map(Verdict::is_valid).collect::<Vec<_>>()
    );

    // The batch isolates every invalid item, sequentially and in parallel, and an all-valid or
    // all-invalid subset keeps its verdicts.
    let parallel = Rayon::new(NZUsize!(4)).unwrap();
    assert_eq!(
        verifier.verify_batch::<_, Sha256, _>(&mut rng, &items, &Sequential),
        expected
    );
    assert_eq!(
        verifier.verify_batch::<_, Sha256, _>(&mut rng, &items, &parallel),
        expected
    );
    for parity in [0, 1] {
        let subset: Vec<_> = items.iter().copied().skip(parity).step_by(2).collect();
        let verdicts: Vec<_> = expected.iter().skip(parity).step_by(2).cloned().collect();
        assert_eq!(
            verifier.verify_batch::<_, Sha256, _>(&mut rng, &subset, &Sequential),
            verdicts
        );
    }
    assert!(
        verifier
            .verify_batch::<_, Sha256, _>(&mut rng, &[], &Sequential)
            .is_empty()
    );
}

both_variants!(
    batch_isolates_invalid_items_for_both_variants,
    batch_isolates_invalid_items
);

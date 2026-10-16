//! Tally aggregates and V-QC / L-QC assembly and verification.

use super::*;

fn tally_aggregate_accepts_only_the_exact_transcript<V: Variant>() {
    let committee = test_committee::<V>();
    let verifier = &committee.verifier;
    let mut rng = test_rng();
    let view = View::new(3);
    let contents = mixed_finals(&committee, view);
    let signature = aggregate_of(&committee, &contents);
    assert!(verifier.verify_tally(&mut rng, &contents, &signature, &Sequential));

    // Agreeing voters share one subject.
    let agreeing: Vec<_> = contents
        .iter()
        .map(|(signer, _)| (*signer, contents[0].1.clone()))
        .collect();
    assert!(verifier.verify_tally(
        &mut rng,
        &agreeing,
        &aggregate_of(&committee, &agreeing),
        &Sequential
    ));

    // Wrong signer: the same contents attributed to a participant outside the quorum.
    let mut relabeled = contents.clone();
    relabeled[0].0 = Participant::from_usize(committee.codec().view_quorum());
    assert!(!verifier.verify_tally(&mut rng, &relabeled, &signature, &Sequential));

    // Mutated content.
    let mut mutated = contents.clone();
    mutated[1].1 = varied(&committee, view, None, true, 4);
    assert!(!verifier.verify_tally(&mut rng, &mutated, &signature, &Sequential));

    // Wrong aggregate: missing one signer, or an unrelated aggregate.
    let partial = aggregate_of(&committee, &contents[1..]);
    assert!(!verifier.verify_tally(&mut rng, &contents, &partial, &Sequential));
    assert!(!verifier.verify_tally(&mut rng, &contents[1..], &signature, &Sequential));
    let other = aggregate_of(&committee, &mixed_finals(&committee, View::new(4)));
    assert!(!verifier.verify_tally(&mut rng, &contents, &other, &Sequential));

    // Mixed contents cannot be swapped between signers.
    let mut swapped = contents.clone();
    let first = swapped[0].1.clone();
    swapped[0].1 = swapped[1].1.clone();
    swapped[1].1 = first;
    assert_ne!(swapped[0].1, contents[0].1);
    assert!(!verifier.verify_tally(&mut rng, &swapped, &signature, &Sequential));

    // Repeated signers, empty transcripts, and the identity aggregate never verify.
    let mut repeated = contents.clone();
    repeated.push(contents[0].clone());
    let repeated_signature = aggregate_of(&committee, &repeated);
    assert!(!verifier.verify_tally(&mut rng, &repeated, &repeated_signature, &Sequential));
    assert!(!verifier.verify_tally::<_, Digest>(&mut rng, &[], &signature, &Sequential));
    let identity = aggregate::Signature::<V>::zero();
    assert!(!verifier.verify_tally(&mut rng, &contents, &identity, &Sequential));
}

both_variants!(
    tally_aggregate_accepts_only_the_exact_transcript_for_both_variants,
    tally_aggregate_accepts_only_the_exact_transcript
);

fn vqc_assembly_and_verification<V: Variant>() {
    let committee = test_committee::<V>();
    let verifier = &committee.verifier;
    let mut rng = test_rng();
    let view = View::new(5);
    let contents = mixed_finals(&committee, view);
    let parent = committee.genesis().vqc();
    let mut votes = attest(&committee, &contents);
    let vqc = verifier
        .assemble_vqc(
            &mut rng,
            parent,
            &votes,
            Vec::new(),
            SignatureVerification::Checked,
            &Sequential,
        )
        .unwrap();
    assert_eq!(vqc.round(), committee.round(view));
    assert_eq!(vqc.contents(), contents);
    assert!(verifier.verify_vqc(&mut rng, &vqc, &Sequential));
    assert_eq!(
        vqc,
        committee.vqc_from(parent, contents.clone(), Vec::new())
    );

    // A non-final vote is not a V-QC entry; a short quorum is not a V-QC.
    let mut pre_vote = contents;
    pre_vote[0].1 = varied(&committee, view, None, false, 0);
    assert!(
        verifier
            .assemble_vqc(
                &mut rng,
                parent,
                &attest(&committee, &pre_vote),
                Vec::new(),
                SignatureVerification::Checked,
                &Sequential,
            )
            .is_err()
    );
    assert!(
        verifier
            .assemble_vqc(
                &mut rng,
                parent,
                &votes[1..],
                Vec::new(),
                SignatureVerification::Checked,
                &Sequential,
            )
            .is_err()
    );

    // An attestation over other content fails a checked assembly; an unchecked one assembles a
    // certificate that never verifies.
    votes[2].1 = committee.sign_vote(votes[2].1.signer(), &votes[0].0);
    assert_eq!(
        verifier
            .assemble_vqc(
                &mut rng,
                parent,
                &votes,
                Vec::new(),
                SignatureVerification::Checked,
                &Sequential,
            )
            .unwrap_err(),
        Error::Signature
    );
    let unchecked = verifier
        .assemble_vqc(
            &mut rng,
            parent,
            &votes,
            Vec::new(),
            SignatureVerification::Preverified,
            &Sequential,
        )
        .unwrap();
    assert!(!verifier.verify_vqc(&mut rng, &unchecked, &Sequential));

    // The aggregate binds the tally and round; another epoch's verifier rejects it.
    let donor = committee.vqc(view);
    let forged = Vqc::new(
        vqc.round(),
        vqc.parent(),
        vqc.tally().clone(),
        donor.signature().unwrap().clone(),
        committee.codec(),
    )
    .unwrap();
    assert!(!verifier.verify_vqc(&mut rng, &forged, &Sequential));
    let moved = Vqc::new(
        committee.round(View::new(6)),
        vqc.parent(),
        vqc.tally().clone(),
        vqc.signature().unwrap().clone(),
        committee.codec(),
    )
    .unwrap();
    assert!(!verifier.verify_vqc(&mut rng, &moved, &Sequential));
    let other = Committee::<V>::builder(SEED + 1, PARTICIPANTS)
        .namespace(NAMESPACE)
        .build();
    assert!(!other.verifier.verify_vqc(&mut rng, &vqc, &Sequential));
}

both_variants!(
    vqc_assembly_and_verification_for_both_variants,
    vqc_assembly_and_verification
);

fn lqc_assembly_and_verification<V: Variant>() {
    let committee = test_committee::<V>();
    let verifier = &committee.verifier;
    let mut rng = test_rng();
    let view = View::new(2);
    let leader = committee.leader_block(view).block().clone();
    let digest = leader.digest::<Sha256>();
    let contents: Vec<_> = (0..committee.codec().view_quorum())
        .map(|index| {
            (
                Participant::from_usize(index),
                varied(&committee, view, Some(digest), index % 2 == 0, index as u64),
            )
        })
        .collect();
    let votes = attest(&committee, &contents);
    let lqc = verifier
        .assemble_lqc::<_, Sha256, _>(
            &mut rng,
            leader.clone(),
            &votes,
            SignatureVerification::Checked,
            &Sequential,
        )
        .unwrap();
    assert_eq!(lqc.contents::<Sha256>(), contents);
    assert!(verifier.verify_lqc::<_, Sha256, _>(&mut rng, &lqc, &Sequential));

    // Votes for another leader block or view do not form this L-QC.
    let other = committee
        .leader_block_with(view, committee.genesis().vqc(), keys::digest(b"history", 1))
        .block()
        .clone();
    assert!(
        verifier
            .assemble_lqc::<_, Sha256, _>(
                &mut rng,
                other.clone(),
                &votes,
                SignatureVerification::Checked,
                &Sequential,
            )
            .is_err()
    );
    let later = committee.leader_block(View::new(3)).block().clone();
    assert_eq!(
        verifier
            .assemble_lqc::<_, Sha256, _>(
                &mut rng,
                later,
                &votes,
                SignatureVerification::Checked,
                &Sequential,
            )
            .unwrap_err(),
        Error::Transcript
    );

    // The aggregate binds the leader block.
    let moved = Lqc::new(other, lqc.tally().clone(), lqc.signature().unwrap().clone());
    assert!(!verifier.verify_lqc::<_, Sha256, _>(&mut rng, &moved, &Sequential));
    let donor = committee.lqc(view);
    let forged = Lqc::new(
        leader,
        lqc.tally().clone(),
        donor.signature().unwrap().clone(),
    );
    assert!(!verifier.verify_lqc::<_, Sha256, _>(&mut rng, &forged, &Sequential));
}

both_variants!(
    lqc_assembly_and_verification_for_both_variants,
    lqc_assembly_and_verification
);

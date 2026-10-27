//! Batch verification verdicts and known-message discharge.

use super::*;

fn artifact_batch_returns_per_item_verdicts<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let header = fixture.header(0, 90);
    let valid = fixture.signers[0]
        .sign_transaction_block(header.clone())
        .unwrap();
    let invalid = SignedTransactionBlock::new(
        header,
        Attestation::new(Participant::new(0), Lazy::from(V::Signature::zero())),
    );
    let artifacts = [
        &Artifact::TransactionBlock(valid),
        &Artifact::TransactionBlock(invalid),
    ];

    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &artifacts,
            &[],
            &Sequential
        ),
        vec![true, false],
    );
    let parallel = Rayon::new(NZUsize!(4)).unwrap();
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &artifacts,
            &[],
            &parallel
        ),
        vec![true, false],
    );
}

#[test]
fn artifact_batches_isolate_invalid_items_for_both_variants() {
    artifact_batch_returns_per_item_verdicts::<MinPk>();
    artifact_batch_returns_per_item_verdicts::<MinSig>();
}

/// Artifacts with their individual and expected verdicts, in the same order.
struct Cohort<V: Variant> {
    artifacts: Vec<Artifact<V, Digest>>,
    individual: Vec<bool>,
    expected: Vec<bool>,
}

impl<V: Variant> Cohort<V> {
    /// Checks that batched verification, sequential and parallel, reaches the same verdicts as
    /// the individual verifiers.
    ///
    /// Both paths share the claim builders but check pairings differently: one randomly scaled
    /// product for the batch versus one pairing per claim.
    fn assert_batch_matches_individual(&self, verifier: &Scheme<Ed25519PublicKey, V>) {
        assert_eq!(
            self.individual, self.expected,
            "individual verdicts changed"
        );
        let artifacts = self.artifacts.iter().collect::<Vec<_>>();
        assert_expanded_artifacts(verifier, &artifacts, &[], &self.expected);
        assert_eq!(
            verifier.verify_artifacts::<_, Sha256, Digest>(
                &mut test_rng(),
                &artifacts,
                &[],
                &Sequential
            ),
            self.expected,
            "batched verdicts diverge from individual verification"
        );
        let parallel = Rayon::new(NZUsize!(4)).unwrap();
        assert_eq!(
            verifier.verify_artifacts::<_, Sha256, Digest>(
                &mut test_rng(),
                &artifacts,
                &[],
                &parallel
            ),
            self.expected,
            "parallel batched verdicts diverge from individual verification"
        );
    }
}

/// Builds one valid and, where a forgery exists, one invalid artifact of every signed-message
/// kind.
fn signed_message_cohort<V: Variant>(fixture: &Fixture<V>) -> Cohort<V> {
    let verifier = &fixture.verifier;

    let transaction = fixture.signers[0]
        .sign_transaction_block(fixture.header(0, 90))
        .unwrap();
    let bad_transaction = SignedTransactionBlock::new(
        fixture.header(0, 91),
        Attestation::new(Participant::new(0), Lazy::from(V::Signature::zero())),
    );

    let da_vote = fixture.signers[0]
        .sign_da_vote(fixture.header(1, 92))
        .unwrap();
    // A share moved under a different header signs the wrong message.
    let bad_da_vote = DaVote::new(
        fixture.header(1, 93),
        fixture.signers[1]
            .sign_da_vote(fixture.header(1, 92))
            .unwrap()
            .share()
            .clone(),
    );

    let leader = fixture.leader(95);
    let scheduled = usize::from(
        LeaderSchedule::round_robin(fixture.codec.participants())
            .unwrap()
            .leader(leader.view()),
    );
    let signed_leader = fixture.signers[scheduled]
        .sign_leader_block(leader.clone())
        .unwrap();
    let bad_leader = SignedLeaderBlock::new(
        leader.clone(),
        Attestation::new(
            Participant::new(scheduled as u32),
            Lazy::from(V::Signature::zero()),
        ),
    );

    let vote = fixture.signers[0]
        .sign_vote(fixture.standard_body(&leader))
        .unwrap();
    // A valid attestation over a different body no longer matches its message.
    let bad_vote = Vote::new(
        fixture.body(
            &leader,
            vec![0; PARTICIPANTS as usize],
            vec![Vec::new(); PARTICIPANTS as usize],
        ),
        fixture.signers[1]
            .sign_vote(fixture.standard_body(&leader))
            .unwrap()
            .attestation()
            .clone(),
    );

    let novote = fixture.signers[1].sign_novote(fixture.round).unwrap();
    let nullify = fixture.signers[2].sign_nullify(fixture.round).unwrap();
    let wrong_round = Round::new(
        fixture.round.epoch(),
        View::new(fixture.round.view().get() + 1),
    );
    let bad_nullify = Nullify::new(wrong_round, nullify.share().clone()).unwrap();

    let artifacts = vec![
        Artifact::TransactionBlock(transaction.clone()),
        Artifact::TransactionBlock(bad_transaction.clone()),
        Artifact::DaVote(da_vote.clone()),
        Artifact::DaVote(bad_da_vote.clone()),
        Artifact::LeaderBlock(signed_leader.clone()),
        Artifact::LeaderBlock(bad_leader.clone()),
        Artifact::Vote(vote.clone()),
        Artifact::Vote(bad_vote.clone()),
        Artifact::NoVote(novote.clone()),
        Artifact::Nullify(nullify.clone()),
        Artifact::Nullify(bad_nullify.clone()),
    ];
    let individual = vec![
        verifier.verify_transaction_block(&transaction),
        verifier.verify_transaction_block(&bad_transaction),
        verifier.verify_da_vote(&da_vote),
        verifier.verify_da_vote(&bad_da_vote),
        verifier.verify_leader_block(&signed_leader, &Sequential),
        verifier.verify_leader_block(&bad_leader, &Sequential),
        verifier.verify_vote(&vote),
        verifier.verify_vote(&bad_vote),
        verifier.verify_novote(&novote),
        verifier.verify_nullify(&nullify),
        verifier.verify_nullify(&bad_nullify),
    ];
    // The cohort exercises both outcomes for every kind that has a forgery.
    let expected = vec![
        true, false, true, false, true, false, true, false, true, true, false,
    ];
    Cohort {
        artifacts,
        individual,
        expected,
    }
}

fn batched_verdicts_match_for_signed_messages<V: Variant>() {
    let fixture = Fixture::<V>::new();
    signed_message_cohort(&fixture).assert_batch_matches_individual(&fixture.verifier);
}

#[test]
fn batched_verdicts_match_for_signed_messages_for_both_variants() {
    batched_verdicts_match_for_signed_messages::<MinPk>();
    batched_verdicts_match_for_signed_messages::<MinSig>();
}

/// Builds one valid and one invalid certificate of every kind.
fn certificate_cohort<V: Variant>(fixture: &Fixture<V>) -> Cohort<V> {
    let verifier = &fixture.verifier;

    let da_votes = fixture
        .signers
        .iter()
        .map(|signer| signer.sign_da_vote(fixture.header(1, 92)).unwrap())
        .collect::<Vec<_>>();
    let da_certificate = verifier
        .assemble_da_certificate(&da_votes[..fixture.codec.da_quorum()], &Sequential)
        .unwrap();
    let bad_da_certificate =
        DaCertificate::new(fixture.header(1, 94), da_certificate.certificate().clone());

    let nullifies = fixture
        .signers
        .iter()
        .map(|signer| signer.sign_nullify(fixture.round).unwrap())
        .collect::<Vec<_>>();
    let nullification = verifier
        .assemble_nullification(
            &nullifies[..fixture.codec.nullification_quorum()],
            &Sequential,
        )
        .unwrap();
    let wrong_round = Round::new(
        fixture.round.epoch(),
        View::new(fixture.round.view().get() + 1),
    );
    let bad_nullification =
        Nullification::new(wrong_round, nullification.certificate().clone()).unwrap();

    let leader = fixture.leader(95);
    let quorum_votes = (0..fixture.codec.view_quorum())
        .map(|index| {
            fixture.signers[index]
                .sign_vote(fixture.standard_body(&leader))
                .unwrap()
        })
        .collect::<Vec<_>>();
    let lqc = verifier
        .assemble_lqc::<Sha256, _>(leader.clone(), &quorum_votes, &Sequential)
        .unwrap();
    let vqc = verifier
        .assemble_vqc::<Sha256, _>(
            leader,
            &quorum_votes
                .iter()
                .cloned()
                .map(ViewMessage::Vote)
                .collect::<Vec<_>>(),
            &Sequential,
        )
        .unwrap();
    // Aggregate signatures decode lazily, so a certificate with a corrupted signature
    // round-trips the codec and fails only at verification.
    let bad_vqc = {
        let mut encoded = vqc.encode().to_vec();
        *encoded.last_mut().unwrap() ^= 0x01;
        Vqc::<V, Digest>::decode_cfg(encoded, &fixture.codec)
            .expect("a tampered aggregate signature still decodes")
    };
    let bad_lqc = {
        let mut encoded = lqc.encode().to_vec();
        *encoded.last_mut().unwrap() ^= 0x01;
        Lqc::<V, Digest>::decode_cfg(encoded, &fixture.codec)
            .expect("a tampered aggregate signature still decodes")
    };

    let artifacts = vec![
        Artifact::DaCertificate(da_certificate.clone()),
        Artifact::DaCertificate(bad_da_certificate.clone()),
        Artifact::Nullification(nullification.clone()),
        Artifact::Nullification(bad_nullification.clone()),
        Artifact::Vqc(vqc.clone()),
        Artifact::Vqc(bad_vqc.clone()),
        Artifact::Lqc(lqc.clone()),
        Artifact::Lqc(bad_lqc.clone()),
    ];
    let individual = vec![
        verifier.verify_da_certificate(&da_certificate),
        verifier.verify_da_certificate(&bad_da_certificate),
        verifier.verify_nullification(&nullification),
        verifier.verify_nullification(&bad_nullification),
        verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &vqc, &Sequential)
            .is_some(),
        verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &bad_vqc, &Sequential)
            .is_some(),
        verifier
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &lqc, &Sequential)
            .is_some(),
        verifier
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &bad_lqc, &Sequential)
            .is_some(),
    ];
    let expected = vec![true, false, true, false, true, false, true, false];
    Cohort {
        artifacts,
        individual,
        expected,
    }
}

fn batched_verdicts_match_for_certificates<V: Variant>() {
    let fixture = Fixture::<V>::new();
    certificate_cohort(&fixture).assert_batch_matches_individual(&fixture.verifier);
}

#[test]
fn batched_verdicts_match_for_certificates_for_both_variants() {
    batched_verdicts_match_for_certificates::<MinPk>();
    batched_verdicts_match_for_certificates::<MinSig>();
}

fn batched_verdicts_match_for_every_artifact_kind<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let mut cohort = signed_message_cohort(&fixture);
    let certificates = certificate_cohort(&fixture);
    cohort.artifacts.extend(certificates.artifacts);
    cohort.individual.extend(certificates.individual);
    cohort.expected.extend(certificates.expected);
    cohort.assert_batch_matches_individual(&fixture.verifier);
}

#[test]
fn batched_verdicts_match_for_every_artifact_kind_for_both_variants() {
    batched_verdicts_match_for_every_artifact_kind::<MinPk>();
    batched_verdicts_match_for_every_artifact_kind::<MinSig>();
}

fn known_da_certificates_discharge_only_matching_anchors<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let certify = |marker: u64| {
        let header = fixture.header(0, marker);
        let votes = fixture
            .signers
            .iter()
            .take(fixture.codec.da_quorum())
            .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
            .collect::<Vec<_>>();
        fixture
            .verifier
            .assemble_da_certificate(&votes, &Sequential)
            .unwrap()
    };
    let certificate = certify(501);
    let other_header = certify(502);
    // A certificate whose signature belongs to another header is a forgery for this one.
    let forged = DaCertificate::new(
        certificate.header().clone(),
        other_header.certificate().clone(),
    );
    let anchored = |anchor: DaCertificate<V, Digest>| {
        let proposals = fixture
            .tips
            .iter()
            .enumerate()
            .map(|(index, tip)| {
                let anchor = if index == 0 {
                    Anchor::Certificate(anchor.clone())
                } else {
                    Anchor::Tip(*tip)
                };
                ChainProposal::new(
                    ChainId::new(index as u32),
                    anchor,
                    Vec::new(),
                    fixture.codec.pipeline_depth(),
                )
                .unwrap()
            })
            .collect();
        let leader = LeaderBlock::new(
            fixture.round,
            CertificateId::new(digest(b"parent vqc", 701)),
            digest(b"history", 701),
            proposals,
            fixture.codec,
        )
        .unwrap();
        let scheduled = usize::from(
            LeaderSchedule::round_robin(fixture.codec.participants())
                .unwrap()
                .leader(leader.view()),
        );
        fixture.signers[scheduled]
            .sign_leader_block(leader)
            .unwrap()
    };
    let valid = anchored(certificate.clone());
    let invalid = anchored(forged);

    let artifacts = [
        &Artifact::LeaderBlock(valid.clone()),
        &Artifact::LeaderBlock(valid),
        &Artifact::LeaderBlock(invalid.clone()),
        &Artifact::LeaderBlock(invalid),
    ];
    let held: [&[Verified<'_, V, Digest>]; 4] = [
        // The exact anchor is held, so it costs no pairing.
        &[Verified::DaCertificate(&certificate)],
        // A certificate for another header matches nothing and the anchor is verified.
        &[Verified::DaCertificate(&other_header)],
        // Holding the genuine certificate never excuses a different one for the same header.
        &[Verified::DaCertificate(&certificate)],
        &[],
    ];
    let verdicts = fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
        &mut test_rng(),
        &artifacts,
        &held,
        &Sequential,
    );
    assert_eq!(verdicts, [true, true, false, false]);
    let baseline = fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
        &mut test_rng(),
        &artifacts,
        &[],
        &Sequential,
    );
    assert_eq!(
        baseline, verdicts,
        "held certificates must never change a verdict"
    );
}

#[test]
fn known_da_certificates_discharge_only_matching_anchors_for_both_variants() {
    known_da_certificates_discharge_only_matching_anchors::<MinPk>();
    known_da_certificates_discharge_only_matching_anchors::<MinSig>();
}

#[test]
fn known_messages_discharge_certificate_transcripts_for_both_variants() {
    known_messages_discharge_certificate_transcripts::<MinPk>();
    known_messages_discharge_certificate_transcripts::<MinSig>();
}

fn known_messages_discharge_certificate_transcripts<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let verifier = &fixture.verifier;
    let leader = fixture.leader(7);
    let quorum = fixture.codec.view_quorum();
    let votes = (0..quorum)
        .map(|index| {
            fixture.signers[index]
                .sign_vote(fixture.standard_body(&leader))
                .unwrap()
        })
        .collect::<Vec<_>>();
    // The last quorum member abstains in the V-QC, so both message kinds are covered.
    let novote = fixture.signers[quorum - 1]
        .sign_novote(fixture.round)
        .unwrap();
    let mut messages = votes[..quorum - 1]
        .iter()
        .cloned()
        .map(ViewMessage::Vote)
        .collect::<Vec<_>>();
    messages.push(ViewMessage::NoVote(novote.clone()));
    let vqc = verifier
        .assemble_vqc::<Sha256, _>(leader.clone(), &messages, &Sequential)
        .unwrap();
    let lqc = verifier
        .assemble_lqc::<Sha256, _>(leader.clone(), &votes, &Sequential)
        .unwrap();
    let bad_vqc = {
        let mut encoded = vqc.encode().to_vec();
        *encoded.last_mut().unwrap() ^= 0x01;
        Vqc::<V, Digest>::decode_cfg(encoded, &fixture.codec).unwrap()
    };
    let bad_lqc = {
        let mut encoded = lqc.encode().to_vec();
        *encoded.last_mut().unwrap() ^= 0x01;
        Lqc::<V, Digest>::decode_cfg(encoded, &fixture.codec).unwrap()
    };
    let all_known = votes
        .iter()
        .map(Verified::Vote)
        .chain(std::iter::once(Verified::NoVote(&novote)))
        .collect::<Vec<_>>();
    let half_known = all_known[..quorum / 2].to_vec();
    // A signer's vote for another proposal reproduces no transcript term and falls back to
    // pairing instead of corrupting the remainder.
    let other_leader = fixture.leader(8);
    let mismatched = fixture.signers[0]
        .sign_vote(fixture.standard_body(&other_leader))
        .unwrap();
    let mut mismatched_known = all_known.clone();
    mismatched_known[0] = Verified::Vote(&mismatched);
    // A signer outside the transcript is ignored.
    let stranger = fixture.signers[quorum]
        .sign_vote(fixture.standard_body(&leader))
        .unwrap();
    let mut with_stranger = all_known.clone();
    with_stranger.push(Verified::Vote(&stranger));

    let artifacts = [
        &Artifact::Vqc(vqc.clone()),
        &Artifact::Lqc(lqc.clone()),
        &Artifact::Vqc(bad_vqc),
        &Artifact::Lqc(bad_lqc),
        &Artifact::Vqc(vqc.clone()),
        &Artifact::Lqc(lqc.clone()),
        &Artifact::Vqc(vqc.clone()),
        &Artifact::Lqc(lqc),
        &Artifact::Vqc(vqc),
    ];
    let known: [&[Verified<'_, V, Digest>]; 9] = [
        &all_known,
        &all_known,
        &all_known,
        &all_known,
        &half_known,
        &half_known,
        &mismatched_known,
        &mismatched_known,
        &with_stranger,
    ];
    let verdicts = verifier.verify_artifacts::<_, Sha256, Digest>(
        &mut test_rng(),
        &artifacts,
        &known,
        &Sequential,
    );
    assert_eq!(
        verdicts,
        [true, true, false, false, true, true, true, true, true],
        "known messages must never change a verdict"
    );
    let baseline = verifier.verify_artifacts::<_, Sha256, Digest>(
        &mut test_rng(),
        &artifacts,
        &[],
        &Sequential,
    );
    assert_eq!(baseline, verdicts);
    assert_expanded_artifacts(verifier, &artifacts, &known, &verdicts);
}

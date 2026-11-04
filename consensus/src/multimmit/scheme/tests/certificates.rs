//! V-QC and L-QC assembly and verification.

use super::*;

/// One view's messages: three designated votes with different paths, one conflicting vote for
/// `other`, and one novote.
struct MixedView<S: Suite> {
    leader: LeaderBlock<S, Digest>,
    other: LeaderBlock<S, Digest>,
    designated: Vec<VoteBody<Digest>>,
    messages: Vec<ViewMessage<S, Digest>>,
}

impl<S: Suite> MixedView<S> {
    fn new(fixture: &Fixture<S>) -> Self {
        let leader = fixture.leader(1);
        let other = fixture.leader(2);
        let mut extended = vec![Vec::new(); PARTICIPANTS as usize];
        extended[0] = vec![digest(b"extension", 1)];
        let designated = vec![
            fixture.standard_body(&leader),
            fixture.body(
                &leader,
                vec![0, 1, 1, 1, 1, 1],
                vec![Vec::new(); PARTICIPANTS as usize],
            ),
            fixture.body(&leader, vec![1; PARTICIPANTS as usize], extended),
        ];
        let mut messages = designated
            .iter()
            .enumerate()
            .map(|(index, body)| {
                ViewMessage::Vote(fixture.signers[index].sign_vote(body.clone()).unwrap())
            })
            .collect::<Vec<_>>();
        let conflict = VoteBody::new(
            fixture.round,
            other.digest::<Sha256>(),
            vec![Position::new(0); PARTICIPANTS as usize],
            vec![Extension::empty(); PARTICIPANTS as usize],
            fixture.codec,
        )
        .unwrap();
        messages.push(ViewMessage::Vote(
            fixture.signers[3].sign_vote(conflict).unwrap(),
        ));
        messages.push(ViewMessage::NoVote(
            fixture.signers[4].sign_novote(fixture.round).unwrap(),
        ));
        Self {
            leader,
            other,
            designated,
            messages,
        }
    }
}

fn vqc_carries_designated_conflicting_and_abstaining_messages<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let view = MixedView::new(&fixture);
    let certificate = fixture
        .verifier
        .assemble_vqc::<_, Sha256, _>(
            &mut test_rng(),
            view.leader.clone(),
            &view.messages,
            &Sequential,
        )
        .unwrap();
    let preverified = fixture
        .verifier
        .assemble_vqc_with::<_, Sha256, _>(
            &mut test_rng(),
            view.leader,
            &view.messages,
            SignatureVerification::Preverified,
            &Sequential,
        )
        .unwrap();
    assert_eq!(preverified, certificate);
    assert_expanded_artifacts(
        &fixture.verifier,
        &[&Artifact::Vqc(certificate.clone())],
        &[],
        &[true],
    );
    assert_eq!(certificate.tally().signers().count(), 3);
    assert_eq!(certificate.novoters().count(), 1);
    assert_eq!(certificate.conflicting_votes().len(), 1);
    let id = fixture
        .verifier
        .verify_vqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
        .unwrap();
    assert_eq!(
        id,
        CertificateId::new(Sha256::hash(&[certificate.encode().as_ref()]))
    );
    // A signer can verify certificates too.
    assert!(
        fixture.signers[5]
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
            .is_some()
    );
}

#[test]
fn vqc_carries_designated_conflicting_and_abstaining_messages_for_both_variants() {
    for_each_suite!(vqc_carries_designated_conflicting_and_abstaining_messages);
}

fn vqc_assembly_rejects_overlapping_and_wrong_round_messages<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let view = MixedView::new(&fixture);
    let mut overlapping = view.messages.clone();
    *overlapping.last_mut().unwrap() =
        ViewMessage::NoVote(fixture.signers[0].sign_novote(fixture.round).unwrap());
    for verification in [
        SignatureVerification::Checked,
        SignatureVerification::Preverified,
    ] {
        assert_eq!(
            fixture
                .verifier
                .assemble_vqc_with::<_, Sha256, _>(
                    &mut test_rng(),
                    view.leader.clone(),
                    &overlapping,
                    verification,
                    &Sequential
                )
                .unwrap_err(),
            Error::Signature
        );
    }

    let wrong_round = Round::new(
        fixture.round.epoch(),
        View::new(fixture.round.view().get() + 1),
    );
    let wrong_round_conflict = VoteBody::new(
        wrong_round,
        view.other.digest::<Sha256>(),
        vec![Position::new(0); PARTICIPANTS as usize],
        vec![Extension::empty(); PARTICIPANTS as usize],
        fixture.codec,
    )
    .unwrap();
    let mut wrong_round_messages = view.messages;
    wrong_round_messages[3] =
        ViewMessage::Vote(fixture.signers[3].sign_vote(wrong_round_conflict).unwrap());
    assert_eq!(
        fixture
            .verifier
            .assemble_vqc::<_, Sha256, _>(
                &mut test_rng(),
                view.leader,
                &wrong_round_messages,
                &Sequential
            )
            .unwrap_err(),
        Error::Transcript
    );
}

#[test]
fn vqc_assembly_rejects_overlapping_and_wrong_round_messages_for_both_variants() {
    for_each_suite!(vqc_assembly_rejects_overlapping_and_wrong_round_messages);
}

fn vqc_signature_binds_every_tally_field<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let view = MixedView::new(&fixture);
    let certificate = fixture
        .verifier
        .assemble_vqc::<_, Sha256, _>(
            &mut test_rng(),
            view.leader.clone(),
            &view.messages,
            &Sequential,
        )
        .unwrap();
    let mut mutated = view.designated;
    mutated[0] = fixture.body(
        &view.leader,
        vec![0, 1, 1, 1, 1, 1],
        vec![Vec::new(); PARTICIPANTS as usize],
    );
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&view.leader),
        mutated
            .into_iter()
            .enumerate()
            .map(|(index, body)| (Participant::from_usize(index), body)),
        fixture.codec,
    )
    .unwrap();
    let mutated = Vqc::new(
        view.leader.clone(),
        tally,
        certificate.novoters().clone(),
        certificate.conflicting_votes().to_vec(),
        certificate.signature().clone(),
        fixture.codec,
    )
    .unwrap();
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &mutated, &Sequential)
            .is_none()
    );

    // Moving the abstention to the conflicting voter and back changes who signed what.
    let swapped = Vqc::new(
        view.leader,
        certificate.tally().clone(),
        commonware_cryptography::certificate::Signers::new(PARTICIPANTS, [Participant::new(3)])
            .unwrap(),
        certificate
            .conflicting_votes()
            .iter()
            .map(|vote| {
                crate::multimmit::types::ConflictingVote::new(
                    Participant::new(4),
                    vote.vote_body(fixture.round).unwrap().ballot().clone(),
                    fixture.codec,
                )
                .unwrap()
            })
            .collect(),
        certificate.signature().clone(),
        fixture.codec,
    )
    .unwrap();
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &swapped, &Sequential)
            .is_none()
    );
}

#[test]
fn vqc_signature_binds_every_tally_field_for_both_variants() {
    for_each_suite!(vqc_signature_binds_every_tally_field);
}

fn vqc_accepts_more_than_n_minus_f_messages<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let leader = fixture.leader(1);
    let messages = fixture
        .signers
        .iter()
        .map(|signer| ViewMessage::Vote(signer.sign_vote(fixture.standard_body(&leader)).unwrap()))
        .collect::<Vec<_>>();
    assert!(messages.len() > fixture.codec.view_quorum());

    let certificate = fixture
        .verifier
        .assemble_vqc::<_, Sha256, _>(&mut test_rng(), leader, &messages, &Sequential)
        .unwrap();
    assert_eq!(certificate.tally().signers().count(), messages.len());
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
            .is_some()
    );
    assert_expanded_artifacts(
        &fixture.verifier,
        &[&Artifact::Vqc(certificate.clone())],
        &[],
        &[true],
    );
    let encoded = certificate.encode();
    let bounds = fixture
        .codec
        .encoded_bounds::<S, Digest>()
        .expect("fixture bounds are representable");
    assert!(encoded.len() <= bounds.max_artifact_bytes());
    let decoded = Vqc::<S, Digest>::decode_cfg(encoded, &fixture.codec).unwrap();
    assert_eq!(decoded, certificate);
}

#[test]
fn vqc_accepts_more_than_n_minus_f_messages_for_both_variants() {
    for_each_suite!(vqc_accepts_more_than_n_minus_f_messages);
}

fn lqc_uses_only_the_exact_vote_aggregate<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let leader = fixture.leader(1);
    let votes = fixture
        .signers
        .iter()
        .take(fixture.codec.view_quorum())
        .enumerate()
        .map(|(index, signer)| {
            let positions = if index == 0 {
                vec![0, 1, 1, 1, 1, 1]
            } else {
                vec![1; PARTICIPANTS as usize]
            };
            signer
                .sign_vote(fixture.body(
                    &leader,
                    positions,
                    vec![Vec::new(); PARTICIPANTS as usize],
                ))
                .unwrap()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        fixture
            .verifier
            .assemble_lqc::<_, Sha256, _>(
                &mut test_rng(),
                leader.clone(),
                &votes[..votes.len() - 1],
                &Sequential,
            )
            .unwrap_err(),
        Error::Quorum
    );
    let certificate = fixture
        .verifier
        .assemble_lqc::<_, Sha256, _>(&mut test_rng(), leader.clone(), &votes, &Sequential)
        .unwrap();
    let preverified = fixture
        .verifier
        .assemble_lqc_with::<_, Sha256, _>(
            &mut test_rng(),
            leader.clone(),
            &votes,
            SignatureVerification::Preverified,
            &Sequential,
        )
        .unwrap();
    assert_eq!(preverified, certificate);

    // Swapping two signatures keeps every signer but signs the wrong bodies individually.
    let mut forged = votes.clone();
    forged[0] = Vote::new(
        votes[0].body().clone(),
        Attestation::<S> {
            signer: votes[0].signer(),
            signature: votes[1].attestation().signature.clone(),
        },
    );
    forged[1] = Vote::new(
        votes[1].body().clone(),
        Attestation::<S> {
            signer: votes[1].signer(),
            signature: votes[0].attestation().signature.clone(),
        },
    );
    assert_eq!(
        fixture.verifier.assemble_lqc::<_, Sha256, _>(
            &mut test_rng(),
            leader.clone(),
            &forged,
            &Sequential,
        ),
        Err(Error::Signature)
    );
    // Preverified assembly trusts its inputs: the result is either the genuine certificate
    // (additive aggregates are order-free sums) or one that does not verify.
    let trusted = fixture
        .verifier
        .assemble_lqc_with::<_, Sha256, _>(
            &mut test_rng(),
            leader.clone(),
            &forged,
            SignatureVerification::Preverified,
            &Sequential,
        )
        .unwrap();
    assert_eq!(
        trusted == certificate,
        fixture
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &trusted, &Sequential)
            .is_some()
    );
    let id = fixture
        .verifier
        .verify_lqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
        .unwrap();
    assert_eq!(
        id,
        CertificateId::new(Sha256::hash(&[certificate.encode().as_ref()]))
    );

    let derived = certificate.derive_vqc(fixture.codec).unwrap();
    assert_eq!(derived.leader(), certificate.leader());
    assert_eq!(derived.tally(), certificate.tally());
    assert_eq!(derived.novoters().count(), 0);
    assert!(derived.conflicting_votes().is_empty());
    assert!(certificate.equivalent_vqc(&derived));
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &derived, &Sequential)
            .is_some()
    );

    let mutated_bodies = votes.iter().enumerate().map(|(index, vote)| {
        let body = if index == 0 {
            fixture.standard_body(&leader)
        } else {
            vote.body().clone()
        };
        (vote.signer(), body)
    });
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&leader),
        mutated_bodies,
        fixture.codec,
    )
    .unwrap();
    let mutated = Lqc::new(
        leader,
        tally,
        certificate.signature().clone(),
        fixture.codec,
    )
    .unwrap();
    assert!(
        fixture
            .verifier
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &mutated, &Sequential)
            .is_none()
    );
}

#[test]
fn lqc_uses_only_the_exact_vote_aggregate_for_both_variants() {
    for_each_suite!(lqc_uses_only_the_exact_vote_aggregate);
}

/// Returns every rotation and the reversal of `items`.
fn orders<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    let mut orders = (0..items.len())
        .map(|shift| {
            let mut rotated = items.to_vec();
            rotated.rotate_left(shift);
            rotated
        })
        .collect::<Vec<_>>();
    orders.push(items.iter().rev().cloned().collect());
    orders
}

fn certificate_assembly_is_canonical<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let view = MixedView::new(&fixture);
    let mut vqc = None;
    for messages in orders(&view.messages) {
        for verification in [
            SignatureVerification::Checked,
            SignatureVerification::Preverified,
        ] {
            let certificate = fixture
                .verifier
                .assemble_vqc_with::<_, Sha256, _>(
                    &mut test_rng(),
                    view.leader.clone(),
                    &messages,
                    verification,
                    &Sequential,
                )
                .unwrap();
            let expected = vqc.get_or_insert_with(|| certificate.clone());
            assert_eq!(
                &certificate, expected,
                "V-QC assembly depends on message order"
            );
        }
    }
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &vqc.unwrap(), &Sequential)
            .is_some()
    );

    let leader = fixture.leader(3);
    let votes = fixture.quorum_votes(&leader);
    let mut lqc = None;
    for votes in orders(&votes) {
        let certificate = fixture
            .verifier
            .assemble_lqc::<_, Sha256, _>(&mut test_rng(), leader.clone(), &votes, &Sequential)
            .unwrap();
        let expected = lqc.get_or_insert_with(|| certificate.clone());
        assert_eq!(
            &certificate, expected,
            "L-QC assembly depends on vote order"
        );
    }
    // Signers assemble the same canonical certificate as the verifier.
    assert_eq!(
        fixture.signers[2]
            .assemble_lqc::<_, Sha256, _>(
                &mut test_rng(),
                leader,
                &fixture.quorum_votes(&fixture.leader(3)),
                &Sequential
            )
            .unwrap(),
        lqc.unwrap()
    );
}

#[test]
fn certificate_assembly_is_canonical_for_every_suite() {
    for_each_suite!(certificate_assembly_is_canonical);
}

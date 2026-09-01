//! V-QC and L-QC assembly and verification.

use super::*;

/// One view's messages: three designated votes with different paths, one conflicting vote for
/// `other`, and one novote.
struct MixedView<V: Variant> {
    leader: LeaderBlock<V, Digest>,
    other: LeaderBlock<V, Digest>,
    designated: Vec<VoteBody<Digest>>,
    messages: Vec<ViewMessage<V, Digest>>,
}

impl<V: Variant> MixedView<V> {
    fn new(fixture: &Fixture<V>) -> Self {
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

fn vqc_carries_designated_conflicting_and_abstaining_messages<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let view = MixedView::new(&fixture);
    let certificate = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(view.leader.clone(), &view.messages, &Sequential)
        .unwrap();
    let preverified = fixture
        .verifier
        .assemble_vqc_with::<Sha256, _>(
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
    assert!(
        fixture
            .certificate_verifier()
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
            .is_some()
    );
    assert_eq!(
        id,
        CertificateId::new(Sha256::hash(&[certificate.encode().as_ref()]))
    );
}

#[test]
fn vqc_carries_designated_conflicting_and_abstaining_messages_for_both_variants() {
    vqc_carries_designated_conflicting_and_abstaining_messages::<MinPk>();
    vqc_carries_designated_conflicting_and_abstaining_messages::<MinSig>();
}

fn vqc_assembly_rejects_overlapping_and_wrong_round_messages<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let view = MixedView::new(&fixture);
    let mut overlapping = view.messages.clone();
    *overlapping.last_mut().unwrap() =
        ViewMessage::NoVote(fixture.signers[0].sign_novote(fixture.round).unwrap());
    assert_eq!(
        fixture
            .verifier
            .assemble_vqc::<Sha256, _>(view.leader.clone(), &overlapping, &Sequential)
            .unwrap_err(),
        Error::Signature
    );

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
            .assemble_vqc::<Sha256, _>(view.leader, &wrong_round_messages, &Sequential)
            .unwrap_err(),
        Error::Transcript
    );
}

#[test]
fn vqc_assembly_rejects_overlapping_and_wrong_round_messages_for_both_variants() {
    vqc_assembly_rejects_overlapping_and_wrong_round_messages::<MinPk>();
    vqc_assembly_rejects_overlapping_and_wrong_round_messages::<MinSig>();
}

fn vqc_signature_binds_every_tally_field<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let view = MixedView::new(&fixture);
    let certificate = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(view.leader.clone(), &view.messages, &Sequential)
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
        view.leader,
        tally,
        certificate.novoters().clone(),
        certificate.conflicting_votes().to_vec(),
        certificate.signature().unwrap().clone(),
        fixture.codec,
    )
    .unwrap();
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &mutated, &Sequential)
            .is_none()
    );
}

#[test]
fn vqc_signature_binds_every_tally_field_for_both_variants() {
    vqc_signature_binds_every_tally_field::<MinPk>();
    vqc_signature_binds_every_tally_field::<MinSig>();
}

fn vqc_accepts_more_than_n_minus_f_messages<V: Variant>() {
    let fixture = Fixture::<V>::new();
    let leader = fixture.leader(1);
    let messages = fixture
        .signers
        .iter()
        .map(|signer| ViewMessage::Vote(signer.sign_vote(fixture.standard_body(&leader)).unwrap()))
        .collect::<Vec<_>>();
    assert!(messages.len() > fixture.codec.view_quorum());

    let certificate = fixture
        .verifier
        .assemble_vqc::<Sha256, _>(leader, &messages, &Sequential)
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
        .encoded_bounds::<V, Digest>()
        .expect("fixture bounds are representable");
    assert!(encoded.len() <= bounds.max_artifact_bytes());
    let decoded = Vqc::<V, Digest>::decode_cfg(encoded, &fixture.codec).unwrap();
    assert_eq!(decoded, certificate);
}

#[test]
fn vqc_accepts_more_than_n_minus_f_messages_for_both_variants() {
    vqc_accepts_more_than_n_minus_f_messages::<MinPk>();
    vqc_accepts_more_than_n_minus_f_messages::<MinSig>();
}

fn lqc_uses_only_the_exact_vote_aggregate<V: Variant>() {
    let fixture = Fixture::<V>::new();
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
            .assemble_lqc::<Sha256, _>(leader.clone(), &votes[..votes.len() - 1], &Sequential,)
            .unwrap_err(),
        Error::Quorum
    );
    let certificate = fixture
        .verifier
        .assemble_lqc::<Sha256, _>(leader.clone(), &votes, &Sequential)
        .unwrap();
    let preverified = fixture
        .verifier
        .assemble_lqc_with::<Sha256, _>(
            leader.clone(),
            &votes,
            SignatureVerification::Preverified,
            &Sequential,
        )
        .unwrap();
    assert_eq!(preverified, certificate);
    let mut forged = votes.clone();
    let delta = V::Signature::generator() * &Scalar::random(test_rng());
    let first = *forged[0].attestation().signature().unwrap() + &delta;
    let second = *forged[1].attestation().signature().unwrap() - &delta;
    forged[0] = Vote::new(
        forged[0].body().clone(),
        Attestation::new(forged[0].signer(), Lazy::from(first)),
    );
    forged[1] = Vote::new(
        forged[1].body().clone(),
        Attestation::new(forged[1].signer(), Lazy::from(second)),
    );
    assert_eq!(
        fixture
            .verifier
            .assemble_lqc::<Sha256, _>(leader.clone(), &forged, &Sequential,),
        Err(Error::Signature)
    );
    assert_eq!(
        fixture
            .verifier
            .assemble_lqc_with::<Sha256, _>(
                leader.clone(),
                &forged,
                SignatureVerification::Preverified,
                &Sequential
            )
            .unwrap(),
        certificate
    );
    let id = fixture
        .verifier
        .verify_lqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
        .unwrap();
    assert!(
        fixture
            .certificate_verifier()
            .verify_lqc::<_, Sha256, _>(&mut test_rng(), &certificate, &Sequential)
            .is_some()
    );
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
        certificate.signature().unwrap().clone(),
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
    lqc_uses_only_the_exact_vote_aggregate::<MinPk>();
    lqc_uses_only_the_exact_vote_aggregate::<MinSig>();
}

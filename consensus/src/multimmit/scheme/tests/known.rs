//! Known-message discharge: a held message can only fail an artifact, never pass one.

use super::*;

fn known_da_certificates_discharge_only_matching_anchors<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let certificate = fixture.da_certificate(&fixture.header(0, 501));
    let other_header = fixture.da_certificate(&fixture.header(0, 502));
    // A certificate whose signature belongs to another header is a forgery for this one.
    let forged = DaCertificate::new(
        certificate.header().clone(),
        other_header.certificate().clone(),
    );
    let valid = fixture.sign_leader(fixture.anchored_leader(701, certificate.clone()));
    let invalid = fixture.sign_leader(fixture.anchored_leader(701, forged.clone()));

    let artifacts = [
        &Artifact::LeaderBlock(valid.clone()),
        &Artifact::LeaderBlock(valid.clone()),
        &Artifact::LeaderBlock(invalid.clone()),
        &Artifact::LeaderBlock(invalid.clone()),
        &Artifact::LeaderBlock(valid),
        &Artifact::LeaderBlock(invalid),
    ];
    let held: [&[Verified<'_, S, Digest>]; 6] = [
        // The exact anchor is held, so it needs no verification.
        &[Verified::DaCertificate(&certificate)],
        // A certificate for another header matches nothing and the anchor is verified.
        &[Verified::DaCertificate(&other_header)],
        // Holding the genuine certificate never excuses a different one for the same header.
        &[Verified::DaCertificate(&certificate)],
        &[],
        // Holding the forgery is ignored for a block that anchors on the genuine certificate.
        &[Verified::DaCertificate(&forged)],
        // Held ordinary messages never discharge an anchor.
        &[Verified::DaCertificate(&other_header)],
    ];
    let verdicts = fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
        &mut test_rng(),
        &artifacts,
        &held,
        &Sequential,
    );
    assert_eq!(verdicts, [true, true, false, false, true, false]);
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
    for_each_suite!(known_da_certificates_discharge_only_matching_anchors);
}

/// A V-QC and L-QC over one leader, their tampered variants, and every view message they
/// aggregate.
struct Certified<S: Suite> {
    vqc: Vqc<S, Digest>,
    lqc: Lqc<S, Digest>,
    bad_vqc: Vqc<S, Digest>,
    bad_lqc: Lqc<S, Digest>,
    votes: Vec<Vote<S, Digest>>,
    novote: NoVote<S>,
}

impl<S: Suite> Certified<S> {
    fn new(fixture: &Fixture<S>) -> Self {
        let verifier = &fixture.verifier;
        let leader = fixture.leader(7);
        let quorum = fixture.codec.view_quorum();
        let votes = fixture.quorum_votes(&leader);
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
            .assemble_vqc::<_, Sha256, _>(&mut test_rng(), leader.clone(), &messages, &Sequential)
            .unwrap();
        let lqc = verifier
            .assemble_lqc::<_, Sha256, _>(&mut test_rng(), leader, &votes, &Sequential)
            .unwrap();
        Self {
            bad_vqc: corrupt_tail(&vqc, &fixture.codec),
            bad_lqc: corrupt_tail(&lqc, &fixture.codec),
            vqc,
            lqc,
            votes,
            novote,
        }
    }

    /// Every message the V-QC aggregates.
    fn vqc_known(&self) -> Vec<Verified<'_, S, Digest>> {
        let quorum = self.votes.len();
        self.votes[..quorum - 1]
            .iter()
            .map(Verified::Vote)
            .chain(std::iter::once(Verified::NoVote(&self.novote)))
            .collect()
    }

    /// Every message the L-QC aggregates.
    fn lqc_known(&self) -> Vec<Verified<'_, S, Digest>> {
        self.votes.iter().map(Verified::Vote).collect()
    }
}

fn known_messages_discharge_certificate_transcripts<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let verifier = &fixture.verifier;
    let certified = Certified::new(&fixture);
    let quorum = fixture.codec.view_quorum();
    let all_known = certified
        .votes
        .iter()
        .map(Verified::Vote)
        .chain(std::iter::once(Verified::NoVote(&certified.novote)))
        .collect::<Vec<_>>();
    let half_known = all_known[..quorum / 2].to_vec();
    // A signer's vote for another proposal reproduces no transcript term and is ignored.
    let other_leader = fixture.leader(8);
    let mismatched = fixture.signers[0]
        .sign_vote(fixture.standard_body(&other_leader))
        .unwrap();
    let mut mismatched_known = all_known.clone();
    mismatched_known[0] = Verified::Vote(&mismatched);
    // A signer outside the transcript is ignored.
    let stranger = fixture.signers[quorum]
        .sign_vote(fixture.standard_body(&fixture.leader(7)))
        .unwrap();
    let mut with_stranger = all_known.clone();
    with_stranger.push(Verified::Vote(&stranger));

    let artifacts = [
        &Artifact::Vqc(certified.vqc.clone()),
        &Artifact::Lqc(certified.lqc.clone()),
        &Artifact::Vqc(certified.bad_vqc.clone()),
        &Artifact::Lqc(certified.bad_lqc.clone()),
        &Artifact::Vqc(certified.vqc.clone()),
        &Artifact::Lqc(certified.lqc.clone()),
        &Artifact::Vqc(certified.vqc.clone()),
        &Artifact::Lqc(certified.lqc.clone()),
        &Artifact::Vqc(certified.vqc.clone()),
    ];
    let known: [&[Verified<'_, S, Digest>]; 9] = [
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

#[test]
fn known_messages_discharge_certificate_transcripts_for_both_variants() {
    for_each_suite!(known_messages_discharge_certificate_transcripts);
}

/// Forged, misattributed, and malformed known messages never pass an invalid certificate, and
/// a correct known set never passes a wrong aggregate.
fn hostile_known_messages_never_pass_a_certificate<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let verifier = &fixture.verifier;
    let certified = Certified::new(&fixture);
    let leader = certified.lqc.leader().clone();

    // Signer 0's vote for this exact body, carrying signer 0's signature over another body.
    let elsewhere = fixture.signers[0]
        .sign_vote(fixture.standard_body(&fixture.leader(8)))
        .unwrap();
    let forged = Vote::new(
        certified.votes[0].body().clone(),
        elsewhere.attestation().clone(),
    );
    // Signer 1's term, carrying signer 0's genuine signature over the same body.
    let misattributed = Vote::new(
        certified.votes[1].body().clone(),
        Attestation::<S> {
            signer: Participant::new(1),
            signature: certified.votes[0].attestation().signature.clone(),
        },
    );
    // A known vote whose signature does not decode.
    let unreadable = Vote::new(
        certified.votes[2].body().clone(),
        Attestation::<S> {
            signer: Participant::new(2),
            signature: malformed(),
        },
    );
    // An abstention by signer 0, whose term in both certificates is a vote.
    let abstention = fixture.signers[0].sign_novote(fixture.round).unwrap();
    let lqc_known = certified.lqc_known();
    let hostile = |replace: usize, message| {
        let mut set = lqc_known.clone();
        set[replace] = message;
        set
    };
    let hostile_sets = [
        hostile(0, Verified::Vote(&forged)),
        hostile(1, Verified::Vote(&misattributed)),
        hostile(2, Verified::Vote(&unreadable)),
        hostile(0, Verified::NoVote(&abstention)),
        vec![
            Verified::Vote(&forged),
            Verified::Vote(&misattributed),
            Verified::Vote(&unreadable),
        ],
    ];

    // A wrong aggregate over a transcript the node fully holds.
    let donor = fixture.leader(9);
    let donor_lqc = Lqc::new(
        leader.clone(),
        certified.lqc.tally().clone(),
        fixture.lqc(&donor).signature().clone(),
        fixture.codec,
    )
    .unwrap();
    let invalid = [
        Artifact::Vqc(certified.bad_vqc.clone()),
        Artifact::Lqc(certified.bad_lqc.clone()),
        Artifact::Lqc(donor_lqc),
    ];
    let vqc_known = certified.vqc_known();
    for artifact in &invalid {
        let correct: &[Verified<'_, S, Digest>] = match artifact {
            Artifact::Vqc(_) => &vqc_known,
            _ => &lqc_known,
        };
        for known in hostile_sets.iter().map(Vec::as_slice).chain([correct, &[]]) {
            assert_eq!(
                verifier.verify_artifacts::<_, Sha256, Digest>(
                    &mut test_rng(),
                    &[artifact],
                    &[known],
                    &Sequential
                ),
                [false],
                "a known set passed an invalid certificate"
            );
        }
    }

    // A malformed or mismatched known message is never attached, so a valid certificate still
    // passes. A forged or misattributed one may fail it but never changes an invalid verdict.
    let valid = Artifact::Lqc(certified.lqc.clone());
    for (index, known) in hostile_sets.iter().enumerate() {
        let verdict = verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &[&valid],
            &[known],
            &Sequential,
        )[0];
        if index == 2 || index == 3 {
            assert!(
                verdict,
                "an unattachable known message failed a valid certificate"
            );
        }
    }

    // Leader blocks never consult known votes.
    let signed = fixture.sign_leader(leader);
    assert_eq!(
        verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &[&Artifact::LeaderBlock(signed)],
            &[&lqc_known],
            &Sequential
        ),
        [true]
    );
}

#[test]
fn hostile_known_messages_never_pass_a_certificate_for_every_suite() {
    for_each_suite!(hostile_known_messages_never_pass_a_certificate);
}

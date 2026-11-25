//! Batch verification verdicts and per-artifact attribution.

use super::*;
use commonware_parallel::rayon::ThreadPoolBuilder;

fn artifact_batch_returns_per_item_verdicts<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(0, 90);
    let valid = fixture.signers[0]
        .sign_transaction_block(header.clone())
        .unwrap();
    let invalid = SignedTransactionBlock::new(
        header,
        Attestation::<S> {
            signer: Participant::new(0),
            signature: malformed(),
        },
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
    let parallel = Rayon::new(ThreadPoolBuilder::new(NZUsize!(4))).unwrap();
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
    for_each_suite!(artifact_batch_returns_per_item_verdicts);
}

/// Artifacts with their individual and expected verdicts, in the same order.
pub(super) struct Cohort<S: Suite> {
    pub(super) artifacts: Vec<Artifact<S, Digest>>,
    pub(super) individual: Vec<bool>,
    pub(super) expected: Vec<bool>,
}

impl<S: Suite> Cohort<S> {
    fn extend(&mut self, other: Self) {
        self.artifacts.extend(other.artifacts);
        self.individual.extend(other.individual);
        self.expected.extend(other.expected);
    }

    /// Checks that batched verification, sequential and parallel, reaches the same verdicts as
    /// the individual verifiers.
    fn assert_batch_matches_individual(&self, verifier: &Generic<S>) {
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
        let parallel = Rayon::new(ThreadPoolBuilder::new(NZUsize!(4))).unwrap();
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

    /// Checks that every forged artifact, alone among all the valid ones, fails exactly itself.
    fn assert_each_forgery_is_attributed(&self, verifier: &Generic<S>) {
        let valid = self
            .artifacts
            .iter()
            .zip(&self.expected)
            .filter(|(_, valid)| **valid)
            .map(|(artifact, _)| artifact)
            .collect::<Vec<_>>();
        for (forged, _) in self
            .artifacts
            .iter()
            .zip(&self.expected)
            .filter(|(_, valid)| !**valid)
        {
            // Place the forgery in the middle so it shares batches with valid neighbors.
            let mut batch = valid.clone();
            let position = batch.len() / 2;
            batch.insert(position, forged);
            let mut expected = vec![true; batch.len()];
            expected[position] = false;
            assert_eq!(
                verifier.verify_artifacts::<_, Sha256, Digest>(
                    &mut test_rng(),
                    &batch,
                    &[],
                    &Sequential
                ),
                expected,
                "a forged {:?} must fail only itself",
                forged.kind()
            );
        }
    }
}

/// Builds one valid and, where a forgery exists, one invalid artifact of every signed-message
/// kind. Every forgery carries an honest signature moved to another message.
pub(super) fn signed_message_cohort<S: Suite>(fixture: &Fixture<S>) -> Cohort<S> {
    let verifier = &fixture.verifier;
    let mut rng = test_rng();

    let transaction = fixture.signers[0]
        .sign_transaction_block(fixture.header(0, 90))
        .unwrap();
    let bad_transaction =
        SignedTransactionBlock::new(fixture.header(0, 91), transaction.attestation().clone());

    let da_vote = fixture.signers[0]
        .sign_da_vote(fixture.header(1, 92))
        .unwrap();
    let bad_da_vote = DaVote::new(
        fixture.header(1, 93),
        fixture.signers[1]
            .sign_da_vote(fixture.header(1, 92))
            .unwrap()
            .attestation()
            .clone(),
    );

    let leader = fixture.leader(95);
    let signed_leader = fixture.sign_leader(leader.clone());
    let bad_leader = SignedLeaderBlock::new(
        leader.clone(),
        fixture
            .sign_leader(fixture.leader(96))
            .attestation()
            .clone(),
    );
    // A correctly signed leader block whose anchor carries a certificate for another header.
    let certificate = fixture.da_certificate(&fixture.header(0, 97));
    let forged_anchor =
        DaCertificate::new(fixture.header(0, 98), certificate.certificate().clone());
    let anchored_leader = fixture.sign_leader(fixture.anchored_leader(99, certificate));
    let bad_anchor_leader = fixture.sign_leader(fixture.anchored_leader(99, forged_anchor));

    let vote = fixture.signers[0]
        .sign_vote(fixture.standard_body(&leader))
        .unwrap();
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

    let wrong_round = Round::new(
        fixture.round.epoch(),
        View::new(fixture.round.view().get() + 1),
    );
    let novote = fixture.signers[1].sign_novote(fixture.round).unwrap();
    let bad_novote = NoVote::new(
        fixture.round,
        fixture.signers[2]
            .sign_novote(wrong_round)
            .unwrap()
            .attestation()
            .clone(),
    )
    .unwrap();
    let nullify = fixture.signers[2].sign_nullify(fixture.round).unwrap();
    let bad_nullify = Nullify::new(wrong_round, nullify.attestation().clone()).unwrap();

    let artifacts = vec![
        Artifact::TransactionBlock(transaction.clone()),
        Artifact::TransactionBlock(bad_transaction.clone()),
        Artifact::DaVote(da_vote.clone()),
        Artifact::DaVote(bad_da_vote.clone()),
        Artifact::LeaderBlock(signed_leader.clone()),
        Artifact::LeaderBlock(bad_leader.clone()),
        Artifact::LeaderBlock(anchored_leader.clone()),
        Artifact::LeaderBlock(bad_anchor_leader.clone()),
        Artifact::Vote(vote.clone()),
        Artifact::Vote(bad_vote.clone()),
        Artifact::NoVote(novote.clone()),
        Artifact::NoVote(bad_novote.clone()),
        Artifact::Nullify(nullify.clone()),
        Artifact::Nullify(bad_nullify.clone()),
    ];
    let individual = vec![
        verifier.verify_transaction_block(&mut rng, &transaction, &Sequential),
        verifier.verify_transaction_block(&mut rng, &bad_transaction, &Sequential),
        verifier.verify_da_vote(&mut rng, &da_vote, &Sequential),
        verifier.verify_da_vote(&mut rng, &bad_da_vote, &Sequential),
        verifier.verify_leader_block(&mut rng, &signed_leader, &Sequential),
        verifier.verify_leader_block(&mut rng, &bad_leader, &Sequential),
        verifier.verify_leader_block(&mut rng, &anchored_leader, &Sequential),
        verifier.verify_leader_block(&mut rng, &bad_anchor_leader, &Sequential),
        verifier.verify_vote(&mut rng, &vote, &Sequential),
        verifier.verify_vote(&mut rng, &bad_vote, &Sequential),
        verifier.verify_novote(&mut rng, &novote, &Sequential),
        verifier.verify_novote(&mut rng, &bad_novote, &Sequential),
        verifier.verify_nullify(&mut rng, &nullify, &Sequential),
        verifier.verify_nullify(&mut rng, &bad_nullify, &Sequential),
    ];
    // Every kind appears once valid and once forged.
    let expected = [true, false].repeat(7);
    Cohort {
        artifacts,
        individual,
        expected,
    }
}

/// Builds one valid and two invalid certificates of every kind.
pub(super) fn certificate_cohort<S: Suite>(fixture: &Fixture<S>) -> Cohort<S> {
    let verifier = &fixture.verifier;
    let mut rng = test_rng();

    let da_certificate = fixture.da_certificate(&fixture.header(1, 92));
    let bad_da_certificate =
        DaCertificate::new(fixture.header(1, 94), da_certificate.certificate().clone());
    let corrupt_da_certificate = corrupt_tail(&da_certificate, &fixture.codec);

    let nullification = fixture.nullification(fixture.round);
    let wrong_round = Round::new(
        fixture.round.epoch(),
        View::new(fixture.round.view().get() + 1),
    );
    let bad_nullification =
        Nullification::new(wrong_round, nullification.certificate().clone()).unwrap();
    let corrupt_nullification = corrupt_tail(&nullification, &fixture.codec);

    let leader = fixture.leader(95);
    let lqc = fixture.lqc(&leader);
    let vqc = fixture.vqc(&leader);
    let bad_vqc = corrupt_tail(&vqc, &fixture.codec);
    let bad_lqc = corrupt_tail(&lqc, &fixture.codec);
    // A structurally valid aggregate over the same number of terms from another proposal.
    let donor = fixture.leader(96);
    let donor_vqc = Vqc::new(
        leader.clone(),
        vqc.tally().clone(),
        vqc.novoters().clone(),
        vqc.conflicting_votes().to_vec(),
        fixture.vqc(&donor).signature().clone(),
        fixture.codec,
    )
    .unwrap();
    let donor_lqc = Lqc::new(
        leader,
        lqc.tally().clone(),
        fixture.lqc(&donor).signature().clone(),
        fixture.codec,
    )
    .unwrap();

    let vqc_verdict = |rng: &mut TestRng, certificate: &Vqc<S, Digest>| {
        verifier
            .verify_vqc::<_, Sha256, _>(rng, certificate, &Sequential)
            .is_some()
    };
    let lqc_verdict = |rng: &mut TestRng, certificate: &Lqc<S, Digest>| {
        verifier
            .verify_lqc::<_, Sha256, _>(rng, certificate, &Sequential)
            .is_some()
    };
    let individual = vec![
        verifier.verify_da_certificate(&mut rng, &da_certificate, &Sequential),
        verifier.verify_da_certificate(&mut rng, &bad_da_certificate, &Sequential),
        verifier.verify_da_certificate(&mut rng, &corrupt_da_certificate, &Sequential),
        verifier.verify_nullification(&mut rng, &nullification, &Sequential),
        verifier.verify_nullification(&mut rng, &bad_nullification, &Sequential),
        verifier.verify_nullification(&mut rng, &corrupt_nullification, &Sequential),
        vqc_verdict(&mut rng, &vqc),
        vqc_verdict(&mut rng, &bad_vqc),
        vqc_verdict(&mut rng, &donor_vqc),
        lqc_verdict(&mut rng, &lqc),
        lqc_verdict(&mut rng, &bad_lqc),
        lqc_verdict(&mut rng, &donor_lqc),
    ];
    let artifacts = vec![
        Artifact::DaCertificate(da_certificate),
        Artifact::DaCertificate(bad_da_certificate),
        Artifact::DaCertificate(corrupt_da_certificate),
        Artifact::Nullification(nullification),
        Artifact::Nullification(bad_nullification),
        Artifact::Nullification(corrupt_nullification),
        Artifact::Vqc(vqc),
        Artifact::Vqc(bad_vqc),
        Artifact::Vqc(donor_vqc),
        Artifact::Lqc(lqc),
        Artifact::Lqc(bad_lqc),
        Artifact::Lqc(donor_lqc),
    ];
    let expected = [true, false, false].repeat(4);
    Cohort {
        artifacts,
        individual,
        expected,
    }
}

fn batched_verdicts_match_for_signed_messages<S: Suite>() {
    let fixture = Fixture::<S>::new();
    signed_message_cohort(&fixture).assert_batch_matches_individual(&fixture.verifier);
}

#[test]
fn batched_verdicts_match_for_signed_messages_for_both_variants() {
    for_each_suite!(batched_verdicts_match_for_signed_messages);
}

fn batched_verdicts_match_for_certificates<S: Suite>() {
    let fixture = Fixture::<S>::new();
    certificate_cohort(&fixture).assert_batch_matches_individual(&fixture.verifier);
}

#[test]
fn batched_verdicts_match_for_certificates_for_both_variants() {
    for_each_suite!(batched_verdicts_match_for_certificates);
}

fn batched_verdicts_match_for_every_artifact_kind<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let mut cohort = signed_message_cohort(&fixture);
    cohort.extend(certificate_cohort(&fixture));
    cohort.assert_batch_matches_individual(&fixture.verifier);
}

#[test]
fn batched_verdicts_match_for_every_artifact_kind_for_both_variants() {
    for_each_suite!(batched_verdicts_match_for_every_artifact_kind);
}

fn one_forgery_fails_only_its_artifact<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let mut cohort = signed_message_cohort(&fixture);
    cohort.extend(certificate_cohort(&fixture));
    cohort.assert_each_forgery_is_attributed(&fixture.verifier);
}

#[test]
fn one_forgery_in_a_mixed_batch_fails_only_its_artifact() {
    for_each_suite!(one_forgery_fails_only_its_artifact);
}

fn duplicate_signers_never_fail_their_valid_share<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let header = fixture.header(1, 120);
    let votes = fixture.da_votes(&header);
    // Signer 1's share over another header, moved under this one.
    let forged_vote = DaVote::new(
        header.clone(),
        fixture.signers[1]
            .sign_da_vote(fixture.header(1, 121))
            .unwrap()
            .attestation()
            .clone(),
    );
    let malformed_vote = DaVote::<S, Digest>::new(
        header,
        certificate::Attestation {
            signer: Participant::new(2),
            signature: malformed(),
        },
    );

    let round = fixture.round;
    let shares = fixture.nullifies(round);
    let other_round = Round::new(round.epoch(), View::new(round.view().get() + 5));
    let forged_share = Nullify::new(
        round,
        fixture.signers[1]
            .sign_nullify(other_round)
            .unwrap()
            .attestation()
            .clone(),
    )
    .unwrap();

    // Every order of the forged and the valid share by one signer, inside a batch of others.
    for forged_first in [true, false] {
        let mut artifacts = votes
            .iter()
            .cloned()
            .map(Artifact::DaVote)
            .chain(shares.iter().cloned().map(Artifact::Nullify))
            .collect::<Vec<_>>();
        let mut expected = vec![true; artifacts.len()];
        let forged = [
            Artifact::DaVote(forged_vote.clone()),
            Artifact::DaVote(malformed_vote.clone()),
            Artifact::Nullify(forged_share.clone()),
        ];
        for forgery in forged {
            if forged_first {
                artifacts.insert(0, forgery);
                expected.insert(0, false);
            } else {
                artifacts.push(forgery);
                expected.push(false);
            }
        }
        let artifacts = artifacts.iter().collect::<Vec<_>>();
        for parallel in [false, true] {
            let verdicts = if parallel {
                fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
                    &mut test_rng(),
                    &artifacts,
                    &[],
                    &Rayon::new(ThreadPoolBuilder::new(NZUsize!(4))).unwrap(),
                )
            } else {
                fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
                    &mut test_rng(),
                    &artifacts,
                    &[],
                    &Sequential,
                )
            };
            assert_eq!(verdicts, expected, "forged first: {forged_first}");
        }
    }

    // Two identical valid shares by one signer both verify.
    let duplicated = [
        &Artifact::DaVote(votes[0].clone()),
        &Artifact::DaVote(votes[0].clone()),
        &Artifact::DaVote(votes[1].clone()),
    ];
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &duplicated,
            &[],
            &Sequential
        ),
        [true, true, true]
    );
}

#[test]
fn duplicate_signer_shares_in_one_batch_fail_only_the_forgery() {
    for_each_suite!(duplicate_signers_never_fail_their_valid_share);
}

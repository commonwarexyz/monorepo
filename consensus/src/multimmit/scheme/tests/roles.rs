//! Role and subject-kind separation: a signature of one role or subject kind never verifies as
//! another.
//!
//! Every suite here uses one signature type for all three roles, and one certificate type for
//! both threshold roles, so every cross-role substitution is expressible. Ed25519 signs every
//! role with one key, so only namespaces separate its roles.

use super::*;

/// Returns an ordinary attestation by `signer` carrying `signature`.
fn ordinary<S: Suite>(
    signer: Participant,
    signature: Lazy<OrdinarySignature<S>>,
) -> Attestation<S> {
    certificate::Attestation { signer, signature }
}

fn signatures_never_verify_across_roles_or_kinds<S: Suite>()
where
    S::Da: certificate::Scheme<Signature = OrdinarySignature<S>>,
    S::Nullify: certificate::Scheme<Signature = OrdinarySignature<S>>
        + Verifier<Certificate = DaCertificateOf<S>>,
{
    let fixture = Fixture::<S>::new();
    let leader = fixture.leader(11);
    let view = leader.view();
    let round = leader.round();
    // The scheduled leader produces the chain at its own index, so one participant signs every
    // kind and role.
    let me = fixture.scheduled(view);
    let signer = &fixture.signers[me];
    let index = Participant::from_usize(me);
    let header = fixture.header(me as u32, 12);
    let body = fixture.standard_body(&leader);

    let transaction = signer.sign_transaction_block(header.clone()).unwrap();
    let da_vote = signer.sign_da_vote(header.clone()).unwrap();
    let leader_block = signer.sign_leader_block(leader.clone()).unwrap();
    let vote = signer.sign_vote(body.clone()).unwrap();
    let novote = signer.sign_novote(round).unwrap();
    let nullify = signer.sign_nullify(round).unwrap();
    let signatures = [
        (
            "transaction block",
            transaction.attestation().signature.clone(),
        ),
        ("DA vote", da_vote.attestation().signature.clone()),
        ("leader block", leader_block.attestation().signature.clone()),
        ("vote", vote.attestation().signature.clone()),
        ("novote", novote.attestation().signature.clone()),
        ("nullify", nullify.attestation().signature.clone()),
    ];

    // Each kind's own signature verifies, and every other kind's signature by the same
    // participant fails, including those over the same bytes (a header, or a round).
    for (target, kind) in [
        (0, "transaction block"),
        (1, "DA vote"),
        (2, "leader block"),
        (3, "vote"),
        (4, "novote"),
        (5, "nullify"),
    ] {
        for (source, (label, signature)) in signatures.iter().enumerate() {
            let artifact = match target {
                0 => Artifact::TransactionBlock(SignedTransactionBlock::new(
                    header.clone(),
                    ordinary::<S>(index, signature.clone()),
                )),
                1 => Artifact::DaVote(DaVote::new(
                    header.clone(),
                    certificate::Attestation {
                        signer: index,
                        signature: signature.clone(),
                    },
                )),
                2 => Artifact::LeaderBlock(SignedLeaderBlock::new(
                    leader.clone(),
                    ordinary::<S>(index, signature.clone()),
                )),
                3 => Artifact::Vote(Vote::new(
                    body.clone(),
                    ordinary::<S>(index, signature.clone()),
                )),
                4 => Artifact::NoVote(
                    NoVote::new(round, ordinary::<S>(index, signature.clone())).unwrap(),
                ),
                _ => Artifact::Nullify(
                    Nullify::new(
                        round,
                        certificate::Attestation {
                            signer: index,
                            signature: signature.clone(),
                        },
                    )
                    .unwrap(),
                ),
            };
            assert_eq!(
                fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
                    &mut test_rng(),
                    &[&artifact],
                    &[],
                    &Sequential
                ),
                [source == target],
                "a {label} signature as a {kind}"
            );
        }
    }

    // Threshold certificates of one role never verify as the other's, even when the same
    // participants signed.
    let certificate = fixture.da_certificate(&header);
    let nullification = fixture.nullification(round);
    let as_nullification =
        Nullification::<S>::new(round, certificate.certificate().clone()).unwrap();
    let as_da = DaCertificate::<S, Digest>::new(header, nullification.certificate().clone());
    let mut rng = test_rng();
    assert!(
        fixture
            .verifier
            .verify_da_certificate(&mut rng, &certificate, &Sequential)
    );
    assert!(
        fixture
            .verifier
            .verify_nullification(&mut rng, &nullification, &Sequential)
    );
    assert!(
        !fixture
            .verifier
            .verify_nullification(&mut rng, &as_nullification, &Sequential)
    );
    assert!(
        !fixture
            .verifier
            .verify_da_certificate(&mut rng, &as_da, &Sequential)
    );
    assert_eq!(
        fixture.verifier.verify_artifacts::<_, Sha256, Digest>(
            &mut test_rng(),
            &[
                &Artifact::DaCertificate(certificate),
                &Artifact::Nullification(as_nullification),
                &Artifact::DaCertificate(as_da),
                &Artifact::Nullification(nullification),
            ],
            &[],
            &Sequential
        ),
        [true, false, false, true]
    );
}

#[test]
fn signatures_never_verify_across_roles_or_kinds_for_every_suite() {
    // Swapping certificates across roles needs one certificate type for both, so the suites with
    // aggregate DA certificates are left out.
    signatures_never_verify_across_roles_or_kinds::<Bls<MinPk>>();
    signatures_never_verify_across_roles_or_kinds::<Bls<MinSig>>();
    signatures_never_verify_across_roles_or_kinds::<Sas<MinPk>>();
    signatures_never_verify_across_roles_or_kinds::<Sas<MinSig>>();
    signatures_never_verify_across_roles_or_kinds::<Ed25519>();
    signatures_never_verify_across_roles_or_kinds::<Mock>();
}

/// A vote and novote for one view share their period but not their namespace, so neither
/// signature verifies as the other, and an L-QC aggregate never verifies as a V-QC with the same
/// signers abstaining.
fn same_period_kinds_stay_separated<S: Suite>() {
    let fixture = Fixture::<S>::new();
    let leader = fixture.leader(13);
    let votes = fixture.quorum_votes(&leader);
    let lqc = fixture.lqc(&leader);
    // Every quorum member abstains instead, carrying its vote signature.
    let novoters = commonware_cryptography::certificate::Signers::new(
        PARTICIPANTS,
        votes
            .iter()
            .skip(fixture.codec.designation_quorum())
            .map(|vote| vote.signer()),
    )
    .unwrap();
    let designated = votes[..fixture.codec.designation_quorum()]
        .iter()
        .map(|vote| (vote.signer(), vote.body().clone()));
    let tally = Tally::from_votes(
        DigestedLeader::new::<Sha256>(&leader),
        designated,
        fixture.codec,
    )
    .unwrap();
    let relabeled = Vqc::new(
        leader,
        tally,
        novoters,
        Vec::new(),
        lqc.signature().clone(),
        fixture.codec,
    )
    .unwrap();
    assert!(
        fixture
            .verifier
            .verify_vqc::<_, Sha256, _>(&mut test_rng(), &relabeled, &Sequential)
            .is_none()
    );
}

#[test]
fn same_period_kinds_stay_separated_for_every_suite() {
    for_each_suite!(same_period_kinds_stay_separated);
}

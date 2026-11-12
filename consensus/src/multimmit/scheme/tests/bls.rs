//! Registration, threshold material, and certificate verifiers of the BLS12-381 suites.

use super::*;
use commonware_cryptography::bls12381::primitives::{
    group::Share,
    ops::{self, sas},
};
use commonware_math::algebra::Additive;
use commonware_utils::ordered::Set;
use std::sync::Arc;

/// Returns the fixture's parameters and `count` identity keys in roster order.
fn setting(count: u32) -> (Arc<Parameters>, Vec<Ed25519PublicKey>) {
    let (config, identities) = protocol(count);
    (config.parameters().clone(), identities)
}

/// Returns the fixture's configuration and `count` identity keys in roster order.
fn protocol(count: u32) -> (Protocol<Digest>, Vec<Ed25519PublicKey>) {
    let config = keys::test_config(
        SEED,
        NAMESPACE,
        count,
        (0..count).map(Participant::new).collect(),
        PathLimits::new(2, 2),
    );
    let mut identities = (0..count)
        .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 1).public_key())
        .collect::<Vec<_>>();
    identities.sort();
    (config, identities)
}

/// Generates the shared registration and threshold-material tests of a BLS12-381 suite whose
/// ordinary keys come from `$keypair` and register with the proof `$prove`.
macro_rules! bls_family_tests {
    (
        $module:ident,
        $suite:ident,
        $keypair:ident,
        |$rng:ident, $identity:ident, $private:ident| $prove:expr
    ) => {
        mod $module {
            use super::*;

            type Suite<V> = $suite::Scheme<Ed25519PublicKey, V>;
            type Roster<V> = $suite::Roster<Ed25519PublicKey, V>;

            /// Independently generated material for one committee.
            struct Material<V: Variant> {
                parameters: Arc<Parameters>,
                roster: Roster<V>,
                da: bls12381::DealtSharing<V>,
                nullification: bls12381::DealtSharing<V>,
                keys: Vec<$suite::SignerKeys>,
            }

            impl<V: Variant> Material<V> {
                fn new(rng: &mut TestRng) -> Self {
                    let (parameters, identities) = setting(PARTICIPANTS);
                    let codec = parameters.codec_config();
                    let mut privates = Vec::new();
                    let input = identities
                        .iter()
                        .map(|identity| {
                            let (private, public) = $keypair::keypair::<_, V>(&mut *rng);
                            let proof = {
                                let $rng = &mut *rng;
                                let $identity = identity;
                                let $private = &private;
                                $prove
                            };
                            privates.push(private);
                            (identity.clone(), public, proof)
                        })
                        .collect();
                    let roster =
                        Roster::<V>::verify(NAMESPACE, PARTICIPANTS as usize, input, &Sequential)
                            .unwrap();
                    let da =
                        bls12381::deal_sharing::<V>(rng, PARTICIPANTS, codec.da_quorum() as u32);
                    let nullification = bls12381::deal_sharing::<V>(
                        rng,
                        PARTICIPANTS,
                        codec.nullification_quorum() as u32,
                    );
                    let keys = privates
                        .into_iter()
                        .enumerate()
                        .map(|(index, ordinary)| $suite::SignerKeys {
                            ordinary,
                            da: da.shares[index].clone(),
                            nullification: nullification.shares[index].clone(),
                        })
                        .collect();
                    Self {
                        parameters,
                        roster,
                        da,
                        nullification,
                        keys,
                    }
                }

                fn signer(&self, keys: $suite::SignerKeys) -> Result<Generic<Suite<V>>, Error> {
                    Suite::<V>::signer(
                        &self.parameters,
                        self.roster.clone(),
                        keys,
                        self.da.sharing.clone(),
                        self.nullification.sharing.clone(),
                    )
                }

                fn verifier(&self) -> Generic<Suite<V>> {
                    Suite::<V>::verifier(
                        &self.parameters,
                        self.roster.clone(),
                        self.da.sharing.clone(),
                        self.nullification.sharing.clone(),
                    )
                    .unwrap()
                }

                fn certificate_verifier(&self) -> Generic<Suite<V>> {
                    Suite::<V>::certificate_verifier(
                        &self.parameters,
                        self.roster.clone(),
                        *self.da.sharing.public(),
                        *self.nullification.sharing.public(),
                    )
                    .unwrap()
                }
            }

            fn registered_material_signs_what_every_verifier_accepts<V: Variant>() {
                let material = Material::<V>::new(&mut TestRng::new(1));
                let signers = material
                    .keys
                    .iter()
                    .map(|keys| material.signer(keys.clone()).unwrap())
                    .collect::<Vec<_>>();
                for (index, signer) in signers.iter().enumerate() {
                    assert_eq!(signer.me(), Some(Participant::from_usize(index)));
                    assert_eq!(signer.participants(), material.roster.participants());
                }
                let verifier = material.verifier();
                let certificate_verifier = material.certificate_verifier();
                assert_eq!(verifier.me(), None);
                assert_eq!(certificate_verifier.me(), None);
                let codec = material.parameters.codec_config();
                let epoch = material.parameters.epoch();
                let mut rng = test_rng();

                let header = TransactionBlockHeader::new(
                    epoch,
                    ChainId::new(0),
                    Height::new(1),
                    digest(b"parent", 1),
                    digest(b"commitment", 1),
                )
                .unwrap();
                let block = signers[0].sign_transaction_block(header.clone()).unwrap();
                let votes = signers
                    .iter()
                    .take(codec.da_quorum())
                    .map(|signer| signer.sign_da_vote(header.clone()).unwrap())
                    .collect::<Vec<_>>();
                let certificate = verifier
                    .assemble_da_certificate(&mut rng, &votes, &Sequential)
                    .unwrap();
                let round = Round::new(epoch, View::new(3));
                let shares = signers
                    .iter()
                    .take(codec.nullification_quorum())
                    .map(|signer| signer.sign_nullify(round).unwrap())
                    .collect::<Vec<_>>();
                let nullification = verifier
                    .assemble_nullification(&mut rng, &shares, &Sequential)
                    .unwrap();
                let novote = signers[1].sign_novote(round).unwrap();

                // The certificate verifier checks ordinary signatures and recovered
                // certificates, but cannot check or recover threshold shares.
                for scheme in [&verifier, &certificate_verifier] {
                    assert!(scheme.verify_transaction_block(&mut rng, &block, &Sequential));
                    assert!(scheme.verify_novote(&mut rng, &novote, &Sequential));
                    assert!(scheme.verify_da_certificate(&mut rng, &certificate, &Sequential));
                    assert!(scheme.verify_nullification(&mut rng, &nullification, &Sequential));
                }
                assert!(verifier.verify_da_vote(&mut rng, &votes[0], &Sequential));
                assert!(verifier.verify_nullify(&mut rng, &shares[0], &Sequential));
                assert!(!certificate_verifier.verify_da_vote(&mut rng, &votes[0], &Sequential));
                assert!(!certificate_verifier.verify_nullify(&mut rng, &shares[0], &Sequential));
                assert!(!certificate_verifier.precheck_da_vote(&votes[0]));
                assert_eq!(
                    certificate_verifier.verify_artifacts::<_, Sha256, Digest>(
                        &mut rng,
                        &[
                            &Artifact::DaVote(votes[0].clone()),
                            &Artifact::Nullify(shares[0].clone())
                        ],
                        &[],
                        &Sequential
                    ),
                    [false, false]
                );
                for verification in [
                    SignatureVerification::Checked,
                    SignatureVerification::Preverified,
                ] {
                    assert_eq!(
                        certificate_verifier
                            .assemble_da_certificate_with(
                                &mut rng,
                                &votes,
                                verification,
                                &Sequential
                            )
                            .unwrap_err(),
                        Error::SharingUnavailable
                    );
                    assert_eq!(
                        certificate_verifier
                            .assemble_nullification_with(
                                &mut rng,
                                &shares,
                                verification,
                                &Sequential
                            )
                            .unwrap_err(),
                        Error::SharingUnavailable
                    );
                }
                assert_eq!(
                    certificate_verifier
                        .assemble_da_certificate_optimistic(&mut rng, &votes, &Sequential)
                        .unwrap_err(),
                    DaRecoveryError::Scheme(Error::SharingUnavailable)
                );
            }

            /// A certificate verifier rejects every share without panicking, and otherwise
            /// reaches the verifier's verdicts on every artifact kind.
            fn certificate_verifiers_reject_shares_without_panicking<V: Variant>() {
                let material = Material::<V>::new(&mut TestRng::new(5));
                let (config, _) = protocol(PARTICIPANTS);
                let fixture = Fixture::<Suite<V>> {
                    codec: config.codec_config(),
                    round: Round::new(config.epoch(), View::new(7)),
                    tips: config.genesis().tips().to_vec(),
                    config,
                    signers: material
                        .keys
                        .iter()
                        .map(|keys| material.signer(keys.clone()).unwrap())
                        .collect(),
                    verifier: material.verifier(),
                };
                let certificate_verifier = material.certificate_verifier();
                let mut cohort =
                    crate::multimmit::scheme::tests::batch::signed_message_cohort(&fixture);
                let certificates =
                    crate::multimmit::scheme::tests::batch::certificate_cohort(&fixture);
                assert_eq!(cohort.individual, cohort.expected);
                assert_eq!(certificates.individual, certificates.expected);
                cohort.artifacts.extend(certificates.artifacts);
                cohort.expected.extend(certificates.expected);
                let artifacts = cohort.artifacts.iter().collect::<Vec<_>>();
                let expected = artifacts
                    .iter()
                    .zip(&cohort.expected)
                    .map(|(artifact, valid)| {
                        *valid && !matches!(artifact, Artifact::DaVote(_) | Artifact::Nullify(_))
                    })
                    .collect::<Vec<_>>();
                assert_eq!(
                    certificate_verifier.verify_artifacts::<_, Sha256, Digest>(
                        &mut test_rng(),
                        &artifacts,
                        &[],
                        &Sequential
                    ),
                    expected
                );
                let mut rng = test_rng();
                for artifact in &artifacts {
                    let verdict = match artifact {
                        Artifact::TransactionBlock(block) => certificate_verifier
                            .verify_transaction_block(&mut rng, block, &Sequential),
                        Artifact::DaVote(vote) => {
                            assert!(!certificate_verifier.precheck_da_vote(vote));
                            certificate_verifier.verify_da_vote(&mut rng, vote, &Sequential)
                        }
                        Artifact::DaCertificate(certificate) => certificate_verifier
                            .verify_da_certificate(&mut rng, certificate, &Sequential),
                        Artifact::LeaderBlock(block) => {
                            certificate_verifier.verify_leader_block(&mut rng, block, &Sequential)
                        }
                        Artifact::Vote(vote) => {
                            certificate_verifier.verify_vote(&mut rng, vote, &Sequential)
                        }
                        Artifact::NoVote(novote) => {
                            certificate_verifier.verify_novote(&mut rng, novote, &Sequential)
                        }
                        Artifact::Nullify(nullify) => {
                            certificate_verifier.verify_nullify(&mut rng, nullify, &Sequential)
                        }
                        Artifact::Nullification(nullification) => certificate_verifier
                            .verify_nullification(&mut rng, nullification, &Sequential),
                        Artifact::Vqc(certificate) => certificate_verifier
                            .verify_vqc::<_, Sha256, _>(&mut rng, certificate, &Sequential)
                            .is_some(),
                        Artifact::Lqc(certificate) => certificate_verifier
                            .verify_lqc::<_, Sha256, _>(&mut rng, certificate, &Sequential)
                            .is_some(),
                    };
                    let index = artifacts
                        .iter()
                        .position(|other| std::ptr::eq(*other, *artifact))
                        .unwrap();
                    assert_eq!(verdict, expected[index]);
                }
            }

            #[test]
            fn certificate_verifiers_reject_shares_without_panicking_for_both_variants() {
                certificate_verifiers_reject_shares_without_panicking::<MinPk>();
                certificate_verifiers_reject_shares_without_panicking::<MinSig>();
            }

            #[test]
            fn registered_material_signs_what_every_verifier_accepts_for_both_variants() {
                registered_material_signs_what_every_verifier_accepts::<MinPk>();
                registered_material_signs_what_every_verifier_accepts::<MinSig>();
            }

            fn signer_keys_must_match_the_roster_and_sharings<V: Variant>() {
                let material = Material::<V>::new(&mut TestRng::new(2));
                let mut rng = TestRng::new(8_888);
                let fresh_da = bls12381::deal_sharing::<V>(
                    &mut rng,
                    PARTICIPANTS,
                    material.parameters.codec_config().da_quorum() as u32,
                );
                let fresh_nullification = bls12381::deal_sharing::<V>(
                    &mut rng,
                    PARTICIPANTS,
                    material.parameters.codec_config().nullification_quorum() as u32,
                );

                // An ordinary key outside the roster.
                let (unlisted, _) = $keypair::keypair::<_, V>(&mut rng);
                let mut keys = material.keys[0].clone();
                keys.ordinary = unlisted;
                assert_eq!(material.signer(keys).unwrap_err(), Error::UnknownKey);

                // Shares of another participant.
                for (da, nullification) in [(1, 0), (0, 1)] {
                    let mut keys = material.keys[0].clone();
                    keys.da = material.da.shares[da].clone();
                    keys.nullification = material.nullification.shares[nullification].clone();
                    assert_eq!(material.signer(keys).unwrap_err(), Error::Share);
                }
                // Shares of another sharing at the right index.
                let mut keys = material.keys[0].clone();
                keys.da = fresh_da.shares[0].clone();
                assert_eq!(material.signer(keys).unwrap_err(), Error::Share);
                let mut keys = material.keys[0].clone();
                keys.nullification = fresh_nullification.shares[0].clone();
                assert_eq!(material.signer(keys).unwrap_err(), Error::Share);
                // A share claiming the right index with another participant's secret.
                let mut keys = material.keys[0].clone();
                keys.da = Share::new(Participant::new(0), material.da.shares[1].private.clone());
                assert_eq!(material.signer(keys).unwrap_err(), Error::Share);
            }

            #[test]
            fn signer_keys_must_match_the_roster_and_sharings_for_both_variants() {
                signer_keys_must_match_the_roster_and_sharings::<MinPk>();
                signer_keys_must_match_the_roster_and_sharings::<MinSig>();
            }

            fn threshold_material_must_fit_the_committee<V: Variant>() {
                let material = Material::<V>::new(&mut TestRng::new(3));
                let codec = material.parameters.codec_config();
                let mut rng = TestRng::new(8_889);
                let verifier = |da: &bls12381::DealtSharing<V>,
                                nullification: &bls12381::DealtSharing<V>| {
                    Suite::<V>::verifier(
                        &material.parameters,
                        material.roster.clone(),
                        da.sharing.clone(),
                        nullification.sharing.clone(),
                    )
                    .map(|_| ())
                };
                assert!(verifier(&material.da, &material.nullification).is_ok());
                // Wrong thresholds and wrong sizes.
                for (total, required) in [
                    (PARTICIPANTS, codec.view_quorum() as u32),
                    (PARTICIPANTS, codec.da_quorum() as u32 - 1),
                    (PARTICIPANTS + 1, codec.da_quorum() as u32),
                    (PARTICIPANTS - 1, codec.da_quorum() as u32),
                ] {
                    let wrong = bls12381::deal_sharing::<V>(&mut rng, total, required);
                    assert_eq!(
                        verifier(&wrong, &material.nullification).unwrap_err(),
                        Error::Sharing
                    );
                }
                let wrong = bls12381::deal_sharing::<V>(
                    &mut rng,
                    PARTICIPANTS,
                    codec.nullification_quorum() as u32 + 1,
                );
                assert_eq!(verifier(&material.da, &wrong).unwrap_err(), Error::Sharing);
                // Swapped sharings fit neither threshold here.
                assert_ne!(codec.da_quorum(), codec.nullification_quorum());
                assert_eq!(
                    verifier(&material.nullification, &material.da).unwrap_err(),
                    Error::Sharing
                );
                // One sharing for both roles.
                assert_eq!(
                    verifier(&material.da, &material.da).unwrap_err(),
                    Error::SharedIdentity
                );

                let certificate_verifier = |da: V::Public, nullification: V::Public| {
                    Suite::<V>::certificate_verifier(
                        &material.parameters,
                        material.roster.clone(),
                        da,
                        nullification,
                    )
                    .map(|_| ())
                };
                let da = *material.da.sharing.public();
                let nullification = *material.nullification.sharing.public();
                assert_eq!(
                    certificate_verifier(V::Public::zero(), nullification).unwrap_err(),
                    Error::Sharing
                );
                assert_eq!(
                    certificate_verifier(da, V::Public::zero()).unwrap_err(),
                    Error::Sharing
                );
                assert_eq!(
                    certificate_verifier(da, da).unwrap_err(),
                    Error::SharedIdentity
                );

                // A roster for another committee size.
                let (one, _) = setting(1);
                assert_eq!(
                    Suite::<V>::verifier(
                        &one,
                        material.roster.clone(),
                        material.da.sharing.clone(),
                        material.nullification.sharing.clone(),
                    )
                    .unwrap_err(),
                    Error::Participants
                );
                // In a committee of one, both quorums are one, so only distinct identities
                // separate the roles.
                let (_, identities) = setting(1);
                let (private, public) = $keypair::keypair::<_, V>(&mut rng);
                let proof = {
                    let $rng = &mut rng;
                    let $identity = &identities[0];
                    let $private = &private;
                    $prove
                };
                let roster = Roster::<V>::verify(
                    NAMESPACE,
                    1,
                    vec![(identities[0].clone(), public, proof)],
                    &Sequential,
                )
                .unwrap();
                let same = bls12381::deal_sharing::<V>(&mut rng, 1, 1);
                let keys = $suite::SignerKeys {
                    ordinary: private,
                    da: same.shares[0].clone(),
                    nullification: same.shares[0].clone(),
                };
                assert_eq!(
                    Suite::<V>::signer(&one, roster, keys, same.sharing.clone(), same.sharing)
                        .unwrap_err(),
                    Error::SharedIdentity
                );
            }

            #[test]
            fn threshold_material_must_fit_the_committee_for_both_variants() {
                threshold_material_must_fit_the_committee::<MinPk>();
                threshold_material_must_fit_the_committee::<MinSig>();
            }

            fn schemes_reject_rosters_from_other_namespaces<V: Variant>() {
                let material = Material::<V>::new(&mut TestRng::new(4));
                let codec = material.parameters.codec_config();
                for namespace in [
                    &NAMESPACE[..NAMESPACE.len() - 1],
                    b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_OTHER",
                ] {
                    let other = Arc::new(
                        Parameters::new(
                            material.parameters.epoch(),
                            namespace,
                            codec.participants(),
                            material.parameters.producers().to_vec(),
                            codec.limits(),
                        )
                        .unwrap(),
                    );
                    assert_eq!(
                        Suite::<V>::verifier(
                            &other,
                            material.roster.clone(),
                            material.da.sharing.clone(),
                            material.nullification.sharing.clone(),
                        )
                        .unwrap_err(),
                        Error::Namespace
                    );
                    assert_eq!(
                        Suite::<V>::certificate_verifier(
                            &other,
                            material.roster.clone(),
                            *material.da.sharing.public(),
                            *material.nullification.sharing.public(),
                        )
                        .unwrap_err(),
                        Error::Namespace
                    );
                    assert_eq!(
                        Suite::<V>::signer(
                            &other,
                            material.roster.clone(),
                            material.keys[0].clone(),
                            material.da.sharing.clone(),
                            material.nullification.sharing.clone(),
                        )
                        .unwrap_err(),
                        Error::Namespace
                    );
                }
            }

            #[test]
            fn schemes_reject_rosters_from_other_namespaces_for_both_variants() {
                schemes_reject_rosters_from_other_namespaces::<MinPk>();
                schemes_reject_rosters_from_other_namespaces::<MinSig>();
            }

            fn roster_binds_proofs_to_identities_and_namespaces<V: Variant>() {
                let mut rng = TestRng::new(4_244);
                let (_, identities) = setting(2);
                let entries = identities
                    .iter()
                    .map(|identity| {
                        let (private, public) = $keypair::keypair::<_, V>(&mut rng);
                        let proof = {
                            let $rng = &mut rng;
                            let $identity = identity;
                            let $private = &private;
                            $prove
                        };
                        (identity.clone(), public, proof)
                    })
                    .collect::<Vec<_>>();

                // Proofs verify for the identities they were made for, in any input order.
                let roster =
                    Roster::<V>::verify(NAMESPACE, 2, entries.clone(), &Sequential).unwrap();
                let reversed = Roster::<V>::verify(
                    NAMESPACE,
                    2,
                    entries.iter().rev().cloned().collect(),
                    &Sequential,
                )
                .unwrap();
                assert_eq!(roster.participants(), reversed.participants());
                assert_eq!(roster.public_keys(), reversed.public_keys());
                assert_eq!(
                    roster.participants(),
                    &Set::try_from(identities.clone()).unwrap()
                );

                // A key and proof registered under another identity is rejected.
                let swapped = vec![
                    (entries[0].0.clone(), entries[1].1, entries[1].2.clone()),
                    (entries[1].0.clone(), entries[0].1, entries[0].2.clone()),
                ];
                assert_eq!(
                    Roster::<V>::verify(NAMESPACE, 2, swapped, &Sequential).unwrap_err(),
                    Error::ProofOfKnowledge
                );
                // A proof made for another key is rejected.
                let crossed = vec![
                    (entries[0].0.clone(), entries[0].1, entries[1].2.clone()),
                    entries[1].clone(),
                ];
                assert_eq!(
                    Roster::<V>::verify(NAMESPACE, 2, crossed, &Sequential).unwrap_err(),
                    Error::ProofOfKnowledge
                );
                // A proof made under another namespace is rejected.
                assert_eq!(
                    Roster::<V>::verify(
                        b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_OTHER",
                        2,
                        entries.clone(),
                        &Sequential
                    )
                    .unwrap_err(),
                    Error::ProofOfKnowledge
                );

                // Bounds and duplicates.
                assert_eq!(
                    Roster::<V>::verify(NAMESPACE, 1, entries.clone(), &Sequential).unwrap_err(),
                    Error::Participants
                );
                assert_eq!(
                    Roster::<V>::verify(NAMESPACE, 3, entries.clone(), &Sequential).unwrap_err(),
                    Error::Participants
                );
                assert_eq!(
                    Roster::<V>::verify(NAMESPACE, 0, Vec::new(), &Sequential).unwrap_err(),
                    Error::Participants
                );
                assert_eq!(
                    Roster::<V>::verify(
                        NAMESPACE,
                        2,
                        vec![
                            entries[0].clone(),
                            (entries[0].0.clone(), entries[1].1, entries[1].2.clone()),
                        ],
                        &Sequential,
                    )
                    .unwrap_err(),
                    Error::DuplicateParticipant
                );
                assert_eq!(
                    Roster::<V>::verify(
                        NAMESPACE,
                        2,
                        vec![
                            entries[0].clone(),
                            (entries[1].0.clone(), entries[0].1, entries[0].2.clone()),
                        ],
                        &Sequential,
                    )
                    .unwrap_err(),
                    Error::DuplicateParticipant
                );
            }

            #[test]
            fn roster_binds_proofs_to_identities_for_both_variants() {
                roster_binds_proofs_to_identities_and_namespaces::<MinPk>();
                roster_binds_proofs_to_identities_and_namespaces::<MinSig>();
            }

            fn dealt_signers_sign_what_the_verifier_accepts<V: Variant>() {
                let (parameters, identities) = setting(PARTICIPANTS);
                let identities = Set::try_from(identities).unwrap();
                let dealt = Suite::<V>::deal(&mut test_rng(), &parameters, &identities).unwrap();
                assert_eq!(dealt.signers.len(), PARTICIPANTS as usize);
                assert_eq!(dealt.roster.participants(), &identities);
                for (index, signer) in dealt.signers.iter().enumerate() {
                    assert_eq!(signer.me(), Some(Participant::from_usize(index)));
                }
                let header = TransactionBlockHeader::new(
                    parameters.epoch(),
                    ChainId::new(0),
                    Height::new(1),
                    digest(b"parent", 1),
                    digest(b"commitment", 1),
                )
                .unwrap();
                let votes = (0..parameters.codec_config().da_quorum())
                    .map(|signer| dealt.signers[signer].sign_da_vote(header.clone()).unwrap())
                    .collect::<Vec<_>>();
                assert!(
                    dealt
                        .verifier
                        .assemble_da_certificate(&mut test_rng(), &votes, &Sequential)
                        .is_ok()
                );

                // Dealing requires exactly one identity per participant.
                let one = Set::try_from(vec![identities[0].clone()]).unwrap();
                assert!(matches!(
                    Suite::<V>::deal(&mut test_rng(), &parameters, &one),
                    Err(Error::Participants)
                ));
            }

            #[test]
            fn dealt_signers_sign_what_the_verifier_accepts_for_both_variants() {
                dealt_signers_sign_what_the_verifier_accepts::<MinPk>();
                dealt_signers_sign_what_the_verifier_accepts::<MinSig>();
            }
        }
    };
}

bls_family_tests!(multisig, bls12381, ops, |rng, identity, private| {
    let _ = rng;
    bls12381::Roster::<Ed25519PublicKey, V>::proof_of_possession(NAMESPACE, identity, private)
});

bls_family_tests!(synchronized, bls12381_sas, sas, |rng, identity, private| {
    bls12381_sas::Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
        rng, NAMESPACE, identity, private,
    )
});

fn multisig_roster_rejects_rogue_and_zero_keys<V: Variant>() {
    let mut rng = TestRng::new(4_242);
    let (_, identities) = setting(2);
    let (honest_private, honest_public) = ops::keypair::<_, V>(&mut rng);
    let (attacker_private, attacker_public) = ops::keypair::<_, V>(&mut rng);
    let rogue_public = attacker_public - &honest_public;

    // Without a proof of possession, the attacker alone produces a signature that verifies as
    // the aggregate of both keys on one message.
    let message = b"same vote";
    let signature = ops::sign_message::<V>(&attacker_private, NAMESPACE, message);
    assert!(
        ops::verify_message::<V>(
            &(honest_public + &rogue_public),
            NAMESPACE,
            message,
            &signature
        )
        .is_ok()
    );

    // The attacker cannot prove possession of the rogue key.
    let attacker_proof = bls12381::Roster::<Ed25519PublicKey, V>::proof_of_possession(
        NAMESPACE,
        &identities[1],
        &attacker_private,
    );
    let honest_proof = bls12381::Roster::<Ed25519PublicKey, V>::proof_of_possession(
        NAMESPACE,
        &identities[0],
        &honest_private,
    );
    assert_eq!(
        bls12381::Roster::<Ed25519PublicKey, V>::verify(
            NAMESPACE,
            2,
            vec![
                (identities[0].clone(), honest_public, honest_proof),
                (identities[1].clone(), rogue_public, attacker_proof),
            ],
            &Sequential,
        )
        .unwrap_err(),
        Error::ProofOfKnowledge
    );
    // The identity key has no proof that verifies.
    assert_eq!(
        bls12381::Roster::<Ed25519PublicKey, V>::verify(
            NAMESPACE,
            2,
            vec![
                (identities[0].clone(), honest_public, honest_proof),
                (
                    identities[1].clone(),
                    V::Public::zero(),
                    V::Signature::zero()
                ),
            ],
            &Sequential,
        )
        .unwrap_err(),
        Error::ProofOfKnowledge
    );
}

#[test]
fn multisig_roster_rejects_rogue_keys_for_both_variants() {
    multisig_roster_rejects_rogue_and_zero_keys::<MinPk>();
    multisig_roster_rejects_rogue_and_zero_keys::<MinSig>();
}

fn synchronized_roster_rejects_rogue_and_degenerate_keys<V: Variant>() {
    let mut rng = TestRng::new(4_242);
    let (_, identities) = setting(2);
    let (honest_private, honest_public) = sas::keypair::<_, V>(&mut rng);
    let (attacker_private, attacker_public) = sas::keypair::<_, V>(&mut rng);
    let rogue_public = sas::PublicKey::<V>::new(
        *attacker_public.x() - honest_public.x(),
        *attacker_public.y() - honest_public.y(),
    );

    // Without a proof of knowledge, the attacker alone produces an aggregate over both keys.
    let period = b"rogue-key-period";
    let namespace = b"rogue-key-vector";
    let message = b"same vote";
    let claim = sas::Claim::<V> {
        period,
        signature: sas::sign_message::<V>(&attacker_private, period, namespace, message),
        terms: vec![
            sas::Term {
                public: honest_public,
                namespace,
                message,
            },
            sas::Term {
                public: rogue_public,
                namespace,
                message,
            },
        ],
    };
    assert!(sas::verify_claims(&mut rng, &[claim], &Sequential).is_empty());

    // The attacker cannot prove knowledge of the rogue key's secrets.
    let honest = (
        identities[0].clone(),
        honest_public,
        bls12381_sas::Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
            &mut rng,
            NAMESPACE,
            &identities[0],
            &honest_private,
        ),
    );
    let attacker_proof = bls12381_sas::Roster::<Ed25519PublicKey, V>::proof_of_knowledge(
        &mut rng,
        NAMESPACE,
        &identities[1],
        &attacker_private,
    );
    assert_eq!(
        bls12381_sas::Roster::<Ed25519PublicKey, V>::verify(
            NAMESPACE,
            2,
            vec![
                honest.clone(),
                (identities[1].clone(), rogue_public, attacker_proof.clone()),
            ],
            &Sequential,
        )
        .unwrap_err(),
        Error::ProofOfKnowledge
    );
    // Keys with a zero component are rejected before their proofs are checked.
    for degenerate in [
        sas::PublicKey::<V>::new(V::Public::zero(), *attacker_public.y()),
        sas::PublicKey::<V>::new(*attacker_public.x(), V::Public::zero()),
    ] {
        assert_eq!(
            bls12381_sas::Roster::<Ed25519PublicKey, V>::verify(
                NAMESPACE,
                2,
                vec![
                    honest.clone(),
                    (identities[1].clone(), degenerate, attacker_proof.clone()),
                ],
                &Sequential,
            )
            .unwrap_err(),
            Error::ProofOfKnowledge
        );
    }
}

#[test]
fn roster_rejects_rogue_keys_for_both_variants() {
    synchronized_roster_rejects_rogue_and_degenerate_keys::<MinPk>();
    synchronized_roster_rejects_rogue_and_degenerate_keys::<MinSig>();
}

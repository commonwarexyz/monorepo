//! Data-availability quorum consistency between suites and epoch parameters.

use super::*;

#[test]
fn fault_models_match_the_codec_quorums() {
    for n in 1..=64usize {
        let available = CodecConfig::new(n, 1, PathLimits::new(1, 0)).unwrap();
        let binding = available.with_da_quorum(DaQuorum::Binding);
        assert_eq!(
            Available::quorum(n) as usize,
            available.da_quorum(),
            "n = {n}"
        );
        assert_eq!(Binding::quorum(n) as usize, binding.da_quorum(), "n = {n}");
        assert_eq!(Available::QUORUM, available.da_quorum_kind());
        assert_eq!(Binding::QUORUM, binding.da_quorum_kind());
        for codec in [available, binding] {
            assert_eq!(
                N5f1Nullification::quorum(n) as usize,
                codec.nullification_quorum(),
                "n = {n}"
            );
            assert_eq!(N5f1::quorum(n) as usize, codec.view_quorum(), "n = {n}");
            // A DA certificate always has a correct signer holding the block, and never needs
            // more than a view quorum.
            assert!(codec.da_quorum() > codec.max_faults(), "n = {n}");
            assert!(codec.da_quorum() <= codec.view_quorum(), "n = {n}");
        }
    }
}

/// Returns the fixture's parameters with DA certificates at `quorum`.
fn parameters(quorum: DaQuorum) -> std::sync::Arc<Parameters> {
    let config = keys::test_config(
        SEED,
        NAMESPACE,
        PARTICIPANTS,
        (0..PARTICIPANTS).map(Participant::new).collect(),
        PathLimits::new(2, 2),
    );
    std::sync::Arc::new(
        std::sync::Arc::unwrap_or_clone(config.parameters().clone()).with_da_quorum(quorum),
    )
}

fn identities() -> (
    Vec<Ed25519PrivateKey>,
    commonware_utils::ordered::Set<Ed25519PublicKey>,
) {
    let mut keys = (0..PARTICIPANTS)
        .map(|index| Ed25519PrivateKey::from_seed(u64::from(index) + 1))
        .collect::<Vec<_>>();
    keys.sort_by_key(|key| key.public_key());
    let set = commonware_utils::ordered::Set::try_from(
        keys.iter().map(|key| key.public_key()).collect::<Vec<_>>(),
    )
    .unwrap();
    (keys, set)
}

#[test]
fn ed25519_constructors_reject_a_mismatched_da_quorum() {
    let (keys, participants) = identities();
    for (quorum, matches) in [(DaQuorum::Available, true), (DaQuorum::Binding, false)] {
        let parameters = parameters(quorum);
        let verifier =
            ed25519_suite::Scheme::<Available>::verifier(&parameters, participants.clone());
        let signer = ed25519_suite::Scheme::<Available>::signer(
            &parameters,
            participants.clone(),
            keys[0].clone(),
        );
        let binding = ed25519_suite::Scheme::<Binding>::verifier(&parameters, participants.clone());
        if matches {
            assert!(verifier.is_ok() && signer.is_ok());
            assert_eq!(binding.unwrap_err(), Error::DaQuorum);
        } else {
            assert_eq!(verifier.unwrap_err(), Error::DaQuorum);
            assert_eq!(signer.unwrap_err(), Error::DaQuorum);
            assert!(binding.is_ok());
        }
    }
}

#[test]
fn generic_new_rejects_a_mismatched_da_quorum() {
    let (_, participants) = identities();
    let namespace = NAMESPACE;
    let available = parameters(DaQuorum::Available);
    let binding = parameters(DaQuorum::Binding);
    let roles = || {
        (
            ed25519_suite::ordinary::Scheme::verifier(namespace, participants.clone()),
            ed25519_suite::da::Scheme::verifier(namespace, participants.clone()),
            ed25519_suite::da_binding::Scheme::verifier(namespace, participants.clone()),
            ed25519_suite::nullify::Scheme::verifier(namespace, participants.clone()),
        )
    };
    let (ordinary, da, _, nullify) = roles();
    assert!(Generic::<Ed25519>::new(&available, ordinary, da, nullify).is_ok());
    let (ordinary, da, _, nullify) = roles();
    assert_eq!(
        Generic::<Ed25519>::new(&binding, ordinary, da, nullify).unwrap_err(),
        Error::DaQuorum
    );
    let (ordinary, _, da, nullify) = roles();
    assert!(Generic::<Ed25519<Binding>>::new(&binding, ordinary, da, nullify).is_ok());
    let (ordinary, _, da, nullify) = roles();
    assert_eq!(
        Generic::<Ed25519<Binding>>::new(&available, ordinary, da, nullify).unwrap_err(),
        Error::DaQuorum
    );

    // Roles over another committee size, or disagreeing on the local signer, are rejected.
    let (keys, _) = identities();
    let small = commonware_utils::ordered::Set::try_from(
        keys[..PARTICIPANTS as usize - 1]
            .iter()
            .map(|key| key.public_key())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert_eq!(
        Generic::<Ed25519>::new(
            &available,
            ed25519_suite::ordinary::Scheme::verifier(namespace, small),
            ed25519_suite::da::Scheme::verifier(namespace, participants.clone()),
            ed25519_suite::nullify::Scheme::verifier(namespace, participants.clone()),
        )
        .unwrap_err(),
        Error::Participants
    );
    assert_eq!(
        Generic::<Ed25519>::new(
            &available,
            ed25519_suite::ordinary::Scheme::signer(
                namespace,
                participants.clone(),
                keys[0].clone()
            )
            .unwrap(),
            ed25519_suite::da::Scheme::signer(namespace, participants.clone(), keys[1].clone())
                .unwrap(),
            ed25519_suite::nullify::Scheme::signer(
                namespace,
                participants.clone(),
                keys[0].clone()
            )
            .unwrap(),
        )
        .unwrap_err(),
        Error::Membership
    );
    assert_eq!(
        Generic::<Ed25519>::new(
            &available,
            ed25519_suite::ordinary::Scheme::signer(
                namespace,
                participants.clone(),
                keys[0].clone()
            )
            .unwrap(),
            ed25519_suite::da::Scheme::verifier(namespace, participants.clone()),
            ed25519_suite::nullify::Scheme::signer(namespace, participants, keys[0].clone())
                .unwrap(),
        )
        .unwrap_err(),
        Error::Membership
    );
}

/// Checks that a BLS-family suite at one DA quorum cannot be built over parameters at the
/// other, whichever material it is given.
macro_rules! bls_quorum_test {
    ($name:ident, $suite:ident) => {
        #[test]
        fn $name() {
            fn check<V: Variant>() {
                let (_, identities) = identities();
                let available = parameters(DaQuorum::Available);
                let binding = parameters(DaQuorum::Binding);
                let mut rng = TestRng::new(SEED);
                // Dealing for the matching quorum succeeds, and for the other fails.
                assert!(
                    $suite::Scheme::<Ed25519PublicKey, V, Available>::deal(
                        &mut rng,
                        &available,
                        &identities
                    )
                    .is_ok()
                );
                assert!(
                    $suite::Scheme::<Ed25519PublicKey, V, Binding>::deal(
                        &mut rng,
                        &binding,
                        &identities
                    )
                    .is_ok()
                );
                assert!(matches!(
                    $suite::Scheme::<Ed25519PublicKey, V, Available>::deal(
                        &mut rng,
                        &binding,
                        &identities
                    ),
                    Err(Error::DaQuorum)
                ));
                assert!(matches!(
                    $suite::Scheme::<Ed25519PublicKey, V, Binding>::deal(
                        &mut rng,
                        &available,
                        &identities
                    ),
                    Err(Error::DaQuorum)
                ));

                // Material dealt at one quorum, verified at the other.
                let dealt = $suite::Scheme::<Ed25519PublicKey, V, Binding>::deal(
                    &mut rng,
                    &binding,
                    &identities,
                )
                .unwrap();
                // The binding sharing fits the binding parameters, so only the suite's fault
                // model rejects it.
                assert_eq!(
                    $suite::Scheme::<Ed25519PublicKey, V, Available>::verifier(
                        &binding,
                        dealt.roster.clone(),
                        dealt.da.clone(),
                        dealt.nullification.clone(),
                    )
                    .unwrap_err(),
                    Error::DaQuorum
                );
                assert_eq!(
                    $suite::Scheme::<Ed25519PublicKey, V, Available>::certificate_verifier(
                        &binding,
                        dealt.roster.clone(),
                        *dealt.da.public(),
                        *dealt.nullification.public(),
                    )
                    .unwrap_err(),
                    Error::DaQuorum
                );
                // Under the available parameters the binding suite is rejected outright, and the
                // binding sharing has the wrong threshold for the available suite.
                assert_eq!(
                    $suite::Scheme::<Ed25519PublicKey, V, Binding>::verifier(
                        &available,
                        dealt.roster.clone(),
                        dealt.da.clone(),
                        dealt.nullification.clone(),
                    )
                    .unwrap_err(),
                    Error::DaQuorum
                );
                assert_eq!(
                    $suite::Scheme::<Ed25519PublicKey, V, Available>::verifier(
                        &available,
                        dealt.roster.clone(),
                        dealt.da.clone(),
                        dealt.nullification.clone(),
                    )
                    .unwrap_err(),
                    Error::Sharing
                );
            }
            check::<MinPk>();
            check::<MinSig>();
        }
    };
}

bls_quorum_test!(
    bls12381_constructors_reject_a_mismatched_da_quorum,
    bls12381
);
bls_quorum_test!(
    bls12381_sas_constructors_reject_a_mismatched_da_quorum,
    bls12381_sas
);

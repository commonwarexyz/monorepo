//! Key-material and configuration checks in the scheme constructors.

use super::*;

fn schemes_check_roster_against_parameters<V: Variant>() {
    let committee = test_committee::<V>();
    let config = &committee.config;
    let codec = config.codec_config();
    let other = Protocol::new(
        b"_COMMONWARE_CONSENSUS_MULTIMMIT_TEST_OTHER",
        codec.participants(),
        config.producers().to_vec(),
        codec.window(),
        config.genesis().clone(),
    )
    .unwrap();
    assert_eq!(
        Scheme::verifier(other.parameters(), committee.roster.clone()).unwrap_err(),
        Error::Namespace
    );
    assert_eq!(
        Scheme::signer(
            other.parameters(),
            committee.roster.clone(),
            committee.privates[0].clone()
        )
        .unwrap_err(),
        Error::Namespace
    );

    let larger = Committee::<V>::builder(SEED, PARTICIPANTS + 1)
        .namespace(NAMESPACE)
        .build();
    assert_eq!(
        Scheme::verifier(larger.config.parameters(), committee.roster.clone()).unwrap_err(),
        Error::Participants
    );

    let (stranger, _) = ops::keypair::<_, V>(&mut TestRng::new(77));
    assert_eq!(
        Scheme::signer(config.parameters(), committee.roster.clone(), stranger).unwrap_err(),
        Error::UnknownKey
    );
}

both_variants!(
    schemes_check_roster_against_parameters_for_both_variants,
    schemes_check_roster_against_parameters
);

fn roles_expose_only_their_material<V: Variant>() {
    let committee = test_committee::<V>();
    for (index, signer) in committee.signers.iter().enumerate() {
        assert_eq!(signer.me(), Some(Participant::from_usize(index)));
        assert_eq!(signer.namespace, Namespace::new(NAMESPACE));
    }
    assert_eq!(committee.verifier.me(), None);
    assert_eq!(
        committee.verifier.participants().len(),
        PARTICIPANTS as usize
    );
    let content = varied(&committee, View::new(1), None, false, 0);
    assert_eq!(
        committee.verifier.sign_vote(&content).unwrap_err(),
        Error::VerifierOnly
    );
    let leader = committee.leader_block(View::new(1)).block().clone();
    assert_eq!(
        committee.verifier.sign_leader_block(leader).unwrap_err(),
        Error::VerifierOnly
    );
}

both_variants!(
    roles_expose_only_their_material_for_both_variants,
    roles_expose_only_their_material
);

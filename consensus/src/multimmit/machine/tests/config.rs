//! Machine construction under extreme profile bounds.

use crate::multimmit::{
    config::{Error as ConfigError, Profile, Role, Tuning},
    machine::{CoreState, reducer::machine::Machine, testing::fixtures::TestConfig},
};
use commonware_cryptography::{Sha256, bls12381::primitives::variant::MinPk};
use std::num::NonZeroUsize;

#[test]
fn extreme_accepted_artifact_ceiling_does_not_preallocate_scratch() {
    let protocol = TestConfig::new(6).depth(1).extensions(0).build();
    let tuning = |limit| Tuning {
        max_artifact_bytes: NonZeroUsize::new(limit),
        ..Tuning::default()
    };
    let Err(ConfigError::ArtifactByteLimitTooLarge { max, .. }) =
        Profile::new::<MinPk>(protocol.clone(), Role::Observer, tuning(usize::MAX))
    else {
        panic!("an overflowing artifact ceiling was accepted");
    };
    let profile = Profile::new::<MinPk>(protocol, Role::Observer, tuning(max))
        .expect("the artifact ceiling is a bound, not an eager allocation request");

    // The core derives its lane byte budgets from the largest accepted ceiling without overflow.
    CoreState::<Sha256, MinPk>::fresh(profile.clone()).expect("core lane budgets fit");
    let machine = Machine::<Sha256, MinPk>::new(profile);
    assert!(machine.store.id_scratch.is_empty());
    assert_eq!(machine.store.id_scratch.capacity(), 0);
}

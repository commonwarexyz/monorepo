use super::*;
use crate::{
    multimmit::{
        config::Limits,
        machine::Machine,
        types::{BlockRef, CertificateId, ChainId, EpochGenesis, Height},
    },
    types::{Epoch, ViewDelta},
};
use commonware_cryptography::{
    Hasher, Sha256,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    sha256::Digest as Sha256Digest,
};
use commonware_utils::N5f1;
use std::num::NonZeroUsize;

const NAMESPACE: &[u8] = b"_COMMONWARE_CONSENSUS_MULTIMMIT_PROFILE_TEST";

fn protocol(participants: u32) -> Config<Sha256Digest> {
    protocol_with_limits(participants, Limits::new(1, 0).unwrap())
}

fn protocol_with_limits(participants: u32, limits: Limits) -> Config<Sha256Digest> {
    let epoch = Epoch::new(7);
    let tips = (0..participants)
        .map(|chain| {
            BlockRef::new(
                ChainId::new(chain),
                Height::zero(),
                Sha256::hash(&[&chain.to_be_bytes()]),
            )
        })
        .collect();
    let genesis = EpochGenesis::new(
        epoch,
        Sha256::hash(&[b"leader genesis"]),
        CertificateId::new(Sha256::hash(&[b"vqc genesis"])),
        CertificateId::new(Sha256::hash(&[b"lqc genesis"])),
        tips,
    )
    .unwrap();

    Config::new(
        epoch,
        NAMESPACE,
        participants as usize,
        (0..participants).map(Participant::new).collect(),
        limits,
        genesis,
    )
    .unwrap()
}

fn tuning(view_retention: u64) -> Tuning {
    Tuning {
        view_retention: ViewDelta::new(view_retention),
        ..Tuning::default()
    }
}

fn profile(participants: u32, view_retention: u64) -> Result<Profile<Sha256, MinPk>, ProfileError> {
    Profile::new(
        protocol(participants),
        Role::Observer,
        tuning(view_retention),
    )
}

fn assert_artifact_byte_limit<V: Variant>() {
    let protocol = protocol_with_limits(11, Limits::new(3, 2).unwrap());
    let required = protocol
        .codec_config()
        .encoded_bounds::<V, Sha256Digest>()
        .unwrap()
        .max_artifact_bytes();
    let exact = NonZeroUsize::new(required).unwrap();

    let profile = Profile::<Sha256, V>::new(
        protocol.clone(),
        Role::Observer,
        Tuning {
            max_artifact_bytes: exact,
            ..tuning(64)
        },
    )
    .expect("the exact derived artifact bound is accepted");
    assert_eq!(profile.resources().max_artifact_bytes(), required);

    let actual = required - 1;
    let error = Profile::<Sha256, V>::new(
        protocol,
        Role::Observer,
        Tuning {
            max_artifact_bytes: NonZeroUsize::new(actual).unwrap(),
            ..tuning(64)
        },
    )
    .unwrap_err();
    assert_eq!(
        error,
        ProfileError::ArtifactByteLimitTooSmall { required, actual }
    );
}

#[test]
fn every_committee_and_retention_window_yields_a_valid_profile() {
    // Internal bounds are derived, so an operator cannot express a manifest the machine rejects.
    // If that ever stops holding, this fails for the exact shape that broke it.
    for participants in [1u32, 2, 5, 6, 7, 11, 16, 32, 64] {
        for view_retention in [1u64, 2, 64, 1_000, 50_000, 1_000_000] {
            let profile = profile(participants, view_retention);
            assert!(
                profile.is_ok(),
                "derived profile rejected for participants={participants} \
                 retention={view_retention}: {:?}",
                profile.err()
            );
        }
    }
}

#[test]
fn zero_retention_is_rejected() {
    assert_eq!(profile(6, 0).unwrap_err(), ProfileError::ZeroViewRetention);
}

#[test]
fn production_profiles_enforce_the_exact_artifact_byte_bound_for_both_variants() {
    assert_artifact_byte_limit::<MinPk>();
    assert_artifact_byte_limit::<MinSig>();
}

#[test]
fn explicit_test_limits_allow_an_undersized_artifact_byte_bound() {
    let protocol = protocol(6);
    let tuning = tuning(64);
    let derived = Profile::<Sha256, MinPk>::new(protocol.clone(), Role::Observer, tuning)
        .unwrap()
        .resources();
    let resources = ResourceLimits {
        max_artifact_bytes: NonZeroUsize::new(1).unwrap(),
        ..derived
    };

    let profile =
        Profile::<Sha256, MinPk>::with_limits(protocol, Role::Observer, tuning, resources).unwrap();
    assert_eq!(profile.resources().max_artifact_bytes(), 1);
}

#[test]
fn extreme_accepted_artifact_ceiling_does_not_preallocate_scratch() {
    let profile = Profile::<Sha256, MinPk>::new(
        protocol(6),
        Role::Observer,
        Tuning {
            max_artifact_bytes: NonZeroUsize::new(usize::MAX).unwrap(),
            ..tuning(64)
        },
    )
    .expect("the artifact ceiling is a bound, not an eager allocation request");

    let machine = Machine::new(profile);
    assert!(machine.artifact_id_scratch.is_empty());
    assert_eq!(machine.artifact_id_scratch.capacity(), 0);
}

#[test]
fn explicit_test_limits_cover_pinned_and_live_finality_partitions() {
    let protocol = protocol(6);
    let tuning = tuning(2);
    let derived = Profile::<Sha256, MinPk>::new(protocol.clone(), Role::Observer, tuning)
        .unwrap()
        .resources();
    let pinned = 3 + derived.max_future_view_distance() as usize;
    let required = pinned + 2;
    let resources = derived.with_max_finality_pools(NonZeroUsize::new(required - 1).unwrap());

    assert_eq!(
        Profile::<Sha256, MinPk>::with_limits(protocol, Role::Observer, tuning, resources)
            .unwrap_err(),
        ProfileError::FinalityPoolCapacityTooSmall {
            required,
            actual: required - 1,
        }
    );
}

#[test]
fn derived_bounds_cover_the_retention_window() {
    // The two relationships the machine depends on: one cache slot per retained view on top of a
    // quorum of live work, and one forwarded V-QC plus one forwarded nullification per retained
    // view.
    for participants in [1u32, 6, 11, 32] {
        for view_retention in [1u64, 64, 10_000] {
            let profile = profile(participants, view_retention).expect("derived profile is valid");
            let resources = profile.resources();
            let quorum = N5f1::l_quorum(participants as usize) as usize;
            let retained = view_retention as usize + 1;
            assert!(
                resources.max_cached_artifacts() >= quorum + 3 + retained,
                "cache does not cover live work plus the retention window \
                 (participants={participants}, retention={view_retention})"
            );
            assert!(
                resources.max_forwarded_certificates() >= 2 * retained,
                "forwarding history does not cover the retention window \
                 (participants={participants}, retention={view_retention})"
            );
            assert_eq!(profile.view_retention(), ViewDelta::new(view_retention));
        }
    }
}

#[test]
fn tuning_is_carried_through_verbatim() {
    let profile = Profile::<Sha256, MinPk>::new(
        protocol(6),
        Role::Observer,
        Tuning {
            view_timeout: Duration::from_millis(750),
            production_interval: Duration::from_millis(25),
            ..tuning(128)
        },
    )
    .expect("derived profile is valid");
    assert_eq!(profile.timers().view_timeout(), Duration::from_millis(750));
    assert_eq!(
        profile.timers().production_interval(),
        Duration::from_millis(25)
    );
    assert_eq!(profile.view_retention(), ViewDelta::new(128));
}

#[test]
fn zero_duration_timers_are_rejected() {
    for (tuning, expected) in [
        (
            Tuning {
                view_timeout: Duration::ZERO,
                ..tuning(64)
            },
            ProfileError::ZeroViewTimeout,
        ),
        (
            Tuning {
                production_interval: Duration::ZERO,
                ..tuning(64)
            },
            ProfileError::ZeroProductionInterval,
        ),
    ] {
        assert_eq!(
            Profile::<Sha256, MinPk>::new(protocol(6), Role::Observer, tuning).unwrap_err(),
            expected
        );
    }
}

#[test]
fn validator_must_be_a_committee_member() {
    let outside = Role::Validator(Participant::new(6));
    assert!(matches!(
        Profile::<Sha256, MinPk>::new(protocol(6), outside, tuning(64)),
        Err(ProfileError::ValidatorOutOfRange(participant)) if participant == Participant::new(6)
    ));
}

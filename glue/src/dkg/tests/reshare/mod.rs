use crate::simulate::{action::Crash, exit::ProcessedHeightAtLeast, plan::PlanBuilder};
use commonware_consensus::types::{Epoch, FixedEpocher};
use commonware_cryptography::{bls12381::primitives::sharing::Mode, ed25519};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::simulated::Link;
use std::time::Duration;

mod harness;
use harness::{final_height, height_round, ReshareEngine, EPOCH_LENGTH};

mod properties;
use properties::{
    AllActiveProcessedHeight, AllNodesRecovered, BoundaryEpochInfos, BoundaryOutputMode,
    EpochInfoContinuity, FailedCeremonyCarryOver, SchemesRegistered, SignerRegistered,
    StateSyncMembership, StateSyncedAtHeight, StateSyncedSigner,
};

fn reshare_plan_with_boundary(
    engine: ReshareEngine,
    final_epoch: u64,
    boundary: BoundaryEpochInfos,
) -> PlanBuilder<ReshareEngine> {
    let schedule = engine.schedule.clone();
    PlanBuilder::new(engine)
        .seed(0)
        .exit_condition(ProcessedHeightAtLeast::new(final_height(final_epoch).get()))
        .property(SignerRegistered)
        .property(boundary)
        .property(EpochInfoContinuity::new(final_epoch + 1, schedule))
        .timeout(Duration::from_secs(60))
}

fn successful_reshare_plan(engine: ReshareEngine, final_epoch: u64) -> PlanBuilder<ReshareEngine> {
    reshare_plan_with_boundary(
        engine,
        final_epoch,
        BoundaryEpochInfos::new(final_epoch + 1).with_no_reveals(),
    )
}

fn successful_reshare_plan_with_schemes(
    engine: ReshareEngine,
    final_epoch: u64,
) -> PlanBuilder<ReshareEngine> {
    reshare_plan_with_schemes(
        engine,
        final_epoch,
        BoundaryEpochInfos::new(final_epoch + 1).with_no_reveals(),
    )
}

fn reshare_plan_with_schemes(
    engine: ReshareEngine,
    final_epoch: u64,
    boundary: BoundaryEpochInfos,
) -> PlanBuilder<ReshareEngine> {
    let participants = engine.participants.clone();
    with_scheme_properties(
        reshare_plan_with_boundary(engine, final_epoch, boundary),
        participants,
        Epoch::new(1),
        Epoch::new(final_epoch + 1),
    )
}

fn with_scheme_properties(
    mut plan: PlanBuilder<ReshareEngine>,
    participants: Vec<ed25519::PublicKey>,
    first: Epoch,
    last: Epoch,
) -> PlanBuilder<ReshareEngine> {
    for epoch in first.get()..=last.get() {
        plan = plan.property(SchemesRegistered::new(
            participants.clone(),
            Epoch::new(epoch),
        ));
    }
    plan
}

fn failed_carry_over_plan(
    engine: ReshareEngine,
    final_epoch: u64,
    boundary: BoundaryEpochInfos,
    failed_epochs: impl IntoIterator<Item = Epoch>,
) -> PlanBuilder<ReshareEngine> {
    let schedule = (*engine.schedule).clone();
    let mut plan = reshare_plan_with_boundary(engine, final_epoch, boundary);
    for epoch in failed_epochs {
        plan = plan.property(FailedCeremonyCarryOver::new(epoch, schedule.clone()));
    }
    plan
}

fn state_sync_next_player_plan(
    engine: ReshareEngine,
    final_epoch: u64,
    delayed_index: usize,
    next_player_epoch: Epoch,
    signer_epoch: Epoch,
    boundary: BoundaryEpochInfos,
) -> PlanBuilder<ReshareEngine> {
    let delayed = engine.participants[delayed_index].clone();
    let midpoint = FixedEpocher::new(EPOCH_LENGTH)
        .midpoint(next_player_epoch)
        .expect("test epoch should be supported");
    let sync_floor = midpoint
        .previous()
        .expect("midpoint must have a sync floor");
    let registrations = engine.registrations.clone();
    let state_syncs = engine.state_syncs.clone();
    let schedule = engine.schedule.clone();
    reshare_plan_with_boundary(engine, final_epoch, boundary)
        .crash(Crash::DelayRound {
            participants: vec![delayed.clone()],
            round: height_round(midpoint),
        })
        .property(StateSyncMembership::new(
            schedule,
            delayed.clone(),
            next_player_epoch,
        ))
        .property(StateSyncedAtHeight::new(
            delayed.clone(),
            sync_floor,
            final_height(next_player_epoch.get()),
            state_syncs.clone(),
        ))
        .property(StateSyncedSigner::new(
            delayed,
            signer_epoch,
            registrations,
            state_syncs,
        ))
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_deterministic() {
    let first = successful_reshare_plan(ReshareEngine::new(), 1)
        .run()
        .unwrap()
        .pop()
        .unwrap()
        .state;
    let second = successful_reshare_plan(ReshareEngine::new(), 1)
        .run()
        .unwrap()
        .pop()
        .unwrap()
        .state;
    assert_eq!(first, second);
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_deterministic_multiple_seeds() {
    for seed in 0..3 {
        let first = successful_reshare_plan(ReshareEngine::new(), 1)
            .seed(seed)
            .run()
            .unwrap()
            .pop()
            .unwrap()
            .state;
        let second = successful_reshare_plan(ReshareEngine::new(), 1)
            .seed(seed)
            .run()
            .unwrap()
            .pop()
            .unwrap()
            .state;
        assert_eq!(first, second);
    }
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_single_participant_two_epochs() {
    successful_reshare_plan_with_schemes(ReshareEngine::with_committee(1, 1), 1)
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_rotates_participants() {
    successful_reshare_plan_with_schemes(ReshareEngine::new(), 0)
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_roots_of_unity_output() {
    successful_reshare_plan_with_schemes(
        ReshareEngine::new().with_sharing_mode(Mode::RootsOfUnity),
        0,
    )
    .property(BoundaryOutputMode::new(
        Epoch::zero(),
        Mode::RootsOfUnity as u8,
    ))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs() {
    successful_reshare_plan_with_schemes(ReshareEngine::new(), 4)
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs_rotating_subset() {
    successful_reshare_plan_with_schemes(ReshareEngine::with_committee(7, 4), 4)
        .timeout(Duration::from_secs(90))
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_failed_ceremony_carries_committee() {
    failed_carry_over_plan(
        ReshareEngine::new().with_failures([0]),
        0,
        BoundaryEpochInfos::new(1).with_min_successes(0),
        [Epoch::zero()],
    )
    .timeout(Duration::from_secs(60))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_consecutive_failed_ceremonies_carry_state() {
    failed_carry_over_plan(
        ReshareEngine::new().with_failures([0, 1]),
        2,
        BoundaryEpochInfos::new(3)
            .with_min_successes(1)
            .with_no_reveals(),
        [Epoch::zero(), Epoch::new(1)],
    )
    .timeout(Duration::from_secs(90))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_many_failed_ceremonies_carry_state() {
    failed_carry_over_plan(
        ReshareEngine::with_committees(8, vec![4, 5]).with_failures([0, 2, 3]),
        4,
        BoundaryEpochInfos::new(5)
            .with_min_successes(2)
            .with_no_reveals(),
        [Epoch::zero(), Epoch::new(2), Epoch::new(3)],
    )
    .timeout(Duration::from_secs(120))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_four_epochs_changing_size() {
    successful_reshare_plan_with_schemes(ReshareEngine::with_committees(8, vec![4, 5, 6, 7, 4]), 4)
        .run()
        .unwrap();
}

fn crash_storm_plan(
    engine: ReshareEngine,
    final_epoch: u64,
    crash: Crash<ed25519::PublicKey>,
) -> PlanBuilder<ReshareEngine> {
    let participants = engine.participants.clone();
    let target_height = final_height(final_epoch);
    successful_reshare_plan_with_schemes(engine, final_epoch)
        .crash(crash)
        .exit_condition(AllActiveProcessedHeight::new(
            target_height,
            participants.len(),
        ))
        .property(AllNodesRecovered::new(participants))
        .timeout(Duration::from_secs(120))
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs_with_random_crashes() {
    for seed in 0..3 {
        crash_storm_plan(
            ReshareEngine::new(),
            4,
            Crash::Random {
                frequency: Duration::from_secs(2),
                downtime: Duration::from_millis(750),
                count: 1,
            },
        )
        .seed(seed)
        .timeout(Duration::from_secs(180))
        .run()
        .unwrap();
    }
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs_with_many_random_crashes() {
    crash_storm_plan(
        ReshareEngine::new(),
        4,
        Crash::Random {
            frequency: Duration::from_secs(2),
            downtime: Duration::from_millis(750),
            count: 3,
        },
    )
    .timeout(Duration::from_secs(360))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs_with_total_shutdown() {
    crash_storm_plan(
        ReshareEngine::new(),
        3,
        Crash::Random {
            frequency: Duration::from_secs(3),
            downtime: Duration::from_secs(1),
            count: 5,
        },
    )
    .timeout(Duration::from_secs(180))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_next_player() {
    let next_player_epoch = Epoch::new(1);
    state_sync_next_player_plan(
        ReshareEngine::with_committee(6, 4),
        3,
        5,
        next_player_epoch,
        next_player_epoch.next(),
        BoundaryEpochInfos::new(4),
    )
    .timeout(Duration::from_secs(120))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_epoch_zero_next_player() {
    let next_player_epoch = Epoch::zero();
    state_sync_next_player_plan(
        ReshareEngine::new(),
        2,
        4,
        next_player_epoch,
        next_player_epoch.next(),
        BoundaryEpochInfos::new(3).with_no_reveals(),
    )
    .timeout(Duration::from_secs(120))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_next_player_after_failed_ceremony() {
    let engine = ReshareEngine::with_committee(6, 4).with_failures([1]);
    let next_player_epoch = Epoch::new(1);
    let schedule = (*engine.schedule).clone();
    state_sync_next_player_plan(
        engine,
        3,
        5,
        next_player_epoch,
        Epoch::new(3),
        BoundaryEpochInfos::new(4)
            .with_expected_failures([next_player_epoch.get()])
            .with_no_reveals(),
    )
    .property(FailedCeremonyCarryOver::new(next_player_epoch, schedule))
    .timeout(Duration::from_secs(180))
    .run()
    .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_rotating_subset() {
    successful_reshare_plan_with_schemes(ReshareEngine::with_committee(7, 4), 0)
        .run()
        .unwrap();
}

#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_lossy_network() {
    reshare_plan_with_boundary(
        ReshareEngine::new(),
        4,
        BoundaryEpochInfos::new(5)
            .with_min_successes(1)
            .with_no_reveals(),
    )
    .link(Link {
        latency: Duration::from_millis(100),
        jitter: Duration::from_millis(50),
        success_rate: 0.7,
    })
    .timeout(Duration::from_secs(720))
    .run()
    .unwrap();
}

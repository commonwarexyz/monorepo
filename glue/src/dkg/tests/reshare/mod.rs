use crate::{
    simulate::{action::Crash, exit::ProcessedHeightAtLeast, plan::PlanBuilder},
    stateful::PruneConfig,
};
use commonware_consensus::types::{Epoch, Epocher, FixedEpocher, Height};
use commonware_cryptography::{bls12381::primitives::sharing::Mode, ed25519};
use commonware_macros::{test_group, test_traced};
use commonware_p2p::simulated::Link;
use commonware_utils::probability;
use rstest::rstest;
use std::time::Duration;

mod harness;
use harness::{
    EPOCH_LENGTH, MIN_RETENTION_PRUNING, Network, ReshareEngine, final_height, height_round,
};

mod properties;
use properties::{
    AllActiveProcessedHeight, AllNodesRecovered, BoundaryEpochInfos, BoundaryOutputMode,
    EpochInfoContinuity, FailedCeremonyCarryOver, NotarizedInEpoch, SchemesRegistered,
    SignerRegistered, StateSyncMembership, StateSyncedAtHeight, StateSyncedSigner,
    ValidatorsProcessedHeight,
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
    let midpoint = FixedEpocher::new(EPOCH_LENGTH)
        .midpoint(next_player_epoch)
        .expect("test epoch should be supported");
    state_sync_next_player_plan_starting_at(
        engine,
        final_epoch,
        delayed_index,
        midpoint,
        next_player_epoch,
        signer_epoch,
        boundary,
    )
}

fn state_sync_next_player_plan_starting_at(
    engine: ReshareEngine,
    final_epoch: u64,
    delayed_index: usize,
    start_height: Height,
    next_player_epoch: Epoch,
    signer_epoch: Epoch,
    boundary: BoundaryEpochInfos,
) -> PlanBuilder<ReshareEngine> {
    let delayed = engine.participants[delayed_index].clone();
    let configured_floor = engine.state_sync_floor();
    let sync_floor = configured_floor.unwrap_or_else(|| {
        // Entering the delayed round does not prove the preceding height is finalized.
        FixedEpocher::new(EPOCH_LENGTH)
            .first(next_player_epoch)
            .expect("test epoch should be supported")
    });
    let max_sync_floor = configured_floor.unwrap_or_else(|| final_height(next_player_epoch.get()));
    let registrations = engine.registrations.clone();
    let state_syncs = engine.state_syncs.clone();
    let schedule = engine.schedule.clone();
    reshare_plan_with_boundary(engine, final_epoch, boundary)
        .crash(Crash::DelayRound {
            participants: vec![delayed.clone()],
            round: height_round(start_height),
        })
        .property(StateSyncMembership::new(
            schedule,
            delayed.clone(),
            next_player_epoch,
        ))
        .property(StateSyncedAtHeight::new(
            delayed.clone(),
            sync_floor,
            max_sync_floor,
            state_syncs.clone(),
        ))
        .property(StateSyncedSigner::new(
            delayed,
            signer_epoch,
            registrations,
            state_syncs,
        ))
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_deterministic(#[case] network: Network) {
    let first = successful_reshare_plan(ReshareEngine::new(network), 1)
        .run()
        .unwrap()
        .pop()
        .unwrap()
        .state;
    let second = successful_reshare_plan(ReshareEngine::new(network), 1)
        .run()
        .unwrap()
        .pop()
        .unwrap()
        .state;
    assert_eq!(first, second);
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_deterministic_multiple_seeds(#[case] network: Network) {
    for seed in 0..3 {
        let first = successful_reshare_plan(ReshareEngine::new(network), 1)
            .seed(seed)
            .run()
            .unwrap()
            .pop()
            .unwrap()
            .state;
        let second = successful_reshare_plan(ReshareEngine::new(network), 1)
            .seed(seed)
            .run()
            .unwrap()
            .pop()
            .unwrap()
            .state;
        assert_eq!(first, second);
    }
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_single_participant_two_epochs(#[case] network: Network) {
    successful_reshare_plan_with_schemes(ReshareEngine::with_committee(network, 1, 1), 1)
        .run()
        .unwrap();
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_rotates_participants(#[case] network: Network) {
    successful_reshare_plan_with_schemes(ReshareEngine::new(network), 0)
        .run()
        .unwrap();
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_roots_of_unity_output(#[case] network: Network) {
    successful_reshare_plan_with_schemes(
        ReshareEngine::new(network).with_sharing_mode(Mode::RootsOfUnity),
        0,
    )
    .property(BoundaryOutputMode::new(
        Epoch::zero(),
        Mode::RootsOfUnity as u8,
    ))
    .run()
    .unwrap();
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs(#[case] network: Network) {
    successful_reshare_plan_with_schemes(ReshareEngine::new(network), 4)
        .run()
        .unwrap();
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs_rotating_subset(#[case] network: Network) {
    successful_reshare_plan_with_schemes(ReshareEngine::with_committee(network, 7, 4), 4)
        .timeout(Duration::from_secs(90))
        .run()
        .unwrap();
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_failed_ceremony_carries_committee(#[case] network: Network) {
    failed_carry_over_plan(
        ReshareEngine::new(network).with_failures([0]),
        0,
        BoundaryEpochInfos::new(1).with_min_successes(0),
        [Epoch::zero()],
    )
    .timeout(Duration::from_secs(60))
    .run()
    .unwrap();
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_consecutive_failed_ceremonies_carry_state(#[case] network: Network) {
    failed_carry_over_plan(
        ReshareEngine::new(network).with_failures([0, 1]),
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

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_many_failed_ceremonies_carry_state(#[case] network: Network) {
    failed_carry_over_plan(
        ReshareEngine::with_committees(network, 8, vec![4, 5]).with_failures([0, 2, 3]),
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

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_four_epochs_changing_size(#[case] network: Network) {
    successful_reshare_plan_with_schemes(
        ReshareEngine::with_committees(network, 8, vec![4, 5, 6, 7, 4]),
        4,
    )
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
    reshare_plan_with_schemes(
        engine,
        final_epoch,
        BoundaryEpochInfos::new(final_epoch + 1),
    )
    .crash(crash)
    .exit_condition(AllActiveProcessedHeight::new(
        target_height,
        participants.len(),
    ))
    .property(AllNodesRecovered::new(participants))
    .timeout(Duration::from_secs(120))
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs_with_random_crashes(#[case] network: Network) {
    for seed in 0..3 {
        crash_storm_plan(
            ReshareEngine::new(network),
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

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs_with_many_random_crashes(#[case] network: Network) {
    crash_storm_plan(
        ReshareEngine::new(network),
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

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_multiple_epochs_with_total_shutdown(#[case] network: Network) {
    crash_storm_plan(
        ReshareEngine::new(network),
        3,
        Crash::Random {
            // Leave more uninterrupted uptime than `certification_timeout` so recovery can make
            // progress before the next total shutdown.
            frequency: Duration::from_secs(4),
            downtime: Duration::from_secs(1),
            count: 5,
        },
    )
    .timeout(Duration::from_secs(180))
    .run()
    .unwrap();
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_epoch_first_next_player(#[case] network: Network) {
    let next_player_epoch = Epoch::new(1);
    let state_sync_floor = FixedEpocher::new(EPOCH_LENGTH)
        .first(next_player_epoch)
        .expect("test epoch should be supported");
    state_sync_next_player_plan(
        ReshareEngine::with_committee(network, 6, 4).with_state_sync_floor(state_sync_floor),
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

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_restart_before_epoch_boundary(#[case] network: Network) {
    let next_player_epoch = Epoch::new(1);
    let state_sync_floor = FixedEpocher::new(EPOCH_LENGTH)
        .first(next_player_epoch)
        .expect("test epoch should be supported");
    let crash_window_start = state_sync_floor.get() + EPOCH_LENGTH.get() / 2;
    // The node processes nothing until state sync finishes, and sync converges
    // only when two fetch round trips fit inside one block interval. The fast
    // link below guarantees that, so the processed hold, not sync timing, parks
    // the node at `crash_window_start`.
    let crash_window_end = FixedEpocher::new(EPOCH_LENGTH)
        .first(next_player_epoch.next())
        .expect("test epoch should be supported");
    let engine =
        ReshareEngine::with_committee(network, 6, 4).with_state_sync_floor(state_sync_floor);
    let delayed = engine.participants[5].clone();
    let engine = engine.with_processed_hold(delayed.clone(), Height::new(crash_window_start));
    let state_sync_starts = engine.state_sync_starts.clone();
    let result = state_sync_next_player_plan_starting_at(
        engine,
        3,
        5,
        state_sync_floor,
        next_player_epoch,
        next_player_epoch.next(),
        BoundaryEpochInfos::new(4),
    )
    .link(Link {
        latency: Duration::from_millis(4),
        jitter: Duration::from_millis(1),
        success_rate: probability!(1.0),
    })
    .crash(Crash::ProcessedHeight {
        participant: delayed.clone(),
        heights: crash_window_start..=crash_window_end.get(),
        downtime: Duration::from_millis(250),
    })
    .timeout(Duration::from_secs(120))
    .run()
    .unwrap()
    .pop()
    .unwrap();

    assert_eq!(result.crashes, 1);
    assert_eq!(state_sync_starts.lock().get(&delayed), Some(&1));
}

/// A node restarted with a persisted state-sync floor must ignore bootstrap
/// replies below that floor's epoch and resume state sync.
#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_restart_with_stale_bootstrap(#[case] network: Network) {
    // The delayed node probes mid-epoch 1, so its persisted floor is in epoch 1
    // or later.
    let epoch = Epoch::new(1);
    let start_height = FixedEpocher::new(EPOCH_LENGTH)
        .midpoint(epoch)
        .expect("test epoch should be supported");

    // On restart, every bootstrap member's first latest reply is an epoch-0
    // finalization. A probe not given the persisted floor completes its sample
    // from any f + 1 of them, and pairing that floor with the resulting epoch-0
    // info panics.
    let engine = ReshareEngine::with_committee(network, 6, 4).with_stale(final_height(0));
    let delayed = engine.participants[5].clone();
    let state_sync_starts = engine.state_sync_starts.clone();

    // Startup persists the floor before the node can crash, and the node
    // processes nothing until state sync completes, so a crash at processed
    // height zero restarts it in between.
    let result = reshare_plan_with_boundary(engine, 3, BoundaryEpochInfos::new(4))
        .crash(Crash::DelayRound {
            participants: vec![delayed.clone()],
            round: height_round(start_height),
        })
        .crash(Crash::ProcessedHeight {
            participant: delayed.clone(),
            heights: 0..=0,
            downtime: Duration::from_millis(250),
        })
        .timeout(Duration::from_secs(120))
        .run()
        .unwrap()
        .pop()
        .unwrap();

    // Both boots state sync, and the exit condition requires the restarted
    // node to process past its floor.
    assert_eq!(result.crashes, 1);
    assert_eq!(state_sync_starts.lock().get(&delayed), Some(&2));
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_active_player_late_restart(#[case] network: Network) {
    let epoch = Epoch::new(1);
    let epocher = FixedEpocher::new(EPOCH_LENGTH);
    let state_sync_floor = epocher
        .first(epoch)
        .expect("test epoch should be supported");
    let late_height = epocher
        .midpoint(epoch)
        .expect("test epoch should be supported")
        .next();
    // Failure in epoch 0 carries the genesis output and share into the synced
    // epoch, so the delayed node is an active dealer and player after joining.
    let engine = ReshareEngine::with_committee(network, 4, 4)
        .with_failures([0])
        .with_state_sync_floor(state_sync_floor);
    let delayed = engine.participants[3].clone();
    let engine = engine.with_processed_hold(delayed.clone(), late_height);
    let state_syncs = engine.state_syncs.clone();
    let state_sync_starts = engine.state_sync_starts.clone();
    let result = reshare_plan_with_boundary(
        engine,
        2,
        BoundaryEpochInfos::new(3).with_expected_failures([0]),
    )
    .link(Link {
        latency: Duration::from_millis(4),
        jitter: Duration::from_millis(1),
        success_rate: probability!(1.0),
    })
    .crash(Crash::DelayRound {
        participants: vec![delayed.clone()],
        round: height_round(state_sync_floor),
    })
    .crash(Crash::ProcessedHeight {
        participant: delayed.clone(),
        heights: late_height.get()..=final_height(epoch.get()).get(),
        downtime: Duration::from_millis(250),
    })
    .property(StateSyncedAtHeight::new(
        delayed.clone(),
        state_sync_floor,
        state_sync_floor,
        state_syncs,
    ))
    .property(SchemesRegistered::new(vec![delayed.clone()], epoch.next()))
    .timeout(Duration::from_secs(120))
    .run()
    .unwrap()
    .pop()
    .unwrap();

    assert_eq!(result.crashes, 1);
    assert_eq!(state_sync_starts.lock().get(&delayed), Some(&1));
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_late_state_sync_carries_share_across_failure(#[case] network: Network) {
    let epoch = Epoch::new(1);
    let epocher = FixedEpocher::new(EPOCH_LENGTH);
    let state_sync_floor = epocher
        .midpoint(epoch)
        .expect("test epoch should be supported")
        .next();
    let start_height = epocher
        .last(epoch)
        .and_then(Height::previous)
        .expect("test epoch should be supported");
    let engine = ReshareEngine::with_committee(network, 4, 4)
        .with_failures([0, 1])
        .with_state_sync_floor(state_sync_floor);
    let delayed = engine.participants[3].clone();
    let state_syncs = engine.state_syncs.clone();
    let state_sync_starts = engine.state_sync_starts.clone();
    reshare_plan_with_boundary(
        engine,
        2,
        BoundaryEpochInfos::new(3).with_expected_failures([0, 1]),
    )
    .link(Link {
        latency: Duration::from_millis(4),
        jitter: Duration::from_millis(1),
        success_rate: probability!(1.0),
    })
    .crash(Crash::DelayRound {
        participants: vec![delayed.clone()],
        round: height_round(start_height),
    })
    .property(StateSyncedAtHeight::new(
        delayed.clone(),
        state_sync_floor,
        state_sync_floor,
        state_syncs,
    ))
    .property(SchemesRegistered::new(vec![delayed.clone()], epoch.next()))
    .timeout(Duration::from_secs(120))
    .run()
    .unwrap();

    assert_eq!(state_sync_starts.lock().get(&delayed), Some(&1));
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_epoch_crosses_during_sync(#[case] network: Network) {
    // The node probes mid-epoch 1, fixing its floor and epoch info together,
    // then the harness holds bootstrap until the sampled committee finishes
    // epoch 1 so the network crosses an epoch boundary while the node is
    // still syncing. The node must sync at its epoch-1 floor, start the
    // epoch-1 engine with full info, catch up through ordinary marshal
    // delivery, and participate normally afterward: dealt to as a player
    // during epoch 3, it registers as a signer for epoch 4.
    let probe_epoch = Epoch::new(1);
    let epocher = FixedEpocher::new(EPOCH_LENGTH);
    let start_height = epocher
        .midpoint(probe_epoch)
        .expect("test epoch should be supported");
    let engine = ReshareEngine::with_committee(network, 6, 4).with_epoch_cross_during_sync();
    let delayed = engine.participants[5].clone();
    let registrations = engine.registrations.clone();
    let state_syncs = engine.state_syncs.clone();
    let state_sync_starts = engine.state_sync_starts.clone();
    reshare_plan_with_boundary(engine, 4, BoundaryEpochInfos::new(5))
        .crash(Crash::DelayRound {
            participants: vec![delayed.clone()],
            round: height_round(start_height),
        })
        .property(StateSyncedAtHeight::new(
            delayed.clone(),
            epocher
                .first(probe_epoch)
                .expect("test epoch should be supported"),
            final_height(probe_epoch.get()),
            state_syncs.clone(),
        ))
        .property(StateSyncedSigner::new(
            delayed.clone(),
            Epoch::new(4),
            registrations,
            state_syncs,
        ))
        .timeout(Duration::from_secs(180))
        .run()
        .unwrap();

    assert_eq!(state_sync_starts.lock().get(&delayed), Some(&1));
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_epoch_zero_next_player(#[case] network: Network) {
    let next_player_epoch = Epoch::zero();
    state_sync_next_player_plan(
        ReshareEngine::new(network),
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

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_next_player_after_failed_ceremony(#[case] network: Network) {
    let engine = ReshareEngine::with_committee(network, 6, 4).with_failures([1]);
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

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_state_sync_existing_player_after_failed_ceremony(#[case] network: Network) {
    let failed_epoch = Epoch::zero();
    let engine = ReshareEngine::new(network).with_failures([failed_epoch.get()]);
    let delayed = engine.participants[1].clone();
    let midpoint = FixedEpocher::new(EPOCH_LENGTH)
        .midpoint(failed_epoch)
        .expect("test epoch should be supported");
    reshare_plan_with_boundary(
        engine,
        1,
        BoundaryEpochInfos::new(2).with_expected_failures([failed_epoch.get()]),
    )
    .crash(Crash::DelayRound {
        participants: vec![delayed.clone()],
        round: height_round(midpoint),
    })
    .property(SchemesRegistered::new(vec![delayed], failed_epoch.next()))
    .timeout(Duration::from_secs(180))
    .run()
    .unwrap();
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_rotating_subset(#[case] network: Network) {
    successful_reshare_plan_with_schemes(ReshareEngine::with_committee(network, 7, 4), 0)
        .run()
        .unwrap();
}

/// A validator that crashed early in an epoch restarts while the rest of the
/// committee waits on the epoch's final block. Another validator stopped at the
/// block before it and never certifies it, so the restarted validator completes
/// the only possible quorum and must certify the final block while it is still
/// replaying the epoch's dealing window.
#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_boundary_lagging_validator(#[case] network: Network) {
    let epoch = Epoch::new(1);
    let epocher = FixedEpocher::new(EPOCH_LENGTH);
    let first = epocher
        .first(epoch)
        .expect("epocher must know the test epoch");
    let midpoint = epocher
        .midpoint(epoch)
        .expect("epocher must know the test epoch");
    let last = final_height(epoch.get());
    let stopped_at = last.previous().expect("final height must have a parent");

    let engine = ReshareEngine::with_committee(network, 4, 4);
    let stopped = engine.participants[2].clone();
    let lagging = engine.participants[3].clone();
    let active = engine.participants.len() - 1;
    let engine = engine.with_processed_hold(stopped.clone(), stopped_at);
    PlanBuilder::new(engine)
        .seed(0)
        .crash(Crash::ProcessedHeight {
            participant: lagging,
            heights: first.next().get()..=midpoint.get() - 8,
            downtime: Duration::from_secs(10),
        })
        .crash(Crash::ProcessedHeight {
            participant: stopped,
            heights: stopped_at.get()..=stopped_at.get(),
            downtime: Duration::from_secs(3600),
        })
        .exit_condition(AllActiveProcessedHeight::new(last, active))
        .timeout(Duration::from_secs(60))
        .run()
        .unwrap();
}

/// A boundary scenario for epoch 1 in which share holders state sync to a
/// floor and the epoch's final block needs their votes.
///
/// Failure in epoch 0 carries the genesis output and shares into epoch 1, so
/// the synced validators hold a share for the epoch they join.
struct BoundarySync {
    network: Network,
    floor: Height,
    /// Validators, by index, that state sync to `floor`.
    synced: Vec<usize>,
    /// Whether the synced validators run from genesis and are crashed once
    /// they process the floor, then restarted with empty chain storage, rather
    /// than being delayed until shortly before the stopped validator stops.
    resync: bool,
    /// Whether a third validator stops two blocks before the final block, so
    /// the remaining blocks need every synced validator's vote.
    stop: bool,
    /// Whether each synced validator is crashed once it processes a block
    /// beyond the floor and restarted a second later.
    restart: bool,
    prune_config: Option<PruneConfig>,
}

impl BoundarySync {
    fn new(network: Network, floor: Height) -> Self {
        Self {
            network,
            floor,
            synced: vec![3],
            resync: false,
            stop: true,
            restart: false,
            prune_config: None,
        }
    }

    fn plan(&self) -> PlanBuilder<ReshareEngine> {
        assert!(
            !(self.resync && self.restart),
            "a validator holds at one processed height per run"
        );
        let epoch = Epoch::new(1);
        let last = final_height(epoch.get());
        let stopped_at = Height::new(last.get() - 2);

        let mut engine = ReshareEngine::with_committee(self.network, 4, 4)
            .with_failures([0])
            .with_state_sync_floor(self.floor);
        if let Some(prune_config) = self.prune_config {
            engine = engine.with_pruning(prune_config);
        }
        let synced = self
            .synced
            .iter()
            .map(|index| engine.participants[*index].clone())
            .collect::<Vec<_>>();
        let stopped = self.stop.then(|| engine.participants[2].clone());
        assert!(
            stopped.iter().all(|stopped| !synced.contains(stopped)),
            "the stopped validator cannot also state sync"
        );
        let state_syncs = engine.state_syncs.clone();
        let notarized = engine.notarized.clone();

        // The validators that neither stop nor sync apply the final block only
        // once it finalizes, which needs every synced validator's finalize
        // vote. A synced validator's own application may converge past the
        // final block and never apply it.
        let appliers = engine
            .participants
            .iter()
            .filter(|validator| !synced.contains(validator) && stopped.as_ref() != Some(*validator))
            .cloned()
            .collect();

        // Each crash parks its validator at its first processed height at or
        // above the hold, which for a synced validator is wherever its state
        // sync completed, so the crash window reaches the block before the
        // final one. The stopped validator keeps the chain below the final
        // block until every synced validator has joined.
        let mut crashes = Vec::new();
        if self.resync {
            engine = engine.with_resync(synced.iter().cloned());
            for validator in &synced {
                crashes.push((validator.clone(), self.floor, self.floor, 1));
            }
        }
        if self.restart {
            let window_end = last.previous().expect("final height must have a parent");
            for validator in &synced {
                crashes.push((validator.clone(), self.floor.next(), window_end, 1));
            }
        }
        if let Some(stopped) = stopped {
            crashes.push((stopped, stopped_at, stopped_at, 3600));
        }
        for (validator, hold, _, _) in &crashes {
            engine = engine.with_processed_hold(validator.clone(), *hold);
        }

        let mut plan = PlanBuilder::new(engine);
        if !self.resync {
            // `stopped_at` finalizes in a later round than this start, so the
            // synced validators start no later than the stopped one stops.
            plan = plan.crash(Crash::DelayRound {
                participants: synced.clone(),
                round: height_round(
                    stopped_at
                        .previous()
                        .expect("stop height must have a parent"),
                ),
            });
        }
        for (participant, hold, window_end, downtime) in crashes {
            plan = plan.crash(Crash::ProcessedHeight {
                participant,
                heights: hold.get()..=window_end.get(),
                downtime: Duration::from_secs(downtime),
            });
        }
        for validator in synced {
            plan = plan
                .property(StateSyncedAtHeight::new(
                    validator.clone(),
                    self.floor,
                    self.floor,
                    state_syncs.clone(),
                ))
                .property(NotarizedInEpoch::new(validator, epoch, notarized.clone()));
        }
        plan.exit_condition(ValidatorsProcessedHeight::new(last, appliers))
            .timeout(Duration::from_secs(60))
    }
}

/// A floor two blocks into the first half of epoch 1.
fn early_floor() -> Height {
    FixedEpocher::new(EPOCH_LENGTH)
        .first(Epoch::new(1))
        .expect("test epoch should be supported")
        .next()
        .next()
}

/// A floor two blocks after the midpoint of epoch 1, which skips the first
/// two blocks of the inclusion window.
fn late_floor() -> Height {
    FixedEpocher::new(EPOCH_LENGTH)
        .midpoint(Epoch::new(1))
        .expect("test epoch should be supported")
        .next()
        .next()
}

/// A validator state synced before the midpoint holds a share of its synced
/// epoch and must vote with it from its first view: with one validator stopped,
/// the epoch's final block finalizes only with its votes. The seeds vary when
/// its consensus engine starts relative to the reshare actor's registration of
/// its signer.
#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_boundary_participating_synced_validator(#[case] network: Network) {
    // Clones of an engine share its stores and observations, so each seed
    // builds a fresh one.
    for seed in 0..=5 {
        BoundarySync::new(network, early_floor())
            .plan()
            .seed(seed)
            .run()
            .unwrap();
    }
}

/// A validator state synced after the midpoint applies the dealer logs of the
/// inclusion-window blocks below its floor, so it derives the final block's
/// epoch info and certifies it when its vote completes the only possible
/// quorum.
#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_boundary_late_synced_validator(#[case] network: Network) {
    for seed in 0..=3 {
        BoundarySync::new(network, late_floor())
            .plan()
            .seed(seed)
            .run()
            .unwrap();
    }
}

/// A late-synced validator restarted after applying a block beyond the floor
/// re-applies the persisted window and still certifies the final block.
#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_boundary_late_synced_validator_restart(#[case] network: Network) {
    for seed in 0..=3 {
        let result = BoundarySync {
            restart: true,
            ..BoundarySync::new(network, late_floor())
        }
        .plan()
        .seed(seed)
        .run()
        .unwrap()
        .pop()
        .unwrap();
        assert_eq!(result.crashes, 2);
    }
}

/// With `f + 1` share holders state synced after the midpoint, the final block
/// cannot finalize unless they derive its epoch info, even with no faulty
/// validator. The holders run from genesis and resync after a crash, since a
/// chain of four cannot progress while two of them are absent.
#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_boundary_two_late_synced_validators(#[case] network: Network) {
    for seed in 0..=3 {
        let result = BoundarySync {
            synced: vec![2, 3],
            resync: true,
            stop: false,
            ..BoundarySync::new(network, late_floor())
        }
        .plan()
        .seed(seed)
        .run()
        .unwrap()
        .pop()
        .unwrap();
        assert_eq!(result.crashes, 2);
    }
}

/// Peers pruning at the minimum marshal retention still serve the boundary
/// block and the inclusion window a late state sync needs.
#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_boundary_late_synced_validator_with_pruning(#[case] network: Network) {
    for seed in 0..=3 {
        BoundarySync {
            prune_config: Some(MIN_RETENTION_PRUNING),
            ..BoundarySync::new(network, late_floor())
        }
        .plan()
        .seed(seed)
        .run()
        .unwrap();
    }
}

/// A validator restarted from its own storage after the midpoint, with pruning
/// at the minimum marshal retention, still finds its epoch's boundary block
/// and completes the ceremony.
#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_late_restart_with_pruning(#[case] network: Network) {
    let epoch = Epoch::new(1);
    let restart_at = late_floor();
    for seed in 0..=3 {
        let engine =
            ReshareEngine::with_committee(network, 4, 4).with_pruning(MIN_RETENTION_PRUNING);
        let participants = engine.participants.clone();
        let restarted = participants[3].clone();
        let engine = engine.with_processed_hold(restarted.clone(), restart_at);
        let result = PlanBuilder::new(engine)
            .seed(seed)
            .crash(Crash::ProcessedHeight {
                participant: restarted,
                heights: restart_at.get()..=restart_at.get(),
                downtime: Duration::from_secs(1),
            })
            .property(SignerRegistered)
            .property(SchemesRegistered::new(participants, epoch.next()))
            .exit_condition(ProcessedHeightAtLeast::new(final_height(epoch.get()).get()))
            .timeout(Duration::from_secs(60))
            .run()
            .unwrap()
            .pop()
            .unwrap();
        assert_eq!(result.crashes, 1);
    }
}

#[rstest]
#[case::discovery(Network::Discovery)]
#[case::lookup(Network::Lookup)]
#[test_group("slow")]
#[test_traced("INFO")]
fn reshare_e2e_lossy_network(#[case] network: Network) {
    reshare_plan_with_boundary(
        ReshareEngine::new(network),
        4,
        BoundaryEpochInfos::new(5)
            .with_min_successes(1)
            .with_no_reveals(),
    )
    .link(Link {
        latency: Duration::from_millis(100),
        jitter: Duration::from_millis(50),
        success_rate: probability!(0.7),
    })
    .timeout(Duration::from_secs(720))
    .run()
    .unwrap();
}

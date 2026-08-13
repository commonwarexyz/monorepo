//! Unit-test entry point for shared timer benchmark helpers.

// This target imports complete benchmark modules for helper and orchestration
// tests, so the unselected benchmark entry points are intentionally unused.
#![allow(dead_code)]

mod accuracy;
mod config;
pub(crate) use config::{Backend, Config};
mod report;
mod utils;
mod worst_case;

use clap::error::ErrorKind;
use commonware_runtime::{Runner as _, tokio as commonware_tokio};
use std::{
    io,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

#[test]
fn cli_activates_only_for_cargo_bench_and_keeps_arguments_strict() {
    for arguments in [
        Vec::<&str>::new(),
        vec!["--list"],
        vec!["--scenario", "accuracy"],
    ] {
        assert!(Config::parse_from(arguments).unwrap().is_none());
    }

    let defaults = Config::parse_from(["--bench"])
        .unwrap()
        .expect("Cargo's benchmark marker did not activate the suite");
    assert_eq!(defaults.backend, None);

    let selected = Config::parse_from([
        "--scenario",
        "cancellation",
        "--backend",
        "commonware",
        "--worker-threads",
        "4",
        "--accuracy-batches",
        "2",
        "--worst-batches",
        "1",
        "--bench",
    ])
    .unwrap()
    .expect("valid benchmark configuration stayed idle");
    assert_eq!(selected.backend, Some(Backend::Commonware));
    assert_eq!(selected.cancellation_producer_counts(), [1, 4, 16]);

    let error = Config::parse_from(["--backnd=tokio", "--bench"])
        .expect_err("unknown benchmark option was accepted");
    assert_eq!(error.kind(), ErrorKind::UnknownArgument);

    for (option, value) in [
        ("--worker-threads", "129"),
        ("--accuracy-batches", "101"),
        ("--worst-batches", "101"),
    ] {
        let error = Config::parse_from([option, value, "--bench"])
            .expect_err("out-of-range benchmark configuration was accepted");
        assert_eq!(error.kind(), ErrorKind::ValueValidation, "{option}");
    }
}

#[test]
fn deadline_pair_preserves_each_backend_measurement_contract() {
    let target = Duration::from_millis(50);
    let commonware = utils::DeadlinePair::new(Backend::Commonware, target);
    let tokio = utils::DeadlinePair::new(Backend::Tokio, target);

    // Derive Commonware's monotonic clock-pair uncertainty.
    let span = commonware
        .tokio
        .into_std()
        .saturating_duration_since(commonware.measurement_deadline);

    // Tokio is exact, while Commonware retains its conservative bound.
    assert_eq!(tokio.measurement_deadline, tokio.tokio.into_std());
    assert_eq!(
        tokio
            .measurement_deadline
            .saturating_duration_since(tokio.measurement_origin),
        target
    );
    assert_eq!(tokio.clock_pair_span, None);
    assert_eq!(
        commonware
            .measurement_deadline
            .saturating_duration_since(commonware.measurement_origin),
        target
    );
    assert_eq!(commonware.clock_pair_span, Some(span));
}

#[test]
fn callback_boundaries_preserve_dispatch_lateness_and_suspended_peer_gap() {
    // Let the peer run once before callbacks start.
    let start = Instant::now();
    let before_callbacks = start + Duration::from_micros(5);
    let mut gap = utils::PeerGap::new(start);
    let target = Duration::from_micros(10);

    assert!(!gap.observe(before_callbacks, false, false));
    assert!(gap.observe(before_callbacks + Duration::from_micros(20), true, true));

    // Only the active window counts, and early dispatch is invalid.
    assert_eq!(gap.maximum(), Duration::from_micros(20));
    assert_eq!(
        utils::dispatch_lateness(Duration::from_micros(9), target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        utils::dispatch_lateness(Duration::from_micros(13), target).unwrap(),
        Duration::from_micros(3)
    );
}

#[test]
fn storm_validation_rejects_late_or_incomplete_wake_targets() {
    let deadline = Duration::from_micros(10);
    let mut ready: Vec<utils::BenchSleep> = vec![Box::pin(std::future::ready(()))];
    worst_case::validate_storm_completion(&mut ready, deadline, deadline).unwrap();

    let mut late: Vec<utils::BenchSleep> = vec![Box::pin(std::future::ready(()))];
    assert_eq!(
        worst_case::validate_storm_completion(
            &mut late,
            deadline + Duration::from_nanos(1),
            deadline,
        )
        .unwrap_err()
        .kind(),
        io::ErrorKind::TimedOut
    );

    let mut incomplete: Vec<utils::BenchSleep> = vec![Box::pin(std::future::pending())];
    assert_eq!(
        worst_case::validate_storm_completion(&mut incomplete, deadline, deadline)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
}

#[test]
fn latency_statistics_preserve_percentiles_and_drain_boundary() {
    // Use unsorted samples and out-of-order producer completions.
    let samples = [
        Duration::from_nanos(3),
        Duration::from_nanos(1),
        Duration::from_nanos(2),
    ];
    let start = Instant::now();
    let completions = [
        start + Duration::from_micros(4),
        start + Duration::from_micros(9),
        start + Duration::from_micros(6),
    ];

    let distribution = report::Distribution::new(&samples).unwrap();
    let drain = report::elapsed_through_last(start, completions).unwrap();
    let invalid =
        report::elapsed_through_last(start, [start.checked_sub(Duration::from_nanos(1)).unwrap()]);

    // Percentiles use nearest rank and drain ignores join order.
    assert_eq!(distribution.p50, Duration::from_nanos(2));
    assert_eq!(distribution.p99, Duration::from_nanos(3));
    assert_eq!(distribution.max, Duration::from_nanos(3));
    assert_eq!(drain, Duration::from_micros(9));
    assert_eq!(invalid.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn cancellation_orchestration_handles_each_backend_and_producer_topology() {
    let runner =
        commonware_tokio::Runner::new(commonware_tokio::Config::default().with_worker_threads(2));

    runner.start(|context| async move {
        let clock = Arc::new(context);
        let configurations = [
            (Backend::Commonware, 2, 1, 1),
            (Backend::Commonware, 8, 4, 4),
            (Backend::Tokio, 2, 1, 1),
            (Backend::Tokio, 8, 4, 4),
        ];
        for (batch, (backend, timers, canceled, producers)) in
            configurations.into_iter().enumerate()
        {
            let batch = u64::try_from(batch).expect("configuration count fits u64");
            // Successful completion exercises setup, coordination,
            // concurrent cancellation, and cleanup without deadlock or early expiry.
            worst_case::run_cancellation_batch(
                Arc::clone(&clock),
                backend,
                timers,
                canceled,
                producers,
                batch,
            )
            .await
            .unwrap();
        }
    });
}

#[test]
fn storm_registration_exceeds_tokios_cooperative_budget_without_losing_timers() {
    let runner =
        commonware_tokio::Runner::new(commonware_tokio::Config::default().with_worker_threads(1));

    runner.start(|context| async move {
        worst_case::run_storm_batch(
            &context,
            Backend::Tokio,
            256,
            Duration::from_millis(50),
            Duration::from_millis(5),
        )
        .await
        .unwrap();
    });
}

#[test]
fn recorder_timestamps_first_and_final_callbacks() {
    let multiple = worst_case::Recorder::new(Instant::now(), 3);
    let single = worst_case::Recorder::new(Instant::now(), 1);

    multiple.record();
    let first = multiple.first_ns.load(Ordering::Acquire);
    multiple.record();

    // Only the first boundary has been timestamped.
    assert_ne!(first, 0);
    assert_eq!(multiple.first_ns.load(Ordering::Acquire), first);
    assert_eq!(multiple.last_ns.load(Ordering::Acquire), 0);

    multiple.record();
    single.record();

    // Final and target-one callbacks publish both boundaries.
    assert_eq!(multiple.completed.load(Ordering::Relaxed), 3);
    assert!(multiple.last_ns.load(Ordering::Acquire) >= first);
    let single_first = single.first_ns.load(Ordering::Acquire);
    assert_ne!(single_first, 0);
    assert_eq!(single.last_ns.load(Ordering::Acquire), single_first);
    assert_eq!(single.completed.load(Ordering::Relaxed), 1);
}

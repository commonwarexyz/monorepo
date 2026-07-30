//! Unit-test entry point for shared timer benchmark helpers.

// This target imports complete benchmark modules for helper and orchestration
// tests, so the unselected benchmark entry points are intentionally unused.
#![allow(dead_code)]

mod accuracy;
mod backend;
pub(crate) use backend::{BenchSleep, poll_once, sleep_for, sleep_until, sleep_until_wall};
mod config;
pub(crate) use config::{Backend, Config, checked_observations};
mod peer_gap;
mod producer_gate;
mod report;
mod worst_case;

use clap::error::ErrorKind;
use commonware_runtime::{Runner as _, tokio as commonware_tokio};
use std::{
    io,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

#[test]
fn worst_batch_overflow_is_rejected_before_allocation() {
    let worst_batches = usize::MAX.to_string();

    for scenario in ["registration", "cancellation", "expiry"] {
        let error = Config::parse_from(["--scenario", scenario, "--worst-batches", &worst_batches])
            .expect_err("overflowing workload reached benchmark execution");

        assert_eq!(error.kind(), ErrorKind::ValueValidation, "{scenario}");
    }
}

#[test]
fn deadline_pair_preserves_each_backend_measurement_contract() {
    let target = Duration::from_millis(50);
    let commonware = backend::DeadlinePair::new(Backend::Commonware, target);
    let tokio = backend::DeadlinePair::new(Backend::Tokio, target);

    // Derive Commonware's monotonic clock-pair uncertainty.
    let span = commonware
        .tokio
        .into_std()
        .saturating_duration_since(commonware.measurement_deadline);

    // Tokio is exact; Commonware retains its conservative bound.
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
    let mut gap = peer_gap::PeerGap::new(start);
    let target = Duration::from_micros(10);

    assert!(!gap.observe(before_callbacks, false, false));
    assert!(gap.observe(before_callbacks + Duration::from_micros(20), true, true));

    // Only the active window counts, and early dispatch is invalid.
    assert_eq!(gap.maximum(), Duration::from_micros(20));
    assert_eq!(
        peer_gap::dispatch_lateness(Duration::from_micros(9), target)
            .unwrap_err()
            .kind(),
        io::ErrorKind::InvalidData
    );
    assert_eq!(
        peer_gap::dispatch_lateness(Duration::from_micros(13), target).unwrap(),
        Duration::from_micros(3)
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

    // Percentiles use nearest rank and drain ignores join order.
    assert_eq!(distribution.p50, Duration::from_nanos(2));
    assert_eq!(distribution.p99, Duration::from_nanos(3));
    assert_eq!(distribution.max, Duration::from_nanos(3));
    assert_eq!(drain, Duration::from_micros(9));
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

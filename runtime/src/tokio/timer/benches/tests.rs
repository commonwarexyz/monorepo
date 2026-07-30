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

use commonware_runtime::{Runner as _, tokio as commonware_tokio};
use std::{
    io,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant},
};

#[test]
fn lateness_rejects_early_completion() {
    // Setup: Place one observation before the requested deadline and another
    // at a known distance after it.
    let observed_early = Instant::now();
    let deadline = observed_early
        .checked_add(Duration::from_millis(1))
        .unwrap();
    let observed_late = deadline.checked_add(Duration::from_micros(7)).unwrap();

    // Action: Calculate lateness for the early and late observations.
    let early = accuracy::checked_lateness(observed_early, deadline).unwrap_err();
    let late = accuracy::checked_lateness(observed_late, deadline).unwrap();

    // Assertion: An early callback is a correctness error, while an on-time or
    // late callback contributes its actual duration to the distribution.
    assert_eq!(early.kind(), io::ErrorKind::InvalidData);
    assert_eq!(late, Duration::from_micros(7));
}

#[test]
fn deadline_pair_preserves_each_backend_measurement_contract() {
    // Setup: Construct each selected measurement around a bracketed wall snapshot.
    let target = Duration::from_millis(50);
    let commonware = backend::DeadlinePair::new(Backend::Commonware, target).unwrap();
    let tokio = backend::DeadlinePair::new(Backend::Tokio, target).unwrap();

    // Action: Derive the bracket width from Commonware's selected pair.
    let observed_span = commonware
        .tokio
        .into_std()
        .saturating_duration_since(commonware.measurement_deadline);

    // Assertion: Tokio measurements use its exact deadline, while Commonware
    // measurements retain the conservative lower bound and its uncertainty.
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
    assert_eq!(commonware.clock_pair_span, Some(observed_span));
}

#[test]
fn cli_routes_foreign_and_timer_specific_invocations() {
    // Setup: Choose representative Cargo filters, libtest flags, Criterion
    // flags, and the dashboard's exact output-format argument.
    let foreign = [
        &["--bench", "iobuf"][..],
        &["--bench", "--list"],
        &["--bench", "--sample-size", "10"],
        &["--bench", "--output-format=bencher"],
    ];

    for invocation in foreign {
        // Action: Parse each outer-harness invocation.
        let parsed = Config::parse_from(invocation.iter().copied()).unwrap();

        // Assertion: The production-sized timer suite remains idle.
        assert!(parsed.is_none(), "unexpected timer run for {invocation:?}");
    }

    // Setup: Combine a timer selector with removed or foreign controls.
    let invalid = [
        &["--scenario", "expiry", "--storm-timers", "1"][..],
        &["--bench", "--scenario", "expiry", "--noplot"],
    ];

    for invocation in invalid {
        // Action: Parse each explicitly timer-directed invocation.
        let error = Config::parse_from(invocation.iter().copied()).unwrap_err();

        // Assertion: Timer selectors never hide invalid controls by going idle.
        assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
    }
}

#[test]
fn cli_selects_requested_measurement_topology() {
    // Setup: Mix inline and separate selectors with every configurable count.
    let arguments = [
        "--scenario=worst-case",
        "--backend",
        "tokio",
        "--worker-threads=2",
        "--accuracy-batches",
        "4",
        "--worst-batches=1",
        "--bench",
    ];

    // Action: Parse and validate the complete timer command line.
    let config = Config::parse_from(arguments).unwrap().unwrap();

    // Assertion: The harness will run exactly the requested backend and topology.
    assert_eq!(config.scenario, config::ScenarioSelection::WorstCase);
    assert_eq!(config.backend, config::BackendSelection::Tokio);
    assert_eq!(config.worker_threads, 2);
    assert_eq!(config.accuracy_batches, 4);
    assert_eq!(config.worst_batches, 1);
    assert_eq!(config.cancellation_producer_counts(), [1, 2, 8]);

    // Setup: Select each cancellation-only profiling topology.
    let profiles = [
        ("cancellation", &[1, 2, 8][..]),
        ("cancellation-single", &[1][..]),
        ("cancellation-multi", &[2, 8][..]),
    ];

    for (scenario, expected) in profiles {
        // Action: Parse the profiling selector at the same worker count.
        let arguments = ["--scenario", scenario, "--worker-threads", "2"];
        let config = Config::parse_from(arguments).unwrap().unwrap();

        // Assertion: Each profile measures only its intended contention levels.
        assert_eq!(config.cancellation_producer_counts(), expected);
    }
}

#[test]
fn callback_boundaries_preserve_dispatch_lateness_and_suspended_peer_gap() {
    // Setup: Let the peer run once before callbacks, then choose one requested
    // callback deadline.
    let initialized = Instant::now();
    let before_callbacks = initialized + Duration::from_micros(5);
    let after_completion = before_callbacks + Duration::from_micros(20);
    let mut gap = peer_gap::PeerGap::new(initialized);
    let target = Duration::from_micros(10);

    // Action: Record the peer boundary and derive lateness on either side of
    // the callback's requested dispatch time.
    let before_completed = gap.observe(before_callbacks, false, false);
    let completed = gap.observe(after_completion, true, true);
    let early = peer_gap::dispatch_lateness(Duration::from_micros(9), target);
    let late = peer_gap::dispatch_lateness(Duration::from_micros(13), target);

    // Assertion: Termination retains the entire suspended interval, early
    // dispatch is invalid, and late dispatch retains only its excess.
    assert!(!before_completed);
    assert!(completed);
    assert_eq!(gap.maximum(), Duration::from_micros(20));
    assert_eq!(early.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(late.unwrap(), Duration::from_micros(3));
}

#[test]
fn latency_statistics_preserve_percentiles_and_drain_boundary() {
    // Setup: Use unsorted samples where floor-based p99 would select the median.
    let samples = [
        Duration::from_nanos(3),
        Duration::from_nanos(1),
        Duration::from_nanos(2),
    ];

    // Action: Summarize the samples through the production report helper.
    let distribution = report::Distribution::new(&samples).unwrap();

    // Assertion: Nearest-rank p50 is the median and p99 selects the maximum.
    assert_eq!(distribution.p50, Duration::from_nanos(2));
    assert_eq!(distribution.p99, Duration::from_nanos(3));
    assert_eq!(distribution.max, Duration::from_nanos(3));

    // Setup: Record producer completions after one common release time.
    let start = Instant::now();
    let completions = [
        start + Duration::from_micros(4),
        start + Duration::from_micros(9),
        start + Duration::from_micros(6),
    ];

    // Action: Derive drain from completion timestamps rather than join time.
    let drain = report::elapsed_through_last(start, completions).unwrap();

    // Assertion: Join order cannot replace the final measured completion.
    assert_eq!(drain, Duration::from_micros(9));
}

#[test]
fn cancellation_orchestration_handles_one_and_multiple_producers() {
    // Setup: Start the production runtime used by both benchmark backends and
    // choose tiny partitions that give every producer work.
    let runner =
        commonware_tokio::Runner::new(commonware_tokio::Config::default().with_worker_threads(2));

    // Action: Run latency and throughput passes at one and four producers for
    // both backends through the dedicated threads and blocking coordinator.
    let results = runner.start(|context| async move {
        let clock = Arc::new(context);
        let configurations = [
            (Backend::Commonware, 2, 1, 1),
            (Backend::Commonware, 8, 4, 4),
            (Backend::Tokio, 2, 1, 1),
            (Backend::Tokio, 8, 4, 4),
        ];
        let mut results = Vec::new();
        let mut batch = 0;
        for (backend, timers, canceled, producers) in configurations {
            for pass in [
                worst_case::CancellationPass::Latency,
                worst_case::CancellationPass::Throughput,
            ] {
                let result = worst_case::run_cancellation_batch(
                    Arc::clone(&clock),
                    backend,
                    timers,
                    canceled,
                    producers,
                    batch,
                    pass,
                )
                .await
                .unwrap();
                results.push((pass, canceled, producers, result));
                batch += 1;
            }
        }
        results
    });

    // Assertion: Latency passes retain every initialized sample and producer
    // setup, while throughput passes allocate neither result buffer.
    for (pass, canceled, producers, result) in results {
        match pass {
            worst_case::CancellationPass::Latency => {
                assert_eq!(result.setup.len(), producers);
                assert_eq!(result.cancellation.len(), canceled);
                assert!(
                    result
                        .cancellation
                        .iter()
                        .all(|sample| *sample != Duration::MAX)
                );
            }
            worst_case::CancellationPass::Throughput => {
                assert!(result.setup.is_empty());
                assert!(result.cancellation.is_empty());
                assert_eq!(result.setup.capacity(), 0);
                assert_eq!(result.cancellation.capacity(), 0);
            }
        }
    }
}

#[test]
fn recorder_timestamps_first_and_final_callbacks() {
    // Multiple-callback case - Setup: Start with both boundaries unset.
    let multiple = worst_case::Recorder::new(Instant::now(), 3);

    // Multiple-callback case - Action: Record the first and one interior callback.
    multiple.record();
    let first = multiple.first_ns.load(Ordering::Acquire);
    let last_after_first = multiple.last_ns.load(Ordering::Acquire);
    multiple.record();
    let first_after_middle = multiple.first_ns.load(Ordering::Acquire);
    let last_after_middle = multiple.last_ns.load(Ordering::Acquire);

    // Multiple-callback case - Assertion: Only the first boundary is timestamped.
    assert_ne!(first, 0);
    assert_eq!(last_after_first, 0);
    assert_eq!(first_after_middle, first);
    assert_eq!(last_after_middle, 0);

    // Multiple-callback case - Action: Record the final callback.
    multiple.record();
    let last = multiple.last_ns.load(Ordering::Acquire);

    // Multiple-callback case - Assertion: The final boundary is timestamped.
    assert_eq!(multiple.completed.load(Ordering::Relaxed), 3);
    assert!(last >= first);

    // Single-callback case - Setup: The first callback is also the final callback.
    let single = worst_case::Recorder::new(Instant::now(), 1);

    // Single-callback case - Action: Record the sole callback.
    single.record();
    let first = single.first_ns.load(Ordering::Acquire);
    let last = single.last_ns.load(Ordering::Acquire);

    // Single-callback case - Assertion: One timestamp supports both boundaries.
    assert_ne!(first, 0);
    assert_eq!(last, first);
    assert_eq!(single.completed.load(Ordering::Relaxed), 1);
}

//! Tests for benchmark configuration that controls measured work.

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
        let parsed = super::Config::parse_from(invocation.iter().copied()).unwrap();

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
        let error = super::Config::parse_from(invocation.iter().copied()).unwrap_err();

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
    let config = super::Config::parse_from(arguments).unwrap().unwrap();

    // Assertion: The harness will run exactly the requested backend and topology.
    assert_eq!(config.scenario, super::ScenarioSelection::WorstCase);
    assert_eq!(config.backend, super::BackendSelection::Tokio);
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
        let config = super::Config::parse_from(arguments).unwrap().unwrap();

        // Assertion: Each profile measures only its intended contention levels.
        assert_eq!(config.cancellation_producer_counts(), expected);
    }
}

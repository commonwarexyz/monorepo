//! Tests for benchmark configuration and sample accounting.

#[test]
fn sample_accounting_is_checked() {
    // Setup: Choose ordinary and overflowing batch dimensions.
    let batches = 3;
    let concurrency = 7;

    // Action: Compute both observation counts through the shared helper.
    let observations = super::checked_observations(batches, concurrency);
    let overflow = super::checked_observations(usize::MAX, 2);

    // Assertion: Ordinary multiplication succeeds and overflow is rejected.
    assert_eq!(observations.unwrap(), 21);
    assert_eq!(
        overflow.unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
}

#[test]
fn cli_accepts_inline_values_and_cargo_marker() {
    // Setup: Mix inline and separate values with Cargo's trailing marker.
    let arguments = [
        "--scenario=worst-case",
        "--backend",
        "tokio",
        "--worker-threads=2",
        "--accuracy-concurrency",
        "3,5",
        "--worst-batches",
        "1",
        "--bench",
    ]
    .into_iter()
    .map(str::to_owned);

    // Action: Parse and validate the complete synthetic command line.
    let config = super::Config::parse_from(arguments).unwrap().unwrap();

    // Assertion: Every selected value and derived producer count is retained.
    assert_eq!(config.scenario, super::ScenarioSelection::WorstCase);
    assert_eq!(config.backend, super::BackendSelection::Tokio);
    assert_eq!(config.worker_threads, 2);
    assert_eq!(config.accuracy_concurrency, [3, 5]);
    assert_eq!(config.worst_batches, 1);
    assert_eq!(config.cancellation_producer_counts(), [1, 2, 8]);
}

#[test]
fn cli_skips_harness_and_filtered_invocations() {
    // Setup: Select representative Criterion and libtest arguments used by
    // filtered, listing, test, and benchmark-reporting workflows.
    let invocations = [
        vec!["iobuf"],
        vec!["--list"],
        vec!["-v"],
        vec!["-vn"],
        vec!["-cnever"],
        vec!["--test"],
        vec!["--noplot"],
        vec!["--no-capture"],
        vec!["--shuffle-seed", "7"],
        vec!["--sample-size", "10"],
        vec!["--output-format", "bencher"],
        vec!["--output-format=bencher"],
    ];

    for invocation in invocations {
        // Action: Parse each compatibility invocation through the production path.
        let parsed = super::Config::parse_from(invocation.into_iter().map(str::to_owned)).unwrap();

        // Assertion: The custom harness exits without running its expensive suite.
        assert!(parsed.is_none());
    }
}

#[test]
fn cli_rejects_unknown_timer_options() {
    // Setup: Supply one dashed option outside the timer and harness interfaces.
    let arguments = ["--unknown-timer-option", "value"]
        .into_iter()
        .map(str::to_owned);

    // Action: Parse the unsupported timer invocation.
    let error = super::Config::parse_from(arguments).unwrap_err();

    // Assertion: Compatibility handling does not hide misspelled timer options.
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("unknown option"));
}

#[test]
fn cli_rejects_zero_for_positive_options() {
    // Setup: Supply zero for an option that controls a nonempty batch.
    let arguments = ["--accuracy-batches", "0"].into_iter().map(str::to_owned);

    // Action: Parse the invalid synthetic command line.
    let error = super::Config::parse_from(arguments).unwrap_err();

    // Assertion: Validation fails as invalid input rather than panicking.
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn cli_rejects_zero_peer_lead() {
    // Setup: Request a fairness peer that starts at the storm deadline.
    let arguments = ["--peer-lead-us", "0"].into_iter().map(str::to_owned);

    // Action: Parse the invalid synthetic command line.
    let error = super::Config::parse_from(arguments).unwrap_err();

    // Assertion: The peer must have time to become runnable before expiry.
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("--peer-lead-us"));
}

#[test]
fn cli_requires_peer_lead_before_storm_deadline() {
    // Setup: Choose peer leads equal to and greater than the storm lead.
    let invalid_leads = [("50", "50"), ("50", "51")];

    for (storm_lead, peer_lead) in invalid_leads {
        // Action: Parse each ordering through the complete configuration path.
        let arguments = ["--storm-lead-us", storm_lead, "--peer-lead-us", peer_lead]
            .into_iter()
            .map(str::to_owned);
        let error = super::Config::parse_from(arguments).unwrap_err();

        // Assertion: The fairness peer cannot be configured to start at or
        // after timer expiry.
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("smaller"));
    }
}

#[test]
fn cli_requires_one_registered_timer_per_producer() {
    // Setup: Select eight producers but only seven cancellation timers.
    let arguments = [
        "--worker-threads",
        "2",
        "--cancellation-timers",
        "7",
        "--cancel-percent",
        "100",
    ]
    .into_iter()
    .map(str::to_owned);

    // Action: Parse the undersized cancellation workload.
    let error = super::Config::parse_from(arguments).unwrap_err();

    // Assertion: Empty producer partitions are rejected before the benchmark.
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("every producer registers"));
}

#[test]
fn cli_requires_one_canceled_timer_per_producer() {
    // Setup: Register one timer per producer but cancel only half of them.
    let arguments = [
        "--worker-threads",
        "2",
        "--cancellation-timers",
        "8",
        "--cancel-percent",
        "50",
    ]
    .into_iter()
    .map(str::to_owned);

    // Action: Parse the cancellation workload with idle measured producers.
    let error = super::Config::parse_from(arguments).unwrap_err();

    // Assertion: Every advertised producer must perform measured cancellation.
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(error.to_string().contains("every producer cancels"));
}

#[test]
fn accuracy_only_ignores_cancellation_topology() {
    // Setup: Select only accuracy with invalid unused cancellation and expiry relationships.
    let arguments = [
        "--scenario",
        "accuracy",
        "--worker-threads",
        "4",
        "--cancellation-timers",
        "1",
        "--cancel-percent",
        "101",
        "--storm-lead-us",
        "1",
        "--peer-lead-us",
        "2",
    ]
    .into_iter()
    .map(str::to_owned);

    // Action: Parse a configuration that never runs cancellation.
    let config = super::Config::parse_from(arguments).unwrap().unwrap();

    // Assertion: Unused producer topology does not reject the accuracy workload.
    assert_eq!(config.scenario, super::ScenarioSelection::Accuracy);
    assert_eq!(config.cancellation_timers, 1);
    assert_eq!(config.cancel_percent, 101);
}

#[test]
fn registration_only_ignores_accuracy_dimensions() {
    // Setup: Select registration with an overflowing unused accuracy sample count.
    let arguments = vec![
        "--scenario".to_owned(),
        "registration".to_owned(),
        "--accuracy-batches".to_owned(),
        "2".to_owned(),
        "--accuracy-concurrency".to_owned(),
        usize::MAX.to_string(),
    ];

    // Action: Parse a configuration that never allocates accuracy samples.
    let config = super::Config::parse_from(arguments).unwrap().unwrap();

    // Assertion: Only registration validation applies to the selected workload.
    assert_eq!(config.scenario, super::ScenarioSelection::Registration);
    assert_eq!(config.accuracy_concurrency, [usize::MAX]);
}

#[test]
fn cancellation_scenarios_select_requested_producer_levels() {
    // Setup: Choose one worker topology and every cancellation selector.
    let scenarios = [
        ("cancellation", vec![1, 2, 8]),
        ("cancellation-single", vec![1]),
        ("cancellation-multi", vec![2, 8]),
    ];

    for (scenario, expected) in scenarios {
        // Action: Parse the selector through the production command-line path.
        let arguments = [
            "--scenario",
            scenario,
            "--worker-threads",
            "2",
            "--cancellation-timers",
            "8",
            "--cancel-percent",
            "100",
        ]
        .into_iter()
        .map(str::to_owned);
        let config = super::Config::parse_from(arguments).unwrap().unwrap();

        // Assertion: Profiling can isolate single or contending cancellation.
        assert_eq!(config.cancellation_producer_counts(), expected);
    }
}

#[test]
fn single_producer_validation_ignores_unselected_topology() {
    // Setup: Configure fewer timers than the unselected oversubscribed level.
    let arguments = [
        "--scenario",
        "cancellation-single",
        "--worker-threads",
        "4",
        "--cancellation-timers",
        "1",
        "--cancel-percent",
        "100",
    ]
    .into_iter()
    .map(str::to_owned);

    // Action: Parse the isolated single-producer cancellation workload.
    let config = super::Config::parse_from(arguments).unwrap().unwrap();

    // Assertion: Validation requires only the one producer that will run.
    assert_eq!(config.cancellation_producer_counts(), [1]);
}

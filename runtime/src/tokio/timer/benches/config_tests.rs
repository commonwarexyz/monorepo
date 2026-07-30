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
fn cli_selects_profiles_and_uses_fixed_workloads() {
    // Setup: Mix inline and separate selectors with Cargo's trailing marker.
    let arguments = [
        "--scenario=worst-case",
        "--backend=all",
        "--backend",
        "tokio",
        "--worker-threads=2",
        "--accuracy-batches",
        "4",
        "--worst-batches=1",
        "--bench",
    ];

    // Action: Parse and validate the complete synthetic command line.
    let config = super::Config::parse_from(arguments).unwrap().unwrap();

    // Assertion: Selectors are retained while workload dimensions stay fixed.
    assert_eq!(config.scenario, super::ScenarioSelection::WorstCase);
    assert_eq!(config.backend, super::BackendSelection::Tokio);
    assert_eq!(config.worker_threads, 2);
    assert_eq!(config.accuracy_batches, 4);
    assert_eq!(config.worst_batches, 1);
    assert_eq!(super::ACCURACY_CONCURRENCY, [1_000, 10_000]);
    assert_eq!(super::REGISTRATION_TIMERS, 50_000);
    assert_eq!(super::CANCELLATION_TIMERS, 100_000);
    assert_eq!(super::STORM_TIMERS, 50_000);
    assert_eq!(config.cancellation_producer_counts(), [1, 2, 8]);
}

#[test]
fn cli_skips_cargo_harness_and_filtered_invocations() {
    // Setup: Choose representative filters and Criterion or libtest flags.
    let invocations = [
        &["--bench", "iobuf"][..],
        &["--bench", "--list"],
        &["--bench", "-v"],
        &["--bench", "--noplot"],
        &["--bench", "--no-capture"],
        &["--bench", "--sample-size", "10"],
        &["--bench", "--output-format=bencher"],
    ];

    for invocation in invocations {
        // Action: Parse each invocation through the production compatibility path.
        let parsed = super::Config::parse_from(invocation.iter().copied()).unwrap();

        // Assertion: The custom harness does not run its production-sized suite.
        assert!(parsed.is_none());
    }
}

#[test]
fn cli_keeps_timer_invocations_strict() {
    // Setup: Choose invalid values, a removed workload knob, and a mixed
    // timer-plus-Criterion invocation.
    let invocations = [
        &["--worker-threads", "0"][..],
        &["--scenario", "unknown"],
        &["--scenario", "expiry", "--storm-timers", "1"],
        &["--bench", "--scenario", "expiry", "--noplot"],
    ];

    for invocation in invocations {
        // Action: Parse each invalid timer invocation through clap.
        let error = super::Config::parse_from(invocation.iter().copied()).unwrap_err();

        // Assertion: Timer selections do not hide invalid or obsolete options.
        assert!(matches!(
            error.kind(),
            clap::error::ErrorKind::InvalidValue
                | clap::error::ErrorKind::UnknownArgument
                | clap::error::ErrorKind::ValueValidation
        ));
    }
}

#[test]
fn cli_help_describes_only_supported_controls() {
    // Setup: Request help through the timer-specific command line.
    let arguments = ["--help"];

    // Action: Render the clap help diagnostic.
    let error = super::Config::parse_from(arguments).unwrap_err();
    let help = error.to_string();

    // Assertion: Profiling controls are present and workload tuning is absent.
    assert_eq!(error.kind(), clap::error::ErrorKind::DisplayHelp);
    assert!(help.contains("--scenario"));
    assert!(help.contains("--backend"));
    assert!(help.contains("--worker-threads"));
    assert!(help.contains("--accuracy-batches"));
    assert!(help.contains("--worst-batches"));
    assert!(!help.contains("--storm-timers"));
    assert!(!help.contains("--cancel-percent"));
}

#[test]
fn validation_applies_only_to_selected_workloads() {
    // Setup: Overflow accuracy accounting in selected and unselected scenarios.
    let batches = usize::MAX.to_string();
    let selected = ["--scenario", "accuracy", "--accuracy-batches", &batches];
    let unselected = ["--scenario", "registration", "--accuracy-batches", &batches];

    // Action: Parse both configurations through clap and derived validation.
    let selected_error = super::Config::parse_from(selected).unwrap_err();
    let unselected_config = super::Config::parse_from(unselected).unwrap().unwrap();

    // Assertion: Only a workload that will run validates its sample count.
    assert_eq!(
        selected_error.kind(),
        clap::error::ErrorKind::ValueValidation
    );
    assert_eq!(unselected_config.accuracy_batches, usize::MAX);
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
        let arguments = ["--scenario", scenario, "--worker-threads", "2"];
        let config = super::Config::parse_from(arguments).unwrap().unwrap();

        // Assertion: Profiling can isolate single or contending cancellation.
        assert_eq!(config.cancellation_producer_counts(), expected);
    }
}

#[test]
fn cli_rejects_oversubscribed_fixed_cancellation_workload() {
    // Setup: Select more producers than the fixed cancellation workload serves.
    let worker_threads = 25_000usize;
    let arguments = [
        "--scenario".to_owned(),
        "cancellation-multi".to_owned(),
        "--worker-threads".to_owned(),
        worker_threads.to_string(),
    ];

    // Action: Parse the oversubscribed producer topology.
    let error = super::Config::parse_from(arguments).unwrap_err();

    // Assertion: Every advertised producer must cancel at least one timer.
    assert_eq!(error.kind(), clap::error::ErrorKind::ValueValidation);
    assert!(error.to_string().contains("fixed workload"));
}

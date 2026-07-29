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
    assert_eq!(config.producer_counts(), [1, 2, 8]);
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

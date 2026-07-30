//! Tests for equivalent benchmark backend deadlines.

#[test]
fn deadline_pair_preserves_each_backend_measurement_contract() {
    use std::time::Duration;

    // Setup: Construct each selected measurement around a bracketed wall snapshot.
    let target = Duration::from_millis(50);
    let commonware = super::DeadlinePair::new(super::Backend::Commonware, target).unwrap();
    let tokio = super::DeadlinePair::new(super::Backend::Tokio, target).unwrap();

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

#![recursion_limit = "256"]

#[cfg(feature = "mocks")]
pub mod marshal;
#[cfg(feature = "mocks")]
pub mod scenarios;

// What a scaffold's thin target imports from the crate root: the trusted entries, the
// base inputs and the schemes the bases run.
#[cfg(feature = "mocks")]
pub use commonware_consensus_fuzz_core::{
    SimplexCertificateMock, SimplexCertificateMockByzantineFirstLeader,
};
#[cfg(feature = "mocks")]
pub use marshal::{
    MarshalDisrupterInput, MarshalTwinsInput, fuzz_marshal_coding_block_poison_with_prefix,
    fuzz_marshal_coding_disrupter_with_prefix, fuzz_marshal_coding_twins_with_prefix,
    fuzz_marshal_standard_block_dissemination_with_prefix,
    fuzz_marshal_standard_certificate_poison_with_prefix,
    fuzz_marshal_standard_deferred_cert_mock_twins_split_header_with_prefix,
    fuzz_marshal_standard_disrupter_with_prefix,
    fuzz_marshal_standard_inline_cert_mock_twins_split_header_with_prefix,
    fuzz_marshal_standard_twins_with_prefix,
};

/// Runs one target under a fixed input and requires each of `actors` to have
/// acted.
#[cfg(all(test, feature = "mocks"))]
pub(crate) fn assert_adversary_acted(actors: &[&'static str], run: impl FnOnce()) {
    use commonware_consensus_fuzz_core::byzantine;

    byzantine::reset();
    run();
    for actor in actors {
        assert!(
            byzantine::count(actor) > 0,
            "{actor} took no action: {:?}",
            byzantine::snapshot()
        );
    }
}

/// Runs one target under a fixed input and requires each of `events` to have
/// been reached.
#[cfg(all(test, feature = "mocks"))]
pub(crate) fn assert_reached(events: &[&'static str], run: impl FnOnce()) {
    use commonware_consensus_fuzz_core::reach;

    reach::reset();
    run();
    for event in events {
        assert!(
            reach::count(event) > 0,
            "{event} was never reached: {:?}",
            reach::snapshot()
        );
    }
}

/// The reach event an honest node's prepare answered under `handoff` counts under.
#[cfg(all(test, feature = "mocks"))]
pub(crate) const fn prepare_event(handoff: commonware_consensus::Handoff<()>) -> &'static str {
    use marshal::end_to_end::invariants::{PREPARE_STAGE, PREPARE_VOTE, PREPARE_WAIT};

    match handoff {
        commonware_consensus::Handoff::Wait => PREPARE_WAIT,
        commonware_consensus::Handoff::Stage(()) => PREPARE_STAGE,
        commonware_consensus::Handoff::Vote(()) => PREPARE_VOTE,
    }
}

/// Runs one target under an honest input and requires no Byzantine action.
#[cfg(all(test, feature = "mocks"))]
pub(crate) fn assert_adversary_silent(run: impl FnOnce()) {
    use commonware_consensus_fuzz_core::byzantine;

    byzantine::reset();
    run();
    assert_eq!(
        byzantine::total(),
        0,
        "an honest run counted Byzantine actions: {:?}",
        byzantine::snapshot()
    );
}

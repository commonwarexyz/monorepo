#![recursion_limit = "256"]

#[cfg(feature = "mocks")]
pub mod marshal;
#[cfg(feature = "mocks")]
pub mod scenarios;

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

#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        fuzz, FuzzInput, SimplexCertificateMock, StateCoverage, TwinsMutator,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMock, TwinsMutator, StateCoverage>(input);
    });
}

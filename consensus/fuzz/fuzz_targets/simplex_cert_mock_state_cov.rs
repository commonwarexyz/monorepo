#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        fuzz, FuzzInput, SimplexCertificateMock, Standard, StateCoverage,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMock, Standard, StateCoverage>(input);
    });
}

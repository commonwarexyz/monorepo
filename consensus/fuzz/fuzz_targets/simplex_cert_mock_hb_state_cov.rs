#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        FuzzInput, HappensBeforeStateCoverage, SimplexCertificateMock, Standard, fuzz,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMock, Standard, HappensBeforeStateCoverage>(input);
    });
}

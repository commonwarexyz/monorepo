#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        fuzz, CodeCoverage, FuzzInput, SimplexCertificateMock, Standard,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMock, Standard, CodeCoverage>(input);
    });
}

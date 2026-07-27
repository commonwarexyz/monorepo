#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{Chaos, CodeCoverage, FuzzInput, SimplexCertificateMock, fuzz};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMock, Chaos, CodeCoverage>(input);
    });
}

#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{fuzz_state_cov, FuzzInput, SimplexCertificateMock};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz_state_cov::<SimplexCertificateMock>(input);
    });
}

#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{SimplexCertificateMock, marshal::fuzz_split_notarization};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|seed: u64| {
        fuzz_split_notarization::<SimplexCertificateMock>(seed);
    });
}

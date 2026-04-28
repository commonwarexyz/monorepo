#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{fuzz, AdversarialNetwork, FuzzInput, SimplexCertificateMock};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMock, AdversarialNetwork>(input);
    });
}

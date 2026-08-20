#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        FuzzInput, SimplexCertificateMock, fuzz_audit_notarize_omission,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz_audit_notarize_omission::<SimplexCertificateMock>(input);
    });
}

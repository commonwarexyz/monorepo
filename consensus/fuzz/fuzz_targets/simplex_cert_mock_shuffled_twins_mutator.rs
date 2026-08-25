#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        CodeCoverage, FuzzInput, SimplexCertificateMockCustomRoundRobin, TwinsMutator, fuzz,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMockCustomRoundRobin, TwinsMutator, CodeCoverage>(input);
    });
}

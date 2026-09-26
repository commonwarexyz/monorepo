#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus::simplex::statelens;
    use commonware_consensus_fuzz_simplex::{
        CodeCoverage, FuzzInput, SimplexCertificateMock, TwinsMutator, fuzz,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        statelens::reset();
        fuzz::<SimplexCertificateMock, TwinsMutator, CodeCoverage>(input);
        statelens::clear_compromised();
    });
}

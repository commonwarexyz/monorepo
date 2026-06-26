#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        fuzz, FuzzInput, SimplexCertificateMock, StateCoverage, TwinsCampaign,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz::<SimplexCertificateMock, TwinsCampaign, StateCoverage>(input);
    });
}

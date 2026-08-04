#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        SimplexCertificateMock,
        marshal::{NotarizationBlockSplitScenarioInput, fuzz_marshal_standard_scenarios},
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: NotarizationBlockSplitScenarioInput| {
        fuzz_marshal_standard_scenarios::<SimplexCertificateMock>(input);
    });
}

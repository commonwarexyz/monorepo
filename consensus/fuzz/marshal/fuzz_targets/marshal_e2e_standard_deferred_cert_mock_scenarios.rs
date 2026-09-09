#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz_core::SimplexCertificateMock;
    use commonware_consensus_fuzz_marshal::marshal::{
        NotarizationBlockSplitScenarioInput, fuzz_marshal_standard_scenarios,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: NotarizationBlockSplitScenarioInput| {
        fuzz_marshal_standard_scenarios::<SimplexCertificateMock>(input);
    });
}

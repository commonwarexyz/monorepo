#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::{
        SimplexCertificateMock,
        scenarios::{MarshalScenarioPrefixInput, fuzz_marshal_scenario_prefix_deferred},
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalScenarioPrefixInput| {
        fuzz_marshal_scenario_prefix_deferred::<SimplexCertificateMock>(input);
    });
}

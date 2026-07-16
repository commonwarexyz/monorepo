#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus::marshal::mocks::harness::StandardHarness;
    use commonware_consensus_fuzz::marshal::{MarshalLivenessInput, fuzz_marshal_liveness};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalLivenessInput| {
        fuzz_marshal_liveness::<StandardHarness>(input);
    });
}

#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus::marshal::mocks::harness::CodingHarness;
    use commonware_consensus_fuzz::marshal::{MarshalFuzzInput, fuzz_marshal_single_node};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: MarshalFuzzInput| {
        fuzz_marshal_single_node::<CodingHarness>(input);
    });
}

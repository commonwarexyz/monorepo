#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus::marshal::mocks::harness::CodingHarness;
    use commonware_consensus_fuzz::{marshal::fuzz_marshal_liveness, FuzzInput};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: FuzzInput| {
        fuzz_marshal_liveness::<CodingHarness>(input);
    });
}

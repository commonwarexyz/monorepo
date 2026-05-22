#![no_main]

use commonware_consensus::marshal::mocks::harness::StandardHarness;
use commonware_consensus_fuzz::marshal::{fuzz_marshal, MarshalFuzzInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: MarshalFuzzInput| {
    fuzz_marshal::<StandardHarness>(input);
});

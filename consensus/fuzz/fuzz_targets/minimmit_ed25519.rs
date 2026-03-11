#![no_main]

use commonware_consensus_fuzz::{minimmit_fuzz, MinimmitEd25519, MinimmitFuzzInput, Standard};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: MinimmitFuzzInput| {
    minimmit_fuzz::<MinimmitEd25519, Standard>(input.into());
});

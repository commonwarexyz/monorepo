#![no_main]

use commonware_consensus_fuzz::{minimmit_fuzz, MinimmitFuzzInput, MinimmitSecp256r1, Standard};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: MinimmitFuzzInput| {
    minimmit_fuzz::<MinimmitSecp256r1, Standard>(input.into());
});

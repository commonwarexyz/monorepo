#![no_main]

use commonware_consensus_fuzz::{minimmit_fuzz, MinimmitEd25519, MinimmitFuzzInput, Twinable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: MinimmitFuzzInput| {
    minimmit_fuzz::<MinimmitEd25519, Twinable>(input.into());
});

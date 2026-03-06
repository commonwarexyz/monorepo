#![no_main]

use commonware_consensus_fuzz::{
    minimmit_fuzz, MinimmitBls12381MinPk, MinimmitFuzzInput, Twinable,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: MinimmitFuzzInput| {
    minimmit_fuzz::<MinimmitBls12381MinPk, Twinable>(input.into());
});

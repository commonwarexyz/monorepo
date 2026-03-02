#![no_main]

use commonware_consensus_fuzz::{
    minimmit_fuzz, MinimmitBls12381MultisigMinSig, MinimmitFuzzInput, Twinable,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: MinimmitFuzzInput| {
    minimmit_fuzz::<MinimmitBls12381MultisigMinSig, Twinable>(input.into());
});

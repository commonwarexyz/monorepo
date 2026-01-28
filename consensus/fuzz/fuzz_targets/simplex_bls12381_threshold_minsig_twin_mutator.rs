#![no_main]

use commonware_consensus_fuzz::{fuzz_with_twin_mutator, FuzzInput, SimplexBls12381MinSig};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz_with_twin_mutator::<SimplexBls12381MinSig>(input);
});

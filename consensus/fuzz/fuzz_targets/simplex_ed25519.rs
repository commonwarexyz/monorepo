#![no_main]

use commonware_consensus_fuzz::{FuzzInput, SimplexEd25519, Standard, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519, Standard>(input);
});

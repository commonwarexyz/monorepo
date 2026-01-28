#![no_main]

use commonware_consensus_fuzz::{fuzz_with_twin_mutator, FuzzInput, SimplexEd25519};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz_with_twin_mutator::<SimplexEd25519>(input);
});

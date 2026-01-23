#![no_main]

use commonware_consensus_fuzz::{fuzz_with_twin_mutator, FuzzInput, SimplexSecp256r1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz_with_twin_mutator::<SimplexSecp256r1>(input);
});

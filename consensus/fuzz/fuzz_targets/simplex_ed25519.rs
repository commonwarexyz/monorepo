#![no_main]

use commonware_consensus_fuzz::{fuzz, FuzzInput, SimplexEd25519, Standard};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519, Standard>(input);
});

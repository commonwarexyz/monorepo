#![no_main]

use commonware_consensus_fuzz::{fuzz, CodeCoverage, FuzzInput, SimplexEd25519, Standard};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519, Standard, CodeCoverage>(input);
});

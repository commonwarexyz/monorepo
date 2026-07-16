#![no_main]

use commonware_consensus_fuzz::{CodeCoverage, FaultyNet, FuzzInput, SimplexEd25519, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519, FaultyNet, CodeCoverage>(input);
});

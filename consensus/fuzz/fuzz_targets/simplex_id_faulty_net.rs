#![no_main]

use commonware_consensus_fuzz::{CodeCoverage, FaultyNet, FuzzInput, SimplexId, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, FaultyNet, CodeCoverage>(input);
});

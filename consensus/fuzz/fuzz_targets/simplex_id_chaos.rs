#![no_main]

use commonware_consensus_fuzz::{Chaos, CodeCoverage, FuzzInput, SimplexId, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, Chaos, CodeCoverage>(input);
});

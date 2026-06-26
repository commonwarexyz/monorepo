#![no_main]

use commonware_consensus_fuzz::{fuzz, FuzzInput, SimplexId, Standard, StateCoverage};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, Standard, StateCoverage>(input);
});

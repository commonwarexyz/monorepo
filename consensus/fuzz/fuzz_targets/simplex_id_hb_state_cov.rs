#![no_main]

use commonware_consensus_fuzz::{fuzz, FuzzInput, HappensBeforeStateCoverage, SimplexId, Standard};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, Standard, HappensBeforeStateCoverage>(input);
});

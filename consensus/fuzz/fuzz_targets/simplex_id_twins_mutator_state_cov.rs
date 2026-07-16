#![no_main]

use commonware_consensus_fuzz::{FuzzInput, SimplexId, StateCoverage, TwinsMutator, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, TwinsMutator, StateCoverage>(input);
});

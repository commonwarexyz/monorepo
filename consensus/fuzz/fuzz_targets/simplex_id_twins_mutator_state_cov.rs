#![no_main]

use commonware_consensus_fuzz::{fuzz, FuzzInput, SimplexId, StateCoverage, TwinsMutator};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, TwinsMutator, StateCoverage>(input);
});

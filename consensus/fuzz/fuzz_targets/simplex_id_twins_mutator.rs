#![no_main]

use commonware_consensus_fuzz::{fuzz, CodeCoverage, FuzzInput, SimplexId, TwinsMutator};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, TwinsMutator, CodeCoverage>(input);
});

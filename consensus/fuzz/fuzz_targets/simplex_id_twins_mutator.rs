#![no_main]

use commonware_consensus_fuzz::{CodeCoverage, FuzzInput, SimplexId, TwinsMutator, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, TwinsMutator, CodeCoverage>(input);
});

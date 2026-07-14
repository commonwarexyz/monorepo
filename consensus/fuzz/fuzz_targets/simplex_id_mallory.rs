#![no_main]

use commonware_consensus_fuzz::{fuzz, CodeCoverage, FuzzInput, Mallory, SimplexId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, Mallory, CodeCoverage>(input);
});

#![no_main]

use commonware_consensus_fuzz::{fuzz, CodeCoverage, FuzzInput, MalloryContainer, SimplexId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, MalloryContainer, CodeCoverage>(input);
});

#![no_main]

use commonware_consensus_fuzz::{fuzz, CodeCoverage, FuzzInput, MalloryTime, SimplexId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, MalloryTime, CodeCoverage>(input);
});

#![no_main]

use commonware_consensus_fuzz::{fuzz, ByzzfuzzQLearn, CodeCoverage, FuzzInput, SimplexId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, ByzzfuzzQLearn, CodeCoverage>(input);
});

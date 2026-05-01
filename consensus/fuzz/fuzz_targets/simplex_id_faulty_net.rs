#![no_main]

use commonware_consensus_fuzz::{fuzz, FaultyNet, FuzzInput, SimplexId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, FaultyNet>(input);
});

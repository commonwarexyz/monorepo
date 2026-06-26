#![no_main]

use commonware_consensus_fuzz::{fuzz_state_cov, FuzzInput, SimplexId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz_state_cov::<SimplexId>(input);
});

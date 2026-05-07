#![no_main]

use commonware_consensus_fuzz::{fuzz, ByzzfuzzLiveness, FuzzInput, SimplexId};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexId, ByzzfuzzLiveness>(input);
});

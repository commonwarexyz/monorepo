#![no_main]

use commonware_consensus_fuzz::{FuzzInput, SimplexId, fuzz_audit};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz_audit::<SimplexId>(input);
});

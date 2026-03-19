#![no_main]

use commonware_consensus_fuzz::{fuzz, FuzzInput, SimplexSecp256r1, Standard};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexSecp256r1, Standard>(input);
});

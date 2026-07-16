#![no_main]

use commonware_consensus_fuzz::{CodeCoverage, FuzzInput, SimplexSecp256r1, Standard, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexSecp256r1, Standard, CodeCoverage>(input);
});

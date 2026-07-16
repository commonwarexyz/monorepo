#![no_main]

use commonware_consensus_fuzz::{FuzzInput, SimplexSecp256r1, Twinable, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexSecp256r1, Twinable>(input);
});

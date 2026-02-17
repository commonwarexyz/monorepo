#![no_main]

use commonware_consensus_fuzz::{fuzz, FuzzInput, SimplexEd25519CustomRoundRobin, Twinable};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519CustomRoundRobin, Twinable>(input);
});

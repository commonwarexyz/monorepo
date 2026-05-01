#![no_main]

use commonware_consensus_fuzz::{fuzz, FaultyMessaging, FuzzInput, SimplexEd25519};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexEd25519, FaultyMessaging>(input);
});

#![no_main]

use commonware_consensus_fuzz::{fuzz, FaultyMessaging, FuzzInput, SimplexSecp256r1};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<SimplexSecp256r1, FaultyMessaging>(input);
});

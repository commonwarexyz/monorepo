#![no_main]

use commonware_consensus_fuzz::protocol_ed25519::{fuzz_protocol_ed25519, ProtocolFuzzInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: ProtocolFuzzInput| {
    fuzz_protocol_ed25519(input);
});

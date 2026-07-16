#![no_main]

use commonware_cryptography_fuzz::certificate::{Ed25519, FuzzInput, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Ed25519>(input);
});

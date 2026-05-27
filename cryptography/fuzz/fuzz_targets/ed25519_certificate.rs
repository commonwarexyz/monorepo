#![no_main]

use commonware_cryptography_fuzz::certificate::{fuzz, Ed25519, FuzzInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Ed25519>(input);
});

#![no_main]

use commonware_cryptography_fuzz::certificate::{FuzzInput, Secp256r1, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Secp256r1>(input);
});

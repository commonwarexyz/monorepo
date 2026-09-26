#![no_main]

use commonware_cryptography::reed_solomon::engine::Scalar;
use commonware_cryptography_fuzz::reed_solomon::{FuzzInput, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Scalar>(input);
});

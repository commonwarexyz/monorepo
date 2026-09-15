#![no_main]

use commonware_cryptography::reed_solomon::fuzz::differential_engine;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    differential_engine(input);
});

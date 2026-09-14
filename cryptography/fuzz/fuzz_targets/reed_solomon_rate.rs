#![no_main]

use commonware_cryptography::reed_solomon::fuzz::differential_rate;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    differential_rate(input);
});

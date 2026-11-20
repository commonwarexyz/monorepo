#![no_main]

use commonware_consensus::fuzz::simplex::{FuzzInput, Mode, Scheme};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    Scheme::MultisigMinSig.run(input, Mode::Twin);
});

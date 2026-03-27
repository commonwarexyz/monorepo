#![no_main]

use commonware_coding::{ReedSolomon16, ReedSolomon8};
use commonware_coding_fuzz::{fuzz, FuzzInput};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<ReedSolomon16<Sha256>>(input.clone());

    if input.min.saturating_add(input.recovery) <= 255 {
        fuzz::<ReedSolomon8<Sha256>>(input);
    }
});

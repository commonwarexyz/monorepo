#![no_main]

use commonware_coding::NoCoding;
use commonware_coding_fuzz::{fuzz, FuzzInput};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<NoCoding<Sha256>>(input);
});

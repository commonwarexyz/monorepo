#![no_main]

use commonware_coding::Zoda;
use commonware_coding_fuzz::{fuzz, FuzzInput};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Zoda<Sha256>>(input);
});

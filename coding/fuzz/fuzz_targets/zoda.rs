#![no_main]

use commonware_coding::Zoda;
use commonware_coding_fuzz::{fuzz_phased, PhasedFuzzInput};
use commonware_cryptography::Sha256;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: PhasedFuzzInput| {
    fuzz_phased::<Zoda<Sha256>>(input);
});

#![no_main]

use commonware_p2p_fuzz::{fuzz, FuzzInput, Lookup};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Lookup>(input);
});

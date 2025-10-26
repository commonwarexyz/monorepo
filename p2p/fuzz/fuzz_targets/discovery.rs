#![no_main]

use commonware_p2p_fuzz::{fuzz, Discovery, FuzzInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Discovery>(input);
});

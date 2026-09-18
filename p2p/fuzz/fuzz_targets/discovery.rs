#![no_main]

use commonware_p2p_fuzz::{Discovery, FuzzInput, fuzz};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    fuzz::<Discovery>(input);
});

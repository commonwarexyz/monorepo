#![no_main]

use commonware_p2p_fuzz::{fuzz_network, Discovery, FuzzInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FuzzInput| {
    futures::executor::block_on(fuzz_network::<Discovery>(input));
});

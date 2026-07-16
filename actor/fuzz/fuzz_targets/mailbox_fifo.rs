#![no_main]

use commonware_actor_fuzz::{FifoInput, fuzz_fifo};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FifoInput| {
    fuzz_fifo(input);
});

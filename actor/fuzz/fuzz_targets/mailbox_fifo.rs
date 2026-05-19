#![no_main]

use commonware_actor_fuzz::{fuzz_fifo, FifoInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: FifoInput| {
    fuzz_fifo(input);
});

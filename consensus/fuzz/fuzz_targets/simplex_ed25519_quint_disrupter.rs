#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus_fuzz::{run_quint_disrupter_recording, FuzzInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut u) else {
        return;
    };
    run_quint_disrupter_recording(input, data);
});

#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_consensus_fuzz::{run_quint_byzantine_tracing, FuzzInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(input) = FuzzInput::arbitrary(&mut u) else {
        return;
    };
    let actor = input
        .byzantine_actor
        .expect("byzantine fuzz target requires input.byzantine_actor = Some(...)");
    run_quint_byzantine_tracing(actor, input, data);
});

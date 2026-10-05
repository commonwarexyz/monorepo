#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::reed_solomon::fuzz::EnginePlan;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let mut u = Unstructured::new(input);
    if let Ok(plan) = EnginePlan::arbitrary(&mut u) {
        let _ = plan.run(&mut u);
    }
});

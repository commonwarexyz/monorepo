#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use commonware_cryptography::reed_solomon::fuzz::RatePlan;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: &[u8]| {
    let mut u = Unstructured::new(input);
    if let Ok(plan) = RatePlan::arbitrary(&mut u) {
        let _ = plan.run(&mut u);
    }
});

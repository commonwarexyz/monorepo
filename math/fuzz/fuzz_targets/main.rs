#![no_main]

libfuzzer_sys::fuzz_target!(|input: &[u8]| {
    use arbitrary::{Arbitrary, Unstructured};
    let mut u = Unstructured::new(input);
    if let Ok(plan) = commonware_math::fuzz::Plan::arbitrary(&mut u) {
        let _ = plan.run(&mut u);
    }
});

#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_consensus_fuzz::aggregation_decode::fuzz;
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|data: &[u8]| {
        fuzz(data);
    });
}

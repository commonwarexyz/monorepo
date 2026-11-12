#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::dkg::{DkgStateSyncFuzzInput, fuzz_dkg_state_sync};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: DkgStateSyncFuzzInput| {
        fuzz_dkg_state_sync(input);
    });
}

#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::dkg::{DkgReshareRestartsFuzzInput, fuzz_dkg_reshare_restarts};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: DkgReshareRestartsFuzzInput| {
        fuzz_dkg_reshare_restarts(input);
    });
}

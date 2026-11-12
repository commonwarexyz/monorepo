#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::dkg::{DkgReshareFuzzInput, fuzz_dkg_reshare};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: DkgReshareFuzzInput| {
        fuzz_dkg_reshare(input);
    });
}

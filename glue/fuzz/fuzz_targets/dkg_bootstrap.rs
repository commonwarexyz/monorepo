#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::dkg::{DkgBootstrapFuzzInput, fuzz_dkg_bootstrap};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: DkgBootstrapFuzzInput| {
        fuzz_dkg_bootstrap(input);
    });
}

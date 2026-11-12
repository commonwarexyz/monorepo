#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::dkg::{DkgBootstrapRestartsFuzzInput, fuzz_dkg_bootstrap_restarts};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: DkgBootstrapRestartsFuzzInput| {
        fuzz_dkg_bootstrap_restarts(input);
    });
}

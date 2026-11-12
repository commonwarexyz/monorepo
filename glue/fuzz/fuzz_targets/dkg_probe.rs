#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::dkg::{DkgProbeFuzzInput, fuzz_dkg_probe};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: DkgProbeFuzzInput| {
        fuzz_dkg_probe(input);
    });
}

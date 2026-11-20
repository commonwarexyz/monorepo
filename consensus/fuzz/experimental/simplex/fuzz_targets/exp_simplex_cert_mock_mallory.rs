#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use arbitrary::{Arbitrary as _, Unstructured};
    use commonware_consensus_fuzz_simplex::{
        CodeCoverage, FuzzInput, MalloryContainer, SimplexCertificateMock, fuzz, mallory_mutate,
        mallory_observe_input,
    };
    use libfuzzer_sys::{fuzz_mutator, fuzz_target};

    // Decodes the input by hand (mirroring the typed `fuzz_target!` form, which
    // skips an undecodable input) because the mutator keys its per-input traces by
    // the raw bytes.
    fuzz_target!(|data: &[u8]| {
        let Ok(input) = FuzzInput::arbitrary_take_rest(Unstructured::new(data)) else {
            return;
        };
        mallory_observe_input(data);
        fuzz::<SimplexCertificateMock, MalloryContainer, CodeCoverage>(input);
    });

    fuzz_mutator!(|data: &mut [u8], size: usize, max_size: usize, seed: u32| {
        mallory_mutate(data, size, max_size, seed)
    });
}

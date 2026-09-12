#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::stateful::{StatefulProbeFuzzInput, fuzz_stateful_probe};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: StatefulProbeFuzzInput| {
        fuzz_stateful_probe(input);
    });
}

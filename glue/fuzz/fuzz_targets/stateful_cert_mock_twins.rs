#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::stateful::{StatefulTwinsFuzzInput, fuzz_stateful_cert_mock_twins};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: StatefulTwinsFuzzInput| {
        fuzz_stateful_cert_mock_twins(input);
    });
}

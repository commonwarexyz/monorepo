#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::stateful::{
        StatefulDbTwinsFuzzInput, fuzz_stateful_cert_mock_twins_db,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: StatefulDbTwinsFuzzInput| {
        fuzz_stateful_cert_mock_twins_db(input);
    });
}

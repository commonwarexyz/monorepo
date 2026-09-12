#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::stateful::{
        StatefulDbRestartsFuzzInput, fuzz_stateful_cert_mock_restarts_db,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: StatefulDbRestartsFuzzInput| {
        fuzz_stateful_cert_mock_restarts_db(input);
    });
}

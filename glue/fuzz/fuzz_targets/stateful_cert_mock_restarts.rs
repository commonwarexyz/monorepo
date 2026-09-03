#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::stateful::{
        StatefulRestartsFuzzInput, fuzz_stateful_cert_mock_restarts,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: StatefulRestartsFuzzInput| {
        fuzz_stateful_cert_mock_restarts(input);
    });
}

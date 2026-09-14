#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::stateful::{
        StatefulStateSyncFuzzInput, fuzz_stateful_cert_mock_state_sync,
    };
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: StatefulStateSyncFuzzInput| {
        fuzz_stateful_cert_mock_state_sync(input);
    });
}

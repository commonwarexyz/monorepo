#![no_main]

#[cfg(feature = "mocks")]
mod fuzz {
    use commonware_glue_fuzz::stateful::{StatefulDbSyncFuzzInput, fuzz_stateful_db_sync};
    use libfuzzer_sys::fuzz_target;

    fuzz_target!(|input: StatefulDbSyncFuzzInput| {
        fuzz_stateful_db_sync(input);
    });
}

#![no_main]

use insitu_fuzz::{run_fuzz_iteration, setup_panic_hook, test_registry};
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Once;

static INIT: Once = Once::new();

// Single-test fuzzer for consensus simplex test_all_online (~55s, 9954 messages)
static TEST_ENTRY: Lazy<&'static test_registry::TestEntry> = Lazy::new(|| {
    test_registry::get_test_by_name("consensus_simplex_tests::test_all_online")
        .expect("Test not found in registry")
});

fuzz_target!(|data: &[u8]| {
    INIT.call_once(setup_panic_hook);
    let entry = *TEST_ENTRY;
    run_fuzz_iteration(data, entry.message_count, entry.test_fn);
});

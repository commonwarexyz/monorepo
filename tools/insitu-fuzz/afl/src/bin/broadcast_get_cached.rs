/// AFL++ harness for broadcast_buffered_tests::test_get_cached only
///
/// Single-test harness for focused fuzzing of the get_cached test.
/// Input format: [msg_idx:u16][xor_key...]
///
/// Usage:
///   ./afl.sh --target=broadcast_get_cached run
use insitu_fuzz::{run_fuzz_iteration, setup_panic_hook, test_registry};
use std::sync::Once;

static INIT: Once = Once::new();

fn main() {
    setup_panic_hook();
    let entry = test_registry::get_test_by_name("broadcast_buffered_tests::test_get_cached")
        .expect("Test not found in registry");

    afl::fuzz!(|data: &[u8]| {
        run_fuzz_iteration(data, entry.message_count, entry.test_fn);
    });
}

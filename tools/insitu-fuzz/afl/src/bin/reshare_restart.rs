/// AFL++ harness for reshare restart test with deferred fork server
///
/// Targets test_restart_threshold_slow_ which has 134,898 messages.
/// Uses MSG_IDX to specify the fork point for targeted fuzzing.
///
/// Usage:
///   MSG_IDX=1000 ./afl.sh --target=reshare_restart run
use insitu_fuzz::{set_expected_messages, setup_panic_hook, test_registry};
use once_cell::sync::Lazy;
use std::panic;

/// MSG_IDX from environment (required for deferred fork)
static MSG_IDX: Lazy<usize> = Lazy::new(|| {
    std::env::var("MSG_IDX")
        .expect("MSG_IDX environment variable required")
        .parse::<usize>()
        .expect("MSG_IDX must be a valid number")
});

fn main() {
    setup_panic_hook();

    // Validate MSG_IDX early
    let _ = *MSG_IDX;

    let entry =
        test_registry::get_test_by_name("reshare_validator_test::test_restart_threshold_slow_")
            .expect("test_restart_threshold_slow_ not found in registry");

    // Set expected messages for validation (input comes later via insitu_fuzz_checkpoint)
    // Flow:
    // 1. Messages 0..fork_point run without corruption (FUZZER_INPUT is empty)
    // 2. At fork point, insitu_fuzz_checkpoint() calls __afl_manual_init()
    // 3. Parent pauses, child wakes up and reads fresh input from stdin
    // 4. Child continues with fuzzed input for remaining messages
    // 5. If MSG_IDX range end specified, exits cleanly when exceeded
    set_expected_messages(entry.message_count);
    let _ = panic::catch_unwind(entry.test_fn);

    // If we get here, test completed (child exited or no fork happened)
    std::process::exit(0);
}

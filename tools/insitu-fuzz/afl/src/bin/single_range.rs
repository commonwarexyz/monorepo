/// AFL++ harness for message corruption fuzzing with deferred fork server
///
/// Targets a specific test/message range for message corruption.
/// The runtime replays messages 0..N-1 once, then AFL forks at message N.
/// Each child reads fresh input from stdin (XOR key for message corruption).
///
/// Usage:
///   TEST_IDX=5 MSG_IDX=2 ./afl.sh --target=single_range run      # Target message 2
///   TEST_IDX=5 MSG_IDX=50..60 ./afl.sh --target=single_range run # Target messages 50-60

// Tell AFL++ to defer fork server until __afl_manual_init() is called
#[used]
#[no_mangle]
pub static __AFL_DEFER_FORKSRV: [u8; 25] = *b"##SIG_AFL_DEFER_FORKSRV##";

use insitu_fuzz::{
    set_deferred_fork_range, set_deferred_mode, set_expected_messages, setup_panic_hook,
    test_registry, DeferredMode,
};
use once_cell::sync::Lazy;

/// TEST_IDX from environment (required)
static TEST_IDX: Lazy<usize> = Lazy::new(|| {
    std::env::var("TEST_IDX")
        .expect("TEST_IDX environment variable required")
        .parse::<usize>()
        .expect("TEST_IDX must be a valid number")
});

/// MSG_IDX from environment: single index "50" or range "50..60"
static MSG_IDX: Lazy<(usize, Option<usize>)> = Lazy::new(|| {
    let s = std::env::var("MSG_IDX").expect("MSG_IDX required");
    match s.split_once("..") {
        Some((a, b)) => (a.parse().unwrap(), Some(b.parse().unwrap())),
        None => (s.parse().unwrap(), None),
    }
});

fn main() {
    // Abort on any panic so AFL sees crashes
    setup_panic_hook();

    let test_idx = *TEST_IDX;
    let (msg_start, msg_end) = *MSG_IDX;

    if test_idx >= test_registry::NUM_TESTS {
        eprintln!(
            "TEST_IDX must be 0-{} (got: {})",
            test_registry::NUM_TESTS - 1,
            test_idx
        );
        std::process::exit(1);
    }

    let entry = &test_registry::TESTS[test_idx];

    // Configure deferred fork for message corruption
    // Flow:
    // 1. Messages 0..fork_point run without corruption (FUZZER_INPUT is empty)
    // 2. At fork point, insitu_fuzz_checkpoint() calls __afl_manual_init()
    // 3. Parent becomes fork server, child reads fresh input from stdin
    // 4. Child continues with fuzzed input (XOR key) for message corruption
    // 5. If range end specified, exits cleanly when exceeded
    set_expected_messages(entry.message_count);
    set_deferred_mode(DeferredMode::MessageCorruption);
    set_deferred_fork_range(msg_start, msg_end);

    // Run test - panic = crash = AFL finding
    (entry.test_fn)();

    std::process::exit(0);
}

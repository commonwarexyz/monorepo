/// AFL++ harness for slow tests only (>=100ms)
///
/// Fuzzes only slow tests for deeper coverage.
/// Input format: [test_selector:u16][msg_idx:u16][xor_key...]
///
/// Usage:
///   ./afl.sh --target=slow_tests run
use insitu_fuzz::{run_fuzz_iteration, setup_panic_hook, test_registry};
use once_cell::sync::Lazy;

/// Duration threshold in milliseconds
const SLOW_THRESHOLD_MS: u32 = 100;

/// Slow test entries (filtered at startup)
static SLOW_TESTS: Lazy<Vec<&'static test_registry::TestEntry>> = Lazy::new(|| {
    test_registry::TESTS
        .iter()
        .filter(|e| e.duration_ms >= SLOW_THRESHOLD_MS)
        .collect()
});

fn main() {
    setup_panic_hook();

    if SLOW_TESTS.is_empty() {
        eprintln!("No slow tests found (threshold: {}ms)", SLOW_THRESHOLD_MS);
        std::process::exit(1);
    }

    afl::fuzz!(|data: &[u8]| {
        if data.len() < 2 {
            return;
        }
        let selector = u16::from_le_bytes([data[0], data[1]]) as usize;
        if selector >= SLOW_TESTS.len() {
            return;
        }
        let entry = SLOW_TESTS[selector];
        run_fuzz_iteration(&data[2..], entry.message_count, entry.test_fn);
    });
}

/// AFL++ harness for fast tests only (<100ms)
///
/// Fuzzes only fast tests for higher throughput.
/// Input format: [test_selector:u16][msg_idx:u16][xor_key...]
///
/// Usage:
///   ./afl.sh --target=fast_tests run
use insitu_fuzz::{run_fuzz_iteration, setup_panic_hook, test_registry};
use once_cell::sync::Lazy;

/// Duration threshold in milliseconds
const FAST_THRESHOLD_MS: u32 = 1000;

/// Fast test indices (filtered at startup)
static FAST_TESTS: Lazy<Vec<&'static test_registry::TestEntry>> = Lazy::new(|| {
    test_registry::TESTS
        .iter()
        .filter(|e| e.duration_ms < FAST_THRESHOLD_MS)
        .collect()
});

fn main() {
    setup_panic_hook();

    if FAST_TESTS.is_empty() {
        eprintln!("No fast tests found (threshold: {}ms)", FAST_THRESHOLD_MS);
        std::process::exit(1);
    }

    afl::fuzz!(|data: &[u8]| {
        if data.len() < 2 {
            return;
        }
        let selector = u16::from_le_bytes([data[0], data[1]]) as usize;
        if selector >= FAST_TESTS.len() {
            return;
        }
        let entry = FAST_TESTS[selector];
        run_fuzz_iteration(&data[2..], entry.message_count, entry.test_fn);
    });
}

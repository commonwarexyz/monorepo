/// AFL++ harness for task order fuzzing - fast tests only
///
/// Tests task scheduling order in the deterministic runtime.
/// Unlike message mutation fuzzing, task reordering should NEVER cause panics
/// in correct code. Any panic here indicates a real bug.
///
/// Key differences from message mutation harness:
/// - NO panic filtering (setup_panic_hook)
/// - Panics propagate directly to AFL as crashes
///
/// Input format: [test_selector:u16][task_order_bytes...]
use insitu_fuzz::{set_task_order_bytes, test_registry};
use once_cell::sync::Lazy;

/// Duration threshold in milliseconds
const FAST_THRESHOLD_MS: u32 = 100;

/// Fast tests (filtered at startup)
static FAST_TESTS: Lazy<Vec<&'static test_registry::TestEntry>> = Lazy::new(|| {
    test_registry::TESTS
        .iter()
        .filter(|e| e.duration_ms < FAST_THRESHOLD_MS)
        .collect()
});

fn main() {
    // NO setup_panic_hook() - panics should crash

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

        // Remaining bytes control task scheduling order
        set_task_order_bytes(&data[2..]);

        // Run test directly - panic = crash = finding
        (entry.test_fn)();
    });
}

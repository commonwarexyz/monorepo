#![no_main]
//! LibFuzzer harness for fast tests only (<100ms)
//!
//! Fuzzes only fast tests for higher throughput.
//! Input format: [test_selector:u16][msg_idx:u16][xor_key...]
//!
//! Usage:
//!   ./fuzz.sh --target=fast_tests run

use insitu_fuzz::{run_fuzz_iteration, setup_panic_hook, test_registry};
use libfuzzer_sys::fuzz_target;
use once_cell::sync::Lazy;
use std::sync::Once;

/// Duration threshold in milliseconds
const FAST_THRESHOLD_MS: u32 = 100;

static INIT: Once = Once::new();

/// Fast tests (filtered at startup)
static FAST_TESTS: Lazy<Vec<&'static test_registry::TestEntry>> = Lazy::new(|| {
    test_registry::TESTS
        .iter()
        .filter(|e| e.duration_ms < FAST_THRESHOLD_MS)
        .collect()
});

fuzz_target!(|data: &[u8]| {
    INIT.call_once(setup_panic_hook);
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

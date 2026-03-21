#![no_main]
//! Task order fuzzing - any panic is a bug
//!
//! This harness tests task scheduling order in the deterministic runtime.
//! Unlike message mutation fuzzing, task reordering should NEVER cause panics
//! in correct code. Any panic here indicates a real bug (race condition,
//! ordering assumption, etc).
//!
//! Key differences from message mutation harness:
//! - NO panic filtering (setup_panic_hook)
//! - NO catch_unwind
//! - Panics propagate directly to fuzzer as crashes
//!
//! Currently limited to fast tests (<100ms) for higher throughput.

use insitu_fuzz::{set_task_order_bytes, test_registry};
use libfuzzer_sys::fuzz_target;
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

fuzz_target!(|data: &[u8]| {
    // Need at least 2 bytes for test selector
    if data.len() < 2 {
        return;
    }

    // First 2 bytes select the test from fast tests only
    let selector = u16::from_le_bytes([data[0], data[1]]) as usize;
    if selector >= FAST_TESTS.len() {
        return;
    }

    let entry = FAST_TESTS[selector];

    // Remaining bytes control task scheduling order
    // These are read by the runtime via FFI (commonware_fuzz_get_task_order_bytes)
    set_task_order_bytes(&data[2..]);

    // Run test directly - panic = crash = finding
    // No panic filtering, no catch_unwind
    (entry.test_fn)();
});

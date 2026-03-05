#![no_main]

use insitu_fuzz::{run_fuzz_iteration, setup_panic_hook, test_registry};
use libfuzzer_sys::fuzz_target;
use std::sync::Once;

static INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    INIT.call_once(setup_panic_hook);
    if data.len() < 2 {
        return;
    }
    let selector = u16::from_le_bytes([data[0], data[1]]) as usize;
    if selector >= test_registry::NUM_TESTS {
        return;
    }
    if let Some(entry) = test_registry::get_test(selector) {
        run_fuzz_iteration(&data[2..], entry.message_count, entry.test_fn);
    }
});

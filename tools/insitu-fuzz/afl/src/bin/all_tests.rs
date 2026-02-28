/// AFL++ harness for all fuzzable tests (multi-test mode)
///
/// Fuzzes all tests using standard `afl::fuzz!` macro.
/// Input format: [test_selector:u16][msg_idx:u16][xor_key...]
///
/// Usage:
///   ./afl.sh run  # Fuzz all tests
use insitu_fuzz::{run_fuzz_iteration, setup_panic_hook, test_registry};

fn main() {
    setup_panic_hook();

    afl::fuzz!(|data: &[u8]| {
        if data.len() < 2 {
            return;
        }
        let selector = u16::from_le_bytes([data[0], data[1]]) as usize;
        if selector >= test_registry::NUM_TESTS {
            return;
        }
        let entry = &test_registry::TESTS[selector];
        run_fuzz_iteration(&data[2..], entry.message_count, entry.test_fn);
    });
}

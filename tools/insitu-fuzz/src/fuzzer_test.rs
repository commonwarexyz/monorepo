//! Fuzzer tests - unit tests for mechanics and integration tests with real commonware tests.
//!
//! ## Unit Tests
//! Test fuzzer core mechanics in isolation (validation, XOR, message indexing).
//! No external dependencies required.
//!
//! ## Integration Tests (requires `test-registry` feature)
//! Test fuzzer with real commonware tests to verify end-to-end corruption works.

/// Unit tests for fuzzer mechanics (no external deps)
#[cfg(test)]
mod unit {
    use crate::{
        clear_fuzzer_input, corrupt_bytes, enable_stats, get_stats, reset_stats,
        set_expected_messages, set_fuzzer_input,
    };

    /// Reset all fuzzer state for clean test
    fn reset_fuzzer_state() {
        clear_fuzzer_input();
        enable_stats();
        reset_stats();
    }

    #[test]
    fn test_normal_fuzzing_path() {
        reset_fuzzer_state();

        // Setup: 10 messages expected
        set_expected_messages(10);

        // Valid input: target message 5, XOR key [0xFF, 0xFF]
        let input = [5u8, 0, 0xFF, 0xFF];
        assert!(set_fuzzer_input(&input), "Valid input should be accepted");

        // Simulate 10 messages being sent
        let mut corrupted_count = 0;
        for i in 0..10 {
            let mut msg = vec![0xAA; 10];
            if corrupt_bytes(&mut msg) {
                corrupted_count += 1;
                // Message 5 should be corrupted
                assert_eq!(i, 5, "Only message 5 should be corrupted");
                // First two bytes should be XORed with 0xFF
                assert_eq!(msg[0], 0xAA ^ 0xFF);
                assert_eq!(msg[1], 0xAA ^ 0xFF);
                // Rest unchanged
                assert_eq!(msg[2], 0xAA);
            }
        }

        assert_eq!(
            corrupted_count, 1,
            "Exactly one message should be corrupted"
        );
        assert_eq!(get_stats().corrupted_messages, 1);
    }

    #[test]
    fn test_message_index_increments() {
        reset_fuzzer_state();

        set_expected_messages(5);
        let input = [2u8, 0, 0xFF]; // Target message 2
        assert!(set_fuzzer_input(&input));

        // Each corrupt_bytes call increments MESSAGE_INDEX
        let mut msg = vec![0x00; 4];

        // Message 0 - not corrupted
        assert!(!corrupt_bytes(&mut msg));
        assert_eq!(msg, vec![0x00; 4]);

        // Message 1 - not corrupted
        assert!(!corrupt_bytes(&mut msg));
        assert_eq!(msg, vec![0x00; 4]);

        // Message 2 - corrupted!
        assert!(corrupt_bytes(&mut msg));
        assert_eq!(msg[0], 0xFF); // XORed

        // Message 3 - not corrupted (target already passed)
        msg = vec![0x00; 4];
        assert!(!corrupt_bytes(&mut msg));
        assert_eq!(msg, vec![0x00; 4]);
    }

    #[test]
    fn test_validation_rejects_out_of_range() {
        reset_fuzzer_state();

        set_expected_messages(10);

        // Target message 10 (out of range for 0-9)
        let input = [10u8, 0, 0xFF];
        assert!(!set_fuzzer_input(&input), "Out of range should be rejected");

        // Target message 255 (way out of range)
        let input = [255u8, 0, 0xFF];
        assert!(
            !set_fuzzer_input(&input),
            "Way out of range should be rejected"
        );
    }

    #[test]
    fn test_validation_rejects_too_short() {
        reset_fuzzer_state();

        set_expected_messages(10);

        // Only 1 byte (need at least 2 for message index)
        let input = [5u8];
        assert!(!set_fuzzer_input(&input), "Too short should be rejected");

        // Empty
        let input: [u8; 0] = [];
        assert!(!set_fuzzer_input(&input), "Empty should be rejected");
    }

    #[test]
    fn test_no_corruption_without_input() {
        reset_fuzzer_state();

        set_expected_messages(10);
        // Don't set any fuzzer input

        let mut msg = vec![0xAA; 10];
        for _ in 0..10 {
            assert!(!corrupt_bytes(&mut msg));
        }
        assert_eq!(msg, vec![0xAA; 10], "Message should be unchanged");
        assert_eq!(get_stats().corrupted_messages, 0);
    }

    #[test]
    fn test_no_corruption_without_xor_key() {
        reset_fuzzer_state();

        set_expected_messages(10);

        // Valid message index but no XOR key bytes
        let input = [5u8, 0];
        assert!(
            set_fuzzer_input(&input),
            "Should accept (validation passes)"
        );

        let mut msg = vec![0xAA; 10];
        for _ in 0..10 {
            // corrupt_bytes should return false when no key provided
            assert!(!corrupt_bytes(&mut msg));
        }
        assert_eq!(msg, vec![0xAA; 10], "No corruption without XOR key");
    }

    #[test]
    fn test_deferred_fork_path_setup() {
        // This tests the path used by AFL deferred fork mode:
        // 1. set_expected_messages is called
        // 2. Test runs without fuzzer input (no corruption)
        // 3. MESSAGE_INDEX increments as messages pass through
        // 4. At checkpoint, if MESSAGE_INDEX reaches fork point, fork happens
        // 5. After fork, set_fuzzer_input is called with fresh input

        reset_fuzzer_state();

        // Phase 1: Setup (like run_deferred_fork_mode does)
        set_expected_messages(34);

        // Phase 2: Messages flow through without corruption (FUZZER_INPUT empty)
        for _ in 0..10 {
            let mut msg = vec![0xAA; 20];
            assert!(!corrupt_bytes(&mut msg), "No corruption before fork");
        }

        // Phase 3: Simulate fork - now set_fuzzer_input is called
        // (In real AFL, this comes from stdin after __afl_manual_init)
        let input = [10u8, 0, 0xFF, 0xFF]; // Target message 10
        assert!(set_fuzzer_input(&input));

        // Note: MESSAGE_INDEX is NOT reset for AFL (checked via __AFL_SHM_ID)
        // For this test (no __AFL_SHM_ID), it IS reset to 0

        // Phase 4: Continue with corruption enabled
        let mut corrupted = false;
        for i in 0..34 {
            let mut msg = vec![0xAA; 20];
            if corrupt_bytes(&mut msg) {
                corrupted = true;
                assert_eq!(i, 10, "Message 10 should be corrupted");
            }
        }
        assert!(corrupted, "Should have corrupted message 10");
    }

    #[test]
    fn test_xor_key_truncation() {
        reset_fuzzer_state();

        set_expected_messages(5);

        // Long XOR key (10 bytes) but short message (3 bytes)
        let input = [
            0u8, 0, 0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8, 0xF7, 0xF6,
        ];
        assert!(set_fuzzer_input(&input));

        let mut msg = vec![0x00, 0x01, 0x02];
        assert!(corrupt_bytes(&mut msg));

        // Only first 3 bytes of key used
        assert_eq!(msg[0], 0x00 ^ 0xFF);
        assert_eq!(msg[1], 0x01 ^ 0xFE);
        assert_eq!(msg[2], 0x02 ^ 0xFD);
    }

    #[test]
    fn test_xor_key_padding() {
        reset_fuzzer_state();

        set_expected_messages(5);

        // Short XOR key (2 bytes) but longer message (5 bytes)
        let input = [0u8, 0, 0xFF, 0xFE];
        assert!(set_fuzzer_input(&input));

        let mut msg = vec![0x00, 0x01, 0x02, 0x03, 0x04];
        assert!(corrupt_bytes(&mut msg));

        // First 2 bytes XORed, rest unchanged
        assert_eq!(msg[0], 0x00 ^ 0xFF);
        assert_eq!(msg[1], 0x01 ^ 0xFE);
        assert_eq!(msg[2], 0x02); // unchanged
        assert_eq!(msg[3], 0x03); // unchanged
        assert_eq!(msg[4], 0x04); // unchanged
    }
}

/// Integration tests with real commonware tests
#[cfg(all(test, feature = "test-registry"))]
mod integration {
    use crate::{
        clear_fuzzer_input, enable_stats, get_stats, reset_stats, set_expected_messages,
        set_fuzzer_input, Stats,
    };
    use commonware_broadcast::buffered::tests::test_packet_loss;
    use serial_test::serial;
    use std::panic;

    // Test configuration: test_packet_loss has 34 messages
    const EXPECTED_MESSAGES: usize = 34;

    /// Initialize panic hook to suppress test infrastructure panics (one-time setup)
    fn init_panic_hook() {
        use std::sync::Once;
        static INIT: Once = Once::new();

        INIT.call_once(|| {
            let _default_hook = panic::take_hook();
            panic::set_hook(Box::new(move |panic_info| {
                // Suppress all panics during fuzzing tests - we expect corruption to cause failures
                let _ = panic_info;
            }));
        });
    }

    /// Initialize fuzzer state for testing.
    /// NOTE: Tests must use #[serial] - fuzzer state is not concurrency-safe
    fn init_fuzzer_state() {
        init_panic_hook();
        enable_stats();
        reset_stats();
    }

    /// Run the fuzzing test with corruption targeting a specific message position.
    fn run_with_corruption(msg_pos: u16) -> Stats {
        init_fuzzer_state();

        // Format: [msg_idx(2 bytes), raw_key...]
        let msg_idx_bytes = msg_pos.to_le_bytes();
        let fuzzer_input = [msg_idx_bytes[0], msg_idx_bytes[1], 0xFF, 0xFF, 0xFF, 0xFF];

        set_expected_messages(EXPECTED_MESSAGES);
        assert!(
            set_fuzzer_input(&fuzzer_input),
            "Test generated invalid fuzzer input"
        );

        let _ = panic::catch_unwind(test_packet_loss);
        get_stats()
    }

    /// Run the fuzzing test without corruption (fuzzer input disabled).
    fn run_without_corruption() -> Stats {
        init_fuzzer_state();

        set_expected_messages(EXPECTED_MESSAGES);
        clear_fuzzer_input();

        let _ = panic::catch_unwind(test_packet_loss);
        get_stats()
    }

    #[test]
    #[serial]
    fn test_corruption_tracking() {
        // Baseline: no corruption when fuzzer input is disabled
        let baseline_stats = run_without_corruption();
        assert_eq!(
            baseline_stats.corrupted_messages, 0,
            "Should not corrupt without fuzzer input"
        );

        // With corruption: verify exactly one message is corrupted
        let corrupted_stats = run_with_corruption(15);
        assert_eq!(
            corrupted_stats.corrupted_messages, 1,
            "Should corrupt exactly one message"
        );
    }

    #[test]
    #[serial]
    fn test_message_position_targeting() {
        // Test corruption at different message positions
        let positions = [0, 5, 10, (EXPECTED_MESSAGES - 1) as u16];

        for &pos in &positions {
            let stats = run_with_corruption(pos);
            assert_eq!(
                stats.corrupted_messages, 1,
                "Should corrupt exactly one message at position {}",
                pos
            );
        }
    }
}

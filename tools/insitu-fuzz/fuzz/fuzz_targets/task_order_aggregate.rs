#![no_main]
//! Task order fuzzing for aggregation::tests::test_all_online
//!
//! Single-target harness - no test selector needed.
//! All input bytes control task scheduling order.
//!
//! Any panic = real bug (race condition, ordering assumption)

use commonware_consensus::aggregation::tests as consensus_aggregation_tests;
use insitu_fuzz::set_task_order_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // All bytes control task scheduling order
    // (read by runtime via FFI: commonware_fuzz_get_task_order_bytes)
    set_task_order_bytes(data);

    // Run test directly - panic = crash = finding
    consensus_aggregation_tests::test_all_online();
});

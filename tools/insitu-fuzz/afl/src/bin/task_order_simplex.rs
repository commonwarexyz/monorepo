use commonware_consensus::simplex::tests as consensus_simplex_tests;
/// AFL++ harness for task order fuzzing - simplex::tests::test_all_online
///
/// Single-target harness - no test selector needed.
/// All input bytes control task scheduling order.
///
/// Any panic = real bug (race condition, ordering assumption)
use insitu_fuzz::set_task_order_bytes;

fn main() {
    // NO setup_panic_hook() - panics should crash

    afl::fuzz!(|data: &[u8]| {
        // All bytes control task scheduling order
        set_task_order_bytes(data);

        // Run test directly - panic = crash = finding
        consensus_simplex_tests::test_all_online();
    });
}

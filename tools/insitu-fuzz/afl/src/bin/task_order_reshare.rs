/// AFL++ harness for task order fuzzing - reshare restart with deferred fork
///
/// Combines task order fuzzing with deferred fork server for the large
/// test_restart_threshold_slow_ test (134,898 messages).
///
/// Uses MSG_IDX to specify the fork point - messages 0..N-1 run once in parent,
/// then AFL forks and each child gets fresh task order bytes from stdin.
///
/// Any panic = real bug (race condition, ordering assumption)
///
/// Usage:
///   MSG_IDX=1000 ./afl.sh --target=task_order_reshare run      # Fork at msg 1000
///   MSG_IDX=1000..2000 ./afl.sh --target=task_order_reshare run # Fork at 1000, exit after 2000

// Tell AFL++ to defer fork server until __afl_manual_init() is called
#[used]
#[no_mangle]
pub static __AFL_DEFER_FORKSRV: [u8; 25] = *b"##SIG_AFL_DEFER_FORKSRV##";

use insitu_fuzz::{
    set_deferred_fork_range, set_deferred_mode, set_expected_messages, setup_abort_on_panic,
    test_registry, DeferredMode,
};
use once_cell::sync::Lazy;

/// MSG_IDX from environment: single index "1000" or range "1000..2000"
static MSG_IDX: Lazy<(usize, Option<usize>)> = Lazy::new(|| {
    let s = std::env::var("MSG_IDX").expect("MSG_IDX required");
    match s.split_once("..") {
        Some((a, b)) => (a.parse().unwrap(), Some(b.parse().unwrap())),
        None => (s.parse().unwrap(), None),
    }
});

fn main() {
    // Abort immediately on any panic for deferred mode AFL
    setup_abort_on_panic();

    let (msg_start, msg_end) = *MSG_IDX;

    let entry = test_registry::get_test_by_name(
        "reshare_validator_test::reshare_with_many_forced_failures_slow_",
    )
    .expect("test_restart_threshold_slow_ not found in registry");

    // Configure deferred fork to route stdin to task order control
    set_expected_messages(entry.message_count);
    set_deferred_mode(DeferredMode::TaskOrder);
    set_deferred_fork_range(msg_start, msg_end);

    // Run test directly - panic = crash = finding
    (entry.test_fn)();

    std::process::exit(0);
}

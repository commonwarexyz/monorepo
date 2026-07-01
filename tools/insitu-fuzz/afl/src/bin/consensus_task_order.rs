/// AFL++ harness for task-order concurrency fuzzing against consensus invariants.
///
/// Uses deferred fork windows (MSG_IDX) and fuzzes task ordering only.
/// Consensus scenario parameters are fixed to keep this campaign single-axis.
///
/// Usage:
///   MSG_IDX=1000 ./afl.sh --target=consensus_task_order run
///   MSG_IDX=1000..2000 ./afl.sh --target=consensus_task_order run

// Tell AFL++ to defer fork server until __afl_manual_init() is called
#[used]
#[no_mangle]
pub static __AFL_DEFER_FORKSRV: [u8; 25] = *b"##SIG_AFL_DEFER_FORKSRV##";

use commonware_consensus_fuzz::{
    fuzz, strategy::StrategyChoice, utils::Partition, Configuration, FuzzInput, SimplexEd25519,
    Standard, N4F1C3,
};
use insitu_fuzz::{set_deferred_fork_range, set_deferred_mode, setup_abort_on_panic, DeferredMode};
use once_cell::sync::Lazy;

/// MSG_IDX from environment: single index "1000" or range "1000..2000"
static MSG_IDX: Lazy<(usize, Option<usize>)> = Lazy::new(|| {
    let s = std::env::var("MSG_IDX").expect("MSG_IDX required");
    match s.split_once("..") {
        Some((a, b)) => (a.parse().unwrap(), Some(b.parse().unwrap())),
        None => (s.parse().unwrap(), None),
    }
});

fn fixed_input() -> FuzzInput {
    FuzzInput {
        // Fixed RNG seed for consensus fuzz internals; task-order bytes are fuzzed in windows.
        raw_bytes: 0xC0FFEE_u64.to_be_bytes().to_vec(),
        required_containers: 30,
        degraded_network: false,
        configuration: Configuration::new(N4F1C3.n, N4F1C3.faults, N4F1C3.correct),
        partition: Partition::Connected,
        strategy: StrategyChoice::AnyScope,
    }
}

fn main() {
    // Abort immediately on panic in deferred mode so AFL records a crash.
    setup_abort_on_panic();

    let (msg_start, msg_end) = *MSG_IDX;

    // Configure deferred fork to route stdin bytes to task-order control.
    set_deferred_mode(DeferredMode::TaskOrder);
    set_deferred_fork_range(msg_start, msg_end);

    // Run one fixed consensus scenario; each child mutates only task scheduling order.
    fuzz::<SimplexEd25519, Standard>(fixed_input());

    std::process::exit(0);
}

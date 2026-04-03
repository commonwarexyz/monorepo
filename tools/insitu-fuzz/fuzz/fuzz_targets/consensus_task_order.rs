#![no_main]
//! Task order fuzzing with consensus fuzz harness (Disrupter + invariant checks)
//!
//! Combines insitu-fuzz's task permutation with the consensus fuzz harness
//! which runs bounded tests (5-50 containers) with Byzantine Disrupter actors
//! and checks invariants (agreement, no conflicting notarizations, etc.) after
//! every run. This gives the fuzzer tight feedback on task-ordering violations.
//!
//! Input is split: first half controls task scheduling order, second half
//! controls consensus fuzz parameters (partition, strategy, seed, etc.)
//!
//! Any panic = invariant violation = real ordering bug

use commonware_consensus_fuzz::{fuzz, FuzzInput, SimplexEd25519, Standard};
use insitu_fuzz::set_task_order_bytes;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Split input: first half controls task ordering, second half is consensus fuzz input
    let split = data.len() / 2;
    let (task_bytes, consensus_bytes) = data.split_at(split);

    set_task_order_bytes(task_bytes);

    let Ok(input) = arbitrary::Unstructured::new(consensus_bytes).arbitrary::<FuzzInput>() else {
        return;
    };

    // Any panic = invariant violation = real bug
    fuzz::<SimplexEd25519, Standard>(input);
});

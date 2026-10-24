#![no_main]

use commonware_cryptography::{
    Sha512,
    fuzz::{BatchPlan, Plan},
};
use commonware_parallel::{Rayon, mocks::Explorer};
use commonware_utils::NZUsize;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

/// A four-worker explorer that takes every split a hasher offers it. It is built once and reused
/// across invocations because starting a thread pool is expensive.
static STRATEGY: LazyLock<Explorer> =
    LazyLock::new(|| Explorer::parallel(&Rayon::new(NZUsize!(4)).unwrap()));

fuzz_target!(|input: (Plan<Sha512>, BatchPlan<Sha512>)| {
    let (plan, batch_plan) = input;
    plan.run();
    batch_plan.run(&*STRATEGY);
});

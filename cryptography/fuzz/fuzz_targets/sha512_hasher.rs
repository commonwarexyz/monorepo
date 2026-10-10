#![no_main]

use commonware_cryptography::{
    Sha512,
    fuzz::{BatchPlan, Plan},
};
use commonware_parallel::{Manual, Rayon, Strategy as _};
use commonware_utils::NZUsize;
use libfuzzer_sys::fuzz_target;
use std::sync::LazyLock;

/// A four-worker strategy with adaptive decisions disabled, so it takes every split a hasher
/// offers it. It is built once and reused across invocations because starting a thread pool is
/// expensive.
static STRATEGY: LazyLock<Manual<Rayon>> =
    LazyLock::new(|| Rayon::new(NZUsize!(4)).unwrap().manual());

fuzz_target!(|input: (Plan<Sha512>, BatchPlan<Sha512>)| {
    let (plan, batch_plan) = input;
    plan.run(&*STRATEGY);
    batch_plan.run(&*STRATEGY);
});

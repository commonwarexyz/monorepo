#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::bls12381::golden_dkg::{FuzzPlan, Setup};
use commonware_parallel::Sequential;
use libfuzzer_sys::fuzz_target;
use std::{num::NonZeroU32, sync::LazyLock};

/// `FuzzPlan::arbitrary` caps `num_players` at 10, so a setup of that size
/// fits every plan the fuzzer can generate. Built once and reused across
/// invocations because [`Setup::new`] is expensive.
static SETUP: LazyLock<Setup> = LazyLock::new(|| Setup::new(NonZeroU32::new(10).unwrap()));

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    plan: FuzzPlan,
    seed: u64,
}

fuzz_target!(|input: FuzzInput| {
    input
        .plan
        .run(&SETUP, input.seed, &Sequential)
        .expect("fuzz should not panic");
});

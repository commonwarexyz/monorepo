#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::bls12381::golden_dkg::FuzzPlan;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    plan: FuzzPlan,
    seed: u64,
}

fuzz_target!(|input: FuzzInput| {
    input
        .plan
        .run(input.seed)
        .expect("fuzz should succeed");
});

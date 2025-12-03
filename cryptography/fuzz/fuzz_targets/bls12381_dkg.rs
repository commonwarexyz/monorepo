#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::bls12381::{
    dkg2::FuzzPlan,
    primitives::variant::{MinPk, MinSig},
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Variant {
    MinPk,
    MinSig,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    plan: FuzzPlan,
    seed: u64,
    variant: Variant,
}

fuzz_target!(|input: FuzzInput| {
    match input.variant {
        Variant::MinPk => input
            .plan
            .run::<MinPk>(input.seed)
            .expect("fuzz should succeed"),
        Variant::MinSig => input
            .plan
            .run::<MinSig>(input.seed)
            .expect("fuzz should succeed"),
    }
});

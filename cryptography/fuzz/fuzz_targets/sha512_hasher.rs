#![no_main]

use commonware_cryptography::{
    Sha512,
    fuzz::{BatchPlan, Plan},
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|input: (Plan<Sha512>, BatchPlan<Sha512>)| {
    let (plan, batch_plan) = input;
    plan.run();
    batch_plan.run();
});

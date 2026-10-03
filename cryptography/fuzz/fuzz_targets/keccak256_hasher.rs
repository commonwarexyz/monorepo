#![no_main]

use arbitrary::Arbitrary;
use commonware_cryptography::{
    Keccak256,
    fuzz::{BatchPlan, Plan},
};
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
enum Operation {
    /// One-shot and pair entrypoints match streaming.
    Plan(Plan<Keccak256>),
    /// Batch entrypoints match streaming.
    BatchPlan(BatchPlan<Keccak256>),
}

fuzz_target!(|op: Operation| {
    match op {
        Operation::Plan(plan) => plan.run(),
        Operation::BatchPlan(plan) => plan.run(),
    }
});

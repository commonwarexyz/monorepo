//! Simplify testing and fuzzing of distributed systems.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

pub mod minifuzz;

use libfuzzer_sys::Corpus;
use proptest::{
    prelude::Arbitrary,
    strategy::{Strategy, ValueTree},
    test_runner::{Config, RngAlgorithm, TestCaseResult, TestRng, TestRunner},
};

pub trait FuzzPlan: Arbitrary + std::fmt::Debug {
    fn run(self) -> TestCaseResult;
}

#[doc(hidden)]
pub fn fuzz_shim<T: FuzzPlan>(fuzz: &[u8]) -> Corpus {
    let rng = TestRng::from_seed(RngAlgorithm::PassThrough, fuzz);
    let config = Config {
        failure_persistence: None,
        ..Default::default()
    };
    let mut runner = TestRunner::new_with_rng(config, rng);
    eprintln!("fuzz: {:?}", fuzz);

    // Generate exactly one test case from the fuzz input.
    // Using runner.run() would try to run 256 cases, which doesn't make sense
    // when the fuzzer provides a single input.
    eprintln!("calling new_tree...");
    let tree = match T::arbitrary().new_tree(&mut runner) {
        Ok(tree) => {
            eprintln!("new_tree succeeded");
            tree
        }
        Err(e) => {
            eprintln!("new_tree failed: {}", e);
            return Corpus::Reject;
        }
    };
    eprintln!("calling current...");
    let value = tree.current();
    eprintln!("value: {:?}", value);

    match value.run() {
        Ok(()) => Corpus::Keep,
        Err(reason) => panic!("fuzz test failed: {}", reason),
    }
}

#[macro_export]
macro_rules! fuzz_plan_target {
    ($plan:ty) => {
        libfuzzer_sys::fuzz_target!(|input: &[u8]| {
            $crate::fuzz_shim::<$plan>(input);
        });
    };
}

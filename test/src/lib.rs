//! Simplify testing and fuzzing of distributed systems.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use libfuzzer_sys::Corpus;
use proptest::{
    prelude::Arbitrary,
    test_runner::{Config, RngAlgorithm, TestCaseResult, TestError, TestRng, TestRunner},
};

pub trait FuzzPlan: Arbitrary {
    fn run(self) -> TestCaseResult;
}

#[doc(hidden)]
pub fn fuzz_shim<T: FuzzPlan>(fuzz: &[u8]) -> Corpus {
    let rng = TestRng::from_seed(RngAlgorithm::PassThrough, fuzz);
    let config = Config {
        // We want to avoid persisting failures, in the assumption that the fuzz
        // harness already has a system for doing that.
        failure_persistence: None,
        // The defaults are otherwise fine, and we want to keep them to allow
        // using the existing proptest environment variable system for tweaking these.
        ..Default::default()
    };
    let mut runner = TestRunner::new_with_rng(config, rng);
    let result = runner.run(&T::arbitrary(), |t| t.run());
    match result {
        Ok(_) => Corpus::Keep,
        Err(TestError::Abort(_)) => Corpus::Reject,
        Err(TestError::Fail(reason, t)) => panic!("fuzz test failed: {}\n{:#?}", reason, t),
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

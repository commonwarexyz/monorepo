#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

pub mod algebra;
pub mod fields {
    pub mod goldilocks;
}
pub mod ntt;
pub mod poly;
#[cfg(any(test, feature = "fuzz"))]
pub mod test;

#[cfg(feature = "fuzz")]
pub mod fuzz {
    use commonware_test::FuzzPlan;
    use proptest::test_runner::TestCaseResult;
    use proptest_derive::Arbitrary;

    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        Poly(crate::poly::fuzz::Plan),
        Algebra(crate::algebra::fuzz::Plan),
        Goldilocks(crate::fields::goldilocks::fuzz::Plan),
        Test(crate::test::fuzz::Plan),
        Ntt(crate::ntt::fuzz::Plan),
    }

    impl FuzzPlan for Plan {
        fn run(self) -> TestCaseResult {
            panic!("WOAH");
            match self {
                Plan::Poly(plan) => plan.run(),
                Plan::Algebra(plan) => plan.run(),
                Plan::Goldilocks(plan) => plan.run(),
                Plan::Test(plan) => plan.run(),
                Plan::Ntt(plan) => plan.run(),
            }
        }
    }
}

#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

commonware_macros::stability_scope!(ALPHA {
    pub mod fields {
        pub mod goldilocks;
    }
    pub mod ntt;
});
commonware_macros::stability_scope!(BETA {
    pub mod algebra;
    pub mod poly;
});

#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod test;

#[cfg(feature = "fuzz")]
pub mod fuzz {
    use arbitrary::{Arbitrary, Unstructured};

    #[derive(Debug)]
    pub enum Plan {
        Poly(crate::poly::fuzz::Plan),
        Algebra(crate::algebra::fuzz::Plan),
        Goldilocks(crate::fields::goldilocks::fuzz::Plan),
        Test(crate::test::fuzz::Plan),
        Ntt(crate::ntt::fuzz::Plan),
    }

    impl<'a> Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            match u.int_in_range(0..=4)? {
                0 => Ok(Plan::Poly(u.arbitrary()?)),
                1 => Ok(Plan::Algebra(u.arbitrary()?)),
                2 => Ok(Plan::Goldilocks(u.arbitrary()?)),
                3 => Ok(Plan::Test(u.arbitrary()?)),
                _ => Ok(Plan::Ntt(u.arbitrary()?)),
            }
        }
    }

    impl Plan {
        pub fn run(self) {
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

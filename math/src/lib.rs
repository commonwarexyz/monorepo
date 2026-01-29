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
    use arbitrary::Arbitrary;

    #[derive(Debug, Arbitrary)]
    pub enum Plan {
        Poly(crate::poly::fuzz::Plan),
        Algebra(crate::algebra::fuzz::Plan),
        Goldilocks(crate::fields::goldilocks::fuzz::Plan),
        Test(crate::test::fuzz::Plan),
        Ntt(crate::ntt::fuzz::Plan),
    }

    impl Plan {
        pub fn run(self) {
            match self {
                Self::Poly(plan) => plan.run(),
                Self::Algebra(plan) => plan.run(),
                Self::Goldilocks(plan) => plan.run(),
                Self::Test(plan) => plan.run(),
                Self::Ntt(plan) => plan.run(),
            }
        }
    }
}

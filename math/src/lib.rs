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

commonware_macros::stability_scope!(BETA {
    #[cfg(any(test, feature = "fuzz"))]
    pub(crate) mod test;
});

commonware_macros::stability_scope!(ALPHA {
    #[cfg(feature = "fuzz")]
    pub mod fuzz {
        use arbitrary::{Arbitrary, Unstructured};

        #[derive(Debug, Arbitrary)]
        pub enum Plan {
            Poly(crate::poly::fuzz::Plan),
            Algebra(crate::algebra::fuzz::Plan),
            Goldilocks(crate::fields::goldilocks::fuzz::Plan),
            Test(crate::test::fuzz::Plan),
            Ntt(crate::ntt::fuzz::Plan),
        }

        impl Plan {
            pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
                match self {
                    Self::Poly(plan) => plan.run(u),
                    Self::Algebra(plan) => plan.run(u),
                    Self::Goldilocks(plan) => plan.run(u),
                    Self::Test(plan) => plan.run(u),
                    Self::Ntt(plan) => plan.run(u),
                }
            }
        }
    }
});

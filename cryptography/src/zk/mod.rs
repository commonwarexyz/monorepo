#[cfg(feature = "std")]
pub mod bulletproofs;

#[cfg(all(feature = "std", feature = "fuzz"))]
pub mod fuzz {
    use arbitrary::{Arbitrary, Unstructured};

    pub enum Plan {
        Bulletproofs(crate::zk::bulletproofs::fuzz::Plan),
    }

    impl<'a> Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            Ok(Self::Bulletproofs(u.arbitrary()?))
        }
    }

    impl Plan {
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Bulletproofs(plan) => plan.run(u),
            }
        }
    }
}

#[cfg(feature = "std")]
pub mod bulletproofs;
#[cfg(feature = "std")]
pub mod pedersen_to_plain;

#[cfg(all(feature = "std", feature = "fuzz"))]
pub mod fuzz {
    use arbitrary::{Arbitrary, Unstructured};

    pub enum Plan {
        Bulletproofs(crate::zk::bulletproofs::fuzz::Plan),
        PedersenToPlain(crate::zk::pedersen_to_plain::fuzz::Plan),
    }

    impl<'a> Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            match u.int_in_range(0..=1)? {
                0 => Ok(Self::Bulletproofs(u.arbitrary()?)),
                1 => Ok(Self::PedersenToPlain(u.arbitrary()?)),
                _ => unreachable!("plan variant out of range"),
            }
        }
    }

    impl Plan {
        pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Bulletproofs(plan) => plan.run(u),
                Self::PedersenToPlain(plan) => plan.run(u),
            }
        }
    }
}

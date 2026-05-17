pub mod circuit;
pub mod ipa;

#[cfg(feature = "fuzz")]
pub mod fuzz {
    use arbitrary::{Arbitrary, Unstructured};

    pub enum Plan {
        Ipa(crate::zk::bulletproofs::ipa::fuzz::Plan),
        Circuit(crate::zk::bulletproofs::circuit::fuzz::Plan),
    }

    impl<'a> Arbitrary<'a> for Plan {
        fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
            match u.int_in_range(0..=1)? {
                0 => Ok(Self::Ipa(u.arbitrary()?)),
                1 => Ok(Self::Circuit(u.arbitrary()?)),
                _ => unreachable!("plan variant out of range"),
            }
        }
    }

    impl Plan {
        pub(in crate::zk) fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
            match self {
                Self::Ipa(plan) => plan.run(u),
                Self::Circuit(plan) => plan.run(u),
            }
        }
    }
}

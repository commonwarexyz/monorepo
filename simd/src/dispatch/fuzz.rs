//! Shared checks for backend selection and composed operation execution.

use super::dispatch;
use crate::{Neon, Operation, Simd};
use arbitrary::{Arbitrary, Unstructured};

/// A dispatch and composition check.
#[derive(Debug, Arbitrary)]
pub enum Plan {
    /// Checks direct and nested execution, including writes by a portable leaf.
    Execute,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Path {
    Portable,
    Neon,
}

struct Leaf<'a>(&'a mut [u64; 4]);

impl Operation for Leaf<'_> {
    type Output = ();

    // Associated constants cannot be used as const generic chunk sizes.
    #[allow(unknown_lints, clippy::chunks_exact_to_as_chunks)]
    fn portable<S: Simd>(self, s: S) {
        for chunk in self.0.chunks_exact_mut(S::U64_LANES) {
            s.u64_store(s.u64_add(s.u64_load(chunk), s.u64_splat(1)), chunk);
        }
    }
}

struct Child<'a>(&'a mut [u64; 4]);

impl Operation for Child<'_> {
    type Output = (Path, usize);

    fn portable<S: Simd>(self, s: S) -> Self::Output {
        s.execute(Leaf(self.0));
        (Path::Portable, S::U64_LANES)
    }

    fn neon<S: Neon>(self, s: S) -> Self::Output {
        s.execute(Leaf(self.0));
        (Path::Neon, S::U64_LANES)
    }
}

struct Parent<O>(O);

impl<O: Operation> Operation for Parent<O> {
    type Output = O::Output;

    fn portable<S: Simd>(self, s: S) -> Self::Output {
        execute_child(s, self.0)
    }
}

// Keep a consumer frame outlined to test feature-scope reentry through execute.
#[inline(never)]
fn execute_child<S: Simd, O: Operation>(s: S, child: O) -> O::Output {
    s.execute(child)
}

fn expected_backend() -> (Path, usize) {
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("neon") {
        return (Path::Neon, 2);
    }
    (Path::Portable, 1)
}

impl Plan {
    /// Runs the selected check against runtime dispatch and scalar expectations.
    pub fn run(self, u: &mut Unstructured<'_>) -> arbitrary::Result<()> {
        match self {
            Self::Execute => {
                let input: [u64; 4] = u.arbitrary()?;
                let expected = input.map(|v| v.wrapping_add(1));
                let backend = expected_backend();

                let mut direct = input;
                assert_eq!(dispatch(Child(&mut direct)), backend);
                assert_eq!(direct, expected);

                let mut nested = input;
                assert_eq!(dispatch(Parent(Parent(Child(&mut nested)))), backend);
                assert_eq!(nested, expected);

                let mut leaf = input;
                dispatch(Leaf(&mut leaf));
                assert_eq!(leaf, expected);
            }
        }
        Ok(())
    }
}

#[test]
fn test_execute() {
    commonware_invariants::minifuzz::test(|u| Plan::Execute.run(u));
}

//! Fuzzing utilities for [Hasher] implementations.
//!
//! For any hasher, the one-shot [Hasher::hash] and [Hasher::hash_pair]
//! entrypoints must agree with streaming the same bytes through
//! [Hasher::update]. Implementations are free to specialize the one-shot
//! entrypoints for fixed shapes (e.g. with assembly kernels), so the inputs
//! generated here are biased toward the shapes and lengths those
//! specializations match on.

use crate::Hasher;
use arbitrary::{Arbitrary, Unstructured};
use core::{fmt::Debug, marker::PhantomData};

/// Pick a contiguous message length biased toward the boundaries of
/// SHA-256's specialized paths (the pair kernels at 64 and 72 bytes and the
/// two-block fixed path limit at 119 bytes), which are harmless biases for
/// other hashers.
fn arbitrary_len(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    Ok(match u.int_in_range(0..=6)? {
        0 => 55,
        1 => 64,
        2 => 72,
        3 => 119,
        4 => 120,
        5 => 1024,
        _ => u.int_in_range(0..=1024)?,
    })
}

/// Generate a message as parts: either one of the fixed merkle shapes that
/// implementations specialize (e.g. position || left || right), or a
/// length-biased contiguous message split at an arbitrary point.
fn arbitrary_message(u: &mut Unstructured<'_>) -> arbitrary::Result<Vec<Vec<u8>>> {
    fn part(u: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<Vec<u8>> {
        Ok(u.bytes(len)?.to_vec())
    }
    match u.int_in_range(0..=4)? {
        0 => Ok(vec![part(u, 8)?, part(u, 32)?, part(u, 32)?]),
        1 => Ok(vec![part(u, 32)?, part(u, 32)?]),
        2 => Ok(vec![part(u, 8)?, part(u, 32)?]),
        3 => Ok(vec![part(u, 4)?, part(u, 32)?]),
        _ => {
            let len = arbitrary_len(u)?;
            let split = u.int_in_range(0..=len)?;
            let data = part(u, len)?;
            Ok(vec![data[..split].to_vec(), data[split..].to_vec()])
        }
    }
}

/// A pair of multi-part messages to hash through every [Hasher] entrypoint.
pub struct Plan<H: Hasher> {
    left: Vec<Vec<u8>>,
    right: Vec<Vec<u8>>,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> Debug for Plan<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Plan")
            .field("left", &self.left)
            .field("right", &self.right)
            .finish()
    }
}

impl<H: Hasher> Arbitrary<'_> for Plan<H> {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(Self {
            left: arbitrary_message(u)?,
            right: arbitrary_message(u)?,
            _hasher: PhantomData,
        })
    }
}

impl<H: Hasher> Plan<H> {
    /// Construct a plan for two fixed messages, each given as parts.
    ///
    /// Use this to guarantee coverage of a specific shape (e.g. one an
    /// implementation specializes) independent of what the fuzz generators
    /// happen to sample.
    pub const fn new(left: Vec<Vec<u8>>, right: Vec<Vec<u8>>) -> Self {
        Self {
            left,
            right,
            _hasher: PhantomData,
        }
    }

    /// Check that every entrypoint agrees with a single [Hasher::update]
    /// over the concatenated message.
    pub fn run(self) {
        let left: Vec<&[u8]> = self.left.iter().map(Vec::as_slice).collect();
        let right: Vec<&[u8]> = self.right.iter().map(Vec::as_slice).collect();

        let reference = |parts: &[&[u8]]| {
            let mut hasher = H::default();
            hasher.update(&parts.concat());
            hasher.finalize().1
        };
        let expected_left = reference(&left);
        let expected_right = reference(&right);

        // Stream each part separately, reusing the reset hasher returned by
        // finalize for the second message.
        let mut hasher = H::default();
        for part in &left {
            hasher.update(part);
        }
        let (mut hasher, streamed_left) = hasher.finalize();
        for part in &right {
            hasher.update(part);
        }
        let (_, streamed_right) = hasher.finalize();
        assert_eq!(streamed_left, expected_left);
        assert_eq!(streamed_right, expected_right);

        assert_eq!(H::hash(&left), expected_left);
        assert_eq!(H::hash(&right), expected_right);
        let (left_digest, right_digest) = H::hash_pair(&left, &right);
        assert_eq!(left_digest, expected_left);
        assert_eq!(right_digest, expected_right);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Blake3, Sha256};
    use commonware_invariants::minifuzz;

    fn test_fuzz<H: Hasher>() {
        // The generators below always emit at least one part, so pin the
        // zero-parts one-shot to the empty-message digest separately.
        Plan::<H>::new(vec![], vec![]).run();
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(512)
            .test(|u| {
                u.arbitrary::<Plan<H>>()?.run();
                Ok(())
            });
    }

    #[test]
    fn test_fuzz_sha256() {
        test_fuzz::<Sha256>();
    }

    #[test]
    fn test_fuzz_blake3() {
        test_fuzz::<Blake3>();
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fuzz_crc32() {
        test_fuzz::<crate::Crc32>();
    }
}

//! Fuzzing utilities for [Hasher] implementations.
//!
//! For any hasher, the one-shot [Hasher::hash], [Hasher::hash_with],
//! [Hasher::hash_pair], [Hasher::hash_many], and [Hasher::hash_many_parts]
//! entrypoints must agree with streaming the same bytes through
//! [Hasher::update]. Implementations are free to specialize the one-shot
//! entrypoints for fixed shapes (e.g. with assembly kernels), so the inputs
//! generated here are biased toward the shapes and lengths those
//! specializations match on.

use crate::{Hasher, blake3::TASK_LEN};
use arbitrary::{Arbitrary, Unstructured};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, TestRng};
use core::{fmt::Debug, marker::PhantomData};
use rand::Rng as _;
use std::sync::OnceLock;

/// Pick a contiguous message length biased toward the boundaries of the
/// specialized paths: the pair kernels at 64 and 72 bytes, SHA-256's
/// two-block fixed path limit at 119 bytes, and BLAKE3's two-block gather
/// limit at 128 bytes. These are harmless biases for other hashers.
fn arbitrary_len(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    Ok(match u.int_in_range(0..=8)? {
        0 => 55,
        1 => 64,
        2 => 72,
        3 => 119,
        4 => 120,
        5 => 128,
        6 => 129,
        7 => 1024,
        _ => u.int_in_range(0..=1024)?,
    })
}

/// Pick a batch message length while keeping the complete plan bounded.
///
/// Lengths of 36, 40, 64, and 72 bytes match the merkle part layouts, and
/// lengths around 1024 and 2048 bytes span one to three BLAKE3 chunks.
fn arbitrary_batch_len(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    Ok(match u.int_in_range(0..=19)? {
        0 => 0,
        1 => 36,
        2 => 40,
        3 => 55,
        4 => 56,
        5 => 63,
        6 => 64,
        7 => 65,
        8 => 72,
        9 => 119,
        10 => 120,
        11 => 127,
        12 => 128,
        13 => 129,
        14 => 256,
        15 => 1024,
        16 => 1025,
        17 => 2048,
        18 => 2049,
        _ => u.int_in_range(0..=256)?,
    })
}

/// Pick an offset of at most five [TASK_LEN]s, biased toward the multiples of
/// [TASK_LEN] where BLAKE3 splits long messages into subtrees, and toward one
/// byte or one chunk to either side of them.
fn arbitrary_offset(u: &mut Unstructured<'_>) -> arbitrary::Result<usize> {
    let tasks = u.int_in_range(1..=4)? * TASK_LEN;
    Ok(match u.int_in_range(0..=5)? {
        0 => tasks - 1024,
        1 => tasks - 1,
        2 => tasks,
        3 => tasks + 1,
        4 => tasks + 1024,
        _ => tasks + u.int_in_range(0..=TASK_LEN)?,
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

/// Generate a message of `len` bytes split into three parts at arbitrary
/// points.
fn arbitrary_split(u: &mut Unstructured<'_>, len: usize) -> arbitrary::Result<Vec<Vec<u8>>> {
    let data = u.bytes(len)?;
    let first = u.int_in_range(0..=len)?;
    let second = u.int_in_range(first..=len)?;
    Ok(vec![
        data[..first].to_vec(),
        data[first..second].to_vec(),
        data[second..].to_vec(),
    ])
}

impl<H: Hasher> Arbitrary<'_> for Plan<H> {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let left = arbitrary_message(u)?;

        // Pair kernels need equal lengths, so often give the right message
        // the left's length with different parts.
        let right = if u.arbitrary()? {
            arbitrary_split(u, left.iter().map(Vec::len).sum())?
        } else {
            arbitrary_message(u)?
        };
        Ok(Self {
            left,
            right,
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
        assert_eq!(H::hash_with(&Sequential, &left), expected_left);
        assert_eq!(H::hash_with(&Sequential, &right), expected_right);
        let (left_digest, right_digest) = H::hash_pair(&left, &right);
        assert_eq!(left_digest, expected_left);
        assert_eq!(right_digest, expected_right);
    }
}

/// Contiguous messages to hash through [Hasher::hash_many] and
/// [Hasher::hash_many_parts].
pub struct BatchPlan<H: Hasher> {
    messages: Vec<Vec<u8>>,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> Debug for BatchPlan<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BatchPlan")
            .field("messages", &self.messages)
            .finish()
    }
}

impl<H: Hasher> Arbitrary<'_> for BatchPlan<H> {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let count = u.int_in_range(0..=40)?;
        let equal_lengths = u.arbitrary::<bool>()?;
        let common_len = arbitrary_batch_len(u)?;

        // Cap the plan to the remaining input so long messages shrink the plan
        // instead of rejecting the whole input.
        let count = if equal_lengths {
            count.min(u.len() / common_len.max(1))
        } else {
            count
        };
        let mut messages = Vec::with_capacity(count);
        for lane in 0..count {
            let len = if equal_lengths {
                common_len
            } else {
                arbitrary_batch_len(u)?.min(u.len())
            };
            let mut message = u.bytes(len)?.to_vec();
            if let Some(first) = message.first_mut() {
                *first = lane as u8;
            }
            messages.push(message);
        }
        Ok(Self {
            messages,
            _hasher: PhantomData,
        })
    }
}

impl<H: Hasher> BatchPlan<H> {
    /// Check that batch output positions agree with independent streaming hashes.
    pub fn run(self) {
        let expected = self
            .messages
            .iter()
            .map(|message| {
                let mut hasher = H::default();
                hasher.update(message);
                hasher.finalize().1
            })
            .collect::<Vec<_>>();
        assert_eq!(H::hash_many(&self.messages), expected);

        // The same messages split into parts must hash identically. The last
        // parts take up to 32 bytes each and the first part takes the rest,
        // so 72-byte messages arrive in the [8, 32, 32] merkle part layout
        // and 36-, 40-, and 64-byte messages in the [4, 32], [8, 32], and
        // [32, 32] layouts.
        let nodes: Vec<[&[u8]; 3]> = self
            .messages
            .iter()
            .map(|message| {
                let (a, b) = (
                    message.len().saturating_sub(64),
                    message.len().saturating_sub(32),
                );
                [&message[..a], &message[a..b], &message[b..]]
            })
            .collect();
        assert_eq!(H::hash_many_parts(&nodes), expected);
        let pairs: Vec<[&[u8]; 2]> = self
            .messages
            .iter()
            .map(|message| {
                let (prefix, digest) = message.split_at(message.len().saturating_sub(32));
                [prefix, digest]
            })
            .collect();
        assert_eq!(H::hash_many_parts(&pairs), expected);
    }
}

/// A message of 63 KiB to 320 KiB, given as parts, to hash through
/// [Hasher::hash_with] across a parallel strategy.
pub struct ParallelPlan<H: Hasher> {
    seed: u64,
    len: usize,
    cuts: Vec<usize>,
    _hasher: PhantomData<H>,
}

impl<H: Hasher> Debug for ParallelPlan<H> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ParallelPlan")
            .field("seed", &self.seed)
            .field("len", &self.len)
            .field("cuts", &self.cuts)
            .finish()
    }
}

impl<H: Hasher> Arbitrary<'_> for ParallelPlan<H> {
    fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        let len = arbitrary_offset(u)?;

        // Cut anywhere, near a subtree boundary, or again at the previous cut
        // (or the start) to leave an empty part.
        let mut cuts = Vec::new();
        for _ in 0..u.int_in_range(0..=3)? {
            let cut = match u.int_in_range(0..=2)? {
                0 => u.int_in_range(0..=len)?,
                1 => arbitrary_offset(u)?.min(len),
                _ => cuts.last().copied().unwrap_or(0),
            };
            cuts.push(cut);
        }
        cuts.sort_unstable();
        Ok(Self {
            seed: u.arbitrary()?,
            len,
            cuts,
            _hasher: PhantomData,
        })
    }
}

impl<H: Hasher> ParallelPlan<H> {
    /// Check that [Hasher::hash_with] across two workers agrees with
    /// [Hasher::hash].
    pub fn run(self) {
        static STRATEGY: OnceLock<Rayon> = OnceLock::new();
        let strategy = STRATEGY.get_or_init(|| Rayon::new(NZUsize!(2)).unwrap());

        // Expand the seed into the message and cut it into parts.
        let mut message = vec![0; self.len];
        TestRng::new(self.seed).fill_bytes(&mut message);
        let mut parts = Vec::with_capacity(self.cuts.len() + 1);
        let mut start = 0;
        for cut in self.cuts {
            parts.push(&message[start..cut]);
            start = cut;
        }
        parts.push(&message[start..]);
        assert_eq!(H::hash_with(strategy, &parts), H::hash(&parts));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Blake3, Keccak256, Sha256};
    use commonware_invariants::minifuzz;
    use std::rc::Rc;

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

    fn test_fuzz_hash_many<H: Hasher>() {
        let mut saw_empty_batch = false;
        let mut saw_equal_lengths = false;
        let mut saw_partial_batch = false;
        let mut saw_equal_full_blocks = false;
        let mut saw_equal_two_block_padding = false;
        let mut saw_unequal_lengths = false;
        let mut saw_equal_multi_chunk = false;
        let mut saw_equal_leaves = false;
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(512)
            .test(|u| {
                let plan = u.arbitrary::<BatchPlan<H>>()?;
                let first_len = plan.messages.first().map_or(0, Vec::len);
                let equal_lengths = plan
                    .messages
                    .iter()
                    .all(|message| message.len() == first_len);
                for (lane, message) in plan.messages.iter().enumerate() {
                    if let Some(first) = message.first() {
                        assert_eq!(*first, lane as u8);
                    }
                }
                saw_empty_batch |= plan.messages.is_empty();
                saw_equal_lengths |= equal_lengths && plan.messages.len() >= 16;
                saw_partial_batch |= equal_lengths && (10..16).contains(&plan.messages.len());
                saw_equal_full_blocks |=
                    equal_lengths && plan.messages.len() >= 16 && first_len >= 64;
                saw_equal_two_block_padding |=
                    equal_lengths && plan.messages.len() >= 16 && first_len % 64 >= 56;
                saw_unequal_lengths |= !equal_lengths;
                saw_equal_multi_chunk |=
                    equal_lengths && plan.messages.len() >= 2 && first_len > 1024;
                saw_equal_leaves |=
                    equal_lengths && plan.messages.len() >= 3 && matches!(first_len, 36 | 40);
                plan.run();
                Ok(())
            });
        assert!(saw_empty_batch);
        assert!(saw_equal_lengths);
        assert!(saw_partial_batch);
        assert!(saw_equal_full_blocks);
        assert!(saw_equal_two_block_padding);
        assert!(saw_unequal_lengths);
        assert!(saw_equal_multi_chunk);
        assert!(saw_equal_leaves);
    }

    #[test]
    fn test_fuzz_sha256() {
        test_fuzz::<Sha256>();
    }

    #[test]
    fn test_fuzz_hash_many_sha256() {
        test_fuzz_hash_many::<Sha256>();
    }

    #[test]
    fn test_fuzz_blake3() {
        test_fuzz::<Blake3>();
    }

    #[test]
    fn test_fuzz_hash_many_blake3() {
        test_fuzz_hash_many::<Blake3>();
    }

    /// Check long messages through a parallel strategy, and that the generator
    /// reaches messages that fork, cuts at subtree boundaries, and empty middle
    /// parts.
    #[test]
    fn test_fuzz_parallel_blake3() {
        let mut saw_fork = false;
        let mut saw_boundary = false;
        let mut saw_empty = false;
        minifuzz::Builder::default()
            .with_seed(0)
            .with_search_limit(256)
            .test(|u| {
                let plan = u.arbitrary::<ParallelPlan<Blake3>>()?;
                let inner = |cut: &usize| (1..plan.len).contains(cut);
                saw_fork |= plan.len >= 2 * TASK_LEN;
                saw_boundary |= plan
                    .cuts
                    .iter()
                    .any(|cut| inner(cut) && cut % TASK_LEN == 0);
                saw_empty |= plan
                    .cuts
                    .windows(2)
                    .any(|pair| pair[0] == pair[1] && inner(&pair[0]));
                plan.run();
                Ok(())
            });
        assert!(saw_fork);
        assert!(saw_boundary);
        assert!(saw_empty);
    }

    #[test]
    fn test_fuzz_hash_many_keccak256() {
        test_fuzz_hash_many::<Keccak256>();
    }

    #[test]
    fn test_hash_many_default_matches_individual_hashes() {
        let messages = (0..33)
            .map(|lane| Rc::<[u8]>::from(vec![lane as u8; lane]))
            .collect::<Vec<_>>();
        let expected = messages
            .iter()
            .map(|message| {
                let mut hasher = Keccak256::default();
                hasher.update(message);
                hasher.finalize().1
            })
            .collect::<Vec<_>>();
        for count in 0..=messages.len() {
            assert_eq!(Keccak256::hash_many(&messages[..count]), expected[..count]);
        }
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fuzz_crc32() {
        test_fuzz::<crate::Crc32>();
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_fuzz_hash_many_crc32() {
        test_fuzz_hash_many::<crate::Crc32>();
    }
}

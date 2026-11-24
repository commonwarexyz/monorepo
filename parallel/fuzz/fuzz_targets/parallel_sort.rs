#![no_main]

//! Sorts one slice through a sequence of operations with the pool sorts of the parallel crate
//! and checks every sort against the standard library.
//!
//! [`Explorer::parallel`] hands every sort to the pool: `sort_by` runs the parallel merge sort
//! and `sort_unstable_by` the parallel quicksort. The pool has one worker, so the jobs a sort
//! splits off run one after another and a crash input replays the same execution.
//!
//! Each element carries its position in the first slice, which tells equal keys apart. A stable
//! sort must equal `slice::sort_by` element for element. An unstable sort must order the keys as
//! `slice::sort_unstable_by` does and keep every element. A comparator that is not a total order
//! goes to the quicksort only: `an_inconsistent_comparator_still_permutes_the_slice` in
//! `parallel/src/rayon/sort.rs` states that the quicksort then neither panics nor loses an
//! element, and leaves an unspecified order.

use arbitrary::{Arbitrary, Unstructured};
use commonware_parallel::{
    Strategy as _,
    mocks::{self, Explorer},
};
use commonware_utils::{Entropy, FuzzRng};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::{
    cmp::Ordering,
    hash::{DefaultHasher, Hash as _, Hasher as _},
    sync::LazyLock,
};

/// Longest slice: eight of the merge sort's 2,000-element chunks, so its merges pass the 5,000
/// elements below which it merges serially and split at two levels, and the quicksort hands
/// sides longer than 2,000 elements to the pool.
const MAX_LEN: usize = 16_000;

/// Widest key. Narrower keys repeat more often.
const MAX_KEY_BITS: u32 = u16::BITS;

/// Key width of the empty input: 256 distinct keys, so a long slice repeats each one many times.
const DEFAULT_KEY_BITS: u32 = 8;

/// Most operations on the slice.
const MAX_OPERATIONS: usize = 8;

/// Most pairs one perturbation swaps, few enough to leave a sorted slice nearly sorted.
const MAX_SWAPS: usize = 16;

/// Largest N of an inconsistent comparator that answers one comparison in N at random.
const MAX_NOISE: u64 = 64;

/// A strategy that hands every sort to the pool. It is built once and reused across inputs
/// because starting a thread pool is expensive.
static STRATEGY: LazyLock<Explorer> =
    LazyLock::new(|| Explorer::parallel(&mocks::inline(mocks::TASKS)));

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Element {
    key: u16,
    /// Position in the first slice.
    index: u32,
}

/// A total order on elements.
#[derive(Clone, Copy, Debug)]
enum Order {
    Ascending,
    Descending,
    /// Ascending by the key without its low bits, so more elements compare equal.
    Coarse {
        shift: u32,
    },
}

impl Order {
    /// The part of the key this order compares.
    const fn rank(self, element: &Element) -> u16 {
        match self {
            Self::Ascending | Self::Descending => element.key,
            Self::Coarse { shift } => element.key >> shift,
        }
    }

    fn compare(self, a: &Element, b: &Element) -> Ordering {
        match self {
            Self::Descending => self.rank(b).cmp(&self.rank(a)),
            Self::Ascending | Self::Coarse { .. } => self.rank(a).cmp(&self.rank(b)),
        }
    }
}

impl<'a> Arbitrary<'a> for Order {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=2)? {
            0 => Self::Ascending,
            1 => Self::Descending,
            _ => Self::Coarse {
                shift: u.int_in_range(1..=MAX_KEY_BITS - 1)?,
            },
        })
    }
}

#[derive(Debug)]
enum Operation {
    /// `sort_by` equals `slice::sort_by`.
    Stable(Order),
    /// `sort_unstable_by` orders the keys as `slice::sort_unstable_by` and keeps every element.
    Unstable(Order),
    /// `sort_unstable_by` keeps every element under a comparator that answers one comparison in
    /// `noise` by a hash of `salt` and the pair, and compares the keys otherwise.
    Inconsistent { salt: u64, noise: u64 },
    /// Swaps pairs of elements, so the next sort sees a nearly sorted slice.
    Perturb { swaps: usize },
}

impl Operation {
    /// Samples one of the operations that sort.
    fn sort(u: &mut Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match u.int_in_range(0..=2)? {
            0 => Self::Stable(u.arbitrary()?),
            1 => Self::Unstable(u.arbitrary()?),
            _ => Self::Inconsistent {
                salt: u.arbitrary()?,
                noise: u.int_in_range(1..=MAX_NOISE)?,
            },
        })
    }
}

impl<'a> Arbitrary<'a> for Operation {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        if u.int_in_range(0..=3)? < 3 {
            return Self::sort(u);
        }
        Ok(Self::Perturb {
            swaps: u.int_in_range(1..=MAX_SWAPS)?,
        })
    }
}

#[derive(Debug)]
struct FuzzInput {
    len: usize,
    key_bits: u32,
    operations: Vec<Operation>,
    entropy: Entropy,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // An exhausted input samples the low end of each range, so the length counts down from
        // the longest slice and the key width wraps around from the default: the empty input
        // stably sorts a long slice whose keys repeat.
        let len = MAX_LEN - u.int_in_range(0..=MAX_LEN)?;
        let key_bits = (DEFAULT_KEY_BITS + u.int_in_range(0..=MAX_KEY_BITS)?) % (MAX_KEY_BITS + 1);
        // The first operation sorts, so every input runs the code under test.
        let count = u.int_in_range(1..=MAX_OPERATIONS)?;
        let mut operations = vec![Operation::sort(u)?];
        for _ in 1..count {
            operations.push(u.arbitrary()?);
        }
        Ok(Self {
            len,
            key_bits,
            operations,
            entropy: u.arbitrary()?,
        })
    }
}

/// Answers one comparison in `noise` by a hash of `salt` and the pair, and compares the keys
/// otherwise. The answer depends only on the pair, so a run replays exactly.
fn inconsistent(salt: u64, noise: u64, a: &Element, b: &Element) -> Ordering {
    let mut hasher = DefaultHasher::new();
    (salt, a.index, b.index).hash(&mut hasher);
    let hash = hasher.finish();
    if !hash.is_multiple_of(noise) {
        return a.key.cmp(&b.key);
    }
    match hash / noise % 3 {
        0 => Ordering::Less,
        1 => Ordering::Equal,
        _ => Ordering::Greater,
    }
}

/// Asserts that `slice` holds every element of the first slice exactly once, with its key.
fn assert_permutation(slice: &[Element], keys: &[u16]) {
    let mut seen = vec![false; keys.len()];
    for element in slice {
        let index = element.index as usize;
        assert!(
            index < keys.len() && !seen[index],
            "element {index} is not from the first slice or appears twice"
        );
        assert_eq!(element.key, keys[index], "element {index} changed its key");
        seen[index] = true;
    }
}

fn fuzz(input: FuzzInput) {
    let mut rng = FuzzRng::from(input.entropy);
    let mask = ((1u32 << input.key_bits) - 1) as u16;
    let mut slice: Vec<Element> = (0..input.len)
        .map(|index| Element {
            key: rng.next_u32() as u16 & mask,
            index: index as u32,
        })
        .collect();
    let keys: Vec<u16> = slice.iter().map(|element| element.key).collect();

    for operation in input.operations {
        match operation {
            Operation::Stable(order) => {
                let mut expected = slice.clone();
                expected.sort_by(|a, b| order.compare(a, b));
                STRATEGY.sort_by(&mut slice, |a, b| order.compare(a, b));
                let mismatch = slice.iter().zip(&expected).position(|(a, b)| a != b);
                assert_eq!(mismatch, None, "{order:?}: differs from slice::sort_by");
            }
            Operation::Unstable(order) => {
                let mut expected = slice.clone();
                expected.sort_unstable_by(|a, b| order.compare(a, b));
                STRATEGY.sort_unstable_by(&mut slice, |a, b| order.compare(a, b));
                let mismatch = slice
                    .iter()
                    .zip(&expected)
                    .position(|(a, b)| order.rank(a) != order.rank(b));
                assert_eq!(
                    mismatch, None,
                    "{order:?}: keys differ from slice::sort_unstable_by"
                );
                assert_permutation(&slice, &keys);
            }
            Operation::Inconsistent { salt, noise } => {
                STRATEGY.sort_unstable_by(&mut slice, |a, b| inconsistent(salt, noise, a, b));
                assert_permutation(&slice, &keys);
            }
            Operation::Perturb { swaps } => {
                let len = slice.len() as u64;
                if len > 1 {
                    for _ in 0..swaps {
                        let i = (rng.next_u64() % len) as usize;
                        let j = (rng.next_u64() % len) as usize;
                        slice.swap(i, j);
                    }
                }
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});

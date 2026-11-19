#![no_main]

//! Drive long-lived roaring [Bitmap]s and a [Prunable] through a sequence of operations and check
//! each result against a dense model.
//!
//! Every value of an input lies in a block of [SHELVES] containers at the bottom or at the top of
//! `u64`. Values are drawn close together, from the dense corner and the edges of each container,
//! as single values, ranges and strides, so containers change kind and set operations meet every
//! pair of kinds. Results of set operations can replace their operands, and one set can replace
//! the other.

use arbitrary::{Arbitrary, Unstructured};
use commonware_codec::{Decode, Encode, RangeCfg};
use commonware_utils::{
    FuzzRng,
    bitmap::roaring::{Bitmap, Prunable},
};
use libfuzzer_sys::fuzz_target;
use rand_core::Rng as _;
use std::fmt::Debug;

/// Bytes of the stream an input is sampled from, and of the input's head that seeds the stream.
const STREAM_BYTES: usize = 1 << 12;
const SEED_BYTES: usize = 8;

/// Operations an input applies. A set operation meets a pair of container kinds only while both
/// sets hold a container under one key, and the sets fill over many operations, so a shorter
/// sequence leaves most pairs untried.
const MAX_OPS: usize = 128;

/// Weights of the operations, in the order of the [Op] variants. Inserts and set operations are
/// drawn most often, so both sets hold containers when a set operation runs, and the operations
/// that empty a set least often.
const OP_WEIGHTS: [u8; 22] = [
    8, 10, 12, 3, 4, 4, 8, 8, 8, 6, 5, 1, 3, 3, 3, 1, 2, 2, 2, 2, 1, 4,
];

/// Containers in the value domain.
const SHELVES: u64 = 3;

/// Values per container.
const SHELF: u64 = 1 << 16;

/// Size of the value domain and of each model.
const DOMAIN: u64 = SHELVES * SHELF;

/// Indices a word of a model holds.
const WORD: u64 = 64;

/// Most values an array container holds.
const ARRAY_MAX: u64 = 4_096;

/// Size of the dense corner at the bottom of a shelf.
const WINDOW: u64 = 256;

/// Most distance from the top of a shelf for edge values.
const EDGE: u64 = 16;

/// Longest short range, and longest range, which covers a whole container.
const SHORT_RANGE: u64 = 64;
const MAX_RANGE: u64 = 1 << 17;

/// Weights of the range lengths: at most [SHORT_RANGE], at most [ARRAY_MAX], and at most
/// [MAX_RANGE]. Every later operation on a set walks the values a long range left in it, so
/// shorter ranges are drawn more often.
const RANGE_WEIGHTS: [u8; 3] = [2, 1, 1];

/// Largest step between the values of a stride.
const MAX_STEP: u64 = 16;

/// Most values of a short stride, and of any stride.
const SHORT_STRIDE: u64 = 16;
const MAX_STRIDE: u64 = 8_192;

/// Weights of the stride lengths: at most [SHORT_STRIDE] values, at most [MAX_STRIDE], and more
/// than [ARRAY_MAX], which can overflow an array container into a bitmap container.
const STRIDE_WEIGHTS: [u8; 3] = [2, 1, 1];

/// One stride in this many replaces its set instead of extending it.
const FRESH_ONE_IN: u8 = 8;

/// Largest short limit, and largest finite limit, of a set operation.
const SHORT_LIMIT: u64 = 16;
const MAX_LIMIT: u64 = 1 << 17;

/// Weights of the limits: none, at most [SHORT_LIMIT], and at most [MAX_LIMIT]. A short limit
/// ends a set operation inside its first containers, which often hold only a few values.
const LIMIT_WEIGHTS: [u8; 3] = [2, 1, 1];

/// Returns the index of an entry of `weights`, drawn in proportion to the entry.
fn weighted(u: &mut Unstructured<'_>, weights: &[u8]) -> arbitrary::Result<usize> {
    let sum: u8 = weights.iter().sum();
    let draw = u.int_in_range(0..=sum - 1)?;
    let mut total = 0;
    Ok(weights
        .iter()
        .position(|weight| {
            total += weight;
            draw < total
        })
        .expect("the draw is below the sum"))
}

/// Where the value domain starts. Both origins are multiples of [SHELF], so each shelf of the
/// model is one container.
#[derive(Clone, Copy, Debug)]
enum Origin {
    Low,
    High,
}

impl Origin {
    const fn base(self) -> u64 {
        match self {
            Self::Low => 0,
            Self::High => u64::MAX - (DOMAIN - 1),
        }
    }
}

impl<'a> Arbitrary<'a> for Origin {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(if u.arbitrary()? {
            Self::High
        } else {
            Self::Low
        })
    }
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum Slot {
    A,
    B,
}

impl Slot {
    const fn at(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

/// An index into the value domain.
#[derive(Clone, Copy, Debug)]
struct Index(u64);

impl<'a> Arbitrary<'a> for Index {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let shelf = u.int_in_range(0..=SHELVES - 1)?;
        let low = match u.int_in_range(0..=3)? {
            0 | 1 => u.int_in_range(0..=WINDOW - 1)?,
            2 => SHELF - 1 - u.int_in_range(0..=EDGE - 1)?,
            _ => u64::from(u.arbitrary::<u16>()?),
        };
        Ok(Self(shelf * SHELF + low))
    }
}

/// The length of a range.
#[derive(Clone, Copy, Debug)]
struct Len(u64);

impl<'a> Arbitrary<'a> for Len {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(match weighted(u, &RANGE_WEIGHTS)? {
            0 => u.int_in_range(0..=SHORT_RANGE)?,
            1 => u.int_in_range(1..=ARRAY_MAX)?,
            _ => u.int_in_range(1..=MAX_RANGE)?,
        }))
    }
}

/// Evenly spaced values from a start.
#[derive(Clone, Copy, Debug)]
struct Stride {
    step: u64,
    count: u64,
}

impl<'a> Arbitrary<'a> for Stride {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        let step = u.int_in_range(1..=MAX_STEP)?;
        let count = match weighted(u, &STRIDE_WEIGHTS)? {
            0 => u.int_in_range(1..=SHORT_STRIDE)?,
            1 => u.int_in_range(1..=MAX_STRIDE)?,
            _ => u.int_in_range(ARRAY_MAX + 1..=MAX_STRIDE)?,
        };
        Ok(Self { step, count })
    }
}

/// The most values a set operation returns.
#[derive(Clone, Copy, Debug)]
struct Limit(u64);

impl<'a> Arbitrary<'a> for Limit {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(match weighted(u, &LIMIT_WEIGHTS)? {
            0 => u64::MAX,
            1 => u.int_in_range(0..=SHORT_LIMIT)?,
            _ => u.int_in_range(0..=MAX_LIMIT)?,
        }))
    }
}

#[derive(Debug)]
enum Op {
    Insert {
        slot: Slot,
        index: Index,
    },
    InsertRange {
        slot: Slot,
        start: Index,
        len: Len,
    },
    InsertStride {
        slot: Slot,
        start: Index,
        stride: Stride,
        fresh: bool,
    },
    Contains {
        slot: Slot,
        index: Index,
    },
    IterRange {
        slot: Slot,
        start: Index,
        len: Len,
    },
    Inspect {
        slot: Slot,
    },
    Union {
        limit: Limit,
        store: Option<Slot>,
    },
    Intersection {
        limit: Limit,
        store: Option<Slot>,
    },
    Difference {
        from: Slot,
        limit: Limit,
        store: Option<Slot>,
    },
    Relations,
    Codec {
        slot: Slot,
    },
    Clear {
        slot: Slot,
    },
    PrunableInsert {
        index: Index,
    },
    PrunableInsertRange {
        start: Index,
        len: Len,
    },
    PrunableExtend {
        start: Index,
        stride: Stride,
    },
    PrunableContains {
        index: Index,
    },
    PrunableIterRange {
        start: Index,
        len: Len,
    },
    Prune {
        index: Index,
    },
    PrunableInspect,
    PrunableCodec,
    PrunableClear,
    Copy {
        from: Slot,
    },
}

impl<'a> Arbitrary<'a> for Op {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(match weighted(u, &OP_WEIGHTS)? {
            0 => Self::Insert {
                slot: u.arbitrary()?,
                index: u.arbitrary()?,
            },
            1 => Self::InsertRange {
                slot: u.arbitrary()?,
                start: u.arbitrary()?,
                len: u.arbitrary()?,
            },
            2 => Self::InsertStride {
                slot: u.arbitrary()?,
                start: u.arbitrary()?,
                stride: u.arbitrary()?,
                fresh: u.ratio(1u8, FRESH_ONE_IN)?,
            },
            3 => Self::Contains {
                slot: u.arbitrary()?,
                index: u.arbitrary()?,
            },
            4 => Self::IterRange {
                slot: u.arbitrary()?,
                start: u.arbitrary()?,
                len: u.arbitrary()?,
            },
            5 => Self::Inspect {
                slot: u.arbitrary()?,
            },
            6 => Self::Union {
                limit: u.arbitrary()?,
                store: u.arbitrary()?,
            },
            7 => Self::Intersection {
                limit: u.arbitrary()?,
                store: u.arbitrary()?,
            },
            8 => Self::Difference {
                from: u.arbitrary()?,
                limit: u.arbitrary()?,
                store: u.arbitrary()?,
            },
            9 => Self::Relations,
            10 => Self::Codec {
                slot: u.arbitrary()?,
            },
            11 => Self::Clear {
                slot: u.arbitrary()?,
            },
            12 => Self::PrunableInsert {
                index: u.arbitrary()?,
            },
            13 => Self::PrunableInsertRange {
                start: u.arbitrary()?,
                len: u.arbitrary()?,
            },
            14 => Self::PrunableExtend {
                start: u.arbitrary()?,
                stride: u.arbitrary()?,
            },
            15 => Self::PrunableContains {
                index: u.arbitrary()?,
            },
            16 => Self::PrunableIterRange {
                start: u.arbitrary()?,
                len: u.arbitrary()?,
            },
            17 => Self::Prune {
                index: u.arbitrary()?,
            },
            18 => Self::PrunableInspect,
            19 => Self::PrunableCodec,
            20 => Self::PrunableClear,
            _ => Self::Copy {
                from: u.arbitrary()?,
            },
        })
    }
}

#[derive(Debug)]
struct FuzzInput {
    origin: Origin,
    ops: Vec<Op>,
}

impl<'a> Arbitrary<'a> for FuzzInput {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        // The input's head seeds a fixed-size stream that the rest of the input overwrites from
        // its start, so even an empty input samples a whole sequence of operations.
        let seed = u.bytes(u.len().min(SEED_BYTES))?.to_vec();
        let mut stream = vec![0; STREAM_BYTES.max(u.len())];
        FuzzRng::new(seed).fill_bytes(&mut stream);
        let literal = u.bytes(u.len())?;
        stream[..literal.len()].copy_from_slice(literal);
        let u = &mut Unstructured::new(&stream);

        Ok(Self {
            origin: u.arbitrary()?,
            ops: (0..MAX_OPS)
                .map(|_| u.arbitrary())
                .collect::<arbitrary::Result<_>>()?,
        })
    }
}

/// Presence of every index of the domain, one bit each.
#[derive(Clone)]
struct Model(Vec<u64>);

impl Model {
    fn new() -> Self {
        Self(vec![0; (DOMAIN / WORD) as usize])
    }

    /// The first `limit` indices present in `combine` of each word of `a` and of `b`, ascending.
    fn first(limit: u64, a: &Self, b: &Self, combine: impl Fn(u64, u64) -> u64) -> Self {
        let mut model = Self::new();
        let mut left = limit;
        for (word, (a, b)) in model.0.iter_mut().zip(a.0.iter().zip(&b.0)) {
            let mut bits = combine(*a, *b);
            while u64::from(bits.count_ones()) > left {
                bits &= !(1 << (WORD - 1 - u64::from(bits.leading_zeros())));
            }
            *word = bits;
            left -= u64::from(bits.count_ones());
        }
        model
    }

    fn get(&self, index: u64) -> bool {
        self.0[(index / WORD) as usize] >> (index % WORD) & 1 == 1
    }

    /// Marks `index` present and returns whether it was absent.
    fn set(&mut self, index: u64) -> bool {
        let word = &mut self.0[(index / WORD) as usize];
        let bit = 1 << (index % WORD);
        let absent = *word & bit == 0;
        *word |= bit;
        absent
    }

    /// Marks the indices of `start..end` present and returns how many were absent.
    fn set_range(&mut self, start: u64, end: u64) -> u64 {
        let mut absent = 0;
        if start >= end {
            return absent;
        }
        for word in start / WORD..end.div_ceil(WORD) {
            let (low, high) = (start.max(word * WORD), end.min((word + 1) * WORD));
            let bits = (u64::MAX >> (WORD - (high - low))) << (low % WORD);
            let word = &mut self.0[word as usize];
            absent += u64::from((bits & !*word).count_ones());
            *word |= bits;
        }
        absent
    }

    fn count(&self) -> u64 {
        self.0.iter().map(|word| u64::from(word.count_ones())).sum()
    }

    /// The present indices of `start..end`, ascending.
    fn present(&self, start: u64, end: u64) -> impl Iterator<Item = u64> + '_ {
        let end = end.max(start);
        (start / WORD..end.div_ceil(WORD))
            .flat_map(move |word| {
                let mut bits = self.0[word as usize];
                std::iter::from_fn(move || {
                    (bits != 0).then(|| {
                        let index = word * WORD + u64::from(bits.trailing_zeros());
                        bits &= bits - 1;
                        index
                    })
                })
            })
            .filter(move |index| (start..end).contains(index))
    }

    /// The lowest and the highest present index.
    fn bounds(&self) -> Option<(u64, u64)> {
        let low = self.0.iter().position(|word| *word != 0)?;
        let high = self.0.iter().rposition(|word| *word != 0)?;
        Some((
            low as u64 * WORD + u64::from(self.0[low].trailing_zeros()),
            high as u64 * WORD + WORD - 1 - u64::from(self.0[high].leading_zeros()),
        ))
    }

    fn shelves_used(&self) -> usize {
        self.0
            .chunks((SHELF / WORD) as usize)
            .filter(|shelf| shelf.iter().any(|word| *word != 0))
            .count()
    }

    /// Marks every index below `end`, a multiple of [SHELF], absent.
    fn clear_below(&mut self, end: u64) {
        self.0[..(end / WORD) as usize].fill(0);
    }

    fn clear(&mut self) {
        self.0.fill(0);
    }
}

/// The exclusive end of a range from `start`, clamped below the last index of the domain.
fn range_end(start: u64, len: Len) -> u64 {
    (start + len.0).min(DOMAIN - 1)
}

/// The indices of a stride from `start` that lie in the domain.
fn stride_indices(start: u64, stride: Stride) -> impl Iterator<Item = u64> {
    (0..stride.count)
        .map(move |i| start + i * stride.step)
        .take_while(|&index| index < DOMAIN)
}

/// Folds `index` into the part of the domain at or above the watermark.
fn fold(index: Index, base: u64, watermark: u64) -> u64 {
    let live = watermark.saturating_sub(base);
    live + index.0 % (DOMAIN - live)
}

/// Asserts that `values` are exactly the present indices of `model` shifted by `base`, and that
/// their size hint bounds how many are left, before the first value and inside a container.
fn assert_values(mut values: impl Iterator<Item = u64>, model: &Model, base: u64) {
    let mut expected = model.present(0, DOMAIN).map(|index| base + index);
    let mut left = model.count() as usize;
    for _ in 0..2 {
        let (lower, upper) = values.size_hint();
        assert!(lower <= left && upper.is_none_or(|upper| left <= upper));
        assert_eq!(values.next(), expected.next());
        left = left.saturating_sub(1);
    }
    assert!(values.eq(expected));
}

/// Asserts the observers of a set against its model.
fn assert_contents(
    model: &Model,
    base: u64,
    len: u64,
    is_empty: bool,
    min: Option<u64>,
    max: Option<u64>,
    values: impl Iterator<Item = u64>,
) {
    let bounds = model.bounds();
    assert_eq!(len, model.count());
    assert_eq!(is_empty, bounds.is_none());
    assert_eq!(min, bounds.map(|(low, _)| base + low));
    assert_eq!(max, bounds.map(|(_, high)| base + high));
    assert_values(values, model, base);
}

/// Asserts that `value` survives an encoding round trip and returns the decoded copy.
fn round_trip<T>(value: &T) -> T
where
    T: Encode + Decode<Cfg = RangeCfg<usize>> + PartialEq + Debug,
{
    let encoded = value.encode();
    assert_eq!(value.encode_size(), encoded.len());
    let cfg: RangeCfg<usize> = (..=SHELVES as usize).into();
    let decoded = T::decode_cfg(encoded.clone(), &cfg).expect("encoding decodes");
    assert_eq!(&decoded, value);
    assert_eq!(decoded.encode(), encoded);
    decoded
}

fn fuzz(input: FuzzInput) {
    let base = input.origin.base();
    let mut sets = [Bitmap::new(), Bitmap::new()];
    let mut models = [Model::new(), Model::new()];
    let mut prunable = Prunable::new();
    let mut prunable_model = Model::new();
    let mut watermark = 0u64;

    for op in input.ops {
        match op {
            Op::Insert { slot, index } => {
                let (set, model) = (&mut sets[slot.at()], &mut models[slot.at()]);
                assert_eq!(set.insert(base + index.0), model.set(index.0));
                assert!(set.contains(base + index.0));
                assert_eq!(set.len(), model.count());
            }
            Op::InsertRange { slot, start, len } => {
                let (set, model) = (&mut sets[slot.at()], &mut models[slot.at()]);
                let end = range_end(start.0, len);
                let absent = model.set_range(start.0, end);
                assert_eq!(set.insert_range(base + start.0..base + end), absent);
                assert_eq!(set.len(), model.count());
            }
            Op::InsertStride {
                slot,
                start,
                stride,
                fresh,
            } => {
                let (set, model) = (&mut sets[slot.at()], &mut models[slot.at()]);
                let values = stride_indices(start.0, stride).map(|index| base + index);
                if fresh {
                    *set = values.collect();
                    model.clear();
                } else {
                    set.extend(values);
                }
                for index in stride_indices(start.0, stride) {
                    model.set(index);
                }
                assert_eq!(set.len(), model.count());
            }
            Op::Contains { slot, index } => {
                assert_eq!(
                    sets[slot.at()].contains(base + index.0),
                    models[slot.at()].get(index.0)
                );
            }
            Op::IterRange { slot, start, len } => {
                let end = range_end(start.0, len);
                let actual: Vec<u64> = sets[slot.at()]
                    .iter_range(base + start.0..base + end)
                    .collect();
                let expected: Vec<u64> = models[slot.at()]
                    .present(start.0, end)
                    .map(|index| base + index)
                    .collect();
                assert_eq!(actual, expected);
            }
            Op::Inspect { slot } => {
                let (set, model) = (&sets[slot.at()], &models[slot.at()]);
                assert_contents(
                    model,
                    base,
                    set.len(),
                    set.is_empty(),
                    set.min(),
                    set.max(),
                    set.iter(),
                );
                assert!(set.container_count() >= model.shelves_used());
            }
            Op::Union { limit, store } => {
                let result = sets[0].union(&sets[1], limit.0);
                let (a, b) = (&models[0], &models[1]);
                let expected = Model::first(limit.0, a, b, |a, b| a | b);
                assert_values(result.iter(), &expected, base);
                if let Some(slot) = store {
                    sets[slot.at()] = result;
                    models[slot.at()] = expected;
                    assert_eq!(sets[slot.at()].len(), models[slot.at()].count());
                }
            }
            Op::Intersection { limit, store } => {
                let result = sets[0].intersection(&sets[1], limit.0);
                let (a, b) = (&models[0], &models[1]);
                let expected = Model::first(limit.0, a, b, |a, b| a & b);
                assert_values(result.iter(), &expected, base);
                if let Some(slot) = store {
                    sets[slot.at()] = result;
                    models[slot.at()] = expected;
                    assert_eq!(sets[slot.at()].len(), models[slot.at()].count());
                }
            }
            Op::Difference { from, limit, store } => {
                let other = from.other();
                let result = sets[from.at()].difference(&sets[other.at()], limit.0);
                let (a, b) = (&models[from.at()], &models[other.at()]);
                let expected = Model::first(limit.0, a, b, |a, b| a & !b);
                assert_values(result.iter(), &expected, base);
                if let Some(slot) = store {
                    sets[slot.at()] = result;
                    models[slot.at()] = expected;
                    assert_eq!(sets[slot.at()].len(), models[slot.at()].count());
                }
            }
            Op::Relations => {
                let (a, b) = (&models[0].0, &models[1].0);
                let a_in_b = a.iter().zip(b).all(|(a, b)| a & !b == 0);
                let b_in_a = a.iter().zip(b).all(|(a, b)| b & !a == 0);
                let overlap = a.iter().zip(b).any(|(a, b)| a & b != 0);
                assert_eq!(sets[0].is_subset(&sets[1]), a_in_b);
                assert_eq!(sets[1].is_subset(&sets[0]), b_in_a);
                assert_eq!(sets[0].intersects(&sets[1]), overlap);
            }
            Op::Codec { slot } => {
                round_trip(&sets[slot.at()]);
            }
            Op::Clear { slot } => {
                sets[slot.at()].clear();
                models[slot.at()].clear();
                assert!(sets[slot.at()].is_empty());
                assert_eq!(sets[slot.at()].len(), 0);
            }
            Op::PrunableInsert { index } => {
                let index = fold(index, base, watermark);
                assert_eq!(prunable.insert(base + index), prunable_model.set(index));
                assert!(prunable.contains(base + index));
                assert_eq!(prunable.len(), prunable_model.count());
            }
            Op::PrunableInsertRange { start, len } => {
                let start = fold(start, base, watermark);
                let end = range_end(start, len);
                let absent = prunable_model.set_range(start, end);
                assert_eq!(prunable.insert_range(base + start..base + end), absent);
                assert_eq!(prunable.len(), prunable_model.count());
            }
            Op::PrunableExtend { start, stride } => {
                let start = fold(start, base, watermark);
                prunable.extend(stride_indices(start, stride).map(|index| base + index));
                for index in stride_indices(start, stride) {
                    prunable_model.set(index);
                }
                assert_eq!(prunable.len(), prunable_model.count());
            }
            Op::PrunableContains { index } => {
                let index = fold(index, base, watermark);
                assert_eq!(prunable.contains(base + index), prunable_model.get(index));
            }
            Op::PrunableIterRange { start, len } => {
                let start = fold(start, base, watermark);
                let end = range_end(start, len);
                let actual: Vec<u64> = prunable.iter_range(base + start..base + end).collect();
                let expected: Vec<u64> = prunable_model
                    .present(start, end)
                    .map(|index| base + index)
                    .collect();
                assert_eq!(actual, expected);
            }
            Op::Prune { index } => {
                let aligned = (base + index.0) & !(SHELF - 1);
                if aligned > watermark {
                    watermark = aligned;
                    prunable_model.clear_below(aligned - base);
                }
                assert_eq!(prunable.prune(base + index.0), watermark);
                assert_eq!(prunable.pruned_below(), watermark);
                assert_eq!(prunable.len(), prunable_model.count());
            }
            Op::PrunableInspect => {
                assert_contents(
                    &prunable_model,
                    base,
                    prunable.len(),
                    prunable.is_empty(),
                    prunable.min(),
                    prunable.max(),
                    prunable.iter(),
                );
                assert_eq!(prunable.pruned_below(), watermark);
                assert_eq!(watermark % SHELF, 0);
                assert!(prunable.iter().all(|value| value >= watermark));
            }
            Op::PrunableCodec => {
                let decoded = round_trip(&prunable);
                assert_eq!(decoded.pruned_below(), watermark);
            }
            Op::PrunableClear => {
                prunable.clear();
                prunable_model.clear();
                assert!(prunable.is_empty());
                assert_eq!(prunable.len(), 0);
                assert_eq!(prunable.pruned_below(), watermark);
            }
            Op::Copy { from } => {
                let other = from.other();
                sets[other.at()] = sets[from.at()].clone();
                models[other.at()] = models[from.at()].clone();
                assert_eq!(sets[other.at()], sets[from.at()]);
                assert_eq!(sets[other.at()].len(), models[other.at()].count());
            }
        }
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});

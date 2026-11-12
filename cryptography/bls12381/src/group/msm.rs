//! The variable-time multi-scalar multiplication, by Straus's or Pippenger's method, whichever
//! costs less for the count of elements.
//!
//! [`batched`] implements `Space::msm` for both groups: it runs one [`Msm`] kernel per batch
//! of the strategy and adds the results. [`Msm`] takes the method that [`Method::choose`]
//! estimates cheapest for its count and lane width.
//!
//! The operations and memory accesses of both methods depend on the scalars, which must therefore
//! be public.

use super::{
    Scalar,
    kernel::{Group, Kernel, identity, load_each, signed_digits, sum_lanes, windows},
};
use crate::core::{
    curve::Points,
    field::{MAX_LANES, arithmetic::Field},
};
use alloc::{vec, vec::Vec};
use commonware_math::algebra::Additive;
use commonware_parallel::Strategy;
use commonware_simd::Simd;
use core::{num::NonZeroUsize, ops::RangeInclusive};

/// Fewest elements of [`batched`] that a parallel strategy gives one kernel.
// Every kernel pays for its own bucket sums and doublings, which cost about as much as adding a
// few hundred elements.
pub const MSM_BATCH: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// Window widths that [`Method::choose`] considers for Straus's method.
const STRAUS_WIDTHS: RangeInclusive<u32> = 2..=8;

/// Window widths that [`Method::choose`] considers for Pippenger's method. The widest bounds the
/// buckets at `2^11` points per lane.
const PIPPENGER_WIDTHS: RangeInclusive<u32> = 2..=12;

/// Elements whose images and digits Pippenger's method holds at once, as [`Method::choose`]
/// sets it.
// Every group of windows reads the images of a chunk once, so the chunk bounds the memory of the
// images whatever the count of elements, and its images stay cached from one group to the next.
// Chunks of 64 through 4096 elements take the same time within one percent.
const PIPPENGER_CHUNK: NonZeroUsize = NonZeroUsize::new(256).unwrap();

/// Estimated cost of an addition of points, in units of [`Method::cost`].
const ADD_COST: usize = 10;

/// Estimated cost of a doubling, which takes about two thirds of an addition's products.
const DOUBLE_COST: usize = 7;

/// Estimated cost of a negation or an endomorphism, a few products reduced one after another,
/// which overlap less than a formula's.
const IMAGE_COST: usize = 4;

/// Bits that the signed digits of a whole scalar cover: scalars lie below `r < 2^255`, so the
/// top digit absorbs the carry.
const SCALAR_BITS: u32 = 256;

/// Raw form of one lane of the points of the group `G` in the representation `F`.
type Raw<S, F, G> = <<G as Group>::Points<S, F> as Points<S>>::Raw;

/// Method and signed window width of a multi-scalar multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    /// Straus's method: each lane multiplies its own elements through tables of their multiples,
    /// sharing one chain of doublings. With `split`, the scalars split into their components
    /// and the tables hold the images of every multiple, which divides the doublings by the
    /// number of components at the cost of the images: worthwhile for a few elements.
    Straus { width: u32, split: bool },
    /// Pippenger's method: each lane sums one window of every component of every element into
    /// its own buckets, holding the images of `chunk` elements at once.
    Pippenger { width: u32, chunk: NonZeroUsize },
}

impl Method {
    /// Returns the method of least estimated cost for `count` elements of `G` on `lanes` lanes.
    pub fn choose<G: Group>(count: usize, lanes: usize) -> Self {
        STRAUS_WIDTHS
            .flat_map(|width| [false, true].map(|split| Self::Straus { width, split }))
            .chain(PIPPENGER_WIDTHS.map(|width| Self::Pippenger {
                width,
                chunk: PIPPENGER_CHUNK,
            }))
            .min_by_key(|method| method.cost::<G>(count, lanes))
            .expect("the widths are not empty")
    }

    /// Returns the components and windows of `width` bits that Straus's method takes from each
    /// scalar: every component with `split`, and otherwise the whole scalar as one.
    const fn shape<G: Group>(width: u32, split: bool) -> (usize, usize) {
        if split {
            (G::COMPONENTS, windows::<G>(width))
        } else {
            (1, SCALAR_BITS.div_ceil(width) as usize)
        }
    }

    /// Returns the estimated cost of the method, counting the additions, doublings, negations, and
    /// endomorphisms of points on all lanes at once.
    const fn cost<G: Group>(self, count: usize, lanes: usize) -> usize {
        match self {
            Self::Straus { width, split } => {
                // Each group of lanes builds a table of its multiples, the images of every
                // entry, and their negations, then adds one entry per component and window.
                let (components, windows) = Self::shape::<G>(width, split);
                let groups = count.div_ceil(lanes);
                let entries = 1 << (width - 1);
                ADD_COST * groups * (entries - 1 + components * windows)
                    + IMAGE_COST * groups * (2 * components - 1) * entries
                    + DOUBLE_COST * width as usize * windows
            }
            Self::Pippenger { width, .. } => {
                // Each group of windows adds every image of every element and sums the buckets
                // in two running sums, then shifts the accumulated windows by `width * lanes`
                // bits.
                let components = G::COMPONENTS;
                let groups = windows::<G>(width).div_ceil(lanes);
                let buckets = 1 << (width - 1);
                let images = count.div_ceil(lanes);
                ADD_COST * groups * (count * components + 2 * buckets)
                    + IMAGE_COST * images * (2 * components - 1)
                    + DOUBLE_COST * width as usize * lanes * groups
            }
        }
    }
}

/// Returns `a + b` as its own kernel, so that the many additions of [`Msm`] share one copy.
#[inline(always)]
fn outlined_add<S: Simd, P: Points<S>>(simd: S, a: P, b: P) -> P {
    simd.execute(
        #[inline(always)]
        move |simd: S| a.add(simd, b),
    )
}

/// Returns `2 * point` as its own kernel, so that the doublings of [`Msm`] share one copy.
#[inline(always)]
fn outlined_double<S: Simd, P: Points<S>>(simd: S, point: P) -> P {
    simd.execute(
        #[inline(always)]
        move |simd: S| point.double(simd),
    )
}

/// Returns the raw form of the first lane of `points`.
#[inline(always)]
fn first_raw<S: Simd, F: Field<S>, G: Group>(simd: S, points: G::Points<S, F>) -> Raw<S, F, G> {
    let mut raw = [Raw::<S, F, G>::default()];
    points.store_raw(simd, &mut raw);
    raw[0]
}

/// Loads lane `i` from `points[i]`, for one entry per lane.
#[inline(always)]
fn load_each_raw<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    points: &[Raw<S, F, G>],
) -> G::Points<S, F> {
    const { assert!(F::LANES <= MAX_LANES) };
    let mut lanes = [&points[0]; MAX_LANES];
    for (lane, point) in lanes.iter_mut().zip(points).take(F::LANES) {
        *lane = point;
    }
    G::Points::<S, F>::load_raw(simd, &lanes[..F::LANES])
}

/// Returns the signed digits of every component of every scalar in base `2^width`, `stride`
/// digits per component, by scalar then by component, with the odd components negated as
/// [`Group::components`] counts them; or, without `split`, of every whole scalar as its only
/// component.
///
/// `stride` digits must cover [`Group::COMPONENT_BITS`] or [`SCALAR_BITS`] bits.
fn component_digits<G: Group>(
    scalars: &[Scalar],
    width: u32,
    stride: usize,
    split: bool,
) -> Vec<i16> {
    let components = if split { G::COMPONENTS } else { 1 };
    let mut digits = vec![0; scalars.len() * components * stride];
    let mut digits_by_scalar = digits.chunks_exact_mut(components * stride);
    for (scalar, digits) in scalars.iter().zip(&mut digits_by_scalar) {
        if split {
            let components = G::components(scalar);
            for (c, digits) in digits.chunks_exact_mut(stride).enumerate() {
                signed_digits(&components[c], width, c % 2 == 1, digits);
            }
        } else {
            signed_digits(&scalar.to_words(), width, false, digits);
        }
    }
    digits
}

/// Stores the raw form of every image of every element under the powers of the endomorphism,
/// each followed by that of its negation, by element then by component.
///
/// `prepared` must hold [`Group::COMPONENTS`] entries per element.
#[cfg_attr(not(debug_assertions), inline(always))]
fn prepare<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    identity: Raw<S, F, G>,
    prepared: &mut [[Raw<S, F, G>; 2]],
) {
    const { assert!(F::LANES <= MAX_LANES) };
    debug_assert_eq!(prepared.len(), elements.len() * G::COMPONENTS);
    let mut stored = [identity; MAX_LANES];
    let span = F::LANES * G::COMPONENTS;
    for (elements, prepared) in elements.chunks(F::LANES).zip(prepared.chunks_mut(span)) {
        let mut points = load_each::<S, F, G>(simd, elements);
        for c in 0..G::COMPONENTS {
            if c > 0 {
                points = points.endomorphism(simd);
            }
            points.store_raw(simd, &mut stored[..elements.len()]);
            for (prepared, stored) in prepared[c..].iter_mut().step_by(G::COMPONENTS).zip(&stored) {
                prepared[0] = *stored;
            }
            points
                .negate(simd)
                .store_raw(simd, &mut stored[..elements.len()]);
            for (prepared, stored) in prepared[c..].iter_mut().step_by(G::COMPONENTS).zip(&stored) {
                prepared[1] = *stored;
            }
        }
    }
}

/// Returns the sum of the elements times their scalars by Straus's method.
///
/// Each lane holds one element of every group of [`Field::LANES`]. A group's table holds, for
/// each component, the multiples of its elements' images by `1` through `2^(width - 1)` and
/// their negations, so that each signed digit selects one entry per lane, and every window shares
/// the doublings of one accumulator. A group skips a component's addition in a window where that
/// component's digit is zero in every lane.
#[cfg_attr(not(debug_assertions), inline(always))]
fn straus<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    scalars: &[Scalar],
    width: u32,
    split: bool,
) -> G {
    let identity = identity::<S, F, G>(simd);
    let zero = first_raw::<S, F, G>(simd, identity);
    let (components, windows) = Method::shape::<G>(width, split);
    let digits = component_digits::<G>(scalars, width, windows, split);
    let entries = 1 << (width - 1);

    // Entry 2 c entries + k of a group's table holds k + 1 times the c-th images of its
    // elements, one lane each, and entry (2 c + 1) entries + k their negations.
    let span = 2 * entries * F::LANES * components;
    let mut tables = vec![zero; elements.len().div_ceil(F::LANES) * span];
    for (elements, table) in elements.chunks(F::LANES).zip(tables.chunks_exact_mut(span)) {
        let base = load_each::<S, F, G>(simd, elements);
        let mut multiple = base;
        for k in 0..entries {
            if k % 2 == 1 {
                // k + 1 is even, so double entry (k - 1) / 2, which holds (k + 1) / 2 times the
                // base.
                let half = (k - 1) / 2;
                multiple = outlined_double(
                    simd,
                    load_each_raw::<S, F, G>(simd, &table[half * F::LANES..]),
                );
            } else if k > 0 {
                multiple = outlined_add(simd, multiple, base);
            }
            let mut image = multiple;
            for c in 0..components {
                if c > 0 {
                    image = image.endomorphism(simd);
                }
                let entry = (2 * c * entries + k) * F::LANES;
                image.store_raw(simd, &mut table[entry..entry + F::LANES]);
                let negated = entry + entries * F::LANES;
                image
                    .negate(simd)
                    .store_raw(simd, &mut table[negated..negated + F::LANES]);
            }
        }
    }

    let mut total = identity;
    let mut started = false;
    let stride = components * windows;
    for window in (0..windows).rev() {
        if started {
            for _ in 0..width {
                total = outlined_double(simd, total);
            }
        }
        for (group, table) in tables.chunks_exact(span).enumerate() {
            let group_digits = &digits[group * F::LANES * stride..];
            for c in 0..components {
                let mut entries_used = [&zero; MAX_LANES];
                let mut any = false;
                for (lane, digits) in group_digits.chunks_exact(stride).take(F::LANES).enumerate() {
                    let digit = digits[c * windows + window];
                    if digit != 0 {
                        let magnitude = digit.unsigned_abs() as usize;
                        let entry =
                            2 * c * entries + magnitude - 1 + if digit < 0 { entries } else { 0 };
                        entries_used[lane] = &table[entry * F::LANES + lane];
                        any = true;
                    }
                }
                if any {
                    let term = G::Points::<S, F>::load_raw(simd, &entries_used[..F::LANES]);
                    total = outlined_add(simd, total, term);
                    started = true;
                }
            }
        }
    }
    sum_lanes::<S, F, G>(simd, total)
}

/// Returns the sum of the elements times their scalars by Pippenger's method.
///
/// Lane `l` of group `g` takes window `g * F::LANES + l` of every component of every scalar,
/// and adds each element's image, negated for a negative digit, to the lane's bucket for the
/// digit's magnitude; no two lanes share a bucket. Buckets stay in raw form, and each
/// addition gathers one bucket per lane. The elements enter `chunk` at a time, each chunk into
/// the buckets of every group, so the images of one chunk are all that is held beside the
/// buckets. Running sums over the buckets weight each by its magnitude, and the groups
/// combine by doubling, from the most significant down. Finally lane `l` is shifted by
/// `width * l` bits and the lanes are summed.
#[cfg_attr(not(debug_assertions), inline(always))]
fn pippenger<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    scalars: &[Scalar],
    width: u32,
    chunk: NonZeroUsize,
) -> G {
    let identity = identity::<S, F, G>(simd);
    let zero = first_raw::<S, F, G>(simd, identity);
    let chunk = chunk.get();
    let groups = windows::<G>(width).div_ceil(F::LANES);
    let span = groups * F::LANES;

    // Bucket b of lane l of a group, for magnitude b + 1, is entry b * F::LANES + l of the
    // group's buckets, and `used` holds the largest magnitude each group has seen.
    let group_buckets = F::LANES << (width - 1);
    let mut buckets = vec![zero; groups * group_buckets];
    let mut used = vec![0; groups];
    let mut prepared = vec![[zero; 2]; elements.len().min(chunk) * G::COMPONENTS];
    let mut stored = [zero; MAX_LANES];
    for (elements, scalars) in elements.chunks(chunk).zip(scalars.chunks(chunk)) {
        let digits = component_digits::<G>(scalars, width, span, true);
        let prepared = &mut prepared[..elements.len() * G::COMPONENTS];
        prepare::<S, F, G>(simd, elements, zero, prepared);
        for (group, (buckets, used)) in buckets
            .chunks_exact_mut(group_buckets)
            .zip(&mut used)
            .enumerate()
        {
            for (element, digits) in prepared.iter().zip(digits.chunks_exact(span)) {
                let digits = &digits[group * F::LANES..(group + 1) * F::LANES];
                let mut slots = [None; MAX_LANES];
                let mut sums = [&zero; MAX_LANES];
                let mut terms = [&zero; MAX_LANES];
                for (lane, &digit) in digits.iter().enumerate() {
                    if digit != 0 {
                        let magnitude = digit.unsigned_abs() as usize;
                        let slot = (magnitude - 1) * F::LANES + lane;
                        *used = (*used).max(magnitude);
                        slots[lane] = Some(slot);
                        sums[lane] = &buckets[slot];
                        terms[lane] = &element[usize::from(digit < 0)];
                    }
                }
                if slots.iter().all(Option::is_none) {
                    continue;
                }
                let bucket = G::Points::<S, F>::load_raw(simd, &sums[..F::LANES]);
                let term = G::Points::<S, F>::load_raw(simd, &terms[..F::LANES]);
                outlined_add(simd, bucket, term).store_raw(simd, &mut stored[..F::LANES]);
                for (slot, stored) in slots.iter().zip(&stored) {
                    if let Some(slot) = slot {
                        buckets[*slot] = *stored;
                    }
                }
            }
        }
    }

    let mut total = identity;
    let mut started = false;
    for (buckets, &used) in buckets.chunks_exact(group_buckets).zip(&used).rev() {
        if started {
            for _ in 0..width as usize * F::LANES {
                total = outlined_double(simd, total);
            }
        }
        // The running sum adds each bucket once it is reached from the top, so the window sum
        // counts bucket b + 1 times.
        if used > 0 {
            let mut running = load_each_raw::<S, F, G>(simd, &buckets[(used - 1) * F::LANES..]);
            let mut window = running;
            for bucket in (0..used - 1).rev() {
                let bucket = load_each_raw::<S, F, G>(simd, &buckets[bucket * F::LANES..]);
                running = outlined_add(simd, running, bucket);
                window = outlined_add(simd, window, running);
            }
            total = if started {
                outlined_add(simd, total, window)
            } else {
                window
            };
            started = true;
        }
    }

    // Shift lane l by width * l bits: each lane joins after the lanes above it have been
    // doubled width times for every lane between them.
    let mut shifted = identity.select(simd, total, 1 << (F::LANES - 1));
    for lane in (0..F::LANES - 1).rev() {
        for _ in 0..width {
            shifted = outlined_double(simd, shifted);
        }
        shifted = outlined_add(simd, shifted, identity.select(simd, total, 1 << lane));
    }
    sum_lanes::<S, F, G>(simd, shifted)
}

/// Returns the sum of the elements times their scalars, in variable time.
///
/// The scalars must be public: the operations and memory accesses depend on their digits.
#[derive(Clone, Copy)]
pub struct Msm<'a, G> {
    /// The elements.
    pub elements: &'a [G],
    /// The scalars, one per element.
    pub scalars: &'a [Scalar],
    /// The method, or `None` for [`Method::choose`]'s.
    pub method: Option<Method>,
}

// Kernel::prefers_wide_lanes keeps its default: residues finish every count sooner than the
// 64-bit lanes, in both groups, because the lanes' bucket sums move elements between lanes, which
// costs more than their wider products save.
impl<G: Group> Kernel for Msm<'_, G> {
    type Output = G;

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        // Both methods convert each element once and keep every intermediate point in the
        // representation's own form, through raw coordinates. They skip zero digits and index
        // tables or buckets by the digits.
        let count = self.elements.len().min(self.scalars.len());
        if count == 0 {
            return G::from_coordinates(G::IDENTITY);
        }
        let (elements, scalars) = (&self.elements[..count], &self.scalars[..count]);
        match self
            .method
            .unwrap_or_else(|| Method::choose::<G>(count, F::LANES))
        {
            Method::Straus { width, split } => {
                straus::<S, F, G>(simd, elements, scalars, width, split)
            }
            Method::Pippenger { width, chunk } => {
                pippenger::<S, F, G>(simd, elements, scalars, width, chunk)
            }
        }
    }
}

/// Returns the sum of the points times their scalars, in variable time, through one [`Msm`] per
/// batch of at least [`MSM_BATCH`] points that the strategy runs.
pub fn batched<G: Group + Additive>(
    points: &[G],
    scalars: &[Scalar],
    strategy: &impl Strategy,
) -> G {
    let count = points.len().min(scalars.len());
    let (points, scalars) = (&points[..count], &scalars[..count]);
    strategy.run_batches(count, MSM_BATCH, 1, |batches| {
        batches
            .map_collect_vec(
                |ranges| ranges,
                |range| {
                    Msm {
                        elements: &points[range.clone()],
                        scalars: &scalars[range],
                        method: None,
                    }
                    .dispatch()
                },
            )
            .iter()
            .fold(G::zero(), |sum, batch| sum + batch)
    })
}

//! Kernels for the group operations, each written once over every base field representation.
//!
//! A kernel implements [`Kernel::run`] once, generically over the representation, and the
//! public operations run it through [`Kernel::dispatch`]. G1 and G2 implement [`Group`], which
//! gives the kernels their coordinates, their points in each representation, and the split of
//! their scalars.
//!
//! [`Kernel::dispatch`] selects the backend and the base field representation. Elements cross
//! into a kernel as canonical coordinates, so every kernel loads its inputs and stores its
//! outputs.
//!
//! Operations over slices of elements ([`Sum`], [`MultiplyEach`], and [`Msm`]) hold one element
//! per lane, so one kernel runs many elements and fills every lane; the single-element
//! operations use one lane, so their cost is the latency of one lane's formulas.
//!
//! The operations over slices also implement [`Batch`], and the public operations run them
//! through [`Batch::dispatch_batches`], which dispatches one kernel per batch that a strategy
//! supplies.

use super::{Scalar, msm::Msm};
use crate::core::{
    curve::Points,
    field::{
        MAX_LANES,
        arithmetic::Field,
        fp::{rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
    },
};
use alloc::vec::Vec;
use commonware_parallel::Strategy;
use commonware_simd::{Operation, Simd, X86V4C};
use core::{fmt::Debug, mem, num::NonZeroUsize, ops::Range};

/// Width in bits of the signed scalar windows of [`multiply`].
const WINDOW_BITS: u32 = 5;

/// Entries of a table of multiples: `1` through `TABLE` times the base, the magnitudes of the
/// signed windows of [`WINDOW_BITS`] bits.
const TABLE: usize = 1 << (WINDOW_BITS - 1);

/// Most components a scalar splits into, by the endomorphism of G2.
pub const MAX_COMPONENTS: usize = 4;

/// Most windows of [`WINDOW_BITS`] bits in a component, for the halves of a scalar split by the
/// endomorphism of G1. [`digits`] checks that it covers every group.
const MAX_WINDOWS: usize = 26;

/// Signed digits of a scalar, by component then by window from the least significant.
type Digits = [[i16; MAX_WINDOWS]; MAX_COMPONENTS];

/// An operation written once over every base field representation.
pub trait Kernel: Sized {
    /// The result of the operation.
    type Output;

    /// Returns whether the operation finishes sooner in a 64-bit representation than in residues.
    ///
    /// Defaults to `false`.
    fn prefers_wide_lanes(&self) -> bool {
        false
    }

    /// Runs the operation in the representation `F`.
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> Self::Output;

    /// Runs the operation on the best available backend.
    fn dispatch(self) -> Self::Output {
        /// Runs a kernel in residues on x86v4c, or in 64-bit lanes when the kernel prefers wide
        /// lanes, as sums and multiples of many elements of G1 do; elsewhere, in 32-bit lanes.
        struct Run<K>(K);

        impl<S: Simd, K: Kernel> Operation<S> for Run<K> {
            type Output = K::Output;

            #[inline(always)]
            fn portable(self, simd: S) -> K::Output {
                self.0.run::<S, Unsat28<S>>(simd)
            }

            #[inline(always)]
            fn x86_v4c(self, simd: S) -> K::Output
            where
                S: X86V4C,
            {
                if self.0.prefers_wide_lanes() {
                    self.0.run::<S, Unsat49<S>>(simd)
                } else {
                    self.0.run::<S, Rns<S>>(simd)
                }
            }
        }

        commonware_simd::dispatch(Run(self))
    }
}

/// Returns the number of lanes of the representation in which [`Kernel::dispatch`] runs a
/// kernel that does not prefer wide lanes. No representation that [`Kernel::dispatch`] selects
/// has fewer.
pub fn lanes() -> usize {
    /// Returns the number of lanes of the representation that it runs in.
    struct Lanes;

    impl Kernel for Lanes {
        type Output = usize;

        #[inline(always)]
        fn run<S: Simd, F: Field<S>>(self, _: S) -> usize {
            F::LANES
        }
    }

    Lanes.dispatch()
}

/// An operation over a slice of items that splits into the same operation over parts of the
/// items, whose results join into the result of the whole.
pub trait Batch: Kernel<Output: Send> + Send {
    /// Estimated work of one item, in additions of G1.
    const WORK: usize;

    /// Returns the number of items.
    fn len(&self) -> usize;

    /// Splits the operation into one operation per range of items.
    ///
    /// The ranges are consecutive and cover every item from the first.
    fn split(self, ranges: Vec<Range<usize>>) -> Vec<Self>;

    /// Runs the whole operation as one kernel on the best available backend.
    fn dispatch_one(self) -> Self::Output;

    /// Combines the results of the parts, in the order of their ranges.
    fn join(outputs: &[Self::Output]) -> Self::Output;

    /// Runs the operation as one kernel per batch of items that the strategy supplies.
    ///
    /// The strategy cuts batches of whole groups of [`lanes`] items. Each batch dispatches on
    /// its own, so it runs in the representation that finishes its own items soonest.
    // A strategy keeps its measurements by call site. Tracking the caller gives each operation
    // its own, as long as no macro makes the call: every call in a macro reports the line that
    // invokes the macro.
    #[track_caller]
    fn dispatch_batches(self, strategy: &impl Strategy) -> Self::Output {
        let len = self.len();
        let lanes = lanes();
        let groups = len.div_ceil(lanes);
        // One group never splits.
        if groups < 2 {
            return self.dispatch_one();
        }
        // G1 and G2 share the call site of an operation. Their estimates of work, which differ
        // fourfold, keep the strategy's measurements of them apart.
        let work = Self::WORK.saturating_mul(lanes);
        strategy.run_batches(groups, NonZeroUsize::MIN, work, |batches| {
            if batches.is_whole() {
                return self.dispatch_one();
            }
            let outputs = batches.map_collect_vec(
                |ranges| {
                    let items = |group: usize| group.saturating_mul(lanes).min(len);
                    self.split(
                        ranges
                            .into_iter()
                            .map(|range| items(range.start)..items(range.end))
                            .collect(),
                    )
                },
                Self::dispatch_one,
            );
            Self::join(&outputs)
        })
    }
}

/// A group whose elements cross kernel boundaries as canonical projective coordinates.
pub trait Group: Copy + Send + Sync {
    /// Canonical projective coordinates of one element.
    type Coordinates: Copy + Send + Sync + PartialEq + Debug;

    /// Elements of the group, one per lane of the representation `F`.
    type Points<S: Simd, F: Field<S>>: Points<S, Coordinates = Self::Coordinates>;

    /// The identity.
    const IDENTITY: Self::Coordinates;

    /// Estimated work of an addition, in additions of G1.
    const WORK: usize;

    /// Runs a sum through [`Kernel::dispatch`].
    fn dispatch_sum(kernel: Sum<'_, Self>) -> Self;

    /// Runs the multiplications of a slice through [`Kernel::dispatch`].
    fn dispatch_multiply_each(kernel: MultiplyEach<'_, Self>);

    /// Runs a multi-scalar multiplication through [`Kernel::dispatch`].
    fn dispatch_msm(kernel: Msm<'_, Self>) -> Self;

    /// Largest number of elements that [`Sum`] runs in residues, which finish them sooner than
    /// the 64-bit lanes, or `None` when residues finish every count sooner.
    const SUM_BATCH: Option<usize>;

    /// Largest number of elements that [`MultiplyEach`] runs in residues, which finish them
    /// sooner than the 64-bit lanes, or `None` when residues finish every count sooner.
    const MULTIPLY_BATCH: Option<usize>;

    /// Number of components [`Self::components`] splits a scalar into: the powers of the
    /// endomorphism's eigenvalue that span the scalars.
    const COMPONENTS: usize;

    /// Bits that the signed digits of a component cover: one more than the components' width,
    /// so that the top digit absorbs the carry.
    const COMPONENT_BITS: u32;

    /// Splits a scalar `k` into components below `2^(COMPONENT_BITS - 1)`, as little-endian
    /// words, such that `k` is the sum over components `c` of `components[c] (-e)^c`, for the
    /// eigenvalue `e` of [`Points::endomorphism`].
    ///
    /// Components beyond [`Self::COMPONENTS`] are zero. Runs in time independent of the scalar.
    fn components(scalar: &Scalar) -> [[u64; 2]; MAX_COMPONENTS];

    /// Returns the element's coordinates.
    fn coordinates(&self) -> &Self::Coordinates;

    /// Wraps the coordinates of an element of the group.
    fn from_coordinates(coordinates: Self::Coordinates) -> Self;
}

/// Loads `element` into every lane.
#[inline(always)]
fn splat<S: Simd, F: Field<S>, G: Group>(simd: S, element: &G) -> G::Points<S, F> {
    G::Points::<S, F>::load(simd, &[], element.coordinates())
}

/// Loads the identity into every lane.
#[inline(always)]
pub fn identity<S: Simd, F: Field<S>, G: Group>(simd: S) -> G::Points<S, F> {
    G::Points::<S, F>::load(simd, &[], &G::IDENTITY)
}

/// Returns the element in the first lane.
#[inline(always)]
fn first<S: Simd, F: Field<S>, G: Group>(simd: S, points: G::Points<S, F>) -> G {
    let mut output = [G::IDENTITY];
    points.store(simd, &mut output);
    G::from_coordinates(output[0])
}

/// Returns the sum of the elements in every lane.
///
/// Adds the upper half of the lanes to the lower half until one remains, moving elements between
/// lanes through their coordinates.
#[inline(always)]
pub fn sum_lanes<S: Simd, F: Field<S>, G: Group>(simd: S, points: G::Points<S, F>) -> G {
    const { assert!(F::LANES <= MAX_LANES) };
    let mut lanes = [G::IDENTITY; MAX_LANES];
    points.store(simd, &mut lanes);
    let mut count = F::LANES;
    while count > 1 {
        let half = count.div_ceil(2);
        let low = G::Points::<S, F>::load(simd, &lanes[..half], &G::IDENTITY);
        let high = G::Points::<S, F>::load(simd, &lanes[half..count], &G::IDENTITY);
        low.add(simd, high).store(simd, &mut lanes[..half]);
        count = half;
    }
    G::from_coordinates(lanes[0])
}

/// Writes the signed digits of a little-endian integer in base `2^width`, least significant
/// first, one per entry of `digits`, each in `(-2^(width - 1), 2^(width - 1)]`, or their
/// negations for `negate`.
///
/// Requires `2 <= width <= 15` and `value < 2^(width * digits.len() - 1)`, so that the last
/// digit absorbs the carry. Runs in time independent of the value.
pub fn signed_digits(value: &[u64], width: u32, negate: bool, digits: &mut [i16]) {
    debug_assert!((2..=15).contains(&width));
    let width = width as usize;
    let half = 1i32 << (width - 1);
    let sign = if negate { -1 } else { 1 };
    let mut carry = 0;
    for (i, digit) in digits.iter_mut().enumerate() {
        let (word, shift) = (i * width / 64, i * width % 64);
        let mut bits = 0;
        if word < value.len() {
            bits = value[word] >> shift;
            if shift + width > 64 && word + 1 < value.len() {
                bits |= value[word + 1] << (64 - shift);
            }
        }
        let raw = (bits & ((1 << width) - 1)) as i32 + carry;
        carry = i32::from(raw > half);
        *digit = (sign * (raw - (carry << width))) as i16;
    }
    // A value within the bound has no bits at or above the top digit's sign bit, and leaves no
    // carry.
    debug_assert_eq!(carry, 0);
    debug_assert!(value.iter().enumerate().all(|(i, word)| {
        let bound = (width * digits.len() - 1).saturating_sub(64 * i);
        bound >= 64 || word >> bound == 0
    }));
}

/// Returns the number of windows of `width` bits in a component of `G`.
pub const fn windows<G: Group>(width: u32) -> usize {
    G::COMPONENT_BITS.div_ceil(width) as usize
}

/// Returns the signed digits of a scalar in base `2^WINDOW_BITS`, by component then by window,
/// with the odd components negated as [`Group::components`] counts them, so that `k P` is the
/// sum over components `c` and windows `w` of `digits[c][w] 2^(WINDOW_BITS w) psi^c(P)` for
/// the endomorphism `psi`. Each digit's magnitude is at most [`TABLE`].
fn digits<G: Group>(scalar: &Scalar) -> Digits {
    const { assert!(windows::<G>(WINDOW_BITS) <= MAX_WINDOWS) };
    let components = G::components(scalar);
    let mut digits = [[0; MAX_WINDOWS]; MAX_COMPONENTS];
    let windows = windows::<G>(WINDOW_BITS);
    for (c, (digits, component)) in digits.iter_mut().zip(components).enumerate() {
        if c < G::COMPONENTS {
            signed_digits(&component, WINDOW_BITS, c % 2 == 1, &mut digits[..windows]);
        }
    }
    digits
}

/// Returns `1` when `value` is zero and `0` otherwise, without branching.
#[inline(always)]
const fn is_zero(value: u64) -> u64 {
    ((value | value.wrapping_neg()) >> 63) ^ 1
}

/// Returns, in each lane, the table entry for the magnitude of the lane's digit, negated for a
/// negative digit, or the identity for zero.
///
/// Entry `k` of the table holds `k + 1` times a point. Every lane selects from the whole table,
/// so neither the operations nor the memory accesses depend on the digits.
#[inline(always)]
fn lookup<S: Simd, P: Points<S>>(simd: S, identity: P, table: &[P], digits: [i16; MAX_LANES]) -> P {
    let mut negative = 0;
    let mut magnitudes = [0; MAX_LANES];
    for (lane, digit) in digits.iter().enumerate() {
        // The sign extends to a mask that negates the digit without branching.
        let mask = digit >> (i16::BITS - 1);
        negative |= u64::from(mask as u16 & 1) << lane;
        magnitudes[lane] = u64::from((digit ^ mask).wrapping_sub(mask) as u16);
    }
    let mut term = identity;
    for (k, entry) in table.iter().enumerate() {
        let mut lanes = 0;
        for (lane, magnitude) in magnitudes.iter().enumerate() {
            lanes |= is_zero(magnitude ^ (k as u64 + 1)) << lane;
        }
        term = term.select(simd, *entry, lanes);
    }
    term.negate_lanes(simd, negative)
}

/// Returns, in each lane, the lane's point times the lane's scalar.
///
/// `digits(component, window)` returns each lane's digit of the window, as [`digits`] splits
/// them for `components` components of `windows` windows. A table holds the multiples of the
/// base, and every window selects one entry per component through [`lookup`] and combines them
/// by Horner's rule over the endomorphism, from the last component down, then adds the sum to
/// an accumulator doubled [`WINDOW_BITS`] times between windows. The schedule is fixed, so
/// neither the operations nor the memory accesses depend on the digits.
#[cfg_attr(not(debug_assertions), inline(always))]
fn multiply<S: Simd, P: Points<S>>(
    simd: S,
    base: P,
    identity: P,
    components: usize,
    windows: usize,
    digits: impl Fn(usize, usize) -> [i16; MAX_LANES],
) -> P {
    // Entry k holds k + 1 times the base.
    let mut table = [base; TABLE];
    for k in 2..=TABLE {
        table[k - 1] = if k % 2 == 0 {
            table[k / 2 - 1].double(simd)
        } else {
            table[k - 2].add(simd, base)
        };
    }
    let mut result = identity;
    // The endomorphism splits each scalar into two components of 128 bits in G1 and four of 64
    // bits in G2, so the doublings cover one component rather than the whole scalar, at the cost
    // of components - 1 endomorphism images per window.
    for window in (0..windows).rev() {
        let mut term = lookup(simd, identity, &table, digits(components - 1, window));
        for c in (0..components - 1).rev() {
            let entry = lookup(simd, identity, &table, digits(c, window));
            term = term.endomorphism(simd).add(simd, entry);
        }
        if window + 1 < windows {
            for _ in 0..WINDOW_BITS {
                result = result.double(simd);
            }
        }
        result = result.add(simd, term);
    }
    result
}

/// Loads each of up to [`Field::LANES`] elements into its own lane.
#[inline(always)]
pub fn load_each<S: Simd, F: Field<S>, G: Group>(simd: S, elements: &[G]) -> G::Points<S, F> {
    const { assert!(F::LANES <= MAX_LANES) };
    debug_assert!(elements.len() <= F::LANES);
    let mut coordinates = [G::IDENTITY; MAX_LANES];
    for (lane, element) in elements.iter().enumerate() {
        coordinates[lane] = *element.coordinates();
    }
    G::Points::<S, F>::load(simd, &coordinates[..elements.len()], &G::IDENTITY)
}

/// Returns, in each lane, that lane's element times its scalar, for up to [`Field::LANES`] of each.
#[inline(always)]
fn products<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    identity: G::Points<S, F>,
    elements: &[G],
    scalars: &[Scalar],
) -> G::Points<S, F> {
    let mut digits = [[[0; MAX_WINDOWS]; MAX_COMPONENTS]; MAX_LANES];
    for (lane, scalar) in scalars.iter().enumerate().take(elements.len()) {
        digits[lane] = self::digits::<G>(scalar);
    }
    let base = load_each::<S, F, G>(simd, elements);
    let windows = windows::<G>(WINDOW_BITS);
    multiply(simd, base, identity, G::COMPONENTS, windows, |c, w| {
        digits.map(|digits| digits[c][w])
    })
}

/// Adds two elements.
#[derive(Clone, Copy)]
pub struct Add<G>(pub G, pub G);

impl<G: Group> Kernel for Add<G> {
    type Output = G;

    #[inline(always)]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        let sum = splat::<S, F, G>(simd, &self.0).add(simd, splat::<S, F, G>(simd, &self.1));
        first::<S, F, G>(simd, sum)
    }
}

/// Doubles an element.
#[derive(Clone, Copy)]
pub struct Double<G>(pub G);

impl<G: Group> Kernel for Double<G> {
    type Output = G;

    #[inline(always)]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        first::<S, F, G>(simd, splat::<S, F, G>(simd, &self.0).double(simd))
    }
}

/// Multiplies an element by a scalar, in time independent of the scalar.
#[derive(Clone, Copy)]
pub struct Multiply<G> {
    /// The element.
    pub element: G,
    /// The scalar.
    pub scalar: Scalar,
}

impl<G: Group> Kernel for Multiply<G> {
    type Output = G;

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        let identity = identity::<S, F, G>(simd);
        let base = splat::<S, F, G>(simd, &self.element);
        let digits = digits::<G>(&self.scalar);
        let windows = windows::<G>(WINDOW_BITS);
        let product = multiply(simd, base, identity, G::COMPONENTS, windows, |c, w| {
            [digits[c][w]; MAX_LANES]
        });
        first::<S, F, G>(simd, product)
    }
}

/// Returns the sum of the elements, one element per lane.
#[derive(Clone, Copy)]
pub struct Sum<'a, G>(pub &'a [G]);

impl<G: Group> Kernel for Sum<'_, G> {
    type Output = G;

    fn prefers_wide_lanes(&self) -> bool {
        G::SUM_BATCH.is_some_and(|batch| self.0.len() > batch)
    }

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        let mut total = identity::<S, F, G>(simd);
        for elements in self.0.chunks(F::LANES) {
            total = total.add(simd, load_each::<S, F, G>(simd, elements));
        }
        sum_lanes::<S, F, G>(simd, total)
    }
}

impl<G: Group> Batch for Sum<'_, G> {
    const WORK: usize = G::WORK;

    fn len(&self) -> usize {
        self.0.len()
    }

    fn split(self, ranges: Vec<Range<usize>>) -> Vec<Self> {
        ranges
            .into_iter()
            .map(|range| Self(&self.0[range]))
            .collect()
    }

    fn dispatch_one(self) -> G {
        G::dispatch_sum(self)
    }

    fn join(outputs: &[G]) -> G {
        G::dispatch_sum(Sum(outputs))
    }
}

/// Returns the sum of the elements, in the batches that the strategy supplies.
pub fn sum<G: Group>(elements: &[G], strategy: &impl Strategy) -> G {
    Sum(elements).dispatch_batches(strategy)
}

/// Multiplies each element by the scalar at the same index, one element per lane, in time
/// independent of the scalars.
pub struct MultiplyEach<'a, G> {
    /// The elements, replaced by their multiples.
    pub elements: &'a mut [G],
    /// The scalars, one per element.
    pub scalars: &'a [Scalar],
}

impl<G: Group> Kernel for MultiplyEach<'_, G> {
    type Output = ();

    fn prefers_wide_lanes(&self) -> bool {
        G::MULTIPLY_BATCH.is_some_and(|batch| self.elements.len().min(self.scalars.len()) > batch)
    }

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) {
        const { assert!(F::LANES <= MAX_LANES) };
        let identity = identity::<S, F, G>(simd);
        let count = self.elements.len().min(self.scalars.len());
        for (elements, scalars) in self.elements[..count]
            .chunks_mut(F::LANES)
            .zip(self.scalars[..count].chunks(F::LANES))
        {
            let product = products::<S, F, G>(simd, identity, elements, scalars);
            let mut coordinates = [G::IDENTITY; MAX_LANES];
            product.store(simd, &mut coordinates[..elements.len()]);
            for (element, coordinates) in elements.iter_mut().zip(coordinates) {
                *element = G::from_coordinates(coordinates);
            }
        }
    }
}

impl<G: Group> Batch for MultiplyEach<'_, G> {
    // A multiplication doubles once per bit of a component and adds once per window of every
    // component.
    const WORK: usize = 256 * G::WORK;

    fn len(&self) -> usize {
        self.elements.len().min(self.scalars.len())
    }

    fn split(self, ranges: Vec<Range<usize>>) -> Vec<Self> {
        let mut rest = self.elements;
        ranges
            .into_iter()
            .map(|range| {
                let (elements, tail) = mem::take(&mut rest).split_at_mut(range.len());
                rest = tail;
                Self {
                    elements,
                    scalars: &self.scalars[range],
                }
            })
            .collect()
    }

    fn dispatch_one(self) {
        G::dispatch_multiply_each(self);
    }

    fn join(_: &[()]) {}
}

/// Multiplies each element by the scalar at the same index, in the batches that the strategy
/// supplies.
pub fn multiply_each<G: Group>(elements: &mut [G], scalars: &[Scalar], strategy: &impl Strategy) {
    MultiplyEach { elements, scalars }.dispatch_batches(strategy);
}

//! Kernels for the group operations, each written once over every base field representation.
//!
//! Each public operation runs as one kernel through [`dispatch`], which selects the backend at the
//! boundary. The backend's profile then selects the base field representation: on x86v4c,
//! residues, except for the sums and multiples of many elements of G1, whose base field products
//! the 64-bit lanes finish sooner; 32-bit lanes elsewhere. Elements cross the boundary as
//! canonical coordinates, so every kernel loads its inputs and stores its outputs, and loaded
//! coordinates satisfy the bounds of the curve formulas.
//!
//! Operations over slices of elements ([`Sum`], [`MultiplyEach`], and [`Msm`]) hold one element
//! per lane, so they amortize the boundary and fill every lane; the single-element operations
//! use one lane and measure latency. [`Msm`] converts each element once and keeps every
//! intermediate point in the representation's own form, through raw coordinates.

use super::Scalar;
use crate::core::{
    curve::{g1, g2},
    field::{
        arithmetic::Field,
        fp::{rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
    },
};
use alloc::{vec, vec::Vec};
use commonware_simd::{Operation, Simd, X86V4C};

/// Largest lane count of any representation.
pub const MAX_LANES: usize = 16;

/// Width in bits of the scalar windows of [`multiply`].
const WINDOW_BITS: usize = 4;

/// Number of windows in a scalar.
const SCALAR_WINDOWS: usize = 256 / WINDOW_BITS;

/// Bits that the signed digits of [`Msm`] cover. Scalars lie below `r < 2^255`, so these leave
/// room for the carry out of the top digit.
const SCALAR_BITS: u32 = 256;

/// Window widths that [`Plan::choose`] considers for Straus's method.
const STRAUS_WIDTHS: core::ops::RangeInclusive<u32> = 2..=8;

/// Window widths that [`Plan::choose`] considers for Pippenger's method. The widest bounds the
/// buckets at `2^11` points per lane.
const PIPPENGER_WIDTHS: core::ops::RangeInclusive<u32> = 2..=12;

/// Estimated cost of an addition of points, in units of [`Plan::cost`].
const ADD_COST: usize = 10;

/// Estimated cost of a doubling, which takes about two thirds of an addition's products.
const DOUBLE_COST: usize = 7;

/// Estimated cost of a negation, which multiplies one coordinate.
const NEGATE_COST: usize = 2;

/// An operation written once over every base field representation.
pub trait Kernel: Sized {
    /// The result of the operation.
    type Output;

    /// Returns whether the operation holds independent items in every lane of a 64-bit
    /// representation, which then finishes them sooner than residues.
    fn batch(&self) -> bool {
        false
    }

    /// Runs the operation in the representation `F`.
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> Self::Output;

    /// Runs the operation on x86v4c: in 64-bit lanes for a batch of independent items and in
    /// residues otherwise. An operation whose independent items end in a single one may override
    /// this to switch representations in between through canonical encodings.
    #[inline(always)]
    fn x86_v4c<S: X86V4C>(self, simd: S) -> Self::Output {
        if self.batch() {
            self.run::<S, Unsat49<S>>(simd)
        } else {
            self.run::<S, Rns<S>>(simd)
        }
    }
}

/// Runs a kernel in the representation chosen for the backend.
pub struct Run<K>(pub K);

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
        self.0.x86_v4c(simd)
    }
}

/// Runs a kernel on the best available backend.
pub fn dispatch<K: Kernel>(kernel: K) -> K::Output {
    commonware_simd::dispatch(Run(kernel))
}

/// Projective points of one group, one per lane of a base field representation.
pub trait Points<S: Simd>: Copy {
    /// Canonical projective coordinates of one point.
    type Coordinates: Copy;

    /// Loads up to one point per lane, filling the remaining lanes with `fill`.
    fn load(simd: S, points: &[Self::Coordinates], fill: &Self::Coordinates) -> Self;

    /// Stores each lane's canonical coordinates, dropping lanes beyond `points`.
    fn store(self, simd: S, points: &mut [Self::Coordinates]);

    /// Returns `self + rhs`.
    fn add(self, simd: S, rhs: Self) -> Self;

    /// Returns `2 * self`.
    fn double(self, simd: S) -> Self;

    /// Returns `rhs` in every lane whose bit is set in `lanes`, and `self` in the others.
    fn select(self, simd: S, rhs: Self, lanes: u64) -> Self;

    /// Returns `-self`.
    fn negate(self, simd: S) -> Self;

    /// One lane of a point in the representation's own form.
    type Raw: Copy + Default;

    /// Stores each lane in the representation's own form, dropping lanes beyond `points`, without
    /// any conversion.
    fn store_raw(self, simd: S, points: &mut [Self::Raw]);

    /// Loads lane `i` from `points[i]`, as [`Self::store_raw`] stored it, for at least one entry
    /// per lane, without any conversion.
    fn load_raw(simd: S, points: &[&Self::Raw]) -> Self;
}

macro_rules! points {
    ($module:ident, $raw:ty) => {
        impl<S: Simd, F: Field<S>> Points<S> for $module::Point<F> {
            type Coordinates = $module::Coordinates;
            type Raw = $raw;

            #[inline(always)]
            fn load(simd: S, points: &[Self::Coordinates], fill: &Self::Coordinates) -> Self {
                Self::load(simd, points, fill)
            }

            #[inline(always)]
            fn store(self, simd: S, points: &mut [Self::Coordinates]) {
                self.store(simd, points);
            }

            #[inline(always)]
            fn add(self, simd: S, rhs: Self) -> Self {
                self.add(simd, rhs)
            }

            #[inline(always)]
            fn double(self, simd: S) -> Self {
                self.double(simd)
            }

            #[inline(always)]
            fn select(self, simd: S, rhs: Self, lanes: u64) -> Self {
                self.select(simd, rhs, lanes)
            }

            #[inline(always)]
            fn negate(self, simd: S) -> Self {
                self.neg(simd)
            }

            #[inline(always)]
            fn store_raw(self, simd: S, points: &mut [Self::Raw]) {
                self.store_raw(simd, points);
            }

            #[inline(always)]
            fn load_raw(simd: S, points: &[&Self::Raw]) -> Self {
                Self::load_raw(simd, points)
            }
        }
    };
}

points!(g1, [F::Raw; 3]);
points!(g2, [[F::Raw; 2]; 3]);

/// A group whose elements cross kernel boundaries as canonical projective coordinates.
pub trait Group: Copy + Send + Sync {
    /// Canonical projective coordinates of one element.
    type Coordinates: Copy + Send + Sync + PartialEq + ::core::fmt::Debug;

    /// Elements of the group, one per lane of the representation `F`.
    type Points<S: Simd, F: Field<S>>: Points<S, Coordinates = Self::Coordinates>;

    /// The identity.
    const IDENTITY: Self::Coordinates;

    /// Fewest elements for which [`Sum`] favors the 64-bit lanes over residues, or `None` when
    /// residues finish every count sooner.
    const SUM_BATCH: Option<usize>;

    /// Fewest elements for which [`MultiplyEach`] favors the 64-bit lanes over residues, or
    /// `None` when residues finish every count sooner.
    const MULTIPLY_BATCH: Option<usize>;

    /// Returns the element's coordinates.
    fn coordinates(&self) -> &Self::Coordinates;

    /// Wraps the coordinates of an element of the group.
    fn from_coordinates(coordinates: Self::Coordinates) -> Self;

    /// Returns `-self`.
    fn negate(&self) -> Self;

    /// Returns whether this is the identity.
    fn is_identity(&self) -> bool;
}

/// Loads `element` into every lane.
#[inline(always)]
fn splat<S: Simd, F: Field<S>, G: Group>(simd: S, element: &G) -> G::Points<S, F> {
    G::Points::<S, F>::load(simd, &[], element.coordinates())
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
fn sum_lanes<S: Simd, F: Field<S>, G: Group>(simd: S, points: G::Points<S, F>) -> G {
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

/// Returns window `window` of a little-endian integer, or zero beyond its words.
#[inline(always)]
const fn digit(words: &[u64], window: usize) -> u64 {
    let bit = window * WINDOW_BITS;
    if bit / 64 >= words.len() {
        return 0;
    }
    (words[bit / 64] >> (bit % 64)) & ((1 << WINDOW_BITS) - 1)
}

/// Returns `1` when `value` is zero and `0` otherwise, without branching.
#[inline(always)]
const fn is_zero(value: u64) -> u64 {
    ((value | value.wrapping_neg()) >> 63) ^ 1
}

/// Returns, in each lane, the lane's point times the lane's integer.
///
/// `digits(window)` returns each lane's digit of window `window`, for `windows` windows counted
/// from the least significant. Fixed four-bit windows index a table of sixteen multiples, and
/// every window selects from the whole table, so neither the operations nor the memory accesses
/// depend on the digits.
#[cfg_attr(not(debug_assertions), inline(always))]
fn multiply<S: Simd, P: Points<S>>(
    simd: S,
    base: P,
    identity: P,
    windows: usize,
    digits: impl Fn(usize) -> [u64; MAX_LANES],
) -> P {
    let mut table = [identity; 1 << WINDOW_BITS];
    table[1] = base;
    for i in 2..table.len() {
        table[i] = if i % 2 == 0 {
            table[i / 2].double(simd)
        } else {
            table[i - 1].add(simd, base)
        };
    }
    let mut result = identity;
    for window in (0..windows).rev() {
        for _ in 0..WINDOW_BITS {
            result = result.double(simd);
        }
        let digits = digits(window);
        let mut term = table[0];
        for (i, entry) in table.iter().enumerate().skip(1) {
            let mut lanes = 0;
            for (lane, digit) in digits.iter().enumerate() {
                lanes |= is_zero(digit ^ i as u64) << lane;
            }
            term = term.select(simd, *entry, lanes);
        }
        result = result.add(simd, term);
    }
    result
}

/// Loads each of up to [`Field::LANES`] elements into its own lane.
#[inline(always)]
fn lanes<S: Simd, F: Field<S>, G: Group>(simd: S, elements: &[G]) -> G::Points<S, F> {
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
    let mut words = [[0; 4]; MAX_LANES];
    for (lane, scalar) in scalars.iter().enumerate().take(elements.len()) {
        words[lane] = scalar.to_words();
    }
    let base = lanes::<S, F, G>(simd, elements);
    multiply(simd, base, identity, SCALAR_WINDOWS, |window| {
        words.map(|words| digit(&words, window))
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

/// Multiplies an element by a little-endian integer, without branching on the integer.
#[derive(Clone, Copy)]
pub struct Multiply<'a, G> {
    /// The element.
    pub element: G,
    /// The integer's little-endian words.
    pub words: &'a [u64],
}

impl<G: Group> Kernel for Multiply<'_, G> {
    type Output = G;

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        let identity = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
        let base = splat::<S, F, G>(simd, &self.element);
        let words = self.words;
        let windows = words.len() * 64 / WINDOW_BITS;
        let product = multiply(simd, base, identity, windows, |window| {
            [digit(words, window); MAX_LANES]
        });
        first::<S, F, G>(simd, product)
    }
}

/// Returns the sum of the elements, one element per lane.
#[derive(Clone, Copy)]
pub struct Sum<'a, G>(pub &'a [G]);

impl<G: Group> Kernel for Sum<'_, G> {
    type Output = G;

    fn batch(&self) -> bool {
        G::SUM_BATCH.is_some_and(|batch| self.0.len() > batch)
    }

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        let mut total = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
        for elements in self.0.chunks(F::LANES) {
            total = total.add(simd, lanes::<S, F, G>(simd, elements));
        }
        sum_lanes::<S, F, G>(simd, total)
    }
}

/// Multiplies each element by the scalar at the same index, one element per lane.
pub struct MultiplyEach<'a, G> {
    /// The elements, replaced by their multiples.
    pub elements: &'a mut [G],
    /// The scalars, one per element.
    pub scalars: &'a [Scalar],
}

impl<G: Group> Kernel for MultiplyEach<'_, G> {
    type Output = ();

    fn batch(&self) -> bool {
        G::MULTIPLY_BATCH.is_some_and(|batch| self.elements.len().min(self.scalars.len()) > batch)
    }

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) {
        const { assert!(F::LANES <= MAX_LANES) };
        let identity = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
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

/// Raw form of one lane of the points of the group `G` in the representation `F`.
type Raw<S, F, G> = <<G as Group>::Points<S, F> as Points<S>>::Raw;

/// Method and signed window width of a multi-scalar multiplication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Plan {
    /// Straus's method: each lane multiplies its own elements through tables of their multiples,
    /// sharing one chain of doublings.
    Straus(u32),
    /// Pippenger's method: each lane sums one window of every element into its own buckets.
    Pippenger(u32),
}

impl Plan {
    /// Returns the plan of least estimated cost for `count` elements on `lanes` lanes.
    pub fn choose(count: usize, lanes: usize) -> Self {
        let plans = STRAUS_WIDTHS
            .map(Self::Straus)
            .chain(PIPPENGER_WIDTHS.map(Self::Pippenger));
        let mut best = Self::Straus(*STRAUS_WIDTHS.start());
        let mut least = usize::MAX;
        for plan in plans {
            let cost = plan.cost(count, lanes);
            if cost < least {
                (best, least) = (plan, cost);
            }
        }
        best
    }

    /// Returns the estimated cost of the plan, counting the additions, doublings, and negations
    /// of points on all lanes at once.
    const fn cost(self, count: usize, lanes: usize) -> usize {
        match self {
            Self::Straus(width) => {
                // Each group of lanes builds a table of its multiples and their negations, then
                // adds one entry per window.
                let groups = count.div_ceil(lanes);
                let entries = 1 << (width - 1);
                let windows = SCALAR_BITS.div_ceil(width) as usize;
                ADD_COST * groups * (entries - 1 + windows)
                    + NEGATE_COST * groups * entries
                    + DOUBLE_COST * width as usize * windows
            }
            Self::Pippenger(width) => {
                // Each group of windows adds every element and sums the buckets in two running
                // sums, then shifts the accumulated windows by `width * lanes` bits.
                let groups = SCALAR_BITS.div_ceil(width).div_ceil(lanes as u32) as usize;
                let buckets = 1 << (width - 1);
                ADD_COST * groups * (count + 2 * buckets)
                    + NEGATE_COST * count.div_ceil(lanes)
                    + DOUBLE_COST * width as usize * lanes * groups
            }
        }
    }
}

/// Returns `a + b` as its own kernel, so that the many additions of [`Msm`] share one copy.
#[inline(always)]
fn sum<S: Simd, P: Points<S>>(simd: S, a: P, b: P) -> P {
    simd.execute(
        #[inline(always)]
        move |simd: S| a.add(simd, b),
    )
}

/// Returns `2 * point` as its own kernel, so that the doublings of [`Msm`] share one copy.
#[inline(always)]
fn twice<S: Simd, P: Points<S>>(simd: S, point: P) -> P {
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
fn load_lanes<S: Simd, F: Field<S>, G: Group>(simd: S, points: &[Raw<S, F, G>]) -> G::Points<S, F> {
    const { assert!(F::LANES <= MAX_LANES) };
    let mut lanes = [&points[0]; MAX_LANES];
    for (lane, point) in lanes.iter_mut().zip(points).take(F::LANES) {
        *lane = point;
    }
    G::Points::<S, F>::load_raw(simd, &lanes[..F::LANES])
}

/// Returns the signed digits of every scalar in base `2^width`, `stride` digits per scalar.
///
/// `stride` digits must cover [`SCALAR_BITS`] bits.
fn recode(scalars: &[Scalar], width: u32, stride: usize) -> Vec<i16> {
    let mut digits = vec![0; scalars.len() * stride];
    for (scalar, digits) in scalars.iter().zip(digits.chunks_exact_mut(stride)) {
        scalar.signed_digits(width, digits);
    }
    digits
}

/// Returns the raw form of every element followed by that of its negation.
#[cfg_attr(not(debug_assertions), inline(always))]
fn prepare<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    identity: Raw<S, F, G>,
) -> Vec<[Raw<S, F, G>; 2]> {
    const { assert!(F::LANES <= MAX_LANES) };
    let mut prepared = vec![[identity; 2]; elements.len()];
    let mut stored = [identity; MAX_LANES];
    for (elements, prepared) in elements.chunks(F::LANES).zip(prepared.chunks_mut(F::LANES)) {
        let points = lanes::<S, F, G>(simd, elements);
        points.store_raw(simd, &mut stored[..elements.len()]);
        for (prepared, stored) in prepared.iter_mut().zip(&stored) {
            prepared[0] = *stored;
        }
        points
            .negate(simd)
            .store_raw(simd, &mut stored[..elements.len()]);
        for (prepared, stored) in prepared.iter_mut().zip(&stored) {
            prepared[1] = *stored;
        }
    }
    prepared
}

/// Returns the sum of the elements times their scalars by Straus's method.
///
/// Each lane holds one element of every group of [`Field::LANES`]. A group's table holds its
/// multiples by `1` through `2^(width - 1)` and their negations, so that each signed digit
/// selects one entry per lane, and every window shares the doublings of one accumulator. Lanes
/// whose digits are all zero in a window skip that window's addition.
#[cfg_attr(not(debug_assertions), inline(always))]
fn straus<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    scalars: &[Scalar],
    width: u32,
) -> G {
    let identity = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
    let zero = first_raw::<S, F, G>(simd, identity);
    let windows = SCALAR_BITS.div_ceil(width) as usize;
    let digits = recode(scalars, width, windows);
    let entries = 1 << (width - 1);

    // Entry k of a group's table holds k + 1 times its elements, one lane each, and entry
    // entries + k their negations.
    let span = 2 * entries * F::LANES;
    let mut tables = vec![zero; elements.len().div_ceil(F::LANES) * span];
    for (elements, table) in elements.chunks(F::LANES).zip(tables.chunks_exact_mut(span)) {
        let base = lanes::<S, F, G>(simd, elements);
        let mut multiple = base;
        for k in 0..entries {
            if k % 2 == 1 {
                // k + 1 is even, so double the multiple by (k + 1) / 2.
                let half = (k - 1) / 2;
                multiple = twice(simd, load_lanes::<S, F, G>(simd, &table[half * F::LANES..]));
            } else if k > 0 {
                multiple = sum(simd, multiple, base);
            }
            multiple.store_raw(simd, &mut table[k * F::LANES..(k + 1) * F::LANES]);
            let negated = &mut table[(entries + k) * F::LANES..(entries + k + 1) * F::LANES];
            multiple.negate(simd).store_raw(simd, negated);
        }
    }

    let mut total = identity;
    let mut started = false;
    for window in (0..windows).rev() {
        if started {
            for _ in 0..width {
                total = twice(simd, total);
            }
        }
        for (group, table) in tables.chunks_exact(span).enumerate() {
            let mut entries_used = [&zero; MAX_LANES];
            let mut any = false;
            let group_digits = digits[group * F::LANES * windows..].chunks_exact(windows);
            for (lane, digits) in group_digits.take(F::LANES).enumerate() {
                let digit = digits[window];
                if digit != 0 {
                    let magnitude = digit.unsigned_abs() as usize;
                    let entry = magnitude - 1 + if digit < 0 { entries } else { 0 };
                    entries_used[lane] = &table[entry * F::LANES + lane];
                    any = true;
                }
            }
            if any {
                let term = G::Points::<S, F>::load_raw(simd, &entries_used[..F::LANES]);
                total = sum(simd, total, term);
                started = true;
            }
        }
    }
    sum_lanes::<S, F, G>(simd, total)
}

/// Returns the sum of the elements times their scalars by Pippenger's method.
///
/// Lane `l` of group `g` takes window `g * F::LANES + l` of every scalar, and sums each element
/// into its own bucket for the digit's magnitude, negated for a negative digit, so the lanes
/// never touch the same bucket. Buckets stay in raw form, and each addition gathers one bucket
/// per lane. Running sums over the buckets weight each by its magnitude, and the groups combine
/// by doubling, from the most significant down. Finally lane `l` is shifted by `width * l` bits
/// and the lanes are summed.
#[cfg_attr(not(debug_assertions), inline(always))]
fn pippenger<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    scalars: &[Scalar],
    width: u32,
) -> G {
    let identity = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
    let zero = first_raw::<S, F, G>(simd, identity);
    let groups = SCALAR_BITS.div_ceil(width).div_ceil(F::LANES as u32) as usize;
    let span = groups * F::LANES;
    let digits = recode(scalars, width, span);
    let prepared = prepare::<S, F, G>(simd, elements, zero);

    // Bucket b of lane l, for magnitude b + 1, is entry b * F::LANES + l.
    let mut buckets = vec![zero; F::LANES << (width - 1)];
    let mut stored = [zero; MAX_LANES];
    let mut total = identity;
    let mut started = false;
    for group in (0..groups).rev() {
        buckets.fill(zero);
        let mut used = 0;
        for (element, digits) in prepared.iter().zip(digits.chunks_exact(span)) {
            let digits = &digits[group * F::LANES..(group + 1) * F::LANES];
            let mut slots = [None; MAX_LANES];
            let mut sums = [&zero; MAX_LANES];
            let mut terms = [&zero; MAX_LANES];
            for (lane, &digit) in digits.iter().enumerate() {
                if digit != 0 {
                    let magnitude = digit.unsigned_abs() as usize;
                    let slot = (magnitude - 1) * F::LANES + lane;
                    used = used.max(magnitude);
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
            sum(simd, bucket, term).store_raw(simd, &mut stored[..F::LANES]);
            for (slot, stored) in slots.iter().zip(&stored) {
                if let Some(slot) = slot {
                    buckets[*slot] = *stored;
                }
            }
        }

        // The running sum adds each bucket once it is reached from the top, so the window sum
        // counts bucket b + 1 times.
        if used > 0 {
            let mut running = load_lanes::<S, F, G>(simd, &buckets[(used - 1) * F::LANES..]);
            let mut window = running;
            for bucket in (0..used - 1).rev() {
                let bucket = load_lanes::<S, F, G>(simd, &buckets[bucket * F::LANES..]);
                running = sum(simd, running, bucket);
                window = sum(simd, window, running);
            }
            if started {
                for _ in 0..width as usize * F::LANES {
                    total = twice(simd, total);
                }
                total = sum(simd, total, window);
            } else {
                total = window;
                started = true;
            }
        } else if started {
            for _ in 0..width as usize * F::LANES {
                total = twice(simd, total);
            }
        }
    }

    // Shift lane l by width * l bits: each lane joins after the lanes above it have been
    // doubled width times for every lane between them.
    let mut shifted = identity.select(simd, total, 1 << (F::LANES - 1));
    for lane in (0..F::LANES - 1).rev() {
        for _ in 0..width {
            shifted = twice(simd, shifted);
        }
        shifted = sum(simd, shifted, identity.select(simd, total, 1 << lane));
    }
    sum_lanes::<S, F, G>(simd, shifted)
}

/// Returns the sum of the elements times their scalars, in variable time.
///
/// The scalars must be public: the operations and memory accesses depend on their digits.
///
/// Residues finish every count sooner than the 64-bit lanes, in both groups: the lanes' bucket
/// sums move elements between lanes, which costs more than their wider products save.
#[derive(Clone, Copy)]
pub struct Msm<'a, G> {
    /// The elements.
    pub elements: &'a [G],
    /// The scalars, one per element.
    pub scalars: &'a [Scalar],
    /// The method, or `None` for [`Plan::choose`]'s.
    pub plan: Option<Plan>,
}

impl<G: Group> Kernel for Msm<'_, G> {
    type Output = G;

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        let count = self.elements.len().min(self.scalars.len());
        if count == 0 {
            return G::from_coordinates(G::IDENTITY);
        }
        let (elements, scalars) = (&self.elements[..count], &self.scalars[..count]);
        match self.plan.unwrap_or_else(|| Plan::choose(count, F::LANES)) {
            Plan::Straus(width) => straus::<S, F, G>(simd, elements, scalars, width),
            Plan::Pippenger(width) => pippenger::<S, F, G>(simd, elements, scalars, width),
        }
    }
}

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
//!
//! Multiplications split each scalar by the group's endomorphism ([`Group::components`]) into
//! two components of 128 bits in G1 and four of 64 bits in G2, so that the doublings they share
//! cover a component rather than the whole scalar, at the cost of one image per component.

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

/// Width in bits of the signed scalar windows of [`multiply`].
const WINDOW_BITS: usize = 5;

/// Entries of a table of multiples: a signed window selects a multiple by `1` through this.
const TABLE: usize = 1 << (WINDOW_BITS - 1);

/// Most components a scalar splits into, by the endomorphism of G2.
pub const MAX_COMPONENTS: usize = 4;

/// Most windows of [`WINDOW_BITS`] bits in a component, for the halves of a scalar split by the
/// endomorphism of G1.
const MAX_WINDOWS: usize = 26;

/// Signed digits of a scalar, by component then by window from the least significant.
type Digits = [[i16; MAX_WINDOWS]; MAX_COMPONENTS];

/// Window widths that [`Plan::choose`] considers for Straus's method.
const STRAUS_WIDTHS: core::ops::RangeInclusive<u32> = 2..=8;

/// Window widths that [`Plan::choose`] considers for Pippenger's method. The widest bounds the
/// buckets at `2^11` points per lane.
const PIPPENGER_WIDTHS: core::ops::RangeInclusive<u32> = 2..=12;

/// Estimated cost of an addition of points, in units of [`Plan::cost`].
const ADD_COST: usize = 10;

/// Estimated cost of a doubling, which takes about two thirds of an addition's products.
const DOUBLE_COST: usize = 7;

/// Estimated cost of a negation or an endomorphism, a few products reduced one after another,
/// which overlap less than a formula's.
const IMAGE_COST: usize = 4;

/// Bits that the signed digits of a whole scalar cover: scalars lie below `r < 2^255`, so the
/// top digit absorbs the carry.
const SCALAR_BITS: u32 = 256;

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

    /// Returns `-self` in every lane whose bit is set in `lanes`, and `self` in the others.
    fn negate_lanes(self, simd: S, lanes: u64) -> Self;

    /// Returns the image of every lane under the group's endomorphism, which multiplies elements
    /// by the eigenvalue that [`Group::components`] splits scalars by.
    fn endomorphism(self, simd: S) -> Self;

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
            fn negate_lanes(self, simd: S, lanes: u64) -> Self {
                self.negate_lanes(simd, lanes)
            }

            #[inline(always)]
            fn endomorphism(self, simd: S) -> Self {
                self.endomorphism(simd)
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

    /// Number of components [`Self::components`] splits a scalar into: the powers of the
    /// endomorphism's eigenvalue that span the scalars.
    const COMPONENTS: usize;

    /// Bits that the signed digits of a component cover: one more than the components' width,
    /// so that the top digit absorbs the carry.
    const COMPONENT_BITS: u32;

    /// Splits a scalar `k` into components below `2^(COMPONENT_BITS - 1)` such that, for the
    /// eigenvalue `e` of [`Points::endomorphism`], `k` is the sum over components `c` of
    /// `components[c] (-e)^c`: the eigenvalue is the negation of the base in both groups, so
    /// the odd components count negatively. Components beyond [`Self::COMPONENTS`] are zero.
    /// Runs in time independent of the scalar.
    fn components(scalar: &Scalar) -> [u128; MAX_COMPONENTS];

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

/// Writes the signed digits of a little-endian integer in base `2^width`, least significant
/// first, one per entry of `digits`, each in `(-2^(width - 1), 2^(width - 1)]`, or their
/// negations for `negate`.
///
/// Requires `2 <= width <= 15` and `value < 2^(width * digits.len() - 1)`, so that the last
/// digit absorbs the carry. Runs in time independent of the value.
fn signed_digits(value: &[u64], width: u32, negate: bool, digits: &mut [i16]) {
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

/// Returns the little-endian words of a component.
const fn words(component: u128) -> [u64; 2] {
    [component as u64, (component >> 64) as u64]
}

/// Returns the number of windows of `width` bits in a component of `G`.
const fn windows<G: Group>(width: u32) -> usize {
    G::COMPONENT_BITS.div_ceil(width) as usize
}

/// Returns the signed digits of a scalar in base `2^WINDOW_BITS`, by component then by window,
/// with the odd components negated as [`Group::components`] counts them, so that `k P` is the
/// sum over components `c` and windows `w` of `digits[c][w] 2^(WINDOW_BITS w) psi^c(P)` for
/// the endomorphism `psi`. Each digit's magnitude is at most [`TABLE`].
fn digits<G: Group>(scalar: &Scalar) -> Digits {
    let components = G::components(scalar);
    let mut digits = [[0; MAX_WINDOWS]; MAX_COMPONENTS];
    let windows = windows::<G>(WINDOW_BITS as u32);
    for (c, (digits, component)) in digits.iter_mut().zip(components).enumerate() {
        if c < G::COMPONENTS {
            signed_digits(
                &words(component),
                WINDOW_BITS as u32,
                c % 2 == 1,
                &mut digits[..windows],
            );
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
fn gather<S: Simd, P: Points<S>>(simd: S, identity: P, table: &[P], digits: [i16; MAX_LANES]) -> P {
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
/// base, and every window selects one entry per component through [`gather`] and combines them
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
    for window in (0..windows).rev() {
        let mut term = gather(simd, identity, &table, digits(components - 1, window));
        for c in (0..components - 1).rev() {
            let entry = gather(simd, identity, &table, digits(c, window));
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
    let mut digits = [[[0; MAX_WINDOWS]; MAX_COMPONENTS]; MAX_LANES];
    for (lane, scalar) in scalars.iter().enumerate().take(elements.len()) {
        digits[lane] = self::digits::<G>(scalar);
    }
    let base = lanes::<S, F, G>(simd, elements);
    let windows = windows::<G>(WINDOW_BITS as u32);
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

/// Multiplies an element by a scalar, without branching on the scalar.
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
        let identity = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
        let base = splat::<S, F, G>(simd, &self.element);
        let digits = digits::<G>(&self.scalar);
        let windows = windows::<G>(WINDOW_BITS as u32);
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
    /// sharing one chain of doublings. With `split`, the scalars split into their components
    /// and the tables hold the images of every multiple, which halves the doublings at the cost
    /// of the images: worthwhile for a few elements.
    Straus { width: u32, split: bool },
    /// Pippenger's method: each lane sums one window of every component of every element into
    /// its own buckets.
    Pippenger(u32),
}

impl Plan {
    /// Returns the plan of least estimated cost for `count` elements of `G` on `lanes` lanes.
    pub fn choose<G: Group>(count: usize, lanes: usize) -> Self {
        let plans = STRAUS_WIDTHS
            .flat_map(|width| {
                [false, true].map(|split| Self::Straus { width, split })
            })
            .chain(PIPPENGER_WIDTHS.map(Self::Pippenger));
        let mut best = Self::Straus {
            width: *STRAUS_WIDTHS.start(),
            split: false,
        };
        let mut least = usize::MAX;
        for plan in plans {
            let cost = plan.cost::<G>(count, lanes);
            if cost < least {
                (best, least) = (plan, cost);
            }
        }
        best
    }

    /// Returns the estimated cost of the plan, counting the additions, doublings, negations, and
    /// endomorphisms of points on all lanes at once.
    const fn cost<G: Group>(self, count: usize, lanes: usize) -> usize {
        match self {
            Self::Straus { width, split } => {
                // Each group of lanes builds a table of its multiples, the images of every
                // entry, and their negations, then adds one entry per component and window.
                let (components, windows) = if split {
                    (G::COMPONENTS, windows::<G>(width))
                } else {
                    (1, SCALAR_BITS.div_ceil(width) as usize)
                };
                let groups = count.div_ceil(lanes);
                let entries = 1 << (width - 1);
                ADD_COST * groups * (entries - 1 + components * windows)
                    + IMAGE_COST * groups * (2 * components - 1) * entries
                    + DOUBLE_COST * width as usize * windows
            }
            Self::Pippenger(width) => {
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
                signed_digits(&words(components[c]), width, c % 2 == 1, digits);
            }
        } else {
            signed_digits(&scalar.to_words(), width, false, digits);
        }
    }
    digits
}

/// Returns the raw form of every image of every element under the powers of the endomorphism,
/// each followed by that of its negation, by element then by component.
#[cfg_attr(not(debug_assertions), inline(always))]
fn prepare<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    identity: Raw<S, F, G>,
) -> Vec<[Raw<S, F, G>; 2]> {
    const { assert!(F::LANES <= MAX_LANES) };
    let mut prepared = vec![[identity; 2]; elements.len() * G::COMPONENTS];
    let mut stored = [identity; MAX_LANES];
    let span = F::LANES * G::COMPONENTS;
    for (elements, prepared) in elements.chunks(F::LANES).zip(prepared.chunks_mut(span)) {
        let mut points = lanes::<S, F, G>(simd, elements);
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
    prepared
}

/// Returns the sum of the elements times their scalars by Straus's method.
///
/// Each lane holds one element of every group of [`Field::LANES`]. A group's table holds, for
/// each component, the multiples of its elements' images by `1` through `2^(width - 1)` and
/// their negations, so that each signed digit selects one entry per lane, and every window shares
/// the doublings of one accumulator. Lanes whose digits are all zero in a window skip that
/// window's addition.
#[cfg_attr(not(debug_assertions), inline(always))]
fn straus<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    scalars: &[Scalar],
    width: u32,
    split: bool,
) -> G {
    let identity = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
    let zero = first_raw::<S, F, G>(simd, identity);
    let (components, windows) = if split {
        (G::COMPONENTS, windows::<G>(width))
    } else {
        (1, SCALAR_BITS.div_ceil(width) as usize)
    };
    let digits = component_digits::<G>(scalars, width, windows, split);
    let entries = 1 << (width - 1);

    // Entry 2 c entries + k of a group's table holds k + 1 times the c-th images of its
    // elements, one lane each, and entry (2 c + 1) entries + k their negations.
    let span = 2 * entries * F::LANES * components;
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
                total = twice(simd, total);
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
                        let entry = 2 * c * entries + magnitude - 1 + if digit < 0 { entries } else { 0 };
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
    }
    sum_lanes::<S, F, G>(simd, total)
}

/// Returns the sum of the elements times their scalars by Pippenger's method.
///
/// Lane `l` of group `g` takes window `g * F::LANES + l` of every component of every scalar,
/// and sums each element's image into its own bucket for the digit's magnitude, negated for a
/// negative digit, so the lanes never touch the same bucket. Buckets stay in raw form, and each
/// addition gathers one bucket per lane. Running sums over the buckets weight each by its
/// magnitude, and the groups combine by doubling, from the most significant down. Finally lane
/// `l` is shifted by `width * l` bits and the lanes are summed.
#[cfg_attr(not(debug_assertions), inline(always))]
fn pippenger<S: Simd, F: Field<S>, G: Group>(
    simd: S,
    elements: &[G],
    scalars: &[Scalar],
    width: u32,
) -> G {
    let identity = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
    let zero = first_raw::<S, F, G>(simd, identity);
    let groups = windows::<G>(width).div_ceil(F::LANES);
    let span = groups * F::LANES;
    let digits = component_digits::<G>(scalars, width, span, true);
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
        match self.plan.unwrap_or_else(|| Plan::choose::<G>(count, F::LANES)) {
            Plan::Straus { width, split } => {
                straus::<S, F, G>(simd, elements, scalars, width, split)
            }
            Plan::Pippenger(width) => pippenger::<S, F, G>(simd, elements, scalars, width),
        }
    }
}

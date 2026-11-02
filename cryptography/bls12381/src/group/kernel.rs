//! Kernels for the group operations, each written once over every base field representation.
//!
//! Each public operation runs as one kernel through [`dispatch`], which selects the backend at the
//! boundary. The backend's profile then selects the base field representation: on x86v4c,
//! residues for a single item, whose latency they shorten, and 64-bit lanes for independent
//! items; 32-bit lanes elsewhere. Elements cross the boundary as canonical coordinates, so every
//! kernel loads its inputs and stores its outputs, and loaded coordinates satisfy the bounds of
//! the curve formulas.

use super::Scalar;
use crate::core::{
    curve::{g1, g2},
    field::{
        arithmetic::Field,
        fp::{rns::Rns, unsat28::Unsat28, unsat49::Unsat49},
    },
};
use commonware_simd::{Operation, Simd, X86V4C};

/// Largest lane count of any representation.
pub const MAX_LANES: usize = 16;

/// Width in bits of the scalar windows of [`multiply`].
const WINDOW_BITS: usize = 4;

/// Number of windows in a scalar.
const SCALAR_WINDOWS: usize = 256 / WINDOW_BITS;

/// An operation written once over every base field representation.
pub trait Kernel: Sized {
    /// The result of the operation.
    type Output;

    /// Returns whether the operation holds independent items in every lane, which favors wide
    /// representations over the latency of a single item.
    fn batch(&self) -> bool {
        false
    }

    /// Runs the operation in the representation `F`.
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> Self::Output;
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
        if self.0.batch() {
            self.0.run::<S, Unsat49<S>>(simd)
        } else {
            self.0.run::<S, Rns<S>>(simd)
        }
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
}

macro_rules! points {
    ($module:ident) => {
        impl<S: Simd, F: Field<S>> Points<S> for $module::Point<F> {
            type Coordinates = $module::Coordinates;

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
        }
    };
}

points!(g1);
points!(g2);

/// A group whose elements cross kernel boundaries as canonical projective coordinates.
pub trait Group: Copy + Send + Sync {
    /// Canonical projective coordinates of one element.
    type Coordinates: Copy + Send + Sync + PartialEq + ::core::fmt::Debug;

    /// Elements of the group, one per lane of the representation `F`.
    type Points<S: Simd, F: Field<S>>: Points<S, Coordinates = Self::Coordinates>;

    /// The identity.
    const IDENTITY: Self::Coordinates;

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

/// Returns the sum of the elements times their scalars, one element per lane.
#[derive(Clone, Copy)]
pub struct Msm<'a, G> {
    /// The elements.
    pub elements: &'a [G],
    /// The scalars, one per element.
    pub scalars: &'a [Scalar],
}

impl<G: Group> Kernel for Msm<'_, G> {
    type Output = G;

    fn batch(&self) -> bool {
        true
    }

    // Debug builds keep this a call so that each representation's frame stays separate.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn run<S: Simd, F: Field<S>>(self, simd: S) -> G {
        const { assert!(F::LANES <= MAX_LANES) };
        let identity = G::Points::<S, F>::load(simd, &[], &G::IDENTITY);
        let mut total = identity;
        for (elements, scalars) in self
            .elements
            .chunks(F::LANES)
            .zip(self.scalars.chunks(F::LANES))
        {
            let mut coordinates = [G::IDENTITY; MAX_LANES];
            let mut words = [[0; 4]; MAX_LANES];
            for (lane, (element, scalar)) in elements.iter().zip(scalars).enumerate() {
                coordinates[lane] = *element.coordinates();
                words[lane] = scalar.to_words();
            }
            let lanes = elements.len().min(scalars.len());
            let base = G::Points::<S, F>::load(simd, &coordinates[..lanes], &G::IDENTITY);
            let product = multiply(simd, base, identity, SCALAR_WINDOWS, |window| {
                words.map(|words| digit(&words, window))
            });
            total = total.add(simd, product);
        }
        sum_lanes::<S, F, G>(simd, total)
    }
}

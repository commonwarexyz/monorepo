//! Operations shared by G1 and G2, written once over a [`Group`] and dispatched per backend.
//!
//! Each operation is a [`Workload`]: a computation described over any [`Arithmetic`] context
//! whose scalar coordinates are the group's. [`Run`] selects the context for the backend that
//! `commonware-simd` dispatches to. The portable path keeps one point per lane; with the 52-bit
//! multipliers of x86v4c, operations on one point use the residue number system, and
//! operations on many independent points keep one point per lane.

use crate::{
    curve::{Affine, Curve, Projective},
    fp::{Arithmetic, lanes::MAX_LANES},
    scalar::{Digits, Scalar},
};
use alloc::{vec, vec::Vec};
use commonware_math::algebra::{Additive, Field, Ring};
use commonware_simd::{Operation, Simd, X86V4C};
use core::marker::PhantomData;
use subtle::ConstantTimeEq;

/// A prime-order group with its coordinate field and the contexts each backend uses.
pub(crate) trait Group: Copy + Eq + core::fmt::Debug {
    /// The scalar form of a coordinate.
    type Coordinate: Field + Copy + ConstantTimeEq;

    /// The context with one point per lane.
    type Lanes<S: Simd>: Arithmetic<Scalar = Self::Coordinate>;

    /// The context for one point in the residue number system.
    type Rns<S: X86V4C>: Arithmetic<Scalar = Self::Coordinate>;

    /// `3b` for the curve `y^2 = x^3 + b`.
    const B3: Self::Coordinate;

    /// The identity element.
    const IDENTITY: Self;

    /// Returns the lane context for a backend.
    fn lanes<S: Simd>(simd: S) -> Self::Lanes<S>;

    /// Returns the residue context for a backend.
    fn rns<S: X86V4C>(simd: S) -> Self::Rns<S>;

    /// Number of components a scalar decomposes into for the group's endomorphism.
    const DIMENSION: usize;

    /// Bits per decomposed scalar component.
    const COMPONENT_BITS: usize;

    /// Decomposes a scalar into [`Self::DIMENSION`] components matching [`Self::images`], so
    /// that `[k]P = sum_i components[i] * images[i]`. Unused entries are zero.
    fn decompose(scalar: &Scalar) -> [Digits<2>; 4];

    /// Returns `p` followed by its endomorphism images, one per decomposed component. Unused
    /// entries are the identity.
    fn images<F: Arithmetic<Scalar = Self::Coordinate>>(
        curve: &Curve<F>,
        p: Projective<F::Element>,
    ) -> [Projective<F::Element>; 4];

    /// Returns the projective coordinates.
    fn projective(&self) -> &Projective<Self::Coordinate>;

    /// Wraps projective coordinates.
    fn from_projective(point: Projective<Self::Coordinate>) -> Self;

    /// Returns whether this is the identity.
    fn is_identity(&self) -> subtle::Choice {
        self.projective().z.ct_eq(&Self::Coordinate::zero())
    }

    /// Returns the affine coordinates, or `None` for the identity.
    fn to_affine(&self) -> Option<(Self::Coordinate, Self::Coordinate)> {
        if bool::from(self.is_identity()) {
            return None;
        }
        let point = self.projective();
        let z = point.z.inv();
        Some((point.x * &z, point.y * &z))
    }

    /// Converts points to affine coordinates with one shared inversion.
    ///
    /// Identities map to `None`.
    fn to_affine_many(points: &[Self]) -> Vec<Option<(Self::Coordinate, Self::Coordinate)>> {
        // Montgomery's trick: prefix products of the nonzero Z coordinates, one inversion, then
        // peel each inverse off from the top.
        let mut prefix = Vec::with_capacity(points.len());
        let mut product = Self::Coordinate::one();
        for point in points {
            prefix.push(product);
            if !bool::from(point.is_identity()) {
                product *= &point.projective().z;
            }
        }
        let mut inverse = product.inv();
        let mut affine = vec![None; points.len()];
        for (i, point) in points.iter().enumerate().rev() {
            if bool::from(point.is_identity()) {
                continue;
            }
            let point = point.projective();
            let z = inverse * &prefix[i];
            inverse *= &point.z;
            affine[i] = Some((point.x * &z, point.y * &z));
        }
        affine
    }
}

/// One group operation, described once over any arithmetic context.
pub(crate) trait Workload<G: Group>: Sized {
    type Output;

    /// Whether the workload keeps several independent points in flight, so that one point
    /// per lane fills the vectors. Single inputs are better served one point at a time.
    fn parallel(&self) -> bool {
        false
    }

    fn run<F: Arithmetic<Scalar = G::Coordinate>>(self, curve: &Curve<F>) -> Self::Output;
}

/// Runs a workload on the context selected for the backend profile.
pub(crate) struct Run<G, W>(pub W, pub PhantomData<G>);

impl<G, W> Run<G, W> {
    pub const fn new(workload: W) -> Self {
        Self(workload, PhantomData)
    }
}

impl<S: Simd, G: Group, W: Workload<G>> Operation<S> for Run<G, W> {
    type Output = W::Output;

    #[inline(always)]
    fn portable(self, simd: S) -> W::Output {
        simd.execute(OnLanes::<G, W>::new(self.0))
    }

    #[inline(always)]
    fn x86_v4c(self, simd: S) -> W::Output
    where
        S: X86V4C,
    {
        if self.0.parallel() {
            simd.execute(OnLanes::<G, W>::new(self.0))
        } else {
            simd.execute(OnRns::<G, W>::new(self.0))
        }
    }
}

/// Runs a workload with one point per lane.
pub(crate) struct OnLanes<G, W>(pub W, pub PhantomData<G>);

impl<G, W> OnLanes<G, W> {
    pub const fn new(workload: W) -> Self {
        Self(workload, PhantomData)
    }
}

impl<S: Simd, G: Group, W: Workload<G>> Operation<S> for OnLanes<G, W> {
    type Output = W::Output;

    #[inline(always)]
    fn portable(self, simd: S) -> W::Output {
        self.0.run(&Curve::new(G::lanes(simd), G::B3))
    }
}

/// Runs a workload one point at a time in the residue number system.
pub(crate) struct OnRns<G, W>(pub W, pub PhantomData<G>);

impl<G, W> OnRns<G, W> {
    pub const fn new(workload: W) -> Self {
        Self(workload, PhantomData)
    }
}

impl<S: X86V4C, G: Group, W: Workload<G>> Operation<S> for OnRns<G, W> {
    type Output = W::Output;

    #[inline(always)]
    fn portable(self, simd: S) -> W::Output {
        self.0.run(&Curve::new(G::rns(simd), G::B3))
    }
}

/// Reads the single point back from lane zero.
#[inline(always)]
pub(crate) fn first<G: Group, F: Arithmetic<Scalar = G::Coordinate>>(
    curve: &Curve<F>,
    point: Projective<F::Element>,
) -> G {
    let mut output = [*G::IDENTITY.projective()];
    curve.store(point, &mut output);
    G::from_projective(output[0])
}

/// Adds two points.
#[derive(Clone, Copy)]
pub(crate) struct Add<G>(pub G, pub G);

impl<G: Group> Workload<G> for Add<G> {
    type Output = G;

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = G::Coordinate>>(self, curve: &Curve<F>) -> G {
        let (p, q) = (self.0.projective(), self.1.projective());
        first(curve, curve.add(curve.load([p]), curve.load([q])))
    }
}

/// Doubles a point.
#[derive(Clone, Copy)]
pub(crate) struct Double<G>(pub G);

impl<G: Group> Workload<G> for Double<G> {
    type Output = G;

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = G::Coordinate>>(self, curve: &Curve<F>) -> G {
        first(curve, curve.double(curve.load([self.0.projective()])))
    }
}

/// Negates a point.
#[derive(Clone, Copy)]
pub(crate) struct Neg<G>(pub G);

impl<G: Group> Workload<G> for Neg<G> {
    type Output = G;

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = G::Coordinate>>(self, curve: &Curve<F>) -> G {
        first(curve, curve.neg(curve.load([self.0.projective()])))
    }
}

/// Multiplies a point by a scalar.
#[derive(Clone, Copy)]
pub(crate) struct Mul<G>(pub G, pub Scalar);

impl<G: Group> Workload<G> for Mul<G> {
    type Output = G;

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = G::Coordinate>>(self, curve: &Curve<F>) -> G {
        let bases = G::images(curve, curve.load([self.0.projective()]));
        let scalars = G::decompose(&self.1);
        let product = match G::DIMENSION {
            2 => curve.mul([bases[0], bases[1]], &[scalars[0], scalars[1]], G::COMPONENT_BITS),
            4 => curve.mul(bases, &scalars, G::COMPONENT_BITS),
            _ => unreachable!("groups decompose scalars into two or four components"),
        };
        first(curve, product)
    }
}

/// Sums a sequence of points.
#[derive(Clone, Copy)]
pub(crate) struct Sum<'a, G>(pub &'a [G]);

impl<G: Group> Workload<G> for Sum<'_, G> {
    type Output = G;

    fn parallel(&self) -> bool {
        self.0.len() > 1
    }

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = G::Coordinate>>(self, curve: &Curve<F>) -> G {
        // Accumulate one partial sum per lane, then fold the lanes together by halving: the
        // upper half of the stored partials is gathered on top of the lower half.
        let mut partial = curve.identity();
        for chunk in self.0.chunks(F::LANES) {
            partial = curve.add(partial, curve.load(chunk.iter().map(G::projective)));
        }
        let mut partials = [curve.stored_identity(); MAX_LANES];
        curve.scatter(partial, partials.iter_mut());
        let mut width = F::LANES;
        while width > 1 {
            width /= 2;
            let lower = curve.gather(&partials[..width]);
            let upper = curve.gather(&partials[width..2 * width]);
            curve.scatter(curve.add(lower, upper), partials[..width].iter_mut());
        }
        first(curve, curve.gather(&partials[..1]))
    }
}

/// Multi-scalar multiplication by Pippenger's bucket method, with one scalar window per lane.
///
/// Scalars are decomposed through the group's endomorphism, so each point contributes its
/// images with short components. Every window of every component accumulates into its own
/// bucket table, so adding one point to `F::LANES` windows at once is a gather, one mixed
/// addition, and a scatter, with no data-dependent control flow. Bucket reduction likewise
/// runs one window per lane.
#[derive(Clone, Copy)]
pub(crate) struct Msm<'a, G> {
    pub points: &'a [G],
    pub scalars: &'a [Scalar],
}

impl<G> Msm<'_, G> {
    /// Returns the window width balancing accumulation against bucket reduction.
    fn width(count: usize) -> usize {
        (usize::BITS - count.max(1).leading_zeros()) as usize - 1
    }
}

impl<G: Group> Workload<G> for Msm<'_, G> {
    type Output = G;

    fn parallel(&self) -> bool {
        self.points.len() * G::DIMENSION > 1
    }

    #[inline(always)]
    fn run<F: Arithmetic<Scalar = G::Coordinate>>(self, curve: &Curve<F>) -> G {
        let f = curve.field;
        let width = Self::width(self.points.len() * G::DIMENSION).clamp(2, 10);
        let windows = G::COMPONENT_BITS.div_ceil(width);
        let table = 1 << width;
        let identity = curve.stored_identity();

        // Bucket 0 of each window is scratch space that absorbs zero digits.
        let mut buckets = vec![identity; windows * table];
        let mut gathered = [identity; MAX_LANES];
        for (point, scalar) in G::to_affine_many(self.points).into_iter().zip(self.scalars) {
            let Some((x, y)) = point else {
                continue;
            };
            // The images of an affine point are affine, so their Z coordinates stay one.
            let lifted = Projective {
                x: f.constant(x),
                y: f.constant(y),
                z: f.constant(G::Coordinate::one()),
            };
            let bases = G::images(curve, lifted);
            let components = G::decompose(scalar);
            for (base, component) in bases.iter().zip(&components).take(G::DIMENSION) {
                let q = Affine {
                    x: base.x,
                    y: base.y,
                };
                for first in (0..windows).step_by(F::LANES) {
                    let lanes = first..windows.min(first + F::LANES);
                    let index = |window: usize| {
                        window * table + component.bits(window * width, width) as usize
                    };
                    let acc = curve.gather(lanes.clone().map(|window| &buckets[index(window)]));
                    curve.scatter(curve.add_affine(acc, q), gathered.iter_mut());
                    for (lane, window) in lanes.enumerate() {
                        buckets[index(window)] = gathered[lane];
                    }
                }
            }
        }

        // Reduce each window's buckets: sum_d d * B_d as a running sum from the top.
        let mut sums = vec![identity; windows];
        for first in (0..windows).step_by(F::LANES) {
            let lanes = first..windows.min(first + F::LANES);
            let mut running = curve.identity();
            let mut total = curve.identity();
            for digit in (1..table).rev() {
                let bucket =
                    curve.gather(lanes.clone().map(|window| &buckets[window * table + digit]));
                running = curve.add(running, bucket);
                total = curve.add(total, running);
            }
            curve.scatter(total, sums[lanes].iter_mut());
        }

        // Combine the windows from the top with Horner's rule.
        let mut result = curve.identity();
        for sum in sums.iter().rev() {
            for _ in 0..width {
                result = curve.double(result);
            }
            result = curve.add(result, curve.gather([sum]));
        }
        first(curve, result)
    }
}

/// Implements the public group API and the `commonware-math` group traits for a [`Group`].
macro_rules! group_api {
    ($group:ty, $coordinate:ty) => {
        impl $group {
            /// Returns `self + other`.
            pub fn add(&self, other: &Self) -> Self {
                commonware_simd::dispatch($crate::group::Run::new($crate::group::Add(
                    *self, *other,
                )))
            }

            /// Returns `2 * self`.
            pub fn double(&self) -> Self {
                commonware_simd::dispatch($crate::group::Run::new($crate::group::Double(*self)))
            }

            /// Returns `-self`.
            pub fn neg(&self) -> Self {
                commonware_simd::dispatch($crate::group::Run::new($crate::group::Neg(*self)))
            }

            /// Returns `scalar * self`, in constant time with respect to the scalar.
            pub fn mul(&self, scalar: &$crate::scalar::Scalar) -> Self {
                commonware_simd::dispatch($crate::group::Run::new($crate::group::Mul(
                    *self, *scalar,
                )))
            }

            /// Returns whether this is the identity.
            pub fn is_identity(&self) -> subtle::Choice {
                $crate::group::Group::is_identity(self)
            }

            /// Returns the affine coordinates, or `None` for the identity.
            pub fn to_affine(&self) -> Option<($coordinate, $coordinate)> {
                $crate::group::Group::to_affine(self)
            }

            /// Converts points to affine coordinates with one shared inversion.
            ///
            /// Identities map to `None`.
            pub fn to_affine_many(points: &[Self]) -> alloc::vec::Vec<Option<($coordinate, $coordinate)>> {
                $crate::group::Group::to_affine_many(points)
            }

            /// Returns the sum of `points`.
            pub fn sum(points: &[Self]) -> Self {
                commonware_simd::dispatch($crate::group::Run::new($crate::group::Sum(points)))
            }

            /// Returns `sum(scalars[i] * points[i])`.
            ///
            /// Variable-time; the scalars must be public.
            ///
            /// # Panics
            ///
            /// Panics if the slices have different lengths.
            pub fn msm(points: &[Self], scalars: &[$crate::scalar::Scalar]) -> Self {
                assert_eq!(points.len(), scalars.len());
                commonware_simd::dispatch($crate::group::Run::new($crate::group::Msm {
                    points,
                    scalars,
                }))
            }
        }

        impl<'a> core::ops::AddAssign<&'a Self> for $group {
            fn add_assign(&mut self, rhs: &'a Self) {
                *self = Self::add(self, rhs);
            }
        }

        impl<'a> core::ops::Add<&'a Self> for $group {
            type Output = Self;

            fn add(self, rhs: &'a Self) -> Self {
                Self::add(&self, rhs)
            }
        }

        impl<'a> core::ops::SubAssign<&'a Self> for $group {
            fn sub_assign(&mut self, rhs: &'a Self) {
                *self = Self::add(self, &Self::neg(rhs));
            }
        }

        impl<'a> core::ops::Sub<&'a Self> for $group {
            type Output = Self;

            fn sub(self, rhs: &'a Self) -> Self {
                Self::add(&self, &Self::neg(rhs))
            }
        }

        impl core::ops::Neg for $group {
            type Output = Self;

            fn neg(self) -> Self {
                Self::neg(&self)
            }
        }

        impl<'a> core::ops::MulAssign<&'a $crate::scalar::Scalar> for $group {
            fn mul_assign(&mut self, rhs: &'a $crate::scalar::Scalar) {
                *self = Self::mul(self, rhs);
            }
        }

        impl<'a> core::ops::Mul<&'a $crate::scalar::Scalar> for $group {
            type Output = Self;

            fn mul(self, rhs: &'a $crate::scalar::Scalar) -> Self {
                Self::mul(&self, rhs)
            }
        }

        impl commonware_math::algebra::Object for $group {}

        impl commonware_math::algebra::Additive for $group {
            fn zero() -> Self {
                Self::IDENTITY
            }

            fn double(&mut self) {
                *self = Self::double(self);
            }
        }

        impl commonware_math::algebra::Space<$crate::scalar::Scalar> for $group {
            fn msm(
                points: &[Self],
                scalars: &[$crate::scalar::Scalar],
                _: &impl commonware_parallel::Strategy,
            ) -> Self {
                let count = points.len().min(scalars.len());
                Self::msm(&points[..count], &scalars[..count])
            }
        }

        impl commonware_math::algebra::CryptoGroup for $group {
            type Scalar = $crate::scalar::Scalar;

            fn generator() -> Self {
                Self::GENERATOR
            }
        }
    };
}

pub(crate) use group_api;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use commonware_simd::{check_consistent, emulated::EmulatedX86V4C, test_dispatch};

    /// The scalar reference context of a group, for tests.
    pub(crate) trait Reference: Group {
        type Single: Arithmetic<Scalar = Self::Coordinate>;

        fn single() -> Self::Single;
    }

    /// Runs a workload on every context, checking that they all agree with the scalar
    /// reference, and returns the result.
    pub(crate) fn every_context<G: Reference, W: Workload<G> + Copy>(workload: W) -> W::Output
    where
        W::Output: PartialEq + core::fmt::Debug,
    {
        let expected = workload.run(&Curve::new(G::single(), G::B3));
        assert_eq!(test_dispatch(Run::<G, W>::new(workload)), expected);
        assert_eq!(test_dispatch(OnLanes::<G, W>::new(workload)), expected);
        check_consistent(|| OnLanes::<G, W>::new(workload));
        assert_eq!(EmulatedX86V4C.execute(OnRns::<G, W>::new(workload)), expected);
        check_consistent(|| Run::<G, W>::new(workload));
        expected
    }
}

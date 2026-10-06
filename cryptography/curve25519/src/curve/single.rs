//! Point arithmetic for one chain of dependent additions and doublings.
//!
//! Single-signature verification and fixed-base multiplication each follow one chain of point
//! operations, where every operation needs the previous result. [`Single`] describes the
//! operations of such a chain in a backend's native point types, so each algorithm is written
//! once over it, and a backend may run the scalar formulas or pack one point across vector
//! lanes. [`Backend::with_single`](super::Backend::with_single) selects the implementation once,
//! outside the algorithm's loops.

use super::{G, GAffine, GCompleted, GProjective, Niels, ProjectiveNiels, basepoint};

/// Operations on one point at a time, in a backend's native representations.
///
/// Every operation must produce the same projective coordinates, modulo `p`, as the scalar
/// formulas of [`Formulas`] for every input point, including the identity, equal points, a
/// point plus its negation, and points with a torsion component. Every input point, operand, and
/// table entry may have any limbs below `2^52`.
///
/// The point types follow a point through a chain: an addition or doubling returns a
/// [`Single::Completed`] point, which converts to [`Single::Projective`] coordinates for a
/// doubling or to [`Single::Extended`] coordinates for an addition. A backend may skip work for
/// coordinates the next operation does not read.
pub trait Single: Copy {
    /// A point in extended coordinates, the input of an addition.
    type Extended: Copy;

    /// A point in projective coordinates, the input of a doubling.
    type Projective: Copy;

    /// A point as an addition or doubling leaves it, before its final multiplications.
    type Completed: Copy;

    /// A point prepared as the right operand of repeated additions.
    type Cached: Copy;

    /// Converts a point to the native extended representation.
    fn load(self, point: &G) -> Self::Extended;

    /// Converts a native extended point back to a [`G`] with limbs below `2^52`.
    fn store(self, point: Self::Extended) -> G;

    /// Converts a native projective point back to a [`GProjective`] with limbs below `2^52`.
    fn store_projective(self, point: Self::Projective) -> GProjective;

    /// Returns the identity in extended coordinates.
    fn identity(self) -> Self::Extended;

    /// Drops the `T` coordinate, which doubling does not read.
    fn project(self, point: Self::Extended) -> Self::Projective;

    /// Doubles a point with the steps of [`GProjective::double`].
    fn double(self, point: Self::Projective) -> Self::Completed;

    /// Finishes a completed point in projective coordinates.
    fn to_projective(self, point: Self::Completed) -> Self::Projective;

    /// Finishes a completed point in extended coordinates.
    fn to_extended(self, point: Self::Completed) -> Self::Extended;

    /// Prepares a point as an addition operand, as [`G::to_projective_niels`] does.
    fn cache(self, point: Self::Extended) -> Self::Cached;

    /// Adds `cached`, or its negation when `negate` is set, with the steps of
    /// [`G::add_projective_niels`].
    ///
    /// Variable-time in `negate`, which must be public.
    fn add(self, point: Self::Extended, cached: Self::Cached, negate: bool) -> Self::Completed;

    /// Adds an affine point, or its negation when `negate` is set, with the steps of
    /// [`G::add_niels_completed`].
    ///
    /// Variable-time in `negate`, which must be public.
    fn add_niels(self, point: Self::Extended, niels: &Niels, negate: bool) -> Self::Completed;

    /// Adds `digit * P` for `row[k] = (k + 1) * P` and `digit` in `[-8, 8]`.
    ///
    /// Constant time: every entry of `row` is read, and the selection and negation use masks,
    /// so no branch, memory index, or early exit depends on `digit` or on the points.
    fn add_selected(self, point: Self::Extended, row: &[Niels; 8], digit: i8) -> Self::Completed;

    /// Decompresses a point encoding as [`GAffine::decompress`] does.
    #[inline(always)]
    fn decompress(self, encoding: &[u8; 32]) -> Option<GAffine> {
        GAffine::decompress(encoding)
    }

    /// Decompresses two point encodings as [`GAffine::decompress`] does, or returns `None` when
    /// either is invalid.
    ///
    /// The default decodes the second encoding only when the first is valid.
    #[inline(always)]
    fn decompress_pair(self, [first, second]: [&[u8; 32]; 2]) -> Option<[GAffine; 2]> {
        Some([GAffine::decompress(first)?, GAffine::decompress(second)?])
    }
}

/// A computation written once over [`Single`].
///
/// [`Backend::with_single`](super::Backend::with_single) runs it with the backend's native point
/// types, inside the backend's target features.
pub trait WithSingle {
    /// The result of the computation.
    type Output;

    /// Runs with the selected single-point operations.
    fn call<S: Single>(self, single: S) -> Self::Output;
}

/// The scalar formulas, on [`G`], [`GProjective`], [`GCompleted`], and [`ProjectiveNiels`].
///
/// This is the reference for every other [`Single`] implementation. It needs no CPU feature, so
/// it is freely constructible.
#[derive(Clone, Copy)]
pub struct Formulas;

impl Single for Formulas {
    type Extended = G;
    type Projective = GProjective;
    type Completed = GCompleted;
    type Cached = ProjectiveNiels;

    #[inline(always)]
    fn load(self, point: &G) -> G {
        *point
    }

    #[inline(always)]
    fn store(self, point: G) -> G {
        point
    }

    #[inline(always)]
    fn store_projective(self, point: GProjective) -> GProjective {
        point
    }

    #[inline(always)]
    fn identity(self) -> G {
        G::IDENTITY
    }

    #[inline(always)]
    fn project(self, point: G) -> GProjective {
        point.to_projective()
    }

    #[inline(always)]
    fn double(self, point: GProjective) -> GCompleted {
        point.double()
    }

    #[inline(always)]
    fn to_projective(self, point: GCompleted) -> GProjective {
        point.to_projective()
    }

    #[inline(always)]
    fn to_extended(self, point: GCompleted) -> G {
        point.to_extended()
    }

    #[inline(always)]
    fn cache(self, point: G) -> ProjectiveNiels {
        point.to_projective_niels()
    }

    #[inline(always)]
    fn add(self, point: G, cached: ProjectiveNiels, negate: bool) -> GCompleted {
        point.add_projective_niels(if negate { cached.negate() } else { cached })
    }

    #[inline(always)]
    fn add_niels(self, point: G, niels: &Niels, negate: bool) -> GCompleted {
        point.add_niels_completed(if negate { niels.negate() } else { *niels })
    }

    #[inline(always)]
    fn add_selected(self, point: G, row: &[Niels; 8], digit: i8) -> GCompleted {
        point.add_niels_completed(basepoint::select(row, digit))
    }
}

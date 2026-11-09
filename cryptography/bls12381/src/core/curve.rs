//! Elliptic curve arithmetic on several points at once, one per vector lane.

use commonware_simd::Simd;

pub mod g1;
pub mod g2;

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
    /// by the eigenvalue used to split scalars into components.
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

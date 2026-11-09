//! Arithmetic on points of G1, the curve `y^2 = x^3 + 4` over the base field.
//!
//! A [`Point`] holds as many projective points as its field values hold elements, one per lane,
//! and its formulas run once over every base field representation.
//!
//! # Coordinate bounds
//!
//! Every coordinate a formula accepts or returns has positional limb bound `1` and integer bound at
//! most [`BOUND`], as defined by the [base field arithmetic](crate::core::field::arithmetic): the
//! positional representations return at most `73` from the subtraction in [`Point::add`]'s `X`
//! coordinate, and residues reduce to at most `17`. Loaded coordinates and every formula's outputs
//! satisfy this, so points chain through any number of operations without carrying or
//! canonicalizing between them.
//!
//! Raw coordinates hold each lane of a point in the representation's own form, through
//! [`Field::store_raw`] with bound [`BOUND`], so storing and loading them costs no conversion and
//! loaded raw coordinates satisfy the coordinate bounds.
//!
//! Subtractions remove small multiples of reduced products of coordinates. Such a product is
//! bounded by `4p` in the positional representations and by `17p` in residues, so a multiple
//! `C` of it is covered by a bias of `17C` in every representation. Inside a
//! formula, the positional representations reach integer bounds of at most `912` and limb bounds
//! of at most `12`; residues reach integer bounds of at most `629`.

use crate::core::{
    curve::Points,
    field::{
        arithmetic::Field,
        fp::{BYTES, MINUS_ONE, ONE, encode},
    },
};
use commonware_formatting::hex;
use commonware_simd::Simd;

/// Projective coordinates `[X, Y, Z]` as big-endian integers.
pub type Coordinates = [[u8; BYTES]; 3];

/// Largest integer bound of a coordinate, in units of `p`.
pub const BOUND: u64 = 73;

/// The identity `(0 : 1 : 0)` as projective coordinates.
pub const IDENTITY: Coordinates = {
    let mut identity = [[0; BYTES]; 3];
    identity[1][BYTES - 1] = 1;
    identity
};

/// The generator in projective coordinates, with `Z = 1`.
pub const GENERATOR: Coordinates = [
    hex!(
        "17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    ),
    hex!(
        "08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
    ),
    {
        let mut one = [0; BYTES];
        one[BYTES - 1] = 1;
        one
    },
];

/// Largest integer bound of a reduced value in residues, in units of `p`.
///
/// Positional products of coordinates are bounded by `4p`, so multiples of this cover a
/// subtrahend in every representation.
const REDUCED: u64 = 17;

/// Positional bias of every subtraction of products, in units of `p`.
///
/// Covers each negative sum of products, which stays below `64p` in the positional
/// representations.
const PRODUCT_BIAS: u64 = 64;

/// Largest number of points in a value, the widest representation's lane count.
const MAX_LANES: usize = 16;

/// A cube root of unity `beta` such that `(x, y) -> (beta x, y)` multiplies every point of the
/// prime-order subgroup by `-x^2`, for the curve parameter `x`: a cube root of unity modulo the
/// subgroup order `r = x^4 - x^2 + 1`.
const BETA: [u8; BYTES] = encode([
    0x2e01_ffff_fffe_fffe,
    0xde17_d813_620a_0002,
    0xddb3_a93b_e6f8_9688,
    0xba69_c607_6a0f_77ea,
    0x5f19_672f_df76_ce51,
    0,
]);

/// Projective points, one per lane of the field values.
///
/// See the [module documentation](self) for the bounds every coordinate satisfies.
#[derive(Clone, Copy)]
pub struct Point<F> {
    /// The `X` coordinates.
    pub x: F,
    /// The `Y` coordinates.
    pub y: F,
    /// The `Z` coordinates.
    pub z: F,
}

impl<S: Simd, F: Field<S>> Points<S> for Point<F> {
    type Coordinates = Coordinates;
    type Raw = [F::Raw; 3];

    /// Loads up to one projective point per lane, filling the remaining lanes with `fill`.
    #[inline(always)]
    fn load(simd: S, points: &[Coordinates], fill: &Coordinates) -> Self {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[[0; BYTES]; MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        for (i, coordinate) in coordinates.iter_mut().enumerate() {
            for (lane, point) in coordinate.iter_mut().zip(&points[..lanes]) {
                *lane = point[i];
            }
        }
        Self {
            x: F::load(simd, &coordinates[0][..lanes], &fill[0]),
            y: F::load(simd, &coordinates[1][..lanes], &fill[1]),
            z: F::load(simd, &coordinates[2][..lanes], &fill[2]),
        }
    }

    /// Stores each lane's canonical projective coordinates, dropping lanes beyond `points`.
    #[inline(always)]
    fn store(self, simd: S, points: &mut [Coordinates]) {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[[0; BYTES]; MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        self.x.store(simd, &mut coordinates[0][..lanes]);
        self.y.store(simd, &mut coordinates[1][..lanes]);
        self.z.store(simd, &mut coordinates[2][..lanes]);
        for (lane, point) in points[..lanes].iter_mut().enumerate() {
            *point = [
                coordinates[0][lane],
                coordinates[1][lane],
                coordinates[2][lane],
            ];
        }
    }

    /// Returns `rhs` in every lane whose bit is set in `lanes`, and `self` in the others.
    ///
    /// Bit `i` of `lanes` selects lane `i`, without branching on `lanes`.
    #[inline(always)]
    fn select(self, simd: S, rhs: Self, lanes: u64) -> Self {
        Self {
            x: self.x.select(simd, rhs.x, lanes),
            y: self.y.select(simd, rhs.y, lanes),
            z: self.z.select(simd, rhs.z, lanes),
        }
    }

    /// Stores each lane's raw coordinates, dropping lanes beyond `points`.
    #[inline(always)]
    fn store_raw(self, simd: S, points: &mut [[F::Raw; 3]]) {
        const { assert!(F::LANES <= MAX_LANES) };
        let mut coordinates = [[F::Raw::default(); MAX_LANES]; 3];
        let lanes = points.len().min(F::LANES);
        self.x
            .store_raw::<BOUND>(simd, &mut coordinates[0][..lanes]);
        self.y
            .store_raw::<BOUND>(simd, &mut coordinates[1][..lanes]);
        self.z
            .store_raw::<BOUND>(simd, &mut coordinates[2][..lanes]);
        for (lane, point) in points[..lanes].iter_mut().enumerate() {
            *point = [
                coordinates[0][lane],
                coordinates[1][lane],
                coordinates[2][lane],
            ];
        }
    }

    /// Loads lane `i` from the raw coordinates `points[i]`, for at least `F::LANES` entries.
    #[inline(always)]
    fn load_raw(simd: S, points: &[&[F::Raw; 3]]) -> Self {
        const { assert!(F::LANES <= MAX_LANES) };
        let coordinate = |i: usize| {
            let mut lanes = [&points[0][i]; MAX_LANES];
            for (lane, point) in lanes.iter_mut().zip(points).take(F::LANES) {
                *lane = &point[i];
            }
            F::load_raw::<BOUND>(simd, &lanes)
        };
        Self {
            x: coordinate(0),
            y: coordinate(1),
            z: coordinate(2),
        }
    }

    /// Returns `-self`.
    ///
    /// Multiplies `Y` by `-1` rather than subtracting it, so the coordinates keep their bounds.
    #[inline(always)]
    fn negate(self, simd: S) -> Self {
        let minus_one = F::load(simd, &[], &MINUS_ONE);
        Self {
            y: self.y.ready::<1>(simd).mul(simd, minus_one),
            ..self
        }
    }

    /// Returns `-self` in every lane whose bit is set in `lanes`, and `self` in the others.
    ///
    /// Multiplies `Y` by `1` or `-1`, selected without branching on `lanes`.
    #[inline(always)]
    fn negate_lanes(self, simd: S, lanes: u64) -> Self {
        let sign = F::load(simd, &[], &ONE).select(simd, F::load(simd, &[], &MINUS_ONE), lanes);
        Self {
            y: self.y.ready::<1>(simd).mul(simd, sign),
            ..self
        }
    }

    /// Returns the image of every lane under the endomorphism `(x, y) -> (beta x, y)`, which
    /// multiplies points of the prime-order subgroup by `-x^2` for the curve parameter `x`.
    #[inline(always)]
    fn endomorphism(self, simd: S) -> Self {
        let beta = F::load(simd, &[], &BETA);
        Self {
            x: self.x.ready::<1>(simd).mul(simd, beta),
            ..self
        }
    }

    /// Returns `self + rhs`.
    ///
    /// This is Algorithm 7 of Renes, Costello, and Batina, "Complete addition formulas for prime
    /// order elliptic curves" (2016), which accepts any pair of points, including the identity and
    /// equal points. Each output coordinate is a sum of two products with a single reduction, and
    /// each cross term reuses the two known products through [`Field::cross`]. Multiplications by
    /// `3b = 12` use [`Field::mul_small`], leaving twelve products.
    ///
    /// Debug builds keep this a call so that chained formulas fit in a stack frame.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn add(self, simd: S, rhs: Self) -> Self {
        let (x1, y1, z1) = (
            self.x.ready::<1>(simd),
            self.y.ready::<1>(simd),
            self.z.ready::<1>(simd),
        );
        let (x2, y2, z2) = (
            rhs.x.ready::<1>(simd),
            rhs.y.ready::<1>(simd),
            rhs.z.ready::<1>(simd),
        );
        let xx = x1.product(simd, x2);
        let yy = y1.product(simd, y2);
        let zz = z1.product(simd, z2);
        // x1 y2 + y1 x2, y1 z2 + z1 y2, and x1 z2 + z1 x2.
        let xy = F::reduce_signed::<PRODUCT_BIAS>(simd, F::cross(simd, [x1, y1], [x2, y2], xx, yy));
        let yz = F::reduce_signed::<PRODUCT_BIAS>(simd, F::cross(simd, [y1, z1], [y2, z2], yy, zz));
        let xz = F::reduce_signed::<PRODUCT_BIAS>(simd, F::cross(simd, [x1, z1], [x2, z2], xx, zz));
        let xx = F::reduce(simd, xx);
        let yy = F::reduce(simd, yy);
        let zz = F::reduce(simd, zz);
        let xx3 = xx.mul_small::<3>(simd).ready::<3>(simd);
        let b3zz = zz.mul_small::<12>(simd).carry(simd);
        let b3xz = xz.mul_small::<12>(simd).ready::<12>(simd);
        let sum = yy.add(simd, b3zz).ready::<2>(simd);
        let difference = yy.sub::<{ 12 * REDUCED }>(simd, b3zz).ready::<4>(simd);
        let x = F::product_sub::<PRODUCT_BIAS>(
            simd,
            xy.product(simd, difference),
            yz.product(simd, b3xz),
        );
        let y = F::accumulate(simd, b3xz.product(simd, xx3), difference.product(simd, sum));
        let z = F::accumulate(simd, sum.product(simd, yz), xx3.product(simd, xy));
        Self {
            x: F::reduce(simd, x),
            y: F::reduce(simd, y),
            z: F::reduce(simd, z),
        }
    }

    /// Returns `2 * self`.
    ///
    /// This is Algorithm 9 of Renes, Costello, and Batina, which accepts any point, including the
    /// identity. It returns the same point as [`Self::add`] of `self` with itself, with eight
    /// products.
    ///
    /// Debug builds keep this a call so that chained formulas fit in a stack frame.
    #[cfg_attr(not(debug_assertions), inline(always))]
    fn double(self, simd: S) -> Self {
        let (x, y, z) = (
            self.x.ready::<1>(simd),
            self.y.ready::<1>(simd),
            self.z.ready::<1>(simd),
        );
        let yy = y.mul(simd, y);
        let xy = x.mul(simd, y);
        let yz = y.mul(simd, z);
        // 3b z^2 and 9b z^2.
        let b3zz = z.mul(simd, z).mul_small::<12>(simd).carry(simd);
        let b9zz = b3zz.mul_small::<3>(simd).carry(simd);
        let yy8 = yy.mul_small::<8>(simd).ready::<8>(simd);
        // y^2 - 9b z^2 and y^2 + 3b z^2.
        let difference = yy.sub::<{ 36 * REDUCED }>(simd, b9zz).ready::<4>(simd);
        let sum = yy.add(simd, b3zz).ready::<2>(simd);
        let xy2 = xy.double(simd).ready::<2>(simd);
        let y = F::accumulate(simd, difference.product(simd, sum), b3zz.product(simd, yy8));
        Self {
            x: F::reduce(simd, difference.product(simd, xy2)),
            y: F::reduce(simd, y),
            z: F::reduce(simd, yy8.product(simd, yz)),
        }
    }
}

/// Reference arithmetic and coordinate bound hooks for the [curve formula checks](crate::core::curve::fuzz).
#[cfg(any(test, feature = "fuzz"))]
pub(crate) mod fuzz {
    use super::*;
    use crate::core::{
        curve::fuzz::Curve,
        field::fp::reference::{self, Element},
    };
    use arbitrary::Unstructured;

    /// G1 over the reference base field.
    pub(crate) struct G1;

    impl Curve for G1 {
        const NAME: &'static str = "G1";

        type Element = Element;
        type Encoded = [u8; BYTES];

        const ZERO: Element = reference::ZERO;
        const ONE: Element = reference::ONE;
        const B: Element = [4, 0, 0, 0, 0, 0];
        const GENERATOR: Coordinates = GENERATOR;
        const IDENTITY: Coordinates = IDENTITY;

        type Point<S: Simd, F: Field<S>> = Point<F>;

        fn add(a: Element, b: Element) -> Element {
            reference::add(a, b)
        }

        fn sub(a: Element, b: Element) -> Element {
            reference::sub(a, b)
        }

        fn mul(a: Element, b: Element) -> Element {
            reference::mul(a, b)
        }

        fn invert(a: Element) -> Element {
            reference::invert(a)
        }

        fn encode(a: Element) -> [u8; BYTES] {
            reference::to_bytes(a)
        }

        fn decode(bytes: &[u8; BYTES]) -> Element {
            reference::reduce(bytes)
        }

        fn arbitrary(u: &mut Unstructured<'_>) -> arbitrary::Result<Element> {
            reference::canonical(u)
        }

        /// Scales loaded coordinates, with integer bound `2`, by `36`, to integer bound `72`,
        /// in two steps that keep positional limb bounds within the value limits.
        fn widen<S: Simd, F: Field<S>>(simd: S, point: Point<F>) -> Point<F> {
            let widen = |value: F| {
                value
                    .mul_small::<6>(simd)
                    .carry(simd)
                    .mul_small::<{ BOUND / 12 }>(simd)
                    .carry(simd)
            };
            Point {
                x: widen(point.x),
                y: widen(point.y),
                z: widen(point.z),
            }
        }

        fn check_bound<S: Simd, F: Field<S>>(simd: S, point: Point<F>) -> Point<F> {
            for value in [point.x, point.y, point.z] {
                value.neg::<{ BOUND + 1 }>(simd);
            }
            point
        }
    }
}

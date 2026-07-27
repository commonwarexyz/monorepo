//! Points on the twisted Edwards curve `-x^2 + y^2 = 1 + d*x^2*y^2` (the Ed25519 curve, `a = -1`),
//! in extended coordinates `(X, Y, Z, T)` representing the affine point `(X/Z, Y/Z)` with
//! `T = X*Y/Z`.
//!
//! The unified addition formula used here (Hisil-Wong-Carter-Dawson) is complete for `a = -1`: it
//! handles doubling, the identity, and low-order points without special-casing, which is exactly
//! what signature verification needs since inputs are adversarial. Scalar multiplication is plain
//! binary double-and-add; this is variable-time, which is fine since every input is public.

use super::scalar::Scalar;
use crate::{
    field::FieldElement,
    field_vec::{self, LANES, Reduced, Unreduced},
};

#[derive(Copy, Clone, Debug)]
pub(crate) struct EdwardsPoint {
    x: FieldElement,
    y: FieldElement,
    z: FieldElement,
    t: FieldElement,
}

impl EdwardsPoint {
    /// The neutral element, `(0, 1)` in affine coordinates.
    pub(crate) const IDENTITY: Self = Self {
        x: FieldElement::ZERO,
        y: FieldElement::ONE,
        z: FieldElement::ONE,
        t: FieldElement::ZERO,
    };

    /// The standard Ed25519 base point `B`, as its already-decompressed extended coordinates.
    /// Hardcoded rather than computed via [`EdwardsPoint::decompress`] (a full `pow_p58` modular
    /// exponentiation): `B` is a fixed constant, so there is nothing to recompute at every call.
    /// Verified to match `decompress(&BASEPOINT_BYTES)` by the `basepoint_matches_decompression`
    /// test below.
    const BASEPOINT: Self = Self {
        x: FieldElement([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        y: FieldElement([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        z: FieldElement::ONE,
        t: FieldElement([
            1841354044333475,
            16398895984059,
            755974180946558,
            900171276175154,
            1821297809914039,
        ]),
    };

    pub(crate) const fn basepoint() -> Self {
        Self::BASEPOINT
    }

    /// Decompresses a 32-byte point encoding: bit 255 is the sign of `x`, and bits 0-254 encode
    /// `y`. Per ZIP215, `y` encodings are accepted even when `y >= p` (they are simply reduced
    /// mod `p`); the only rejection is when no valid `x` exists.
    pub(crate) fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let sign = bytes[31] >> 7;
        let y = FieldElement::from_bytes(bytes);

        // Recover x from x^2 = u/v, with u = y^2 - 1 and v = d*y^2 + 1, via one combined
        // inverse-square-root exponentiation on the candidate
        //   x_candidate = u * (u * v)^((p-5)/8),
        // for which v*x^2 = u^2 * v * (uv)^((p-5)/4) = chi(uv) * u = +/-u (with chi the Legendre
        // symbol, since (uv)^((p-1)/2) = chi(uv)): exactly the same two-case check as the
        // classic u * v^3 * (u * v^7)^((p-5)/8) candidate (the two differ by v^(3(p-1)/4), a
        // fourth root of unity the sqrt(-1) fixup below absorbs), but with the v^3/v^7 setup
        // (2 squarings + 3 multiplies) replaced by the single u*v multiply.
        let y2 = y.square();
        let u = y2.sub(&FieldElement::ONE);
        let v = FieldElement::EDWARDS_D.mul(&y2).add(&FieldElement::ONE);
        let uv = u.mul(&v);
        let mut x = u.mul(&uv.pow_p58());

        let vxx = v.mul(&x.square());
        if vxx.eq(&u) {
            // x is already correct.
        } else if vxx.eq(&u.neg()) {
            x = x.mul(&FieldElement::SQRT_M1);
        } else {
            return None; // Not a valid point encoding: no square root exists.
        }

        if x.is_zero() && sign == 1 {
            return None; // -0 is not a valid encoding of 0.
        }
        if x.is_odd() != (sign == 1) {
            x = x.neg();
        }

        Some(Self {
            x,
            y,
            z: FieldElement::ONE,
            t: x.mul(&y),
        })
    }

    /// Decompresses `LANES` point encodings at once, running the arithmetic-heavy part of the
    /// sqrt kernel above (the `u`/`v` setup and the `(p-5)/8` exponentiation) 8-wide via
    /// `FieldVec`, then finishing the branchy case analysis and sign fixup per lane exactly as
    /// [`EdwardsPoint::decompress`] does (see there for the candidate's derivation). Point
    /// decompression is a full modular exponentiation per point, so batching it this way (rather
    /// than looping over 8 calls to `decompress`) is where most of batch verification's cost
    /// lives besides the MSM.
    pub(crate) fn decompress_batch(bytes: &[[u8; 32]; LANES]) -> [Option<Self>; LANES] {
        let ys: [FieldElement; LANES] =
            core::array::from_fn(|i| FieldElement::from_bytes(&bytes[i]));
        let y_vec = Unreduced::from_lanes(&ys).reduce();
        let one = Unreduced::splat(FieldElement::ONE).reduce();
        let d = Unreduced::splat(FieldElement::EDWARDS_D).reduce();

        let y2 = y_vec.square();
        let u = y2.sub(&one).reduce();
        let v = d.mul(&y2).add(&one).reduce();
        let uv = u.mul(&v);
        let x_candidate = u.mul(&uv.pow_p58());
        let vxx = v.mul(&x_candidate.square());

        let u_lanes = u.to_lanes();
        let vxx_lanes = vxx.to_lanes();
        let x_lanes = x_candidate.to_lanes();

        core::array::from_fn(|i| {
            let sign = bytes[i][31] >> 7;
            let mut x = x_lanes[i];
            if vxx_lanes[i].eq(&u_lanes[i]) {
                // x is already correct.
            } else if vxx_lanes[i].eq(&u_lanes[i].neg()) {
                x = x.mul(&FieldElement::SQRT_M1);
            } else {
                return None; // Not a valid point encoding: no square root exists.
            }

            if x.is_zero() && sign == 1 {
                return None; // -0 is not a valid encoding of 0.
            }
            if x.is_odd() != (sign == 1) {
                x = x.neg();
            }

            Some(Self {
                x,
                y: ys[i],
                z: FieldElement::ONE,
                t: x.mul(&ys[i]),
            })
        })
    }

    /// Adds two points using the complete HWCD unified formula (valid for addition, doubling,
    /// and any combination involving the identity or low-order points).
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        let a = self.y.sub(&self.x).mul(&rhs.y.sub(&rhs.x));
        let b = self.y.add(&self.x).mul(&rhs.y.add(&rhs.x));
        let td = self.t.mul(&rhs.t).mul(&FieldElement::EDWARDS_D);
        let c = td.add(&td);
        let zz = self.z.mul(&rhs.z);
        let dd = zz.add(&zz);
        let e = b.sub(&a);
        let f = dd.sub(&c);
        let g = dd.add(&c);
        let h = b.add(&a);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Doubles this point via the dedicated `dbl-2008-hwcd` formula (Hisil-Wong-Carter-Dawson):
    /// 4 squarings + 4 multiplies, versus the 9 multiplies [`EdwardsPoint::add`]'s general unified
    /// formula costs for `self.add(self)`. Doubling dominates scalar multiplication and the MSM's
    /// window-shifting (one per bit/window versus one addition per set bit/nonzero digit), so this
    /// matters a lot there.
    pub(crate) fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square();
        let c = c.add(&c);
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = b.sub(&a);
        let f = g.sub(&c);
        let h = a.neg().sub(&b);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    pub(crate) const fn negate(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Adds a mixed-addition-prepared point (implicit `Z = 1`) to this (general) point: 7 field
    /// multiplies instead of [`EdwardsPoint::add`]'s 9. `rhs`'s implicit `Z = 1` makes `D = 2*Z1*Z2`
    /// free (just `Z1 + Z1`, no multiply), and `rhs.t2d` already folds in the `2d` factor
    /// [`EdwardsPoint::add`] would otherwise apply fresh on every call -- both savings only apply
    /// because every point this crate's MSM ever adds is either freshly decompressed or the
    /// hardcoded basepoint, never the output of a prior addition/doubling (see
    /// [`MixedPoint::new`]).
    pub(crate) fn add_mixed(&self, rhs: &MixedPoint) -> Self {
        let a = self.y.sub(&self.x).mul(&rhs.y.sub(&rhs.x));
        let b = self.y.add(&self.x).mul(&rhs.y.add(&rhs.x));
        let c = self.t.mul(&rhs.t2d);
        let d = self.z.add(&self.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Multiplies the point by a scalar via plain binary double-and-add (variable-time).
    pub(crate) fn scalar_mul(&self, scalar: &Scalar) -> Self {
        let mut result = Self::IDENTITY;
        for bit in scalar.bits_be() {
            result = result.double();
            if bit {
                result = result.add(self);
            }
        }
        result
    }

    /// Multiplies the point by the curve's cofactor (8), via three doublings.
    pub(crate) fn mul_by_cofactor(&self) -> Self {
        self.double().double().double()
    }

    /// Returns `true` if this point is the identity element `(0, 1)`.
    pub(crate) fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.eq(&self.z)
    }
}

/// A point prepared for [`EdwardsPoint::add_mixed`]/[`PointVec::add_mixed`]: an affine-origin
/// point (`Z` implicit `1`) together with its precomputed `2d*T` (`T = X*Y`, exactly, since
/// `Z = 1` needs no division to recover it). This is the one sub-computation worth caching once
/// and reusing across every addition a point participates in: a point can be added into a bucket
/// in up to `msm::NUM_WINDOWS` separate windows, and without caching, each of those
/// additions would redo the same `T*2d` multiply on the exact same (unchanging) `T`. `(Y+X)`/
/// `(Y-X)` are *not* cached: recomputing them costs only a field addition/subtraction (not a
/// multiply), so caching them would spend extra storage for no real savings.
#[derive(Copy, Clone, Debug)]
pub(crate) struct MixedPoint {
    x: FieldElement,
    y: FieldElement,
    t2d: FieldElement,
}

impl MixedPoint {
    /// Prepares `point` for mixed addition. `point.z` must be `1` -- true of every point this
    /// crate ever feeds into the MSM: freshly decompressed signatures/keys, or the hardcoded
    /// basepoint (see [`EdwardsPoint::basepoint`]), never the output of a prior addition or
    /// doubling.
    pub(crate) fn new(point: &EdwardsPoint) -> Self {
        debug_assert!(point.z.eq(&FieldElement::ONE));
        Self {
            x: point.x,
            y: point.y,
            t2d: point.t.mul(&FieldElement::EDWARDS_D2),
        }
    }

    /// Negates this point: flips the sign of `x` (and therefore of `t2d`, since
    /// `t2d = 2d*x*y`), leaving `y` untouched -- the same transformation as
    /// [`EdwardsPoint::negate`].
    pub(crate) const fn negate(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            t2d: self.t2d.neg(),
        }
    }
}

/// `LANES` extended-coordinate points, stored the same "structure of arrays" way [`Reduced`]
/// stores field elements (one per coordinate, rather than `LANES` separate [`EdwardsPoint`]s): the
/// layout the MSM's "transposed Pippenger" design (see the design notes' MSM section) needs so
/// that 8 independent bucket updates or 8 independent window doublings can run as one vectorized
/// addition instead of 8 scalar ones. Coordinates are stored [`Reduced`] so every read can feed
/// directly into a `mul`/`square` (via [`Reduced::add`]/[`Reduced::sub`] plus an explicit
/// `.reduce()` where the formula needs one) without a separate bounds check at each use.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PointVec {
    x: Reduced,
    y: Reduced,
    z: Reduced,
    t: Reduced,
}

impl PointVec {
    /// `LANES` copies of the neutral element.
    pub(crate) fn identity() -> Self {
        Self::from_lanes(&[EdwardsPoint::IDENTITY; LANES])
    }

    /// Packs `LANES` points into one `PointVec`.
    pub(crate) fn from_lanes(lanes: &[EdwardsPoint; LANES]) -> Self {
        Self {
            x: Unreduced::from_lanes(&core::array::from_fn(|i| lanes[i].x)).reduce(),
            y: Unreduced::from_lanes(&core::array::from_fn(|i| lanes[i].y)).reduce(),
            z: Unreduced::from_lanes(&core::array::from_fn(|i| lanes[i].z)).reduce(),
            t: Unreduced::from_lanes(&core::array::from_fn(|i| lanes[i].t)).reduce(),
        }
    }

    /// Unpacks this `PointVec` back into `LANES` points.
    pub(crate) fn to_lanes(self) -> [EdwardsPoint; LANES] {
        let x = self.x.to_lanes();
        let y = self.y.to_lanes();
        let z = self.z.to_lanes();
        let t = self.t.to_lanes();
        core::array::from_fn(|i| EdwardsPoint {
            x: x[i],
            y: y[i],
            z: z[i],
            t: t[i],
        })
    }

    /// Adds `LANES` pairs of points at once, via the same complete HWCD unified formula as
    /// [`EdwardsPoint::add`] -- one call here does the work of 8 scalar calls to that function.
    ///
    /// Dispatches to a single fused AVX-512 function when available
    /// ([`field_vec::fused_point_add`]), which computes the whole formula with every intermediate
    /// held in registers instead of round-tripping through memory once per field operation --
    /// profiling on real hardware found that memory traffic, not the arithmetic itself, dominating
    /// this function (see that function's doc comment). Falls back to the same formula written out
    /// against the ordinary `Reduced`/`Unreduced` methods on any CPU without that backend, where
    /// there is no such fused path to miss out on.
    pub(crate) fn add(&self, rhs: &Self) -> Self {
        if let Some((x, y, z, t)) = field_vec::fused_point_add(
            &self.x, &self.y, &self.z, &self.t, &rhs.x, &rhs.y, &rhs.z, &rhs.t,
        ) {
            return Self { x, y, z, t };
        }

        let d = Unreduced::splat(FieldElement::EDWARDS_D).reduce();
        let a = self
            .y
            .sub(&self.x)
            .reduce()
            .mul(&rhs.y.sub(&rhs.x).reduce());
        let b = self
            .y
            .add(&self.x)
            .reduce()
            .mul(&rhs.y.add(&rhs.x).reduce());
        let td = self.t.mul(&rhs.t).mul(&d);
        let c = td.add(&td);
        let zz = self.z.mul(&rhs.z);
        let dd = zz.add(&zz);
        let e = b.sub(&a).reduce();
        let f = dd.sub(&c).reduce();
        let g = dd.add(&c).reduce();
        let h = b.add(&a).reduce();
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Adds `LANES` mixed-addition-prepared points (see [`MixedPointVec`]) at once, the vectorized
    /// analogue of [`EdwardsPoint::add_mixed`]: the same 7-vs-9-multiply saving, applied 8-wide.
    ///
    /// Dispatches to a single fused AVX-512 function when available
    /// ([`field_vec::fused_point_add_mixed`]), same reason and same pattern as [`PointVec::add`]:
    /// an earlier version of this function had no fused kernel and, measured on real AVX-512
    /// hardware, regressed batch-verify throughput by 13-16% relative to the general, fused
    /// [`PointVec::add`] -- the extra `Reduced`/`Unreduced` round trips between each of the 7
    /// unfused steps cost more than the 2-fewer-multiplies saved, since memory traffic (not
    /// multiply count) dominates this backend (see [`field_vec::fused_point_add`]'s doc comment).
    /// Falls back to the same formula written out against the ordinary methods on any CPU without
    /// that backend, where there is no such fused path to miss out on.
    pub(crate) fn add_mixed(&self, rhs: &MixedPointVec) -> Self {
        if let Some((x, y, z, t)) = field_vec::fused_point_add_mixed(
            &self.x, &self.y, &self.z, &self.t, &rhs.x, &rhs.y, &rhs.t2d,
        ) {
            return Self { x, y, z, t };
        }

        let a = self
            .y
            .sub(&self.x)
            .reduce()
            .mul(&rhs.y.sub(&rhs.x).reduce());
        let b = self
            .y
            .add(&self.x)
            .reduce()
            .mul(&rhs.y.add(&rhs.x).reduce());
        let c = self.t.mul(&rhs.t2d);
        let d = self.z.add(&self.z).reduce();
        let e = b.sub(&a).reduce();
        let f = d.sub(&c).reduce();
        let g = d.add(&c).reduce();
        let h = b.add(&a).reduce();
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    /// Doubles `LANES` points at once via the dedicated `dbl-2008-hwcd` formula (see
    /// [`EdwardsPoint::double`]): 4M+4S instead of [`PointVec::add`]'s 9M, and a square costs
    /// less than a full multiply on this backend (15 multiply-accumulates versus 25; see
    /// [`Reduced::square`]'s doc comment) -- a real win, since doubling dominates the MSM's
    /// window-shifting (see `EdwardsPoint::double`'s doc comment).
    ///
    /// Dispatches to a single fused AVX-512 function when available
    /// ([`field_vec::fused_point_double`]), same reason as [`PointVec::add`]: measured on real
    /// hardware, the memory-traffic cost of chaining separate `Reduced`/`Unreduced` method calls
    /// (each its own `load`/`store` round trip) outweighed this formula's multiply-count
    /// advantage over `add(self)`, turning an algorithmic win into a wash or regression. Falls
    /// back to the formula written out against the ordinary methods on any CPU without that
    /// backend, where there is no such fused path to miss out on.
    ///
    /// An earlier version of this function used this same formula directly on the
    /// (then-undivided) `FieldVec` type and, measured on real AVX-512 hardware, diverged from the
    /// scalar reference within ~180 chained doublings (well inside the MSM's ~264): an
    /// under-reduced operand reaching `vpmadd52lo`/`vpmadd52hi`. Every squaring/multiplication
    /// below takes a [`Reduced`] operand -- the type [`Unreduced::reduce`] alone can produce --
    /// so an operand that skipped reduction before reaching `square`/`mul` is now a compile error
    /// rather than a silent hardware bug (see the `field_vec` module docs); the fused backend
    /// carries the same discipline by hand, mirrored from this fallback line for line (see
    /// `field_vec::avx512::point_double`). Re-verify against
    /// `tests::point_vec_interleaved_double_and_add_matches_scalar` (which exercises well past
    /// both the original failure's round count and the real MSM's window count) on real AVX-512
    /// hardware before trusting a further change here.
    pub(crate) fn double(&self) -> Self {
        if let Some((x, y, z, t)) = field_vec::fused_point_double(&self.x, &self.y, &self.z) {
            return Self { x, y, z, t };
        }

        let a = self.x.square();
        let b = self.y.square();
        let c0 = self.z.square();
        let c = c0.add(&c0).reduce();
        let xy2 = self.x.add(&self.y).reduce().square();
        let e = xy2.sub(&a).sub(&Unreduced::from(b)).reduce();
        let g = b.sub(&a).reduce();
        let f = g.sub(&c).reduce();
        let h = a.neg().sub(&Unreduced::from(b)).reduce();
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }
}

/// `LANES` [`MixedPoint`]s, packed the same "structure of arrays" way [`PointVec`] packs
/// [`EdwardsPoint`]s: `Z` stays implicit `1` (no lane row for it), so [`PointVec::add_mixed`] can
/// consume this directly wherever the transposed MSM's bucket-fill wave has `LANES` freshly
/// decompressed (or hardcoded-basepoint) terms ready to add.
#[derive(Clone, Copy, Debug)]
pub(crate) struct MixedPointVec {
    x: Reduced,
    y: Reduced,
    t2d: Reduced,
}

impl MixedPointVec {
    /// Packs `LANES` mixed points into one `MixedPointVec`.
    pub(crate) fn from_lanes(lanes: &[MixedPoint; LANES]) -> Self {
        Self {
            x: Unreduced::from_lanes(&core::array::from_fn(|i| lanes[i].x)).reduce(),
            y: Unreduced::from_lanes(&core::array::from_fn(|i| lanes[i].y)).reduce(),
            t2d: Unreduced::from_lanes(&core::array::from_fn(|i| lanes[i].t2d)).reduce(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::scalar::test_support::rand_scalar;
    use commonware_utils::test_rng;

    fn rand_point(rng: &mut impl rand_core::Rng) -> EdwardsPoint {
        EdwardsPoint::basepoint().scalar_mul(&rand_scalar(rng))
    }

    /// Returns a random `Z = 1` point via rejection-sampled decompression: [`MixedPoint::new`]'s
    /// precondition, unlike [`rand_point`]'s `scalar_mul`-derived points (which generally have
    /// `Z != 1`).
    fn rand_affine_point(rng: &mut impl rand_core::Rng) -> EdwardsPoint {
        loop {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            if let Some(p) = EdwardsPoint::decompress(&bytes) {
                return p;
            }
        }
    }

    /// The compressed encoding of the standard Ed25519 base point `B` (`y = 4/5`, `x` even),
    /// used only to verify [`EdwardsPoint::BASEPOINT`] against decompression below.
    const BASEPOINT_BYTES: [u8; 32] = [
        0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
        0x66, 0x66,
    ];

    #[test]
    fn basepoint_matches_decompression() {
        let decompressed = EdwardsPoint::decompress(&BASEPOINT_BYTES).unwrap();
        let basepoint = EdwardsPoint::basepoint();
        assert_eq!(basepoint.x.0, decompressed.x.0);
        assert_eq!(basepoint.y.0, decompressed.y.0);
        assert_eq!(basepoint.z.0, decompressed.z.0);
        assert_eq!(basepoint.t.0, decompressed.t.0);
    }

    #[test]
    fn double_matches_add_self() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let p = rand_point(&mut rng);
            let expected = p.add(&p);
            assert!(p.double().add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn point_vec_double_matches_scalar_per_lane() {
        let mut rng = test_rng();
        let a: [EdwardsPoint; LANES] = core::array::from_fn(|_| rand_point(&mut rng));

        let actual = PointVec::from_lanes(&a).double().to_lanes();
        for i in 0..LANES {
            let expected = a[i].double();
            assert!(actual[i].add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn point_vec_add_matches_scalar_per_lane() {
        let mut rng = test_rng();
        let a: [EdwardsPoint; LANES] = core::array::from_fn(|_| rand_point(&mut rng));
        let b: [EdwardsPoint; LANES] = core::array::from_fn(|_| rand_point(&mut rng));

        let actual = PointVec::from_lanes(&a)
            .add(&PointVec::from_lanes(&b))
            .to_lanes();
        for i in 0..LANES {
            let expected = a[i].add(&b[i]);
            assert!(actual[i].add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn add_mixed_matches_general_add() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let p = rand_point(&mut rng);
            let q = rand_affine_point(&mut rng);
            let mixed = MixedPoint::new(&q);

            let expected = p.add(&q);
            let actual = p.add_mixed(&mixed);
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn mixed_point_negate_matches_edwards_negate() {
        let mut rng = test_rng();
        for _ in 0..64 {
            let p = rand_point(&mut rng);
            let q = rand_affine_point(&mut rng);
            let mixed = MixedPoint::new(&q);

            let expected = p.add(&q.negate());
            let actual = p.add_mixed(&mixed.negate());
            assert!(actual.add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn point_vec_add_mixed_matches_scalar_per_lane() {
        let mut rng = test_rng();
        let a: [EdwardsPoint; LANES] = core::array::from_fn(|_| rand_point(&mut rng));
        let b: [EdwardsPoint; LANES] = core::array::from_fn(|_| rand_affine_point(&mut rng));
        let mixed_b: [MixedPoint; LANES] = core::array::from_fn(|i| MixedPoint::new(&b[i]));

        let actual = PointVec::from_lanes(&a)
            .add_mixed(&MixedPointVec::from_lanes(&mixed_b))
            .to_lanes();
        for i in 0..LANES {
            let expected = a[i].add(&b[i]);
            assert!(actual[i].add(&expected.negate()).is_identity());
        }
    }

    #[test]
    fn point_vec_identity_round_trips() {
        let lanes = PointVec::identity().to_lanes();
        for point in lanes {
            assert!(point.is_identity());
        }
    }

    /// Regression test for a bug found on real AVX-512 hardware: `PointVec::add`/
    /// `PointVec::double` each pass in isolation (hundreds of chained doublings, or dozens of
    /// chained additions, checked out fine on their own), but *interleaving* many doublings with
    /// only *occasional* additions on the same long-lived accumulator diverged from the scalar
    /// reference after about 19 rounds -- exactly the access pattern the MSM's `result`
    /// accumulator has: it doubles every window (`WIDTH` times) but only adds a nonzero
    /// `window_sum` when that window's digit happens to be nonzero, while `sum`/`window_sum`/
    /// `buckets` themselves reset every window. `ROUNDS` here is well past both the round count
    /// that triggered the original failure and the real MSM's own window count.
    #[test]
    fn point_vec_interleaved_double_and_add_matches_scalar() {
        const ROUNDS: usize = 60;
        const DOUBLINGS_PER_ROUND: u32 = 6;

        let mut rng = test_rng();
        let mut result = PointVec::identity();
        let mut scalar_results = [EdwardsPoint::IDENTITY; LANES];

        for round in 0..ROUNDS {
            for _ in 0..DOUBLINGS_PER_ROUND {
                result = result.double();
            }
            for r in &mut scalar_results {
                for _ in 0..DOUBLINGS_PER_ROUND {
                    *r = r.double();
                }
            }

            // A nonzero "digit" roughly a third of the time, matching how sparse a real window's
            // nonzero digits are; identity (a no-op addition) otherwise.
            let increments: [EdwardsPoint; LANES] = core::array::from_fn(|_| {
                if round % 3 == 0 {
                    rand_point(&mut rng)
                } else {
                    EdwardsPoint::IDENTITY
                }
            });
            result = result.add(&PointVec::from_lanes(&increments));
            for (r, inc) in scalar_results.iter_mut().zip(&increments) {
                *r = r.add(inc);
            }

            let actual = result.to_lanes();
            for lane in 0..LANES {
                assert!(
                    actual[lane]
                        .add(&scalar_results[lane].negate())
                        .is_identity(),
                    "diverged at round {round}, lane {lane}"
                );
            }
        }
    }
}

//! Ed25519 point encoding and signing-specific operations over the selected curve backend.

use super::scalar::Scalar;
use crate::simplified::{Backend, F, FBackend, FVec, GAffineVec, GBackend, GVec, LANES};

/// A point on the Ed25519 curve in extended homogeneous coordinates.
///
/// Signing keeps individual points in this compact form and transposes them into [`GVec`] only
/// while running arithmetic through the selected backend.
#[derive(Copy, Clone, Debug)]
pub(crate) struct EdwardsPoint {
    x: F,
    y: F,
    z: F,
    t: F,
}

impl EdwardsPoint {
    /// The neutral element, `(0, 1)` in affine coordinates.
    pub(crate) const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        z: F::ONE,
        t: F::ZERO,
    };

    /// The standard Ed25519 base point `B`, in extended coordinates.
    const BASEPOINT: Self = Self {
        x: F([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        y: F([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        z: F::ONE,
        t: F([
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

    /// Packs eight compact points into the backend's structure-of-arrays representation.
    pub(crate) fn pack(lanes: &[Self; LANES]) -> GVec {
        GVec {
            x: FVec::from_lanes(&lanes.map(|point| point.x)),
            y: FVec::from_lanes(&lanes.map(|point| point.y)),
            z: FVec::from_lanes(&lanes.map(|point| point.z)),
            t: FVec::from_lanes(&lanes.map(|point| point.t)),
        }
    }

    /// Unpacks the backend's structure-of-arrays representation into compact points.
    pub(crate) fn unpack(point: GVec) -> [Self; LANES] {
        let x = point.x.to_lanes();
        let y = point.y.to_lanes();
        let z = point.z.to_lanes();
        let t = point.t.to_lanes();
        core::array::from_fn(|i| Self {
            x: x[i],
            y: y[i],
            z: z[i],
            t: t[i],
        })
    }

    /// Returns eight copies of this point in backend representation.
    fn splat(self) -> GVec {
        Self::pack(&[self; LANES])
    }

    /// Returns eight copies of the identity in backend representation.
    pub(crate) fn identity_vec() -> GVec {
        Self::IDENTITY.splat()
    }

    /// Decompresses a point encoding, accepting non-canonical `y` values per ZIP215.
    pub(crate) fn decompress<B: Backend>(backend: B, bytes: &[u8; 32]) -> Option<Self> {
        Self::decompress_batch(backend, &[*bytes; LANES])[0]
    }

    /// Decompresses eight point encodings with the square-root calculation performed lane-wise by
    /// the selected backend.
    pub(crate) fn decompress_batch<B: Backend>(
        backend: B,
        bytes: &[[u8; 32]; LANES],
    ) -> [Option<Self>; LANES] {
        let signs = bytes.map(|encoding| encoding[31] >> 7);
        let ys = bytes.map(|encoding| F::from_bytes(&encoding));
        let y = FVec::from_lanes(&ys);
        let one = F::ONE.splat();

        // Recover x from x^2 = u/v, where u = y^2 - 1 and v = d*y^2 + 1.
        let y2 = backend.square(y);
        let u = backend.sub(y2, one);
        let v = backend.add(backend.mul(F::EDWARDS_D.splat(), y2), one);
        let uv = backend.mul(u, v);
        let candidate = backend.mul(u, pow_p58(backend, uv));
        let vxx = backend.mul(v, backend.square(candidate));

        let u_lanes = u.to_lanes();
        let negative_u_lanes = backend.neg(u).to_lanes();
        let vxx_lanes = vxx.to_lanes();
        let factors = core::array::from_fn(|i| {
            if vxx_lanes[i].eq(&u_lanes[i]) {
                Some(F::ONE)
            } else if vxx_lanes[i].eq(&negative_u_lanes[i]) {
                Some(F::SQRT_M1)
            } else {
                None
            }
        });
        let factor_lanes = factors.map(|factor| factor.unwrap_or(F::ONE));
        let x = backend.mul(candidate, FVec::from_lanes(&factor_lanes));
        let x_lanes = x.to_lanes();
        let negative_x_lanes = backend.neg(x).to_lanes();

        let final_x = core::array::from_fn(|i| {
            if x_lanes[i].is_odd() == (signs[i] == 1) {
                x_lanes[i]
            } else {
                negative_x_lanes[i]
            }
        });
        let t_lanes = backend
            .mul(FVec::from_lanes(&final_x), y)
            .to_lanes();

        core::array::from_fn(|i| {
            factors[i]?;
            if x_lanes[i].is_zero() && signs[i] == 1 {
                return None;
            }
            Some(Self {
                x: final_x[i],
                y: ys[i],
                z: F::ONE,
                t: t_lanes[i],
            })
        })
    }

    /// Adds two points using the backend's complete group formula.
    pub(crate) fn add<B: GBackend>(&self, backend: B, rhs: &Self) -> Self {
        Self::unpack(backend.g_add(self.splat(), rhs.splat()))[0]
    }

    /// Doubles this point.
    pub(crate) fn double<B: GBackend>(&self, backend: B) -> Self {
        Self::unpack(backend.g_double(self.splat()))[0]
    }

    /// Negates this point.
    pub(crate) fn negate<B: FBackend>(&self, backend: B) -> Self {
        let point = self.splat();
        Self::unpack(GVec {
            x: backend.neg(point.x),
            y: point.y,
            z: point.z,
            t: backend.neg(point.t),
        })[0]
    }

    /// Multiplies this point by a scalar using variable-time double-and-add.
    pub(crate) fn scalar_mul<B: GBackend>(&self, backend: B, scalar: &Scalar) -> Self {
        let point = self.splat();
        let mut result = Self::identity_vec();
        for bit in scalar.bits_be() {
            result = backend.g_double(result);
            if bit {
                result = backend.g_add(result, point);
            }
        }
        Self::unpack(result)[0]
    }

    /// Multiplies this point by the curve's cofactor (8).
    pub(crate) fn mul_by_cofactor<B: GBackend>(&self, backend: B) -> Self {
        self.double(backend).double(backend).double(backend)
    }

    /// Returns `true` if this point is the identity.
    pub(crate) fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.eq(&self.z)
    }

    /// Sums the lanes of a backend point into one compact point.
    pub(crate) fn sum_lanes<B: GBackend>(backend: B, point: GVec) -> Self {
        Self::unpack(point)
            .iter()
            .fold(Self::IDENTITY, |sum, point| sum.add(backend, point))
    }
}

/// A compact affine point prepared for mixed addition.
#[derive(Copy, Clone, Debug)]
pub(crate) struct MixedPoint {
    x: F,
    y: F,
    t2d: F,
}

impl MixedPoint {
    pub(crate) const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        t2d: F::ZERO,
    };

    /// Prepares one affine point for mixed addition.
    pub(crate) fn new<B: Backend>(backend: B, point: &EdwardsPoint) -> Self {
        Self::from_lanes(backend, &[ *point; LANES ])[0]
    }

    /// Prepares eight affine points for mixed addition in one backend operation.
    pub(crate) fn from_lanes<B: Backend>(
        backend: B,
        points: &[EdwardsPoint; LANES],
    ) -> [Self; LANES] {
        debug_assert!(points.iter().all(|point| point.z.eq(&F::ONE)));
        let packed = EdwardsPoint::pack(points);
        let t2d = backend.mul(packed.t, F::EDWARDS_D2.splat()).to_lanes();
        let x = packed.x.to_lanes();
        let y = packed.y.to_lanes();
        core::array::from_fn(|i| Self {
            x: x[i],
            y: y[i],
            t2d: t2d[i],
        })
    }

    /// Packs eight prepared points for mixed addition.
    pub(crate) fn pack(lanes: &[Self; LANES]) -> GAffineVec {
        GAffineVec {
            x: FVec::from_lanes(&lanes.map(|point| point.x)),
            y: FVec::from_lanes(&lanes.map(|point| point.y)),
            t2d: FVec::from_lanes(&lanes.map(|point| point.t2d)),
        }
    }

    /// Packs prepared points, negating the selected lanes in two backend field operations.
    pub(crate) fn pack_signed<B: FBackend>(
        backend: B,
        lanes: &[Self; LANES],
        negative: &[bool; LANES],
    ) -> GAffineVec {
        let packed = Self::pack(lanes);
        if !negative.iter().any(|&value| value) {
            return packed;
        }

        let x = packed.x.to_lanes();
        let negative_x = backend.neg(packed.x).to_lanes();
        let t2d = packed.t2d.to_lanes();
        let negative_t2d = backend.neg(packed.t2d).to_lanes();
        GAffineVec {
            x: FVec::from_lanes(&core::array::from_fn(|i| {
                if negative[i] { negative_x[i] } else { x[i] }
            })),
            y: packed.y,
            t2d: FVec::from_lanes(&core::array::from_fn(|i| {
                if negative[i] {
                    negative_t2d[i]
                } else {
                    t2d[i]
                }
            })),
        }
    }

}

/// Squares `value` `k` times.
fn pow2k<B: FBackend>(backend: B, mut value: FVec, k: u32) -> FVec {
    for _ in 0..k {
        value = backend.square(value);
    }
    value
}

/// Raises every lane to `2^250 - 1` using the standard addition chain.
fn pow_2_250_minus_1<B: FBackend>(backend: B, value: FVec) -> FVec {
    let a = backend.square(value);
    let a2 = backend.square(backend.square(a));
    let b = backend.mul(value, a2);
    let c = backend.mul(a, b);
    let d = backend.square(c);
    let e = backend.mul(b, d);
    let f = backend.mul(pow2k(backend, e, 5), e);
    let g = backend.mul(pow2k(backend, f, 10), f);
    let h = backend.mul(pow2k(backend, g, 20), g);
    let i = backend.mul(pow2k(backend, h, 10), f);
    let j = backend.mul(pow2k(backend, i, 50), i);
    let k = backend.mul(pow2k(backend, j, 100), j);
    backend.mul(pow2k(backend, k, 50), i)
}

/// Raises every lane to `(p - 5) / 8 = 2^252 - 3` for point decompression.
fn pow_p58<B: FBackend>(backend: B, value: FVec) -> FVec {
    backend.mul(value, pow2k(backend, pow_2_250_minus_1(backend, value), 2))
}

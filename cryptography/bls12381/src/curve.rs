//! Short Weierstrass arithmetic shared by both groups.
//!
//! G1 and G2 are curves `y^2 = x^3 + b` with `a = 0`. Points use homogeneous projective
//! coordinates `(X : Y : Z)` with the complete formulas of Renes, Costello, and Batina
//! ("Complete addition formulas for prime order elliptic curves", 2016; Algorithms 7 to 9), so
//! no operation has exceptional inputs. The formulas are generic over a [`Field`] context, so
//! they apply unchanged to scalar elements, to one point per lane, and to specialized
//! representations.
//!
//! Under the bounds of [`crate::fp::lanes`], every subtrahend below is at most `24p` and
//! every multiplicand at most `2^14 * p`.

use crate::{
    fp::{
        Field, Fp,
        lanes::{FpVec, Lanes, MAX_LANES},
    },
    scalar::{Scalar, WINDOW_BITS, WINDOWS},
};
use commonware_simd::Simd;
use subtle::{Choice, ConstantTimeEq};

/// A point in homogeneous projective coordinates; `Z = 0` is the identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Projective<E> {
    pub x: E,
    pub y: E,
    pub z: E,
}

/// A curve `y^2 = x^3 + b` over a field context, holding the constant `3b` the formulas use.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Curve<F: Field> {
    pub field: F,
    b3: F::Element,
}

impl<F: Field> Curve<F> {
    /// Returns the curve `y^2 = x^3 + b` over `field`.
    #[inline(always)]
    pub fn new(field: F, b: Fp) -> Self {
        Self {
            field,
            b3: field.constant(b.add(b).add(b)),
        }
    }

    /// Returns the identity, `(0 : 1 : 0)`.
    #[inline(always)]
    pub fn identity(&self) -> Projective<F::Element> {
        let f = self.field;
        Projective {
            x: f.constant(Fp::ZERO),
            y: f.constant(Fp::ONE),
            z: f.constant(Fp::ZERO),
        }
    }

    /// Returns `p + q` (Algorithm 7).
    #[inline(always)]
    pub fn add(&self, p: Projective<F::Element>, q: Projective<F::Element>) -> Projective<F::Element> {
        let f = self.field;
        let t0 = f.mul(p.x, q.x);
        let t1 = f.mul(p.y, q.y);
        let t2 = f.mul(p.z, q.z);
        // (X1 + Y1)(X2 + Y2) - X1X2 - Y1Y2 = X1Y2 + X2Y1, and likewise for the other pairs.
        let t3 = f.sub(f.mul(f.add(p.x, p.y), f.add(q.x, q.y)), f.add(t0, t1));
        let t4 = f.sub(f.mul(f.add(p.y, p.z), f.add(q.y, q.z)), f.add(t1, t2));
        let xz = f.sub(f.mul(f.add(p.x, p.z), f.add(q.x, q.z)), f.add(t0, t2));
        let t0 = f.add(f.double(t0), t0);
        let t2 = f.mul(self.b3, t2);
        let z3 = f.add(t1, t2);
        let t1 = f.sub(t1, t2);
        let y3 = f.mul(self.b3, xz);
        Projective {
            x: f.sub(f.mul(t3, t1), f.mul(t4, y3)),
            y: f.add(f.mul(t1, z3), f.mul(y3, t0)),
            z: f.add(f.mul(z3, t4), f.mul(t0, t3)),
        }
    }

    /// Returns `2p` (Algorithm 9).
    #[inline(always)]
    pub fn double(&self, p: Projective<F::Element>) -> Projective<F::Element> {
        let f = self.field;
        let yy = f.square(p.y);
        let z3 = f.double(f.double(f.double(yy)));
        let yz = f.mul(p.y, p.z);
        let bzz = f.mul(self.b3, f.square(p.z));
        let x3 = f.mul(bzz, z3);
        let y3 = f.add(yy, bzz);
        let z3 = f.mul(yz, z3);
        let t0 = f.sub(yy, f.add(f.double(bzz), bzz));
        let xy = f.mul(p.x, p.y);
        Projective {
            x: f.double(f.mul(t0, xy)),
            y: f.add(x3, f.mul(t0, y3)),
            z: z3,
        }
    }

    /// Returns `-p`.
    #[inline(always)]
    pub fn neg(&self, p: Projective<F::Element>) -> Projective<F::Element> {
        Projective {
            x: p.x,
            y: self.field.neg(p.y),
            z: p.z,
        }
    }

    /// Returns `q` where `choice` is set and `p` elsewhere.
    #[inline(always)]
    pub fn select(
        &self,
        p: Projective<F::Element>,
        q: Projective<F::Element>,
        choice: Choice,
    ) -> Projective<F::Element> {
        let f = self.field;
        Projective {
            x: f.select(p.x, q.x, choice),
            y: f.select(p.y, q.y, choice),
            z: f.select(p.z, q.z, choice),
        }
    }

    /// Returns `scalar * p` in constant time with respect to the scalar.
    ///
    /// Fixed four-bit windows index a table of the first sixteen multiples, scanned in full
    /// for every window so the access pattern is independent of the scalar.
    #[inline(always)]
    pub fn mul(&self, p: Projective<F::Element>, scalar: &Scalar) -> Projective<F::Element> {
        let mut table = [self.identity(); 1 << WINDOW_BITS];
        for i in 1..table.len() {
            table[i] = if i % 2 == 0 {
                self.double(table[i / 2])
            } else {
                self.add(table[i - 1], p)
            };
        }
        let mut result = self.identity();
        for window in (0..WINDOWS).rev() {
            for _ in 0..WINDOW_BITS {
                result = self.double(result);
            }
            let digit = scalar.window(window);
            let mut term = table[0];
            for (i, entry) in table.iter().enumerate().skip(1) {
                term = self.select(term, *entry, digit.ct_eq(&(i as u8)));
            }
            result = self.add(result, term);
        }
        result
    }
}

impl<S: Simd> Curve<Lanes<S>> {
    /// Loads the first `S::U64_LANES` points, one per lane.
    ///
    /// # Panics
    ///
    /// Panics if fewer points are supplied.
    #[inline(always)]
    pub fn load(&self, points: &[Projective<Fp>]) -> Projective<FpVec<S>> {
        let simd = self.field.0;
        let coordinate = |get: fn(&Projective<Fp>) -> Fp| {
            let mut column = [Fp::ZERO; MAX_LANES];
            for (lane, point) in column.iter_mut().zip(points) {
                *lane = get(point);
            }
            FpVec::load(simd, &column[..S::U64_LANES])
        };
        Projective {
            x: coordinate(|p| p.x),
            y: coordinate(|p| p.y),
            z: coordinate(|p| p.z),
        }
    }

    /// Stores every lane's point, with canonical coordinates, into the first `S::U64_LANES`
    /// outputs.
    ///
    /// # Panics
    ///
    /// Panics if fewer outputs are supplied.
    #[inline(always)]
    pub fn store(&self, point: Projective<FpVec<S>>, outputs: &mut [Projective<Fp>]) {
        let simd = self.field.0;
        let mut coordinate = |value: FpVec<S>, set: fn(&mut Projective<Fp>, Fp)| {
            let mut column = [Fp::ZERO; MAX_LANES];
            value.store(simd, &mut column);
            for (output, lane) in outputs.iter_mut().zip(column) {
                set(output, lane);
            }
        };
        coordinate(point.x, |p, v| p.x = v);
        coordinate(point.y, |p, v| p.y = v);
        coordinate(point.z, |p, v| p.z = v);
    }
}

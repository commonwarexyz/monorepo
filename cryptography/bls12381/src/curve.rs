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
//!
//! The formulas inline into their callers in release builds so vector kernels stay inside the
//! backend's target-feature scope; debug builds keep them as calls so stack frames stay small.

use crate::{
    fp::{Coordinate, Field, lanes::MAX_LANES},
    scalar::{Scalar, WINDOW_BITS, WINDOWS},
};
use subtle::{Choice, ConstantTimeEq};

/// A point in homogeneous projective coordinates; `Z = 0` is the identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Projective<E> {
    pub x: E,
    pub y: E,
    pub z: E,
}

/// A point in affine coordinates. Cannot represent the identity.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Affine<E> {
    pub x: E,
    pub y: E,
}

/// A curve `y^2 = x^3 + b` over a field context, holding the constant `3b` the formulas use.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Curve<F: Field> {
    pub field: F,
    b3: F::Element,
}

impl<F: Field> Curve<F> {
    /// Returns the curve `y^2 = x^3 + b` over `field`, given `3b`.
    #[inline(always)]
    pub fn new(field: F, b3: F::Scalar) -> Self {
        Self {
            field,
            b3: field.constant(b3),
        }
    }

    /// Returns the identity, `(0 : 1 : 0)`.
    #[inline(always)]
    pub fn identity(&self) -> Projective<F::Element> {
        let f = self.field;
        Projective {
            x: f.constant(F::Scalar::ZERO),
            y: f.constant(F::Scalar::ONE),
            z: f.constant(F::Scalar::ZERO),
        }
    }

    /// Returns `p + q` (Algorithm 7).
    #[cfg_attr(not(debug_assertions), inline(always))]
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

    /// Returns `p + q` for an affine `q` (Algorithm 8).
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn add_affine(
        &self,
        p: Projective<F::Element>,
        q: Affine<F::Element>,
    ) -> Projective<F::Element> {
        let f = self.field;
        let t0 = f.mul(p.x, q.x);
        let t1 = f.mul(p.y, q.y);
        let t3 = f.sub(f.mul(f.add(p.x, p.y), f.add(q.x, q.y)), f.add(t0, t1));
        let t4 = f.add(f.mul(q.y, p.z), p.y);
        let xz = f.add(f.mul(q.x, p.z), p.x);
        let t0 = f.add(f.double(t0), t0);
        let t2 = f.mul(self.b3, p.z);
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
    #[cfg_attr(not(debug_assertions), inline(always))]
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

    /// Returns `words * p` for a public little-endian scalar, in variable time.
    #[cfg_attr(not(debug_assertions), inline(always))]
    pub fn mul_public<const N: usize>(
        &self,
        p: Projective<F::Element>,
        words: &[u64; N],
    ) -> Projective<F::Element> {
        let mut result = self.identity();
        let mut started = false;
        for word in words.iter().rev() {
            for bit in (0..64).rev() {
                if started {
                    result = self.double(result);
                }
                if (word >> bit) & 1 == 1 {
                    result = if started { self.add(result, p) } else { p };
                    started = true;
                }
            }
        }
        result
    }

    /// Returns `scalar * p` in constant time with respect to the scalar.
    ///
    /// Fixed four-bit windows index a table of the first sixteen multiples, scanned in full
    /// for every window so the access pattern is independent of the scalar.
    #[cfg_attr(not(debug_assertions), inline(always))]
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

    /// Loads up to `F::LANES` points, one per lane, filling remaining lanes with the identity.
    #[inline(always)]
    pub fn load<'a>(
        &self,
        points: impl IntoIterator<Item = &'a Projective<F::Scalar>>,
    ) -> Projective<F::Element>
    where
        F::Scalar: 'a,
    {
        let f = self.field;
        let mut x = [F::Scalar::ZERO; MAX_LANES];
        let mut y = [F::Scalar::ONE; MAX_LANES];
        let mut z = [F::Scalar::ZERO; MAX_LANES];
        for (lane, point) in points.into_iter().take(F::LANES).enumerate() {
            x[lane] = point.x;
            y[lane] = point.y;
            z[lane] = point.z;
        }
        Projective {
            x: f.load(&x, F::Scalar::ZERO),
            y: f.load(&y, F::Scalar::ONE),
            z: f.load(&z, F::Scalar::ZERO),
        }
    }

    /// Gathers up to `F::LANES` stored points, one per lane.
    ///
    /// Remaining lanes hold all-zero coordinates, which the formulas accept but which callers
    /// must not read back as points.
    #[inline(always)]
    pub fn gather<'a>(
        &self,
        points: impl IntoIterator<Item = &'a Projective<F::Stored>>,
    ) -> Projective<F::Element> {
        let f = self.field;
        let mut x = [F::Stored::default(); MAX_LANES];
        let mut y = [F::Stored::default(); MAX_LANES];
        let mut z = [F::Stored::default(); MAX_LANES];
        for (lane, point) in points.into_iter().take(F::LANES).enumerate() {
            x[lane] = point.x;
            y[lane] = point.y;
            z[lane] = point.z;
        }
        Projective {
            x: f.gather(&x),
            y: f.gather(&y),
            z: f.gather(&z),
        }
    }

    /// Scatters the lanes' points into the outputs, dropping lanes beyond the outputs.
    #[inline(always)]
    pub fn scatter<'a>(
        &self,
        point: Projective<F::Element>,
        outputs: impl IntoIterator<Item = &'a mut Projective<F::Stored>>,
    ) {
        let f = self.field;
        let mut x = [F::Stored::default(); MAX_LANES];
        let mut y = [F::Stored::default(); MAX_LANES];
        let mut z = [F::Stored::default(); MAX_LANES];
        f.scatter(point.x, x.iter_mut());
        f.scatter(point.y, y.iter_mut());
        f.scatter(point.z, z.iter_mut());
        for (lane, output) in outputs.into_iter().take(F::LANES).enumerate() {
            *output = Projective {
                x: x[lane],
                y: y[lane],
                z: z[lane],
            };
        }
    }

    /// Returns the identity in the stored representation.
    #[inline(always)]
    pub fn stored_identity(&self) -> Projective<F::Stored> {
        let mut stored = [Projective {
            x: F::Stored::default(),
            y: F::Stored::default(),
            z: F::Stored::default(),
        }];
        self.scatter(self.identity(), stored.iter_mut());
        stored[0]
    }

    /// Stores the lanes' points, with canonical coordinates, into the outputs, dropping lanes
    /// beyond the outputs' length.
    #[inline(always)]
    pub fn store(&self, point: Projective<F::Element>, outputs: &mut [Projective<F::Scalar>]) {
        let f = self.field;
        let mut x = [F::Scalar::ZERO; MAX_LANES];
        let mut y = [F::Scalar::ZERO; MAX_LANES];
        let mut z = [F::Scalar::ZERO; MAX_LANES];
        f.store(point.x, &mut x);
        f.store(point.y, &mut y);
        f.store(point.z, &mut z);
        for (lane, output) in outputs.iter_mut().take(F::LANES).enumerate() {
            *output = Projective {
                x: x[lane],
                y: y[lane],
                z: z[lane],
            };
        }
    }
}

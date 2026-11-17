//! Secret keys.

use crate::{Secret, curve::ScalarReadCfg};
use bytes::BufMut;
use commonware_codec::{Buf, Error, FixedSize, Read, Write};
use commonware_math::algebra::Random;
use core::fmt::{Debug, Formatter};
use ctutils::CtEq;
use rand_core::CryptoRng;

/// A private key, which is a nonzero scalar `S`.
#[derive(Clone)]
pub struct Private<S> {
    scalar: Secret<S>,
}

impl<S> Debug for Private<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Private")
            .field("scalar", &self.scalar)
            .finish()
    }
}

impl<S: CtEq> PartialEq for Private<S> {
    fn eq(&self, other: &Self) -> bool {
        self.scalar == other.scalar
    }
}

impl<S: CtEq> Eq for Private<S> {}

impl<S> Private<S> {
    /// Creates a new private key from a scalar.
    pub const fn new(private: S) -> Self {
        Self {
            scalar: Secret::new(private),
        }
    }

    /// Temporarily exposes the inner scalar to a closure.
    ///
    /// See [`Secret::expose`](crate::Secret::expose) for more details.
    pub fn expose<R>(&self, f: impl for<'a> FnOnce(&'a S) -> R) -> R {
        self.scalar.expose(f)
    }

    /// Consumes the private key and returns the inner scalar.
    ///
    /// See [`Secret::expose_unwrap`](crate::Secret::expose_unwrap) for more details.
    pub fn expose_unwrap(self) -> S {
        self.scalar.expose_unwrap()
    }
}

impl<S: Write> Write for Private<S> {
    fn write(&self, buf: &mut impl BufMut) {
        self.expose(|scalar| scalar.write(buf));
    }
}

impl<S: Read<Cfg = ScalarReadCfg>> Read for Private<S> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let scalar = S::read_cfg(buf, &ScalarReadCfg::RejectZero)?;
        Ok(Self::new(scalar))
    }
}

impl<S: FixedSize> FixedSize for Private<S> {
    const SIZE: usize = S::SIZE;
}

impl<S: Random> Random for Private<S> {
    fn random(rng: impl CryptoRng) -> Self {
        Self::new(S::random(rng))
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, S: arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a> for Private<S> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self::new(u.arbitrary::<S>()?))
    }
}

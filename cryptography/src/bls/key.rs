//! Secret keys and shares of them.

use super::variant::{ScalarReadCfg, Variant};
use crate::Secret;
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, FixedSize, Read, ReadExt as _, Write};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_utils::Participant;
use core::fmt::{Debug, Display, Formatter};
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

/// A share of a BLS threshold signing key.
#[derive(Clone)]
pub struct Share<S> {
    /// The share's index in the polynomial.
    pub index: Participant,
    /// The scalar corresponding to the share's secret.
    pub private: Private<S>,
}

impl<S> Debug for Share<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Share")
            .field("index", &self.index)
            .field("private", &self.private)
            .finish()
    }
}

impl<S: CtEq> PartialEq for Share<S> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index && self.private == other.private
    }
}

impl<S: CtEq> Eq for Share<S> {}

impl<S> Share<S> {
    /// Creates a new `Share` with the given index and private key.
    pub const fn new(index: Participant, private: Private<S>) -> Self {
        Self { index, private }
    }

    /// Returns the public key corresponding to the share.
    ///
    /// This can be verified against the public polynomial.
    pub fn public<V: Variant<Scalar = S>>(&self) -> V::Public {
        self.private
            .expose(|private| V::Public::generator() * private)
    }
}

impl<S: Write> Write for Share<S> {
    fn write(&self, buf: &mut impl BufMut) {
        self.index.write(buf);
        self.private.write(buf);
    }
}

impl<S: Read<Cfg = ScalarReadCfg>> Read for Share<S> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        let index = Participant::read(buf)?;
        let private = Private::read(buf)?;
        Ok(Self { index, private })
    }
}

impl<S: EncodeSize> EncodeSize for Share<S> {
    fn encode_size(&self) -> usize {
        self.index.encode_size() + self.private.expose(|private| private.encode_size())
    }
}

impl<S> Display for Share<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, S: arbitrary::Arbitrary<'a>> arbitrary::Arbitrary<'a> for Share<S> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let index = u.arbitrary()?;
        let private = u.arbitrary::<Private<S>>()?;
        Ok(Self { index, private })
    }
}

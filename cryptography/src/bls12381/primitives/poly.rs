//! Polynomial operations over the BLS12-381 scalar field.
//!
//! # Warning
//!
//! The security of the polynomial operations is critical for the overall
//! security of the threshold schemes. Ensure that the scalar field operations
//! are performed over the correct field and that all elements are valid.

use super::variant::Variant;
use crate::bls12381::primitives::group::{self, Element};
use bytes::{Buf, BufMut};
use commonware_codec::{varint::UInt, EncodeSize, Error as CodecError, Read, ReadExt, Write};
pub use commonware_math::poly::Poly;
use core::hash::Hash;

/// Private polynomials are used to generate secret shares.
pub type Private = Poly<group::Private>;

/// Public polynomials represent commitments to secrets on a private polynomial.
pub type Public<V> = Poly<<V as Variant>::Public>;

/// Signature polynomials are used in threshold signing (where a signature
/// is interpolated using at least `threshold` evaluations).
pub type Signature<V> = Poly<<V as Variant>::Signature>;

/// The partial signature type.
pub type PartialSignature<V> = Eval<<V as Variant>::Signature>;

/// A polynomial evaluation at a specific index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Eval<C: Element> {
    pub index: u32,
    pub value: C,
}

impl<C: Element> Write for Eval<C> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.value.write(buf);
    }
}

impl<C: Element> Read for Eval<C> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let index = UInt::read(buf)?.into();
        let value = C::read(buf)?;
        Ok(Self { index, value })
    }
}

impl<C: Element> EncodeSize for Eval<C> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + C::SIZE
    }
}

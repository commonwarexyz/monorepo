//! Polynomial operations over the BLS12-381 scalar field.
//!
//! # Warning
//!
//! The security of the polynomial operations is critical for the overall
//! security of the threshold schemes. Ensure that the scalar field operations
//! are performed over the correct field and that all elements are valid.

use super::variant::Variant;
use crate::bls12381::primitives::group;
use bytes::{Buf, BufMut};
use commonware_codec::{
    varint::UInt, EncodeSize, Error as CodecError, FixedSize, Read, ReadExt, Write,
};
pub use commonware_math::poly::Poly;

/// Private polynomials are used to generate secret shares.
pub type Private = Poly<group::Private>;

/// Public polynomials represent commitments to secrets on a private polynomial.
pub type Public<V> = Poly<<V as Variant>::Public>;

/// Signature polynomials are used in threshold signing (where a signature
/// is interpolated using at least `threshold` evaluations).
pub type Signature<V> = Poly<<V as Variant>::Signature>;

/// A polynomial evaluation at a specific index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartialSignature<V: Variant> {
    pub index: u32,
    pub value: V::Signature,
}

impl<V: Variant> Write for PartialSignature<V> {
    fn write(&self, buf: &mut impl BufMut) {
        UInt(self.index).write(buf);
        self.value.write(buf);
    }
}

impl<V: Variant> Read for PartialSignature<V> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let index = UInt::read(buf)?.into();
        let value = V::Signature::read(buf)?;
        Ok(Self { index, value })
    }
}

impl<V: Variant> EncodeSize for PartialSignature<V> {
    fn encode_size(&self) -> usize {
        UInt(self.index).encode_size() + V::Signature::SIZE
    }
}

#[cfg(feature = "arbitrary")]
impl<'a, V: Variant> arbitrary::Arbitrary<'a> for PartialSignature<V> {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        use commonware_math::algebra::HashToGroup;
        use rand::SeedableRng;

        let index: u32 = u.int_in_range(0..=99)?;
        Ok(Self {
            index,
            value: V::Signature::rand_to_group(&mut rand::rngs::StdRng::seed_from_u64(
                u.arbitrary()?,
            )),
        })
    }
}

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, ReadExt, Write};
use commonware_consensus::{marshal::core::Variant, simplex::types::Finalization};
use commonware_cryptography::certificate::Scheme;

pub(crate) enum Tag {
    Request,
    Response,
}

impl Tag {
    pub(crate) fn read(reader: &mut impl Buf) -> Result<Self, Error> {
        match u8::read(reader)? {
            0 => Ok(Self::Request),
            1 => Ok(Self::Response),
            n => Err(Error::InvalidEnum(n)),
        }
    }
}

/// A message exchanged with peers over the p2p channel during bootstrap.
pub(crate) enum Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    /// Request the receiver's latest [`Finalization`].
    Request,
    /// A [`Finalization`], sent in response to a [`Message::Request`].
    Response(Finalization<S, V::Commitment>),
}

impl<S, V> Write for Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Request => {
                0u8.write(writer);
            }
            Self::Response(finalization) => {
                1u8.write(writer);
                finalization.write(writer);
            }
        }
    }
}

impl<S, V> EncodeSize for Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Request => 0,
            Self::Response(finalization) => finalization.encode_size(),
        }
    }
}

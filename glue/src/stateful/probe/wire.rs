pub(crate) use crate::probe::wire::Tag;
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::simplex::{marshal::core::Variant, types::Finalization};
use commonware_cryptography::certificate::Scheme;

/// A message exchanged with peers over the probe p2p channel.
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
                Tag::Request.write(writer);
            }
            Self::Response(finalization) => {
                Tag::Response.write(writer);
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

impl<S, V> Read for Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    type Cfg = <S::Certificate as Read>::Cfg;

    fn read_cfg(reader: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, Error> {
        match Tag::read(reader)? {
            Tag::Request => Ok(Self::Request),
            Tag::Response => Ok(Self::Response(Finalization::read_cfg(reader, cfg)?)),
        }
    }
}

#[cfg(feature = "arbitrary")]
impl<S, V> arbitrary::Arbitrary<'_> for Message<S, V>
where
    S: Scheme,
    V: Variant,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    V::Commitment: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let tag = Tag::arbitrary(u)?;
        Ok(match tag {
            Tag::Request => Self::Request,
            Tag::Response => Self::Response(Finalization::arbitrary(u)?),
        })
    }
}

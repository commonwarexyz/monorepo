use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{
    marshal::core::Variant,
    simplex::{scheme::Scheme, types::Finalization},
    types::Epoch,
};

/// First byte of a anchor boundary message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) enum Tag {
    /// Request the finalized boundary block and finalization for an epoch.
    Request,
    /// Response carrying the finalized boundary block and finalization.
    Response,
}

impl FixedSize for Tag {
    const SIZE: usize = u8::SIZE;
}

impl Write for Tag {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Request => 0u8.write(writer),
            Self::Response => 1u8.write(writer),
        }
    }
}

impl Read for Tag {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(reader)? {
            0 => Ok(Self::Request),
            1 => Ok(Self::Response),
            n => Err(Error::InvalidEnum(n)),
        }
    }
}

/// Boundary response decoded from a peer.
pub(crate) struct Response<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    pub(crate) finalization: Finalization<S, V::Commitment>,
    pub(crate) block: V::Block,
}

/// Anchor boundary request/response.
pub(crate) enum Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    /// Request the finalized boundary block and finalization for `epoch`.
    Request(Epoch),
    /// Respond with the finalized boundary block and finalization.
    Response(Response<S, V>),
}

impl<S, V> Write for Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Request(epoch) => {
                Tag::Request.write(writer);
                epoch.write(writer);
            }
            Self::Response(response) => {
                Tag::Response.write(writer);
                response.finalization.write(writer);
                response.block.write(writer);
            }
        }
    }
}

impl<S, V> EncodeSize for Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    fn encode_size(&self) -> usize {
        Tag::SIZE
            + match self {
                Self::Request(epoch) => epoch.encode_size(),
                Self::Response(response) => {
                    response.finalization.encode_size() + response.block.encode_size()
                }
            }
    }
}

#[cfg(feature = "arbitrary")]
impl<S, V> arbitrary::Arbitrary<'_> for Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    S::Certificate: for<'a> arbitrary::Arbitrary<'a>,
    V::Commitment: for<'a> arbitrary::Arbitrary<'a>,
    V::Block: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        Ok(match Tag::arbitrary(u)? {
            Tag::Request => Self::Request(Epoch::arbitrary(u)?),
            Tag::Response => Self::Response(Response {
                finalization: Finalization::arbitrary(u)?,
                block: V::Block::arbitrary(u)?,
            }),
        })
    }
}

/// Decode a boundary request.
pub(crate) fn read_request(mut reader: impl Buf) -> Result<Option<Epoch>, Error> {
    let tag = Tag::read(&mut reader)?;
    if tag != Tag::Request {
        return Ok(None);
    }
    Ok(Some(Epoch::read(&mut reader)?))
}

/// Decode a boundary response.
pub(crate) fn read_response<S, V>(
    mut reader: impl Buf,
    certificate_cfg: &<S::Certificate as Read>::Cfg,
    block_codec_config: &<V::ApplicationBlock as Read>::Cfg,
) -> Result<Option<Response<S, V>>, Error>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    let tag = Tag::read(&mut reader)?;
    if tag != Tag::Response {
        return Ok(None);
    }

    let finalization = Finalization::read_cfg(&mut reader, certificate_cfg)?;
    let block_cfg = V::block_cfg(block_codec_config, finalization.proposal.payload);
    let block = V::Block::read_cfg(&mut reader, &block_cfg)?;

    Ok(Some(Response {
        finalization,
        block,
    }))
}

#[cfg(all(test, feature = "arbitrary"))]
mod tests {
    use super::{Message, Tag};
    use crate::dkg::tests::mocks;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<Tag>,
        CodecConformance<Message<mocks::TestScheme, mocks::TestMarshalVariant>>,
    }
}

//! Wire format of DKG probe messages.

use bytes::BufMut;
use commonware_codec::{
    Buf, Decode, DecodeExt, EncodeSize, Error, FixedSize, Read, ReadExt, Write,
};
use commonware_consensus::{
    marshal::core::{ExpectedCommitment, Variant},
    simplex::{scheme::Scheme, types::Finalization},
    types::Epoch,
};
use commonware_parallel::Sequential;

/// First byte of a DKG probe message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) enum Tag {
    /// Request the boundary finalization for an epoch.
    BoundaryRequest,
    /// Response carrying a boundary finalization.
    BoundaryResponse,
    /// Request the boundary block for an epoch.
    BlockRequest,
    /// Response carrying a finalized block.
    BlockResponse,
    /// Request the receiver's latest finalization.
    LatestRequest,
    /// Response carrying the receiver's latest finalization.
    LatestResponse,
}

impl FixedSize for Tag {
    const SIZE: usize = u8::SIZE;
}

impl Write for Tag {
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::BoundaryRequest => 0u8.write(writer),
            Self::BoundaryResponse => 1u8.write(writer),
            Self::BlockRequest => 2u8.write(writer),
            Self::BlockResponse => 3u8.write(writer),
            Self::LatestRequest => 4u8.write(writer),
            Self::LatestResponse => 5u8.write(writer),
        }
    }
}

impl Read for Tag {
    type Cfg = ();

    fn read_cfg(reader: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(reader)? {
            0 => Ok(Self::BoundaryRequest),
            1 => Ok(Self::BoundaryResponse),
            2 => Ok(Self::BlockRequest),
            3 => Ok(Self::BlockResponse),
            4 => Ok(Self::LatestRequest),
            5 => Ok(Self::LatestResponse),
            n => Err(Error::InvalidEnum(n)),
        }
    }
}

/// Request decoded from a peer.
pub(crate) enum Request {
    /// Request the boundary finalization for an epoch.
    Boundary(Epoch),
    /// Request the boundary block for an epoch.
    Block(Epoch),
    /// Request the receiver's latest finalization.
    Latest,
}

/// Response decoded from a peer.
pub(crate) enum Response<S, V, R>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    /// Boundary finalization response.
    Boundary(Finalization<S, V::Commitment>),
    /// Block response whose body remains encoded until the epoch and responding
    /// peer match the outstanding request.
    Block {
        /// Epoch echoed from the request.
        epoch: Epoch,
        /// Encoded block body.
        body: R,
    },
    /// Latest finalization response.
    Latest(Finalization<S, V::Commitment>),
}

/// DKG probe protocol message.
pub(crate) enum Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    /// Request for the finalization of `epoch`'s boundary block.
    BoundaryRequest(Epoch),
    /// Finalization of a requested boundary block.
    BoundaryResponse(Finalization<S, V::Commitment>),
    /// Request for `epoch`'s boundary block.
    BlockRequest(Epoch),
    /// A requested boundary block.
    BlockResponse {
        /// Epoch echoed from the request.
        epoch: Epoch,
        /// Boundary block of `epoch`.
        block: V::Block,
    },
    /// Request for the receiver's latest finalization.
    LatestRequest,
    /// The receiver's latest finalization.
    LatestResponse(Finalization<S, V::Commitment>),
}

impl<S, V> Write for Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::BoundaryRequest(epoch) => {
                Tag::BoundaryRequest.write(writer);
                epoch.write(writer);
            }
            Self::BoundaryResponse(finalization) => {
                Tag::BoundaryResponse.write(writer);
                finalization.write(writer);
            }
            Self::BlockRequest(epoch) => {
                Tag::BlockRequest.write(writer);
                epoch.write(writer);
            }
            Self::BlockResponse { epoch, block } => {
                Tag::BlockResponse.write(writer);
                epoch.write(writer);
                block.write(writer);
            }
            Self::LatestRequest => {
                Tag::LatestRequest.write(writer);
            }
            Self::LatestResponse(finalization) => {
                Tag::LatestResponse.write(writer);
                finalization.write(writer);
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
                Self::BoundaryRequest(epoch) => epoch.encode_size(),
                Self::BoundaryResponse(finalization) => finalization.encode_size(),
                Self::BlockRequest(epoch) => epoch.encode_size(),
                Self::BlockResponse { epoch, block } => epoch.encode_size() + block.encode_size(),
                Self::LatestRequest => 0,
                Self::LatestResponse(finalization) => finalization.encode_size(),
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
            Tag::BoundaryRequest => Self::BoundaryRequest(Epoch::arbitrary(u)?),
            Tag::BoundaryResponse => Self::BoundaryResponse(Finalization::arbitrary(u)?),
            Tag::BlockRequest => Self::BlockRequest(Epoch::arbitrary(u)?),
            Tag::BlockResponse => Self::BlockResponse {
                epoch: Epoch::arbitrary(u)?,
                block: V::Block::arbitrary(u)?,
            },
            Tag::LatestRequest => Self::LatestRequest,
            Tag::LatestResponse => Self::LatestResponse(Finalization::arbitrary(u)?),
        })
    }
}

/// Decodes a request, returning `Ok(None)` if the tag names a response.
pub(crate) fn read_request(mut reader: impl Buf) -> Result<Option<Request>, Error> {
    let tag = Tag::read(&mut reader)?;
    match tag {
        Tag::BoundaryRequest => Ok(Some(Request::Boundary(Epoch::decode(reader)?))),
        Tag::BlockRequest => Ok(Some(Request::Block(Epoch::decode(reader)?))),
        Tag::LatestRequest => Ok(Some(Request::Latest)),
        Tag::BoundaryResponse | Tag::BlockResponse | Tag::LatestResponse => Ok(None),
    }
}

/// Decodes a response, returning `Ok(None)` if the tag names a request.
///
/// A block response's body stays encoded (see [`read_block`]).
pub(crate) fn read_response<S, V, R>(
    mut reader: R,
    certificate_cfg: &<S::Certificate as Read>::Cfg,
) -> Result<Option<Response<S, V, R>>, Error>
where
    S: Scheme<V::Commitment>,
    V: Variant,
    R: Buf,
{
    let tag = Tag::read(&mut reader)?;
    match tag {
        Tag::BoundaryResponse => Ok(Some(Response::Boundary(Finalization::decode_cfg(
            reader,
            certificate_cfg,
        )?))),
        Tag::BlockResponse => Ok(Some(Response::Block {
            epoch: Epoch::read(&mut reader)?,
            body: reader,
        })),
        Tag::LatestResponse => Ok(Some(Response::Latest(Finalization::decode_cfg(
            reader,
            certificate_cfg,
        )?))),
        Tag::BoundaryRequest | Tag::BlockRequest | Tag::LatestRequest => Ok(None),
    }
}

/// Decodes a block response body against `commitment`, the payload of a verified
/// finalization.
pub(crate) fn read_block<V>(
    reader: impl Buf,
    commitment: V::Commitment,
    block_codec_config: &<V::ApplicationBlock as Read>::Cfg,
) -> Result<V::Block, Error>
where
    V: Variant,
{
    V::decode_block(
        reader,
        block_codec_config,
        ExpectedCommitment::Trusted(commitment),
        &Sequential,
    )
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

use bytes::Buf;
use commonware_codec::{Decode, DecodeExt, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{
    marshal::core::Variant,
    simplex::{scheme::Scheme, types::Finalization},
    types::Epoch,
};

/// First byte of a DKG probe message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Read, Write)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) enum Tag {
    /// Request the boundary finalization for an epoch.
    #[codec(tag = 0)]
    BoundaryRequest,
    /// Response carrying a boundary finalization.
    #[codec(tag = 1)]
    BoundaryResponse,
    /// Request the boundary block for an epoch.
    #[codec(tag = 2)]
    BlockRequest,
    /// Response carrying a finalized block.
    #[codec(tag = 3)]
    BlockResponse,
    /// Request the receiver's latest finalization.
    #[codec(tag = 4)]
    LatestRequest,
    /// Response carrying the receiver's latest finalization.
    #[codec(tag = 5)]
    LatestResponse,
}

impl FixedSize for Tag {
    const SIZE: usize = u8::SIZE;
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
    /// Finalized block response. The body remains encoded until the epoch and
    /// responding peer match the outstanding request.
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
#[derive(EncodeSize, Write)]
pub(crate) enum Message<S, V>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    /// Request the boundary finalization for `epoch`.
    #[codec(tag = 0)]
    BoundaryRequest(Epoch),
    /// Respond with a boundary finalization.
    #[codec(tag = 1)]
    BoundaryResponse(Finalization<S, V::Commitment>),
    /// Request the boundary block for `epoch`.
    #[codec(tag = 2)]
    BlockRequest(Epoch),
    /// Respond with a finalized block.
    #[codec(tag = 3)]
    BlockResponse {
        /// Epoch echoed from the request.
        epoch: Epoch,
        /// Requested finalized block.
        block: V::Block,
    },
    /// Request the receiver's latest finalization.
    #[codec(tag = 4)]
    LatestRequest,
    /// Respond with the receiver's latest finalization.
    #[codec(tag = 5)]
    LatestResponse(Finalization<S, V::Commitment>),
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

/// Decode a boundary protocol request.
pub(crate) fn read_request(mut reader: impl Buf) -> Result<Option<Request>, Error> {
    let tag = Tag::read(&mut reader)?;
    match tag {
        Tag::BoundaryRequest => Ok(Some(Request::Boundary(Epoch::decode(reader)?))),
        Tag::BlockRequest => Ok(Some(Request::Block(Epoch::decode(reader)?))),
        Tag::LatestRequest => Ok(Some(Request::Latest)),
        Tag::BoundaryResponse | Tag::BlockResponse | Tag::LatestResponse => Ok(None),
    }
}

/// Decode a boundary protocol response.
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

/// Decode the body of a block response using its authenticated commitment.
pub(crate) fn read_block<V>(
    reader: impl Buf,
    commitment: V::Commitment,
    block_codec_config: &<V::ApplicationBlock as Read>::Cfg,
) -> Result<V::Block, Error>
where
    V: Variant,
{
    let block_cfg = V::block_cfg(block_codec_config, commitment);
    V::Block::decode_cfg(reader, &block_cfg)
}

#[cfg(all(test, feature = "arbitrary"))]
mod tests {
    use super::{Message, Tag};
    use crate::dkg::tests::mocks;
    use commonware_codec::{Encode, conformance::CodecConformance};
    use commonware_consensus::types::Epoch;

    commonware_conformance::conformance_tests! {
        CodecConformance<Tag>,
        CodecConformance<Message<mocks::TestScheme, mocks::TestMarshalVariant>>,
    }

    #[test]
    fn test_message_tag_lockstep() {
        type TestMessage = Message<mocks::TestScheme, mocks::TestMarshalVariant>;
        let epoch = Epoch::new(1);
        let pairs = [
            (TestMessage::BoundaryRequest(epoch), Tag::BoundaryRequest),
            (TestMessage::BlockRequest(epoch), Tag::BlockRequest),
            (TestMessage::LatestRequest, Tag::LatestRequest),
        ];
        for (message, tag) in pairs {
            assert_eq!(message.encode()[0], tag.encode()[0]);
        }
    }
}

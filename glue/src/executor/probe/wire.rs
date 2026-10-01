//! Messages exchanged over the probe's channel.

use super::Checkpoint;
pub(super) use crate::probe::wire::Tag;
use bytes::BufMut;
use commonware_codec::{Buf, Codec, EncodeSize, Error, FixedSize, Read, ReadExt as _, Write};
use commonware_consensus::{
    Block,
    aggregation::{scheme::Scheme, types::Certificate},
};
use std::sync::Arc;

/// A message exchanged with peers over the probe's channel.
pub(super) enum Message<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
{
    /// Asks for the receiver's newest checkpoint.
    Request,
    /// The sender's newest checkpoint.
    Response(Checkpoint<S, B, F>),
}

impl<S, B, F> Write for Message<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Codec,
{
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::Request => Tag::Request.write(writer),
            Self::Response(checkpoint) => {
                Tag::Response.write(writer);
                checkpoint.certificate.write(writer);
                checkpoint.block.write(writer);
                checkpoint.floor.write(writer);
            }
        }
    }
}

impl<S, B, F> EncodeSize for Message<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Codec,
{
    fn encode_size(&self) -> usize {
        Tag::SIZE
            + match self {
                Self::Request => 0,
                Self::Response(checkpoint) => {
                    checkpoint.certificate.encode_size()
                        + checkpoint.block.encode_size()
                        + checkpoint.floor.encode_size()
                }
            }
    }
}

impl<S, B, F> Read for Message<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Codec,
{
    /// The codec configurations of the certificate, the block, and the floor.
    type Cfg = (<S::Certificate as Read>::Cfg, B::Cfg, F::Cfg);

    fn read_cfg(
        reader: &mut impl Buf,
        (certificate, block, floor): &Self::Cfg,
    ) -> Result<Self, Error> {
        match Tag::read(reader)? {
            Tag::Request => Ok(Self::Request),
            Tag::Response => Ok(Self::Response(Checkpoint {
                certificate: Certificate::read_cfg(reader, certificate)?,
                block: Arc::new(B::read_cfg(reader, block)?),
                floor: Option::<F>::read_cfg(reader, floor)?,
            })),
        }
    }
}

impl<S, B, F> Message<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block,
    F: Codec,
{
    /// Returns the codec configuration of a message whose certificates `scheme` verifies.
    pub(super) fn codec(scheme: &S, block: B::Cfg, floor: F::Cfg) -> <Self as Read>::Cfg {
        (scheme.certificate_codec_config(), block, floor)
    }
}

#[cfg(feature = "arbitrary")]
impl<S, B, F> arbitrary::Arbitrary<'_> for Message<S, B, F>
where
    S: Scheme<B::Digest>,
    B: Block + for<'a> arbitrary::Arbitrary<'a>,
    F: for<'a> arbitrary::Arbitrary<'a>,
    Certificate<S, B::Digest>: for<'a> arbitrary::Arbitrary<'a>,
{
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            return Ok(Self::Request);
        }
        Ok(Self::Response(Checkpoint {
            certificate: u.arbitrary()?,
            block: Arc::new(u.arbitrary()?),
            floor: u.arbitrary()?,
        }))
    }
}

use commonware_codec::{EncodeSize, FixedSize, Read, Write};
use commonware_consensus::{marshal::core::Variant, simplex::types::Finalization};
use commonware_cryptography::certificate::Scheme;

/// The first byte of a probe wire message.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Read, Write)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) enum Tag {
    /// A request for the receiver's latest finalization.
    #[codec(tag = 0)]
    Request,
    /// A response carrying a finalization payload.
    #[codec(tag = 1)]
    Response,
}

impl FixedSize for Tag {
    const SIZE: usize = u8::SIZE;
}

/// A message exchanged with peers over the probe p2p channel.
#[derive(EncodeSize, Read, Write)]
pub(crate) enum Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    /// Request the receiver's latest [`Finalization`].
    #[codec(tag = 0)]
    Request,
    /// A [`Finalization`], sent in response to a [`Message::Request`].
    #[codec(tag = 1)]
    Response(#[codec(cfg)] Finalization<S, V::Commitment>),
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

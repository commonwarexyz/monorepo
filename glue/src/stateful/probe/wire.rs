use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, FixedSize, Read, ReadExt, Write};
use commonware_consensus::{marshal::core::Variant, simplex::types::Finalization};
use commonware_cryptography::certificate::Scheme;

/// The first byte of a probe wire message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) enum Tag {
    /// A request for the receiver's latest finalization.
    Request,
    /// A response carrying a finalization payload.
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

    fn read_cfg(reader: &mut impl Buf, _: &Self::Cfg) -> Result<Self, Error> {
        match u8::read(reader)? {
            0 => Ok(Self::Request),
            1 => Ok(Self::Response),
            n => Err(Error::InvalidEnum(n)),
        }
    }
}

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
        Tag::SIZE
            + match self {
                Self::Request => 0,
                Self::Response(finalization) => finalization.encode_size(),
            }
    }
}

impl<S, V> Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    /// Returns the largest encoded size of a message for committees of at most `participants`, or
    /// `None` if `S` cannot bound certificates for `participants` or the size overflows.
    pub fn max_encode_size(participants: usize) -> Option<usize> {
        // After its tag, a request carries nothing and a response a finalization.
        let finalization = Finalization::<S, V::Commitment>::max_encode_size(participants)?;
        Tag::SIZE.checked_add(finalization)
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

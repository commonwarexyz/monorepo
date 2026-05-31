use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error, Read, ReadExt, Write};
use commonware_consensus::{marshal::core::Variant, simplex::types::Finalization};
use commonware_cryptography::certificate::Scheme;

/// A message exchanged with peers over the p2p channel during floor discovery.
pub(crate) enum Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    /// Request the receiver's latest [`Finalization`].
    RequestLatest,
    /// A [`Finalization`], sent in response to a [`Message::RequestLatest`].
    Finalization(Finalization<S, V::Commitment>),
}

impl<S, V> Write for Message<S, V>
where
    S: Scheme,
    V: Variant,
{
    fn write(&self, writer: &mut impl BufMut) {
        match self {
            Self::RequestLatest => {
                0u8.write(writer);
            }
            Self::Finalization(finalization) => {
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
            Self::RequestLatest => 0,
            Self::Finalization(finalization) => finalization.encode_size(),
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
        match u8::read(reader)? {
            0 => Ok(Self::RequestLatest),
            1 => Ok(Self::Finalization(Finalization::read_cfg(reader, cfg)?)),
            n => Err(Error::InvalidEnum(n)),
        }
    }
}

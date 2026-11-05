//! What peers request from the resolver.

use crate::{
    multimmit::types::ChainId,
    types::{Height, View},
};
use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error, Read, ReadExt as _, Write};
use commonware_utils::Span;
use core::fmt;

/// One request a peer serves: a view proof, or a chain's DA certificate.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ResolverKey {
    /// A proof of how a view ended: its V-QC or nullification, or an L-QC at or above it.
    View(View),
    /// The DA certificate of `chain` the server holds durably, if it is above `after`.
    ///
    /// The server answers with its newest certificate, not one at an exact height: lower ones are
    /// compacted once a higher one is durable.
    Certificate {
        /// The requested chain.
        chain: ChainId,
        /// The height the certificate must be above.
        after: Height,
    },
}

impl Write for ResolverKey {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::View(view) => {
                0u8.write(buf);
                view.write(buf);
            }
            Self::Certificate { chain, after } => {
                1u8.write(buf);
                chain.write(buf);
                after.write(buf);
            }
        }
    }
}

impl EncodeSize for ResolverKey {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::View(view) => view.encode_size(),
            Self::Certificate { chain, after } => chain.encode_size() + after.encode_size(),
        }
    }
}

impl Read for ResolverKey {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::View(View::read(buf)?)),
            1 => Ok(Self::Certificate {
                chain: ChainId::read(buf)?,
                after: Height::read(buf)?,
            }),
            tag => Err(Error::InvalidEnum(tag)),
        }
    }
}

impl fmt::Display for ResolverKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::View(view) => write!(f, "view {view}"),
            Self::Certificate { chain, after } => {
                write!(f, "certificate of chain {} above {after}", chain.get())
            }
        }
    }
}

impl Span for ResolverKey {}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for ResolverKey {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        if u.arbitrary()? {
            return Ok(Self::View(View::new(u.arbitrary()?)));
        }
        Ok(Self::Certificate {
            chain: ChainId::new(u.arbitrary()?),
            after: Height::new(u.arbitrary()?),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt as _, Encode as _};

    #[test]
    fn keys_round_trip_and_reject_unknown_tags() {
        for key in [
            ResolverKey::View(View::new(7)),
            ResolverKey::Certificate {
                chain: ChainId::new(3),
                after: Height::new(11),
            },
        ] {
            assert_eq!(ResolverKey::decode(key.encode()).unwrap(), key);
        }
        assert!(matches!(
            ResolverKey::decode(bytes::Bytes::from_static(&[2, 0])),
            Err(Error::InvalidEnum(2))
        ));
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::ResolverKey;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<ResolverKey> => 128,
        }
    }
}

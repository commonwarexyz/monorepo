//! Request and response tags shared by finalization and checkpoint probes.

use bytes::BufMut;
use commonware_codec::{Buf, Error, FixedSize, Read, ReadExt as _, Write};

/// The first byte of a probe wire message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub(crate) enum Tag {
    /// A request for the receiver's latest certified state.
    Request,
    /// A response carrying the receiver's latest certified state.
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

#[cfg(all(test, feature = "arbitrary"))]
mod conformance {
    use super::Tag;
    use commonware_codec::conformance::CodecConformance;

    commonware_conformance::conformance_tests! {
        CodecConformance<Tag>,
    }
}

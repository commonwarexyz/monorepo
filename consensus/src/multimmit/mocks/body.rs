//! A minimal application body for codec and block tests.

use bytes::BufMut;
use commonware_codec::{Buf, EncodeSize, Error as CodecError, Read, ReadExt, Write};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest as Sha256Digest};

/// An application body holding one `u64`, identified by the SHA-256 digest of its big-endian
/// bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MockBody(pub u64);

impl Write for MockBody {
    fn write(&self, buf: &mut impl BufMut) {
        self.0.write(buf);
    }
}

impl Read for MockBody {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        Ok(Self(u64::read(buf)?))
    }
}

impl EncodeSize for MockBody {
    fn encode_size(&self) -> usize {
        self.0.encode_size()
    }
}

impl Digestible for MockBody {
    type Digest = Sha256Digest;

    fn digest(&self) -> Self::Digest {
        Sha256::hash(&[&self.0.to_be_bytes()])
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for MockBody {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

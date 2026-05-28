//! A `u64` encoded with the same framing as a `Vec<u8>` of its big-endian bytes.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, FixedSize, Read, Write};

/// A `u64` encoded with the same framing as a `Vec<u8>` of its big-endian bytes.
///
/// The encoding is a varint length of 8 followed by the 8 big-endian bytes, byte-identical to the
/// codec encoding of a `Vec<u8>` holding those bytes. This lets a typed `u64` share an on-disk
/// format with a value historically stored as a `Vec<u8>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[cfg_attr(feature = "arbitrary", derive(arbitrary::Arbitrary))]
pub struct VecU64(u64);

impl VecU64 {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }
}

impl From<u64> for VecU64 {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<VecU64> for u64 {
    fn from(value: VecU64) -> Self {
        value.0
    }
}

impl From<&VecU64> for u64 {
    fn from(value: &VecU64) -> Self {
        value.0
    }
}

impl Write for VecU64 {
    fn write(&self, buf: &mut impl BufMut) {
        let bytes = self.0.to_be_bytes();
        bytes.len().write(buf);
        buf.put_slice(&bytes);
    }
}

impl EncodeSize for VecU64 {
    fn encode_size(&self) -> usize {
        let bytes = self.0.to_be_bytes();
        bytes.len().encode_size() + bytes.len()
    }
}

impl Read for VecU64 {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let len = usize::read_cfg(buf, &(u64::SIZE..=u64::SIZE).into())?;
        if buf.remaining() < len {
            return Err(CodecError::EndOfBuffer);
        }
        let mut bytes = [0u8; u64::SIZE];
        buf.copy_to_slice(&mut bytes);
        Ok(Self(u64::from_be_bytes(bytes)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn test_vec_u64_matches_vec_encoding() {
        for value in [0u64, 1, 42, u64::MAX] {
            let encoded = VecU64(value).encode();
            assert_eq!(encoded, value.to_be_bytes().to_vec().encode());
            assert_eq!(u64::from(VecU64::decode(encoded).unwrap()), value);
        }
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<VecU64>,
        }
    }
}

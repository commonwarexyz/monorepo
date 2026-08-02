//! Dense ordered-delivery coordinates and application updates.

use crate::Block;
use commonware_codec::{FixedSize, Read, ReadExt, Write};
use commonware_utils::{Acknowledgement, acknowledgement::Exact};
use std::{fmt, sync::Arc};

/// A local coordinate in the dense application delivery stream.
///
/// The index is assigned after Multimmit's cross-chain ordering is reconstructed. It is not a
/// consensus view or a producer-chain height.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OutputIndex(u64);

impl OutputIndex {
    /// The first output in a stream.
    pub const ZERO: Self = Self(0);

    /// Creates an output index.
    pub const fn new(index: u64) -> Self {
        Self(index)
    }

    /// Returns the underlying index.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Returns the next index, or `None` at the end of the coordinate space.
    pub const fn next(self) -> Option<Self> {
        match self.0.checked_add(1) {
            Some(index) => Some(Self(index)),
            None => None,
        }
    }
}

impl fmt::Display for OutputIndex {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl Write for OutputIndex {
    fn write(&self, buf: &mut impl bytes::BufMut) {
        self.0.write(buf);
    }
}

impl FixedSize for OutputIndex {
    const SIZE: usize = u64::SIZE;
}

impl Read for OutputIndex {
    type Cfg = ();

    fn read_cfg(buf: &mut impl bytes::Buf, _: &()) -> Result<Self, commonware_codec::Error> {
        Ok(Self(u64::read(buf)?))
    }
}

/// One complete block in the finalized application stream.
#[derive(Clone, Debug)]
pub enum Update<B: Block, A: Acknowledgement = Exact> {
    /// A block at the exact next dense output index.
    Block {
        /// Marshal-local dense coordinate.
        index: OutputIndex,
        /// Complete block, including its protocol-defined header and opaque application body.
        block: Arc<B>,
        /// Acknowledged after the application has durably applied the block.
        acknowledgement: A,
    },
}

#[cfg(feature = "arbitrary")]
impl<'a> arbitrary::Arbitrary<'a> for OutputIndex {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self(u.arbitrary()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{DecodeExt, Encode};

    #[test]
    fn output_index_round_trip_and_overflow() {
        let index = OutputIndex::new(41);
        assert_eq!(OutputIndex::decode(index.encode()).unwrap(), index);
        assert_eq!(index.next(), Some(OutputIndex::new(42)));
        assert_eq!(OutputIndex::new(u64::MAX).next(), None);
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<OutputIndex> => 1024,
        }
    }
}

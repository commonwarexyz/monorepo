//! Mock implementations for testing.

use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadRangeExt, Write};
use commonware_cryptography::{sha256::Digest, Digestible, Hasher, Sha256};
use commonware_runtime::{Buf, BufMut};

/// A simple test message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestMessage {
    // The commitment of the message.
    pub commitment: Vec<u8>,

    /// The content of the message.
    pub content: Vec<u8>,
}

impl TestMessage {
    pub fn new(commitment: impl Into<Vec<u8>>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            commitment: commitment.into(),
            content: content.into(),
        }
    }

    pub fn shared(msg: impl Into<Vec<u8>>) -> Self {
        let msg = msg.into();
        Self::new(msg.clone(), msg)
    }
}

impl Digestible for TestMessage {
    type Digest = Digest;
    fn digest(&self) -> Digest {
        Sha256::hash(&self.content)
    }
}

impl Write for TestMessage {
    fn write(&self, buf: &mut impl BufMut) {
        self.commitment.write(buf);
        self.content.write(buf);
    }
}

impl EncodeSize for TestMessage {
    fn encode_size(&self) -> usize {
        self.commitment.encode_size() + self.content.encode_size()
    }
}

impl Read for TestMessage {
    type Cfg = RangeCfg<usize>;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        let commitment = Vec::<u8>::read_range(buf, *range)?;
        let content = Vec::<u8>::read_range(buf, *range)?;
        Ok(Self {
            commitment,
            content,
        })
    }
}

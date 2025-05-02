//! Mock implementations for testing.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, ReadRangeExt, Write};
use commonware_cryptography::{hash, sha256::Digest, Committable, Digestible};

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

impl Digestible<Digest> for TestMessage {
    fn digest(&self) -> Digest {
        hash(&self.content)
    }
}

impl Committable<Digest> for TestMessage {
    fn commitment(&self) -> Digest {
        hash(&self.commitment)
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
    type Cfg = RangeCfg;

    fn read_cfg(buf: &mut impl Buf, range: &Self::Cfg) -> Result<Self, CodecError> {
        let commitment = Vec::<u8>::read_range(buf, *range)?;
        let content = Vec::<u8>::read_range(buf, *range)?;
        Ok(Self {
            commitment,
            content,
        })
    }
}

//! Mock implementations for testing.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeConfig, Read, ReadRangeExt, Write};
use commonware_cryptography::{hash, sha256::Digest, Digestible, Identifiable};

/// A simple test message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestMessage {
    // The identity of the message.
    pub identity: Vec<u8>,

    /// The content of the message.
    pub content: Vec<u8>,
}

impl TestMessage {
    pub fn new(identity: impl Into<Vec<u8>>, content: impl Into<Vec<u8>>) -> Self {
        Self {
            identity: identity.into(),
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

impl Identifiable<Digest> for TestMessage {
    fn identity(&self) -> Digest {
        hash(&self.identity)
    }
}

impl Write for TestMessage {
    fn write(&self, buf: &mut impl BufMut) {
        self.content.write(buf);
    }
}

impl EncodeSize for TestMessage {
    fn encode_size(&self) -> usize {
        self.content.encode_size()
    }
}

impl<R: RangeConfig> Read<R> for TestMessage {
    fn read_cfg(buf: &mut impl Buf, range: &R) -> Result<Self, CodecError> {
        let identity = Vec::<u8>::read_range(buf, range.clone())?;
        let content = Vec::<u8>::read_range(buf, range.clone())?;
        Ok(Self { identity, content })
    }
}

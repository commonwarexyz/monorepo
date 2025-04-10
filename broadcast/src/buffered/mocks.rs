//! Mock implementations for testing.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, Read, ReadRangeExt, Write};
use commonware_cryptography::{
    sha256::{Digest as Sha256Digest, Sha256},
    Digestible, Hasher,
};

/// A simple test message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestMessage {
    /// The content of the message.
    pub content: Vec<u8>,
}

impl TestMessage {
    /// Create a new test message with the given content.
    pub fn new(content: impl Into<Vec<u8>>) -> Self {
        Self {
            content: content.into(),
        }
    }
}

impl Digestible<Sha256Digest> for TestMessage {
    fn digest(&self) -> Sha256Digest {
        let mut hasher = Sha256::default();
        hasher.update(&self.content);
        hasher.finalize()
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

impl Read for TestMessage {
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let content = Vec::<u8>::read_range(buf, ..)?;
        Ok(Self { content })
    }
}

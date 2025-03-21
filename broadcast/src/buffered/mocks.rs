//! Mock implementations for testing.

use bytes::{Buf, BufMut};
use commonware_codec::{Codec, Error as CodecError};
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

impl Codec for TestMessage {
    fn write<B: BufMut>(&self, buf: &mut B) {
        self.content.write(buf);
    }

    fn read<B: Buf>(buf: &mut B) -> Result<Self, CodecError> {
        let content = Vec::<u8>::read(buf)?;
        Ok(Self { content })
    }

    fn len_encoded(&self) -> usize {
        self.content.len_encoded()
    }
}

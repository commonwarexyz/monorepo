//! Mock implementations for testing.

use commonware_codec::Codec;
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
    fn write(&self, writer: &mut impl commonware_codec::Writer) {
        self.content.write(writer);
    }

    fn read(reader: &mut impl commonware_codec::Reader) -> Result<Self, commonware_codec::Error> {
        let content = Vec::<u8>::read(reader)?;
        Ok(Self { content })
    }

    fn len_encoded(&self) -> usize {
        self.content.len_encoded()
    }
}

//! Mock implementations for testing.

use bytes::{Buf, BufMut};
use commonware_codec::{Decode, Encode, Error as CodecError};
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

impl Encode for TestMessage {
    fn len_encoded(&self) -> usize {
        self.content.len_encoded()
    }

    fn write(&self, buf: &mut impl BufMut) {
        self.content.write(buf);
    }
}

impl Decode<()> for TestMessage {
    fn read(buf: &mut impl Buf, _: ()) -> Result<Self, CodecError> {
        let content = Vec::<u8>::read(buf, (.., ()))?;
        Ok(Self { content })
    }
}

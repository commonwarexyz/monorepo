//! Mock implementations for testing.

use crate::buffered::{Digestible, Error, Serializable};
use commonware_cryptography::sha256::{Digest as Sha256Digest, Sha256};
use commonware_cryptography::Hasher;

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

impl Serializable for TestMessage {
    fn serialize(&self) -> Vec<u8> {
        self.content.clone()
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self {
            content: bytes.to_vec(),
        })
    }
}

//! Mock implementations for testing.

use commonware_codec::{EncodeSize, RangeCfg, Read, Write};
use commonware_cryptography::{Digestible, Hasher, Sha256, sha256::Digest};

/// A simple test message.
#[derive(Debug, Clone, PartialEq, Eq, Write, EncodeSize, Read)]
#[read_cfg(RangeCfg<usize>)]
pub struct TestMessage {
    // The commitment of the message.
    #[codec(cfg = &(*cfg, ()))]
    pub commitment: Vec<u8>,

    /// The content of the message.
    #[codec(cfg = &(*cfg, ()))]
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
        Sha256::hash(&[&self.content])
    }
}

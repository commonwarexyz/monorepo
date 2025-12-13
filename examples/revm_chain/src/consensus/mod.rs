mod application;
mod mailbox;
mod messages;
mod store;

pub use application::Application;
pub use mailbox::Mailbox;
pub use messages::Message;

use commonware_cryptography::{ed25519, sha256};

pub type ConsensusDigest = sha256::Digest;
pub type PublicKey = ed25519::PublicKey;
pub type FinalizationEvent = (u32, ConsensusDigest);

#[derive(Clone, Copy, Debug)]
pub struct BlockCodecCfg {
    pub max_txs: usize,
    pub max_calldata_bytes: usize,
}

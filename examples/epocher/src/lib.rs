use crate::types::block::Block;
use commonware_consensus::types::Round;
use commonware_cryptography::sha256::Digest;

pub mod application;
pub mod forwarder;
pub mod orchestrator;
pub mod poller;
pub mod supervisor;
pub mod types;

// Parameters for the network

/// The namespace for the network
pub const NAMESPACE: &[u8] = b"EPOCHER";
/// The total number of validators in the network
pub const TOTAL_VALIDATORS: u32 = 10;
/// The number of active validators in the network
pub const ACTIVE_VALIDATORS: u32 = 4;
/// The threshold for the network
pub const THRESHOLD: u32 = 3;
/// Genesis round.
pub const GENESIS_ROUND: Round = Round::new(0, 0);
/// Genesis block.
pub const GENESIS_BLOCK: Block = Block::new(Digest([0; 32]), 0, 0);
/// Number of blocks per epoch.
pub const BLOCKS_PER_EPOCH: u64 = 100;

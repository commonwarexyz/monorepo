pub mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

/// Unique namespace to avoid message replay attacks.
pub const P2P_SUFFIX: &[u8] = b"_P2P";
pub const CONSENSUS_SUFFIX: &[u8] = b"_CONSENSUS";
pub const INDEXER_NAMESPACE: &[u8] = b"_COMMONWARE_INDEXER";

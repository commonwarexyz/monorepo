use crate::Indexer;
use commonware_cryptography::{bls12381::primitives::group, ed25519::PublicKey};
use commonware_resolver::p2p::Coordinator;
use commonware_utils::Array;
use governor::Quota;

/// Configuration for the syncer.
pub struct Config<P: Array, I: Indexer, D: Coordinator<PublicKey = P>> {
    pub partition_prefix: String,

    pub public_key: PublicKey,

    /// Network identity
    pub identity: group::Public,

    /// Coordinator managing the set of peers.
    pub coordinator: D,

    /// Number of messages from consensus to hold in our backlog
    /// before blocking.
    pub mailbox_size: usize,

    pub backfill_quota: Quota,

    pub activity_timeout: u64,

    pub indexer: Option<I>,
}

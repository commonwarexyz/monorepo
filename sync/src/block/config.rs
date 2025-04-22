use crate::{Indexer, OrderedData};
use commonware_cryptography::bls12381::primitives::group;
use std::time::Duration;

/// Configuration for the [`Engine`].
#[derive(Clone, Debug)]
pub struct Config<D: OrderedData, I: Indexer<D>> {
    /// Unique prefix for all storage partitions created by the engine.
    pub partition_prefix: String,

    /// The network's identity.
    pub identity: group::Public,

    /// Buffered mailbox depth before producers are back‑pressured.
    pub mailbox_size: usize,

    /// How long the actor may remain idle before it force-syncs with the network (i.e. polls for new data).
    pub activity_timeout: Duration,

    /// Optional external indexer that receives every contiguous object.
    pub indexer: Option<I>,
}

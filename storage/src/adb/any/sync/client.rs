use super::Error;
use crate::{
    adb::{
        operation::Fixed,
        sync::{
            engine::{SyncTarget, SyncTargetUpdateReceiver},
            resolver::Resolver,
        },
    },
    mmr,
    translator::Translator,
};
use commonware_cryptography::Hasher;
use commonware_runtime::{Clock, Metrics as MetricsTrait, Storage};
use commonware_utils::Array;
use std::num::NonZeroU64;

/// Configuration for the sync client
pub struct Config<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    /// Context for the database.
    pub context: E,

    /// Channel for receiving target updates.
    pub update_receiver: Option<SyncTargetUpdateReceiver<H::Digest>>,

    /// Database configuration.
    pub db_config: crate::adb::any::Config<T>,

    /// Maximum operations to fetch per batch.
    pub fetch_batch_size: NonZeroU64,

    /// Synchronization target (root digest and operation bounds).
    pub target: SyncTarget<H::Digest>,

    /// Resolves requests for proofs and operations.
    pub resolver: R,

    /// Hasher for root digests.
    pub hasher: mmr::hasher::Standard<H>,

    /// The maximum number of operations to keep in memory
    /// before committing the database while applying operations.
    /// Higher value will cause more memory usage during sync.
    pub apply_batch_size: usize,

    /// Maximum number of outstanding requests for operation batches.
    /// Higher values increase parallelism.
    pub max_outstanding_requests: usize,
}

impl<E, K, V, H, T, R> Config<E, K, V, H, T, R>
where
    E: Storage + Clock + MetricsTrait,
    K: Array,
    V: Array,
    H: Hasher,
    T: Translator,
    R: Resolver<Digest = H::Digest, Op = Fixed<K, V>>,
{
    /// Validate the configuration parameters
    pub fn validate(&self) -> Result<(), Error> {
        // Validate bounds (inclusive)
        if self.target.lower_bound_ops > self.target.upper_bound_ops {
            return Err(Error::InvalidTarget {
                lower_bound_pos: self.target.lower_bound_ops,
                upper_bound_pos: self.target.upper_bound_ops,
            });
        }
        Ok(())
    }
}

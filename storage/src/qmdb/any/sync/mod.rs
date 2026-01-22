//! Shared synchronization logic for any databases.
pub(crate) mod impls;

#[cfg(test)]
pub(crate) mod tests;

use crate::{
    index,
    mmr::journaled::Config as MmrConfig,
    qmdb::any::{FixedConfig, VariableConfig},
    translator::Translator,
};
use commonware_runtime::Metrics;

/// Database configurations that support sync operations.
///
/// Both `FixedConfig` and `VariableConfig` implement this trait,
/// allowing the sync implementation to extract common configuration
/// without knowing the specific config type.
pub trait Config: Clone {
    /// Extract the MMR configuration for sync initialization.
    fn mmr_config(&self) -> MmrConfig;
}

impl<T: Translator + Clone> Config for FixedConfig<T> {
    fn mmr_config(&self) -> MmrConfig {
        MmrConfig {
            journal_partition: self.mmr_journal_partition.clone(),
            metadata_partition: self.mmr_metadata_partition.clone(),
            items_per_blob: self.mmr_items_per_blob,
            write_buffer: self.mmr_write_buffer,
            thread_pool: self.thread_pool.clone(),
            buffer_pool: self.buffer_pool.clone(),
        }
    }
}

impl<T: Translator + Clone, C: Clone> Config for VariableConfig<T, C> {
    fn mmr_config(&self) -> MmrConfig {
        MmrConfig {
            journal_partition: self.mmr_journal_partition.clone(),
            metadata_partition: self.mmr_metadata_partition.clone(),
            items_per_blob: self.mmr_items_per_blob,
            write_buffer: self.mmr_write_buffer,
            thread_pool: self.thread_pool.clone(),
            buffer_pool: self.buffer_pool.clone(),
        }
    }
}

/// Indexes that can be constructed during sync operations.
///
/// Both `ordered::Index` and `unordered::Index` have the same
/// constructor signature: `fn new(ctx: impl Metrics, translator: T)`
pub trait Index: Sized {
    type Translator: crate::translator::Translator + Clone;
    /// Create a new index for use during sync.
    fn new(ctx: impl Metrics, translator: Self::Translator) -> Self;
}

impl<T: Translator, V: Eq + Send + Sync> crate::qmdb::any::sync::Index
    for index::unordered::Index<T, V>
{
    type Translator = T;
    fn new(ctx: impl Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

impl<T: Translator, V: Eq + Send + Sync> crate::qmdb::any::sync::Index
    for index::ordered::Index<T, V>
{
    type Translator = T;
    fn new(ctx: impl Metrics, translator: T) -> Self {
        Self::new(ctx, translator)
    }
}

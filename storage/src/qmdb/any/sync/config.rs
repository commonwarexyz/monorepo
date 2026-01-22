use crate::{
    mmr::journaled::Config as MmrConfig,
    qmdb::any::{FixedConfig, VariableConfig},
    translator::Translator,
};

/// Configuration used by a [crate::qmdb::any::db::Db].
pub trait Config: Clone {
    /// Return the MMR configuration.
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

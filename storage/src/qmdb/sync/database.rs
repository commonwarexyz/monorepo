use crate::{mmr::Location, qmdb::sync::Journal, translator::Translator};
use commonware_cryptography::Digest;
use std::{future::Future, ops::Range};

pub trait Config {
    type JournalConfig;
    fn journal_config(&self) -> Self::JournalConfig;
}

impl<T: Translator> Config for crate::qmdb::any::FixedConfig<T> {
    type JournalConfig = crate::journal::contiguous::fixed::Config;

    fn journal_config(&self) -> Self::JournalConfig {
        crate::journal::contiguous::fixed::Config {
            partition: self.log_journal_partition.clone(),
            items_per_blob: self.log_items_per_blob,
            write_buffer: self.log_write_buffer,
            page_cache: self.page_cache.clone(),
        }
    }
}

impl<T: Translator, C: Clone> Config for crate::qmdb::any::VariableConfig<T, C> {
    type JournalConfig = crate::journal::contiguous::variable::Config<C>;

    fn journal_config(&self) -> Self::JournalConfig {
        crate::journal::contiguous::variable::Config {
            items_per_section: self.log_items_per_blob,
            partition: self.log_partition.clone(),
            compression: self.log_compression,
            codec_config: self.log_codec_config.clone(),
            page_cache: self.page_cache.clone(),
            write_buffer: self.log_write_buffer,
        }
    }
}

impl<T: Translator, C: Clone> Config for crate::qmdb::immutable::Config<T, C> {
    type JournalConfig = crate::journal::contiguous::variable::Config<C>;

    fn journal_config(&self) -> Self::JournalConfig {
        crate::journal::contiguous::variable::Config {
            items_per_section: self.log_items_per_section,
            partition: self.log_partition.clone(),
            compression: self.log_compression,
            codec_config: self.log_codec_config.clone(),
            page_cache: self.page_cache.clone(),
            write_buffer: self.log_write_buffer,
        }
    }
}
pub trait Database: Sized + Send {
    type Op: Send;
    type Journal: Journal<Context = Self::Context, Op = Self::Op>;
    type Config: Config<JournalConfig = <Self::Journal as Journal>::Config>;
    type Digest: Digest;
    type Context: commonware_runtime::Storage
        + commonware_runtime::Clock
        + commonware_runtime::Metrics;
    type Hasher: commonware_cryptography::Hasher<Digest = Self::Digest>;

    /// Build a database from the journal and pinned nodes populated by the sync engine.
    fn from_sync_result(
        context: Self::Context,
        config: Self::Config,
        journal: Self::Journal,
        pinned_nodes: Option<Vec<Self::Digest>>,
        range: Range<Location>,
        apply_batch_size: usize,
    ) -> impl Future<Output = Result<Self, crate::qmdb::Error>> + Send;

    /// Get the root digest of the database for verification
    fn root(&self) -> Self::Digest;
}

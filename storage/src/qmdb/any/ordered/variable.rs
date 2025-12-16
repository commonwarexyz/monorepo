//! An authenticated database that provides succinct proofs of _any_ value ever associated
//! with a key, maintains a next-key ordering for each active key, and allows values to have
//! variable sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::qmdb::any::ordered::fixed]
//! instead for better performance._

use super::operation::VariableOperation as Operation;
use crate::{
    index::ordered::Index,
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal},
    },
    mmr::{journaled::Config as MmrConfig, mem::Clean, Location},
    qmdb::{
        any::{ordered::IndexedLog, VariableConfig, VariableValue},
        operation::Committable as _,
        Error,
    },
    translator::Translator,
};
use commonware_codec::Read;
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;
use tracing::warn;

/// A key-value QMDB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Any<E, K, V, H, T, S = Clean<DigestOf<H>>> =
    IndexedLog<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, S>;

impl<E: Storage + Clock + Metrics, K: Array, V: VariableValue, H: Hasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns an [Any] QMDB initialized from `cfg`. Any uncommitted log operations will be
    /// discarded and the state of the db will be as of the last committed operation.
    pub async fn init(
        context: E,
        cfg: VariableConfig<T, <Operation<K, V> as Read>::Cfg>,
    ) -> Result<Self, Error> {
        let mmr_config = MmrConfig {
            journal_partition: cfg.mmr_journal_partition,
            metadata_partition: cfg.mmr_metadata_partition,
            items_per_blob: cfg.mmr_items_per_blob,
            write_buffer: cfg.mmr_write_buffer,
            thread_pool: cfg.thread_pool,
            buffer_pool: cfg.buffer_pool.clone(),
        };

        let journal_config = JournalConfig {
            partition: cfg.log_partition,
            items_per_section: cfg.log_items_per_blob,
            compression: cfg.log_compression,
            codec_config: cfg.log_codec_config,
            buffer_pool: cfg.buffer_pool,
            write_buffer: cfg.log_write_buffer,
        };

        let mut log = authenticated::Journal::<_, Journal<_, _>, _, _>::new(
            context.with_label("log"),
            mmr_config,
            journal_config,
            Operation::is_commit,
        )
        .await?;
        if log.size() == 0 {
            warn!("Authenticated log is empty, initializing new db");
            log.append(Operation::CommitFloor(None, Location::new_unchecked(0)))
                .await?;
            log.sync().await?;
        }

        let index = Index::new(context.with_label("index"), cfg.translator);
        let log = Self::init_from_log(index, log, None, |_, _| {}).await?;

        Ok(log)
    }
}

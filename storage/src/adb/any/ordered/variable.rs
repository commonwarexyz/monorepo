//! An authenticated database (ADB) that provides succinct proofs of _any_ value ever associated
//! with a key, where values can have varying sizes.
//!
//! _If the values you wish to store all have the same size, use [crate::adb::any::ordered::fixed]
//! instead for better performance._

use crate::{
    adb::{
        any::{
            ordered::{IndexedLog, Operation as OperationTrait},
            VariableConfig,
        },
        operation::{variable::ordered::Operation, Committable as _, KeyData},
        Error,
    },
    index::ordered::Index,
    journal::{
        authenticated,
        contiguous::variable::{Config as JournalConfig, Journal},
    },
    mmr::{
        journaled::Config as MmrConfig,
        mem::{Clean, State},
        Location,
    },
    translator::Translator,
};
use commonware_codec::{Codec, Read};
use commonware_cryptography::{DigestOf, Hasher};
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::Array;

impl<K: Array, V: Codec> OperationTrait for Operation<K, V> {
    fn new_update(key: K, value: V, next_key: K) -> Self {
        Self::Update(KeyData {
            key,
            value,
            next_key,
        })
    }

    fn new_delete(key: K) -> Self {
        Self::Delete(key)
    }

    fn new_commit_floor(location: Location) -> Self {
        Self::CommitFloor(None, location)
    }

    fn key_data(&self) -> Option<&KeyData<K, V>> {
        match self {
            Self::Update(key_data) => Some(key_data),
            _ => None,
        }
    }

    fn into_key_data(self) -> Option<KeyData<K, V>> {
        match self {
            Self::Update(key_data) => Some(key_data),
            _ => None,
        }
    }
}

/// A key-value ADB based on an authenticated log of operations, supporting authentication of any
/// value ever associated with a key.
pub type Any<E, K, V, H, T, S = Clean<DigestOf<H>>> =
    IndexedLog<E, Journal<E, Operation<K, V>>, Index<T, Location>, H, S>;

impl<
        E: Storage + Clock + Metrics,
        K: Array,
        V: Codec,
        H: Hasher,
        T: Translator,
        S: State<DigestOf<H>>,
    > Any<E, K, V, H, T, S>
{
    /// Get the location and metadata associated with the last commit, or None if no commit has been
    /// made.
    ///
    /// # Errors
    ///
    /// Returns Error if there is some underlying storage failure.
    pub async fn get_metadata(&self) -> Result<Option<(Location, Option<V>)>, Error> {
        let Some(last_commit) = self.last_commit else {
            return Ok(None);
        };

        let Operation::CommitFloor(metadata, _) = self.log.read(last_commit).await? else {
            unreachable!("last commit should be a commit floor operation");
        };

        Ok(Some((last_commit, metadata)))
    }
}

impl<E: Storage + Clock + Metrics, K: Array, V: Codec, H: Hasher, T: Translator>
    Any<E, K, V, H, T>
{
    /// Returns an [Any] adb initialized from `cfg`. Any uncommitted log operations will be
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

        let log =
            authenticated::Journal::<E, Journal<E, Operation<K, V>>, H, Clean<DigestOf<H>>>::new(
                context.with_label("log"),
                mmr_config,
                journal_config,
                Operation::<K, V>::is_commit,
            )
            .await?;

        let index = Index::new(context.with_label("index"), cfg.translator);
        let log = IndexedLog::init_from_log(index, log, None, |_, _| {}).await?;

        Ok(log)
    }

    /// A version of commit that allows specifying metadata with the operation that can be retrieved
    /// with [Self::get_metadata] so long as it remains the last commit.
    pub async fn commit(&mut self, metadata: Option<V>) -> Result<(), Error> {
        // Raise the inactivity floor by taking `self.steps` steps, plus 1 to account for the
        // previous commit becoming inactive.
        let inactivity_floor_loc = self.raise_floor().await?;

        self.apply_commit_op(Operation::CommitFloor(metadata, inactivity_floor_loc))
            .await
    }
}

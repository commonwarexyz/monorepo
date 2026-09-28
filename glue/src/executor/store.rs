//! The executed chain's archive and its applied cursor. Until a state sync gives the chain a
//! base, the archive holds only the blocks offered as its targets.
//!
//! A storage failure is fatal: the executor stops instead of continuing with a store whose state
//! it no longer knows.

use super::Start;
use commonware_codec::Codec;
use commonware_consensus::{Block, types::Height};
use commonware_runtime::buffer::paged::CacheRef;
use commonware_storage::{
    Context,
    archive::{Archive as _, Identifier, prunable},
    metadata::{self, Metadata},
    translator::Translator,
};
use commonware_utils::{fixed_bytes, sequence::FixedBytes};
use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
};

/// Key of the applied cursor in its metadata partition.
const APPLIED: FixedBytes<1> = fixed_bytes!("00");

/// Storage configuration of the executed chain.
#[derive(Clone)]
pub struct StoreConfig<T: Translator, C> {
    /// Prefix of the archive and cursor partitions.
    pub partition_prefix: String,
    /// Maps block digests to the archive's key index.
    pub translator: T,
    /// Page cache of the archive's key journal.
    pub page_cache: CacheRef,
    /// Blocks per archive section, the granularity of pruning.
    pub items_per_section: NonZeroU64,
    /// Bytes buffered per archive journal before writing.
    pub write_buffer: NonZeroUsize,
    /// Bytes read at once when replaying the archive.
    pub replay_buffer: NonZeroUsize,
    /// Codec configuration of executed blocks.
    pub codec_config: C,
}

/// What an opened [`Store`] holds.
pub(super) enum Opened<B> {
    /// The newest block the consumer applied, which execution resumes from.
    Applied(B),
    /// No base yet: the chain waits for a state sync, toward the recorded target if any.
    Syncing(Option<B>),
}

/// The executed chain, keyed by height and digest, and the highest height its consumer applied.
pub(super) struct Store<E, T, B>
where
    E: Context,
    T: Translator,
    B: Block + Codec,
{
    archive: Option<prunable::Archive<T, E, B::Digest, B>>,
    cursor: Option<Metadata<E, FixedBytes<1>, Height>>,
    applied: Height,
}

impl<E, T, B> Store<E, T, B>
where
    E: Context,
    T: Translator,
    B: Block + Codec,
{
    /// Opens the store. An empty chain archives `genesis` as its applied block when starting from
    /// [`Start::Genesis`], and waits for a state sync otherwise.
    pub(super) async fn init<G>(
        context: E,
        config: StoreConfig<T, B::Cfg>,
        start: Start,
        genesis: impl FnOnce() -> G,
    ) -> (Self, Opened<B>)
    where
        G: Future<Output = B>,
    {
        let prefix = config.partition_prefix;
        let archive = prunable::Archive::init(
            context.child("archive"),
            prunable::Config {
                translator: config.translator,
                metadata_partition: format!("{prefix}_executed_metadata"),
                key_partition: format!("{prefix}_executed_keys"),
                key_page_cache: config.page_cache,
                value_partition: format!("{prefix}_executed_values"),
                compression: None,
                codec_config: config.codec_config,
                items_per_section: config.items_per_section,
                key_write_buffer: config.write_buffer,
                value_write_buffer: config.write_buffer,
                replay_buffer: config.replay_buffer,
            },
        )
        .await
        .expect("failed to open executed chain");
        let cursor = Metadata::init(
            context.child("cursor"),
            metadata::Config {
                partition: format!("{prefix}_applied"),
                codec_config: (),
            },
        )
        .await
        .expect("failed to open applied cursor");
        let applied = cursor.get(&APPLIED).copied();
        let mut store = Self {
            archive: Some(archive),
            cursor: Some(cursor),
            applied: applied.unwrap_or_default(),
        };
        if applied.is_some() {
            let tip = store
                .get(store.applied)
                .await
                .expect("applied block is missing from the executed chain");
            return (store, Opened::Applied(tip));
        }
        // Without an applied cursor, the archive holds the genesis block a crash left before
        // recording it, or the blocks offered as sync targets, the newest of which resumes the
        // sync.
        let archived = match store.archive().last_index() {
            Some(height) => Some(
                store
                    .get(Height::new(height))
                    .await
                    .expect("archived block is retained"),
            ),
            None => None,
        };
        match (start, archived) {
            (Start::Genesis, archived)
                if archived
                    .as_ref()
                    .is_none_or(|block| block.height().is_zero()) =>
            {
                let genesis = genesis().await;
                assert!(
                    genesis.height().is_zero(),
                    "genesis block must be at height zero"
                );
                match archived {
                    None => store.put(&genesis).await,
                    Some(archived) => assert_eq!(
                        archived.digest(),
                        genesis.digest(),
                        "executed chain holds a block other than genesis without an applied cursor"
                    ),
                }
                store.apply(Height::zero()).await;
                (store, Opened::Applied(genesis))
            }
            (_, target) => (store, Opened::Syncing(target)),
        }
    }

    const fn archive(&self) -> &prunable::Archive<T, E, B::Digest, B> {
        self.archive.as_ref().expect("executed chain is open")
    }

    /// Makes every archived block durable.
    async fn sync_archive(&mut self) {
        let archive = self.archive.take().expect("executed chain is open");
        let archive = archive.sync().await.expect("failed to sync executed chain");
        self.archive = Some(archive);
    }

    /// Returns the highest height the consumer applied.
    pub(super) const fn applied(&self) -> Height {
        self.applied
    }

    /// Returns the archived block at `height`, if retained.
    pub(super) async fn get(&self, height: Height) -> Option<B> {
        self.archive()
            .get(Identifier::Index(height.get()))
            .await
            .expect("failed to read executed chain")
    }

    /// Buffers `block` at its height. A block already archived at that height is kept.
    pub(super) async fn put(&mut self, block: &B) {
        let archive = self.archive.take().expect("executed chain is open");
        let archive = archive
            .put(block.height().get(), block.digest(), block)
            .await
            .expect("failed to archive executed block");
        self.archive = Some(archive);
    }

    /// Makes every archived block durable, then durably records that the consumer applied
    /// through `height`.
    pub(super) async fn apply(&mut self, height: Height) {
        self.sync_archive().await;
        let cursor = self.cursor.take().expect("applied cursor is open");
        let cursor = cursor
            .put_sync(APPLIED, height)
            .await
            .expect("failed to record applied height");
        self.cursor = Some(cursor);
        self.applied = height;
    }

    /// Durably records `target` as the block a state sync targets.
    pub(super) async fn record_target(&mut self, target: &B) {
        self.put(target).await;
        self.sync_archive().await;
    }

    /// Prunes blocks below `below`. The applied block is always retained.
    pub(super) async fn prune(&mut self, below: Height) {
        let below = below.min(self.applied);
        let archive = self.archive.take().expect("executed chain is open");
        let archive = archive
            .prune(below.get())
            .await
            .expect("failed to prune executed chain");
        self.archive = Some(archive);
    }
}

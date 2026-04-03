use crate::simulate::processed::ProcessedHeight;
use commonware_consensus::{
    marshal::{self, core::Variant, Identifier as MarshalIdentifier},
    simplex::mocks::scheme::Scheme as MockScheme,
    types::Height,
    Heightable,
};
use commonware_cryptography::{ed25519, sha256, Digestible};
use commonware_runtime::{buffer::paged::CacheRef, Clock, Metrics, Quota, Storage};
use commonware_storage::{
    archive::immutable,
    metadata::{Config as MetadataConfig, Metadata},
};
use commonware_utils::{sequence::U64, sync::Mutex, NZUsize, NZU16, NZU64};
use std::{
    collections::{BTreeMap, HashMap},
    num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

pub(super) const EPOCH_LENGTH: NonZeroU64 = NZU64!(u64::MAX);
pub(super) const NAMESPACE: &[u8] = b"stateful_e2e_test";
pub(super) const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
pub(super) const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);
pub(super) const IO_BUFFER_SIZE: NonZeroUsize = NZUsize!(2048);
pub(super) const TEST_QUOTA: Quota = Quota::per_second(NonZeroU32::MAX);

pub(super) fn u64_to_digest(v: u64) -> sha256::Digest {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&v.to_be_bytes());
    sha256::Digest::from(bytes)
}

pub(super) fn digest_to_u64(d: &sha256::Digest) -> u64 {
    let bytes: &[u8] = d.as_ref();
    u64::from_be_bytes(bytes[..8].try_into().unwrap())
}

pub(super) fn archive_config<C>(
    prefix: &str,
    name: &str,
    page_cache: CacheRef,
    codec_config: C,
) -> immutable::Config<C> {
    immutable::Config {
        metadata_partition: format!("{prefix}-{name}-metadata"),
        freezer_table_partition: format!("{prefix}-{name}-freezer-table"),
        freezer_table_initial_size: 64,
        freezer_table_resize_frequency: 10,
        freezer_table_resize_chunk_size: 10,
        freezer_key_partition: format!("{prefix}-{name}-freezer-key"),
        freezer_key_page_cache: page_cache,
        freezer_value_partition: format!("{prefix}-{name}-freezer-value"),
        freezer_value_target_size: 1024,
        freezer_value_compression: None,
        ordinal_partition: format!("{prefix}-{name}-ordinal"),
        items_per_section: NZU64!(10),
        codec_config,
        replay_buffer: IO_BUFFER_SIZE,
        freezer_key_write_buffer: IO_BUFFER_SIZE,
        freezer_value_write_buffer: IO_BUFFER_SIZE,
        ordinal_write_buffer: IO_BUFFER_SIZE,
    }
}

/// Per-validator state inspectable by test properties.
///
/// Generic over the marshal variant so both single-db and multi-db engines
/// can share the same state type and property implementations.
#[derive(Clone)]
pub(crate) struct MockValidatorState<V: Variant> {
    pub(super) marshal: marshal::core::Mailbox<MockScheme<ed25519::PublicKey>, V>,
    pub(super) startup_sync_height: Option<u64>,
}

impl<V: Variant> PartialEq for MockValidatorState<V> {
    fn eq(&self, other: &Self) -> bool {
        self.startup_sync_height == other.startup_sync_height
    }
}

impl<V> MockValidatorState<V>
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
{
    pub(crate) async fn digest_at_height(&self, height: u64) -> Option<sha256::Digest> {
        self.marshal
            .get_block(MarshalIdentifier::Height(Height::new(height)))
            .await
            .map(|b| b.digest())
    }

    pub(crate) const fn startup_sync_height(&self) -> Option<u64> {
        self.startup_sync_height
    }
}

pub(super) type MarshalMailboxOf<V> = marshal::core::Mailbox<MockScheme<ed25519::PublicKey>, V>;

/// Poll peers for a majority-agreed sync target block.
pub(super) async fn fetch_majority_sync_target<V>(
    mailboxes: &Arc<Mutex<BTreeMap<ed25519::PublicKey, MarshalMailboxOf<V>>>>,
    context: &impl Clock,
    me: &ed25519::PublicKey,
) -> Option<V::Block>
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
{
    for _ in 0..20 {
        let peers_mailboxes: Vec<MarshalMailboxOf<V>> = {
            let guard = mailboxes.lock();
            guard
                .iter()
                .filter(|(peer, _)| *peer != me)
                .map(|(_, mailbox)| mailbox.clone())
                .collect()
        };

        // Collect latest heights from all peers.
        let mut peers: Vec<(MarshalMailboxOf<V>, Height)> = Vec::new();
        for mailbox in peers_mailboxes {
            if let Some(height) = mailbox
                .get_block(MarshalIdentifier::Latest)
                .await
                .map(|b| b.height())
            {
                peers.push((mailbox, height));
            }
        }
        if peers.is_empty() {
            context.sleep(Duration::from_millis(100)).await;
            continue;
        }

        // Find the highest height that a majority of peers have reached.
        let required = peers.len() / 2 + 1;
        let mut heights: Vec<Height> = peers.iter().map(|(_, h)| *h).collect();
        heights.sort();
        let quorum_height = heights[heights.len() - required];

        // Count digests at quorum height and return the first block with majority agreement.
        let mut counts: HashMap<sha256::Digest, (usize, MarshalMailboxOf<V>)> = HashMap::new();
        for (mailbox, h) in &peers {
            if *h < quorum_height {
                continue;
            }
            if let Some(digest) = mailbox
                .get_block(MarshalIdentifier::Height(quorum_height))
                .await
                .map(|b| b.digest())
            {
                counts
                    .entry(digest)
                    .and_modify(|(c, _)| *c += 1)
                    .or_insert((1, mailbox.clone()));
            }
        }
        for (digest, (count, mailbox)) in counts {
            if count >= required {
                if let Some(block) = mailbox.get_block(MarshalIdentifier::Digest(digest)).await {
                    return Some(block);
                }
            }
        }

        context.sleep(Duration::from_millis(100)).await;
    }
    None
}

const STATE_SYNC_METADATA_SUFFIX: &str = "_state_sync_metadata";
const SYNC_DONE_KEY: U64 = U64::new(0);

/// Check whether state sync has already completed for this validator.
pub(super) async fn state_sync_done(
    context: &(impl Storage + Clock + Metrics),
    partition_prefix: &str,
) -> bool {
    let metadata = Metadata::<_, U64, bool>::init(
        context.clone(),
        MetadataConfig {
            partition: format!("{partition_prefix}{STATE_SYNC_METADATA_SUFFIX}"),
            codec_config: (),
        },
    )
    .await
    .expect("failed to read state sync metadata");
    metadata.get(&SYNC_DONE_KEY).copied().unwrap_or(false)
}

impl<V> ProcessedHeight for MockValidatorState<V>
where
    V: Variant,
    V::ApplicationBlock: Digestible<Digest = sha256::Digest>,
{
    async fn processed_height(&self) -> u64 {
        self.marshal
            .get_processed_height()
            .await
            .map_or(0, |height| height.get())
    }
}

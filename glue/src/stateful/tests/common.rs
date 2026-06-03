use crate::simulate::processed::ProcessedHeight;
use commonware_consensus::{
    marshal::{self, core::Variant, Identifier as MarshalIdentifier},
    simplex::mocks::scheme::Scheme as MockScheme,
    types::Height,
};
use commonware_cryptography::{ed25519, sha256, Digestible};
use commonware_runtime::{buffer::paged::CacheRef, Quota};
use commonware_storage::archive::immutable;
use commonware_utils::{NZUsize, NZU16, NZU64};
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64, NonZeroUsize};

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
    pub(super) state_sync_entries: u64,
    pub(super) state_sync_height: Option<u64>,
}

impl<V: Variant> PartialEq for MockValidatorState<V> {
    fn eq(&self, other: &Self) -> bool {
        self.state_sync_entries == other.state_sync_entries
            && self.state_sync_height == other.state_sync_height
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

    pub(crate) const fn state_sync_height(&self) -> Option<u64> {
        self.state_sync_height
    }

    pub(crate) const fn state_sync_entries(&self) -> u64 {
        self.state_sync_entries
    }
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
